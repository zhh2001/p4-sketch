#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> IP_PROTOCOL_TCP = 6;
const bit<8> IP_PROTOCOL_UDP = 17;
const bit<8> SKETCH_SALT0 = 0x11;
const bit<8> SKETCH_SALT1 = 0x37;
const bit<8> SKETCH_SALT2 = 0x9d;

typedef bit<48> mac_addr_t;

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<3> reserved;
    bit<9> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata_t {
    bit<32> estimate;
    bit<32> threshold;
    bit<1> is_heavy;
}

parser ParserImpl(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.flags[0:0],
            hdr.ipv4.frag_offset,
            hdr.ipv4.protocol)
        {
            (4, 5, 0, 0, IP_PROTOCOL_TCP): parse_tcp;
            (4, 5, 0, 0, IP_PROTOCOL_UDP): parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control VerifyChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid() &&
                hdr.ipv4.version == 4 && hdr.ipv4.ihl == 5,
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control IngressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    register<bit<32>>(256) sketch_row0;
    register<bit<32>>(256) sketch_row1;
    register<bit<32>>(256) sketch_row2;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_addr_t dst_mac, mac_addr_t src_mac, bit<9> port) {
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ethernet.src_addr = src_mac;
        standard_metadata.egress_spec = port;
    }

    action set_threshold(bit<32> value) {
        meta.threshold = value;
    }

    action update_sketch() {
        bit<16> src_port;
        bit<16> dst_port;
        bit<32> index0;
        bit<32> index1;
        bit<32> index2;
        bit<32> value0;
        bit<32> value1;
        bit<32> value2;

        if (hdr.tcp.isValid()) {
            src_port = hdr.tcp.src_port;
            dst_port = hdr.tcp.dst_port;
        } else {
            src_port = hdr.udp.src_port;
            dst_port = hdr.udp.dst_port;
        }

        // Per-row permutations give CRC32 distinct collision partitions.
        hash(
            index0,
            HashAlgorithm.crc32,
            (bit<32>) 0,
            {
                SKETCH_SALT0,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                src_port,
                dst_port
            },
            (bit<32>) 256);
        hash(
            index1,
            HashAlgorithm.crc32,
            (bit<32>) 0,
            {
                SKETCH_SALT1,
                dst_port,
                src_port,
                hdr.ipv4.protocol,
                hdr.ipv4.dst_addr,
                hdr.ipv4.src_addr
            },
            (bit<32>) 256);
        hash(
            index2,
            HashAlgorithm.crc32,
            (bit<32>) 0,
            {
                SKETCH_SALT2,
                hdr.ipv4.protocol,
                src_port,
                dst_port,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            (bit<32>) 256);

        sketch_row0.read(value0, index0);
        if (value0 != 0xffffffff) {
            value0 = value0 + 1;
        }
        sketch_row0.write(index0, value0);

        sketch_row1.read(value1, index1);
        if (value1 != 0xffffffff) {
            value1 = value1 + 1;
        }
        sketch_row1.write(index1, value1);

        sketch_row2.read(value2, index2);
        if (value2 != 0xffffffff) {
            value2 = value2 + 1;
        }
        sketch_row2.write(index2, value2);

        meta.estimate = value0;
        if (value1 < meta.estimate) {
            meta.estimate = value1;
        }
        if (value2 < meta.estimate) {
            meta.estimate = value2;
        }

        if (meta.estimate >= meta.threshold) {
            meta.is_heavy = 1;
        } else {
            meta.is_heavy = 0;
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 64;
    }

    table sketch_config {
        actions = {
            @defaultonly set_threshold;
        }
        default_action = set_threshold(50);
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            !hdr.ipv4.isValid()) {
            drop();
            exit;
        }

        if (standard_metadata.checksum_error == 1 ||
            hdr.ipv4.version != 4 || hdr.ipv4.ihl != 5 ||
            hdr.ipv4.ttl <= 1 || hdr.ipv4.total_len < 20 ||
            standard_metadata.packet_length <
                (bit<32>) hdr.ipv4.total_len + 14) {
            drop();
            exit;
        }

        if (hdr.tcp.isValid()) {
            bit<16> tcp_header_len;
            tcp_header_len = ((bit<16>) hdr.tcp.data_offset) << 2;
            if (hdr.tcp.data_offset < 5 ||
                hdr.ipv4.total_len < 20 + tcp_header_len) {
                drop();
                exit;
            }
        }

        if (hdr.udp.isValid() &&
            (hdr.udp.length < 8 ||
             hdr.ipv4.total_len != 20 + hdr.udp.length)) {
            drop();
            exit;
        }

        if (ipv4_lpm.apply().hit) {
            if (hdr.tcp.isValid() || hdr.udp.isValid()) {
                sketch_config.apply();
                update_sketch();
            }

            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
    }
}

control EgressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply { }
}

control ComputeChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()) main;
