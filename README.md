# P4 Count-Min Sketch

This project is a minimal P4_16/v1model reference implementation of packet counting with a Count-Min Sketch. BMv2 performs all sketch updates in the data plane. A Go P4Runtime controller installs the pipeline, IPv4 routes, and heavy-hitter threshold, while deterministic Mininet tests exercise real packet forwarding and register state.

## Topology

```text
h1 10.0.1.1/24 -- port 1 --\
                             s1 -- port 3 -- h3 10.0.3.1/24
h2 10.0.2.1/24 -- port 2 --/
```

`s1` is `simple_switch_grpc` with device ID 1. P4Runtime listens on `127.0.0.1:50051`, and tests connect to BMv2 Thrift on port 9090. Host default routes, permanent neighbor entries, and disabled interface offloads keep packet behavior deterministic and prevent ARP or segmentation offload from obscuring measurements.

## Sketch dataplane

The sketch counts packets, not bytes. It measures only successfully routed, complete, non-fragmented TCP and UDP packets. The key is the unidirectional 5-tuple:

```text
(source IPv4, destination IPv4, protocol, source port, destination port)
```

Reverse directions are separate flows. TCP and UDP with otherwise identical addresses and ports are also separate flows because the protocol is part of the key.

```text
flow 5-tuple
   |
   +--> hash0 --> row0[index0] --\
   +--> hash1 --> row1[index1] ---+--> estimate = minimum
   +--> hash2 --> row2[index2] --/
```

The implementation has three explicit `register<bit<32>>(256)` rows. Each row uses CRC32 with a distinct fixed salt (`0x11`, `0x37`, or `0x9d`) and a distinct permutation containing every key field. A measured packet reads, increments, and writes exactly one counter in each row. Counters saturate at `0xffffffff` and never wrap.

The estimate for the current packet is the minimum of the three updated counters. Collisions can increase counters and therefore may overestimate. A collision in one row does not increase the estimate while another row still contains the flow's exact count. Within the representable counter range, nonnegative updates mean the sketch does not underestimate. Once saturated, the reported value remains capped at `0xffffffff`.

All three read-modify-write sequences are grouped in one ingress action. The implementation relies on BMv2 action execution behavior and does not claim stronger portable consistency guarantees for targets with concurrent packet processing.

## Heavy hitters

`sketch_config` is a keyless table whose default action sets a nonzero 32-bit packet threshold. The controller configures this state through P4Runtime; the default command-line threshold is 50 packets. Classification occurs after the three increments:

```text
is_heavy = (minimum(updated row counters) >= threshold)
```

The estimate and classification remain packet metadata. They do not modify the forwarded packet and are not exported. The controller neither computes hashes nor maintains a software copy of the sketch.

## Forwarding and validation

The controller installs `/24` routes for `10.0.1.0`, `10.0.2.0`, and `10.0.3.0`. Processing is:

```text
parse and validate IPv4
    -> ipv4_lpm route and Ethernet rewrite
    -> update eligible TCP or UDP sketch state
    -> classify against the threshold
    -> decrement TTL
    -> recompute the IPv4 header checksum
```

A route hit selects one output port and rewrites the Ethernet source and destination addresses. IPv4 TTL decreases exactly once. IPv4 addresses, protocol, transport ports, TCP sequence and acknowledgment fields, transport checksum, and payload remain unchanged. A zero UDP checksum remains zero. Transport checksums are preserved rather than validated or recomputed.

Route misses drop before sketch update. Parser errors, a bad incoming IPv4 checksum, TTL 0 or 1, a version other than 4, IHL other than 5, and the checked malformed-length cases also drop without measurement. TCP validation requires a valid minimum data offset and enough declared IPv4 length for that header. UDP length must be at least eight bytes and agree with IPv4 total length.

Routable ICMP and other non-TCP/UDP IPv4 protocols forward normally without changing the sketch. A first fragment with `MF=1` and a non-first fragment with a nonzero offset also forward normally, but neither is measured. Transport ports are never extracted from fragments.

## Control plane

The controller uses [`github.com/zhh2001/p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller), pinned to v1.1.1. It connects to local BMv2, completes primary arbitration, installs the pipeline with `VERIFY_AND_COMMIT`, inserts the three routes, and modifies the threshold default action.

Successful writes are followed by exact readback of the P4Info, device config, route entries, absence of unexpected configuration entries, and threshold default action. `--verify-only` performs arbitration and the same readback without writing state. The controller is a one-shot configuration process; it does not remain resident after successful setup.

## BMv2 register inspection

The `simple_switch_grpc`/v1model combination used here does not provide the usable P4Runtime register read/write workflow required by the tests. Tests use `simple_switch_CLI` over BMv2 Thrift only to read, reset, and seed sketch registers. Pipeline installation, routes, and threshold configuration remain exclusively P4Runtime-driven.

Every scenario reset reads back all 768 cells and verifies that they are zero. Direct cell writes are restricted to saturation test setup.

## Prerequisites

- Linux with sudo privileges
- `p4c-bm2-ss` with P4_16 and v1model support
- BMv2 `simple_switch_grpc` and `simple_switch_CLI`
- Mininet
- Python 3 with Scapy
- Go 1.25 or a compatible toolchain
- `ethtool`, iproute2, and tcpdump/libpcap packet-capture support

The project uses the installed P4 toolchain directly; no container or second toolchain is required.

## Build

```sh
make build
```

This compiles the P4 program with `--Werror`, writes ignored BMv2 JSON and P4Info artifacts under `build/`, and builds the Go controller.

## Run

```sh
make run
```

This starts BMv2, configures it through P4Runtime, and opens a Mininet CLI:

```text
mininet> net
mininet> h1 ping -c 1 10.0.3.1
```

Ping is forwarded but does not update the sketch. Exiting the CLI tears down the network. To select another threshold, run:

```sh
make build
sudo -- python3 mininet/run.py --threshold 75
```

While that switch is running, another terminal can verify its static state:

```sh
build/controller --verify-only --threshold 75
```

## Test

```sh
make test
```

The suite compiles and structurally inspects P4Info and BMv2 JSON, tests the Go configuration and exact readback logic, tests register CLI parsing, and runs real BMv2/P4Runtime/Mininet packet scenarios. Runtime coverage includes exact TCP and UDP counts, protocol and direction separation, bounded deterministic collision discovery, no-underestimation, threshold boundaries, counter saturation, bypass traffic, invalid packets, route misses, exact packet multiplicity, and packet integrity. It also exercises cleanup after an expected configuration failure.

Tests require sudo for Mininet and raw packet access. Bounded packet-processing barriers detect completion of each transmitted batch.

```sh
make clean
```

`make clean` removes only project build output and Python caches.
