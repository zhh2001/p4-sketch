import os
import subprocess
import sys
import threading
import unittest
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import mininet.node as mininet_node
from scapy.compat import raw
from scapy.layers.inet import ICMP, IP, TCP, UDP, in4_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer
from scapy.utils import checksum

from bmv2_registers import COUNTER_MAX, SKETCH_ROWS, SketchRegisters


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "mininet"))

import run as mininet_run
from run import HOSTS, P4RUNTIME_PORT, THRIFT_PORT, port_is_listening, running_network


SOURCE_IP = HOSTS["h1"]["ip"].split("/", maxsplit=1)[0]
DESTINATION_IP = "10.0.3.99"
UNASSIGNED_IPS = {
    "h1": "10.0.1.99",
    "h2": "10.0.2.99",
    "h3": "10.0.3.99",
}
SOURCE_PORT = 12000
DESTINATION_PORT = 23000
SWITCH_INTERFACES = tuple(f"s1-eth{port}" for port in (1, 2, 3))
COLLISION_SEARCH_LIMIT = 32
HEAVY_HITTER_THRESHOLD = 50

MULTI_FLOW_COUNTS = (
    ("a", 20000, 30000, 100),
    ("b", 20001, 30073, 30),
    ("c", 20002, 30146, 5),
)

_SEND_FRAMES = """
import socket
import sys
import time

frames = [bytes.fromhex(line) for line in sys.stdin if line.strip()]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
    sock.bind((sys.argv[1], 0))
    for frame in frames:
        sock.send(frame)
        time.sleep(0.002)
"""


def materialize(packet):
    return Ether(raw(packet))


def ipv4_frame(ip_header, payload, source_name="h1"):
    return materialize(
        Ether(
            src=HOSTS[source_name]["mac"],
            dst=HOSTS[source_name]["switch_mac"],
        )
        / ip_header
        / payload
    )


def non_barrier_packets(captured):
    return [
        packet
        for packet in captured
        if not (
            ICMP in packet
            and Raw in packet
            and raw(packet[Raw]).startswith(b"p4-sketch-barrier-")
        )
    ]


def flow_packet(
    protocol,
    phase,
    sequence,
    source_port=SOURCE_PORT,
    destination_port=DESTINATION_PORT,
    source_name="h1",
    source_ip=None,
    destination_ip=DESTINATION_IP,
):
    if source_ip is None:
        source_ip = HOSTS[source_name]["ip"].split("/", maxsplit=1)[0]
    payload = (
        f"p4-sketch-{protocol}-{phase}-{sequence:03d}-".encode()
        + b"x" * 32
    )
    packet = (
        Ether(
            src=HOSTS[source_name]["mac"],
            dst=HOSTS[source_name]["switch_mac"],
        )
        / IP(
            src=source_ip,
            dst=destination_ip,
            ttl=64,
            id=0x1000 + sequence,
        )
    )
    if protocol == "tcp":
        packet /= TCP(
            sport=source_port,
            dport=destination_port,
            seq=0x10203040 + sequence,
            ack=0x50607080,
            flags="PA",
            window=4096,
        )
    elif protocol == "udp":
        packet /= UDP(sport=source_port, dport=destination_port)
    else:
        raise ValueError(f"unsupported protocol: {protocol}")
    return materialize(packet / Raw(payload))


def barrier_packets(identifier, source_name):
    source_ip = HOSTS[source_name]["ip"].split("/", maxsplit=1)[0]
    sentinels = []
    for ordinal, destination_name in enumerate(HOSTS):
        token = identifier * len(HOSTS) + ordinal
        payload = (
            f"p4-sketch-barrier-{identifier:04x}-{destination_name}".encode()
            + b"b" * 24
        )
        packet = (
            Ether(
                src=HOSTS[source_name]["mac"],
                dst=HOSTS[source_name]["switch_mac"],
            )
            / IP(
                src=source_ip,
                dst=UNASSIGNED_IPS[destination_name],
                ttl=64,
                id=(0x7000 + token) & 0xFFFF,
            )
            / ICMP(type="echo-request", id=token & 0xFFFF, seq=1)
            / Raw(payload)
        )
        sentinels.append((materialize(packet), destination_name, payload))
    return sentinels


def send_frames(host, frames):
    process = host.popen(
        [sys.executable, "-B", "-c", _SEND_FRAMES, host.defaultIntf().name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    encoded = "".join(f"{raw(frame).hex()}\n" for frame in frames)
    try:
        stdout, stderr = process.communicate(encoded, timeout=8)
    except subprocess.TimeoutExpired as error:
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise RuntimeError("packet sender timed out") from error
    if process.returncode != 0:
        detail = stderr.strip() or stdout.strip() or f"exit status {process.returncode}"
        raise RuntimeError(f"packet sender failed: {detail}")


def is_barrier_egress(packet, sentinel, destination_name, payload):
    return (
        packet.sniffed_on == f"s1-eth{HOSTS[destination_name]['port']}"
        and Ether in packet
        and packet[Ether].src == HOSTS[destination_name]["switch_mac"]
        and packet[Ether].dst == HOSTS[destination_name]["mac"]
        and IP in packet
        and packet[IP].src == sentinel[IP].src
        and packet[IP].dst == sentinel[IP].dst
        and packet[IP].id == sentinel[IP].id
        and ICMP in packet
        and packet[ICMP].type == 8
        and packet[ICMP].id == sentinel[ICMP].id
        and packet[ICMP].seq == 1
        and Raw in packet
        and raw(packet[Raw]) == payload
    )


def capture_batch(net, frames, identifier, source_name="h1"):
    sentinels = barrier_packets(identifier, source_name)
    ready = threading.Event()
    barrier_seen = threading.Event()
    observed_egresses = set()

    def observe(packet):
        for sentinel, destination_name, payload in sentinels:
            if is_barrier_egress(packet, sentinel, destination_name, payload):
                observed_egresses.add(destination_name)
        if len(observed_egresses) == len(sentinels):
            barrier_seen.set()

    sniffer = AsyncSniffer(
        iface=list(SWITCH_INTERFACES),
        filter="ip",
        store=True,
        prn=observe,
        started_callback=ready.set,
    )
    sniffer.start()
    captured = None
    try:
        if not ready.wait(timeout=3):
            raise RuntimeError("packet capture did not become ready")
        send_frames(
            net.get(source_name),
            [*frames, *(sentinel for sentinel, _, _ in sentinels)],
        )
        if not barrier_seen.wait(timeout=5):
            raise RuntimeError("packet-processing barrier was not observed")
    finally:
        if ready.is_set() and sniffer.running:
            captured = sniffer.stop()
        else:
            sniffer.join(timeout=1)
            captured = getattr(sniffer, "results", [])
    return list(captured)


def nonzero_cells(values):
    return [(index, value) for index, value in enumerate(values) if value != 0]


def sketch_estimate(rows, indices):
    return min(rows[row][index] for row, index in zip(SKETCH_ROWS, indices))


class RuntimeFailureCleanupTest(unittest.TestCase):
    def test_configuration_failure_cleans_runtime(self):
        ports = (P4RUNTIME_PORT, THRIFT_PORT)
        interfaces = {
            *(f"{name}-eth0" for name in HOSTS),
            *(f"s1-eth{config['port']}" for config in HOSTS.values()),
        }
        self.assertFalse(
            [port for port in ports if port_is_listening(port)],
            "runtime ports must be free before the cleanup test",
        )
        self.assertFalse(
            interfaces & {name for _, name in mininet_run.socket.if_nameindex()},
            "Mininet interfaces must be absent before the cleanup test",
        )

        runtime = TemporaryDirectory(prefix="p4-sketch-failure-")
        runtime_path = Path(runtime.name)
        self.addCleanup(runtime.cleanup)
        real_popen = subprocess.Popen
        switch_path = Path(mininet_run.shutil.which("simple_switch_grpc")).resolve()
        controller_path = mininet_run.CONTROLLER.resolve()
        launched = []
        started = []

        def emergency_cleanup():
            for _, process in reversed(launched):
                if process.returncode is not None:
                    continue
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                except ChildProcessError:
                    pass
            remaining_interfaces = interfaces & {
                name for _, name in mininet_run.socket.if_nameindex()
            }
            for interface in sorted(remaining_interfaces):
                subprocess.run(
                    ["ip", "link", "delete", "dev", interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

        self.addCleanup(emergency_cleanup)

        def record_popen(command, *args, **kwargs):
            process = real_popen(command, *args, **kwargs)
            launched.append((command, process))
            if isinstance(command, (list, tuple)) and command:
                executable = Path(command[0]).resolve()
                if executable in (switch_path, controller_path):
                    started.append((executable, process))
            return process

        with patch.object(
            mininet_run.tempfile,
            "TemporaryDirectory",
            return_value=runtime,
        ), patch.object(
            mininet_run.subprocess,
            "Popen",
            side_effect=record_popen,
        ), patch.object(
            mininet_node,
            "Popen",
            side_effect=record_popen,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "controller exited with status 1",
            ):
                with running_network(0):
                    self.fail("invalid threshold unexpectedly configured")

        for executable in (switch_path, controller_path):
            processes = [process for path, process in started if path == executable]
            self.assertEqual(len(processes), 1, f"{executable.name} launch count")
            process = processes[0]
            self.assertIsNotNone(
                process.returncode,
                f"{executable.name} was not waited for",
            )
            self.assertFalse(
                Path(f"/proc/{process.pid}").exists(),
                f"{executable.name} process {process.pid} was not reaped",
            )
        remaining_children = [
            (process.pid, command)
            for command, process in launched
            if process.returncode is None or Path(f"/proc/{process.pid}").exists()
        ]
        self.assertFalse(
            remaining_children,
            f"child processes remain after configuration failure: {remaining_children}",
        )
        self.assertFalse(runtime_path.exists(), "runtime directory was not removed")
        self.assertFalse(
            [port for port in ports if port_is_listening(port)],
            "runtime port remains in use after configuration failure",
        )
        self.assertFalse(
            interfaces & {name for _, name in mininet_run.socket.if_nameindex()},
            "Mininet interface remains after configuration failure",
        )


class SketchIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network_context = running_network(HEAVY_HITTER_THRESHOLD)
        cls.net = cls.network_context.__enter__()
        cls.addClassCleanup(cls.network_context.__exit__, None, None, None)
        cls.registers = SketchRegisters()
        cls.barrier_identifier = 1
        startup = cls.registers.read_all()
        for row, values in startup.items():
            for index, value in enumerate(values):
                if value != 0:
                    raise AssertionError(
                        f"{row}[{index}]: expected 0 at startup, observed {value}"
                    )

    def capture(self, frames, source_name="h1"):
        identifier = self.__class__.barrier_identifier
        self.__class__.barrier_identifier += 1
        return capture_batch(self.net, frames, identifier, source_name)

    def assert_forwarding(
        self,
        original,
        observed,
        transport,
        destination_name="h3",
    ):
        self.assert_ipv4_integrity(original, observed, destination_name)
        self.assertEqual(observed[transport].sport, original[transport].sport)
        self.assertEqual(observed[transport].dport, original[transport].dport)
        self.assertEqual(observed[transport].chksum, original[transport].chksum)
        self.assertEqual(raw(observed[transport].payload), raw(original[transport].payload))
        if transport is TCP or original[UDP].chksum != 0:
            self.assertEqual(
                in4_chksum(
                    observed[IP].proto,
                    observed[IP],
                    raw(observed[transport]),
                ),
                0,
            )
        if transport is TCP:
            self.assertEqual(observed[TCP].seq, original[TCP].seq)
            self.assertEqual(observed[TCP].ack, original[TCP].ack)
            self.assertEqual(observed[TCP].flags, original[TCP].flags)
            self.assertEqual(observed[TCP].window, original[TCP].window)

    def assert_ipv4_integrity(self, original, observed, destination_name):
        expected = original.copy()
        expected[Ether].src = HOSTS[destination_name]["switch_mac"]
        expected[Ether].dst = HOSTS[destination_name]["mac"]
        expected[IP].ttl -= 1
        del expected[IP].chksum
        expected = materialize(expected)

        self.assertEqual(raw(observed), raw(expected))
        self.assertEqual(
            observed[Ether].src,
            HOSTS[destination_name]["switch_mac"],
        )
        self.assertEqual(observed[Ether].dst, HOSTS[destination_name]["mac"])
        self.assertEqual(observed[IP].src, original[IP].src)
        self.assertEqual(observed[IP].dst, original[IP].dst)
        self.assertEqual(observed[IP].proto, original[IP].proto)
        self.assertEqual(observed[IP].ttl, original[IP].ttl - 1)
        self.assertNotEqual(observed[IP].chksum, original[IP].chksum)
        self.assertEqual(
            checksum(raw(observed[IP])[: observed[IP].ihl * 4]),
            0,
        )

    def assert_batch_forwarding(
        self,
        originals,
        captured,
        transport,
        source_name="h1",
        destination_name="h3",
    ):
        source_interface = f"s1-eth{HOSTS[source_name]['port']}"
        destination_interface = f"s1-eth{HOSTS[destination_name]['port']}"
        expected_payloads = {raw(packet[transport].payload) for packet in originals}
        self.assertEqual(len(expected_payloads), len(originals))
        flow_packets = non_barrier_packets(captured)
        self.assertEqual(len(flow_packets), 2 * len(originals))
        unexpected = [
            (packet.sniffed_on, raw(packet).hex())
            for packet in flow_packets
            if transport not in packet
            or raw(packet[transport].payload) not in expected_payloads
        ]
        self.assertFalse(unexpected, f"unexpected captured packets: {unexpected}")

        by_payload = {
            payload: [
                packet
                for packet in flow_packets
                if raw(packet[transport].payload) == payload
            ]
            for payload in expected_payloads
        }
        self.assertEqual(set(by_payload), expected_payloads)
        originals_by_payload = {
            raw(packet[transport].payload): packet for packet in originals
        }
        for payload, packets in by_payload.items():
            interfaces = Counter(packet.sniffed_on for packet in packets)
            self.assertEqual(
                interfaces,
                Counter({source_interface: 1, destination_interface: 1}),
                f"payload {payload!r}: observed interfaces {interfaces}",
            )
            ingress = next(
                packet for packet in packets if packet.sniffed_on == source_interface
            )
            egress = next(
                packet
                for packet in packets
                if packet.sniffed_on == destination_interface
            )
            original = originals_by_payload[payload]
            self.assertEqual(raw(ingress), raw(original))
            self.assert_forwarding(
                original,
                egress,
                transport,
                destination_name,
            )

    def assert_ipv4_forwarded_once(
        self,
        original,
        captured,
        source_name="h1",
        destination_name="h3",
    ):
        matching = non_barrier_packets(captured)
        source_interface = f"s1-eth{HOSTS[source_name]['port']}"
        destination_interface = f"s1-eth{HOSTS[destination_name]['port']}"
        interfaces = Counter(packet.sniffed_on for packet in matching)
        self.assertEqual(
            interfaces,
            Counter({source_interface: 1, destination_interface: 1}),
            f"observed interfaces {interfaces}",
        )
        ingress = next(
            packet for packet in matching if packet.sniffed_on == source_interface
        )
        egress = next(
            packet for packet in matching if packet.sniffed_on == destination_interface
        )
        self.assertEqual(raw(ingress), raw(original))

        self.assert_ipv4_integrity(original, egress, destination_name)
        return egress

    def assert_ipv4_dropped_once(self, original, captured, source_name="h1"):
        matching = non_barrier_packets(captured)
        source_interface = f"s1-eth{HOSTS[source_name]['port']}"
        interfaces = Counter(packet.sniffed_on for packet in matching)
        self.assertEqual(
            interfaces,
            Counter({source_interface: 1}),
            f"observed interfaces {interfaces}",
        )
        self.assertEqual(raw(matching[0]), raw(original))

    def assert_sketch_unchanged(self, before, description):
        after = self.registers.read_all()
        changes = [
            f"{row}[{index}]: expected {old}, observed {new}"
            for row in SKETCH_ROWS
            for index, (old, new) in enumerate(zip(before[row], after[row]))
            if old != new
        ]
        self.assertFalse(changes, f"{description}: " + "; ".join(changes))

    def assert_bypasses_sketch(
        self,
        packet,
        description,
        source_name="h1",
        destination_name="h3",
    ):
        before = self.registers.reset_all()
        captured = self.capture([packet], source_name)
        egress = self.assert_ipv4_forwarded_once(
            packet,
            captured,
            source_name,
            destination_name,
        )
        self.assert_sketch_unchanged(before, description)
        return egress

    def assert_dropped_without_measurement(
        self,
        packet,
        description,
        source_name="h1",
    ):
        before = self.registers.reset_all()
        captured = self.capture([packet], source_name)
        self.assert_ipv4_dropped_once(packet, captured, source_name)
        self.assert_sketch_unchanged(before, description)

    def assert_row_count(self, rows, expected_count, expected_indices=None):
        indices = []
        for position, row in enumerate(SKETCH_ROWS):
            observed = nonzero_cells(rows[row])
            if expected_indices is None:
                self.assertEqual(len(observed), 1, f"{row}: nonzero cells {observed}")
                index = observed[0][0]
            else:
                index = expected_indices[position]
            self.assertEqual(
                observed,
                [(index, expected_count)],
                f"{row}: expected only [{index}]={expected_count}, observed {observed}",
            )
            indices.append(index)
        estimate = sketch_estimate(rows, indices)
        self.assertEqual(estimate, expected_count)
        return tuple(indices)

    def flow_update(self, previous, current, description):
        deltas = {}
        for row in SKETCH_ROWS:
            deltas[row] = [
                (index, after - before)
                for index, (before, after) in enumerate(
                    zip(previous[row], current[row])
                )
                if after != before
            ]
        if not all(
            len(deltas[row]) == 1 and deltas[row][0][1] == 1
            for row in SKETCH_ROWS
        ):
            self.fail(f"{description}: expected one +1 per row, observed {deltas}")
        indices = tuple(deltas[row][0][0] for row in SKETCH_ROWS)
        estimate = sketch_estimate(current, indices)
        self.assertGreaterEqual(estimate, 1)
        return indices, current

    def observe_flow_indices(self, previous, source_port, destination_port, ordinal):
        packet = flow_packet(
            "udp",
            f"probe-{ordinal}",
            ordinal,
            source_port,
            destination_port,
        )
        captured = self.capture([packet])
        self.assert_batch_forwarding([packet], captured, UDP)
        return self.flow_update(
            previous,
            self.registers.read_all(),
            f"UDP {SOURCE_IP}:{source_port} -> {DESTINATION_IP}:{destination_port}",
        )

    def discover_flow_indices(self, flows):
        previous = self.registers.reset_all()
        indices = {}
        for ordinal, (source_port, destination_port) in enumerate(flows):
            observed, previous = self.observe_flow_indices(
                previous,
                source_port,
                destination_port,
                ordinal,
            )
            indices[(source_port, destination_port)] = observed
        return indices

    def find_single_row_collision(self):
        previous = self.registers.reset_all()
        catalog = []
        for candidate in range(COLLISION_SEARCH_LIMIT):
            source_port = 20000 + candidate
            destination_port = 30000 + ((candidate * 73) % 1000)
            indices, previous = self.observe_flow_indices(
                previous,
                source_port,
                destination_port,
                candidate,
            )
            flow = (source_port, destination_port)
            for earlier_flow, earlier_indices in catalog:
                matching_rows = tuple(
                    position
                    for position, (left, right) in enumerate(
                        zip(earlier_indices, indices)
                    )
                    if left == right
                )
                if len(matching_rows) == 1:
                    return (
                        earlier_flow,
                        earlier_indices,
                        flow,
                        indices,
                        matching_rows[0],
                    )
            catalog.append((flow, indices))
        self.fail(
            f"no exactly-one-row collision in {COLLISION_SEARCH_LIMIT} candidates: "
            f"{catalog}"
        )

    def assert_register_state(self, rows, flows, indices):
        for position, row in enumerate(SKETCH_ROWS):
            expected = Counter()
            for _, source_port, destination_port, count in flows:
                expected[indices[(source_port, destination_port)][position]] += count
            observed = nonzero_cells(rows[row])
            self.assertEqual(
                observed,
                sorted(expected.items()),
                f"{row}: expected {sorted(expected.items())}, observed {observed}",
            )

    def test_unmeasured_ipv4_packets_bypass_sketch(self):
        icmp = ipv4_frame(
            IP(
                src=SOURCE_IP,
                dst=DESTINATION_IP,
                ttl=64,
                id=0x5101,
            ),
            ICMP(type="echo-request", id=0x5101, seq=1)
            / Raw(b"p4-sketch-icmp-bypass".ljust(32, b"i")),
        )
        other_protocol = ipv4_frame(
            IP(
                src=SOURCE_IP,
                dst=DESTINATION_IP,
                ttl=64,
                id=0x5102,
                proto=253,
            ),
            Raw(b"p4-sketch-protocol-bypass".ljust(40, b"p")),
        )

        for description, packet in (
            ("ICMP packet", icmp),
            ("IP protocol 253 packet", other_protocol),
        ):
            with self.subTest(description):
                egress = self.assert_bypasses_sketch(packet, description)
                if ICMP in packet:
                    self.assertEqual(egress[ICMP].chksum, packet[ICMP].chksum)
                    self.assertEqual(checksum(raw(egress[ICMP])), 0)
                    self.assertEqual(raw(egress[ICMP].payload), raw(packet[ICMP].payload))

    def test_ipv4_fragments_bypass_sketch(self):
        datagram_id = 0x5201
        first_payload = raw(
            UDP(
                sport=SOURCE_PORT,
                dport=DESTINATION_PORT,
                len=64,
                chksum=0,
            )
        ) + b"p4-sketch-fragment-first".ljust(24, b"f")[:24]
        last_payload = b"p4-sketch-fragment-last".ljust(32, b"l")
        fragments = (
            (
                "first IPv4 fragment",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=datagram_id,
                        proto=17,
                        flags="MF",
                        frag=0,
                    ),
                    Raw(first_payload),
                ),
            ),
            (
                "non-first IPv4 fragment",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=datagram_id,
                        proto=17,
                        frag=4,
                    ),
                    Raw(last_payload),
                ),
            ),
        )

        for description, packet in fragments:
            with self.subTest(description):
                egress = self.assert_bypasses_sketch(packet, description)
                self.assertEqual(egress[IP].flags, packet[IP].flags)
                self.assertEqual(egress[IP].frag, packet[IP].frag)
                self.assertEqual(raw(egress[IP].payload), raw(packet[IP].payload))
                if packet[IP].frag == 0:
                    self.assertEqual(packet[UDP].chksum, 0)
                    self.assertEqual(egress[UDP].chksum, 0)

    def test_invalid_ipv4_and_route_miss_do_not_update_sketch(self):
        ttl_packets = [
            (
                f"TTL {ttl}",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=ttl,
                        id=0x5300 + ttl,
                    ),
                    UDP(sport=SOURCE_PORT, dport=DESTINATION_PORT)
                    / Raw(f"p4-sketch-ttl-{ttl}".encode().ljust(32, b"t")),
                ),
            )
            for ttl in (0, 1)
        ]

        valid_checksum = ipv4_frame(
            IP(
                src=SOURCE_IP,
                dst=DESTINATION_IP,
                ttl=64,
                id=0x5310,
            ),
            UDP(sport=SOURCE_PORT, dport=DESTINATION_PORT)
            / Raw(b"p4-sketch-bad-checksum".ljust(32, b"c")),
        )
        bad_checksum = valid_checksum.copy()
        bad_checksum[IP].chksum ^= 0xFFFF
        bad_checksum = materialize(bad_checksum)
        self.assertNotEqual(checksum(raw(bad_checksum[IP])[:20]), 0)

        options = ipv4_frame(
            IP(
                src=SOURCE_IP,
                dst=DESTINATION_IP,
                ttl=64,
                id=0x5311,
                options=b"\x01\x01\x01\x01",
            ),
            UDP(sport=SOURCE_PORT, dport=DESTINATION_PORT)
            / Raw(b"p4-sketch-ip-options".ljust(32, b"o")),
        )
        self.assertEqual(options[IP].ihl, 6)
        self.assertEqual(checksum(raw(options[IP])[:24]), 0)

        route_miss = ipv4_frame(
            IP(
                src=SOURCE_IP,
                dst="10.0.4.99",
                ttl=64,
                id=0x5312,
            ),
            UDP(sport=SOURCE_PORT, dport=DESTINATION_PORT)
            / Raw(b"p4-sketch-route-miss".ljust(32, b"r")),
        )

        cases = [
            *ttl_packets,
            ("bad IPv4 checksum", bad_checksum),
            ("IPv4 options", options),
            ("route miss", route_miss),
        ]
        for description, packet in cases:
            with self.subTest(description):
                self.assert_dropped_without_measurement(packet, description)

    def test_malformed_lengths_do_not_update_sketch(self):
        cases = (
            (
                "IPv4 total length below header size",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5401,
                        proto=253,
                        len=19,
                    ),
                    Raw(b"p4-sketch-short-total-length".ljust(40, b"s")),
                ),
            ),
            (
                "IPv4 total length exceeds received packet",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5402,
                        proto=253,
                        len=100,
                    ),
                    Raw(b"p4-sketch-long-total-length".ljust(32, b"l")),
                ),
            ),
            (
                "UDP length disagrees with IPv4 length",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5403,
                        len=60,
                    ),
                    UDP(
                        sport=SOURCE_PORT,
                        dport=DESTINATION_PORT,
                        len=8,
                    )
                    / Raw(b"p4-sketch-udp-length".ljust(32, b"u")),
                ),
            ),
            (
                "UDP length below header size",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5404,
                        len=27,
                    ),
                    UDP(
                        sport=SOURCE_PORT,
                        dport=DESTINATION_PORT,
                        len=7,
                    )
                    / Raw(b"p4-sketch-short-udp".ljust(40, b"u")),
                ),
            ),
            (
                "TCP data offset below minimum",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5405,
                    ),
                    TCP(
                        sport=SOURCE_PORT,
                        dport=DESTINATION_PORT,
                        seq=1,
                        flags="R",
                        dataofs=4,
                    )
                    / Raw(b"p4-sketch-tcp-offset".ljust(32, b"t")),
                ),
            ),
            (
                "TCP header exceeds IPv4 total length",
                ipv4_frame(
                    IP(
                        src=SOURCE_IP,
                        dst=DESTINATION_IP,
                        ttl=64,
                        id=0x5406,
                        len=72,
                    ),
                    TCP(
                        sport=SOURCE_PORT,
                        dport=DESTINATION_PORT,
                        seq=1,
                        flags="R",
                        dataofs=15,
                    )
                    / Raw(b"p4-sketch-long-tcp-header".ljust(32, b"t")),
                ),
            ),
        )

        for description, packet in cases:
            with self.subTest(description):
                header_length = packet[IP].ihl * 4
                self.assertEqual(checksum(raw(packet[IP])[:header_length]), 0)
                self.assert_dropped_without_measurement(packet, description)

    def test_reverse_direction_is_a_distinct_flow(self):
        source_port = 24000
        destination_port = 34000
        forward = flow_packet(
            "udp",
            "direction",
            0,
            source_port,
            destination_port,
            source_name="h1",
            source_ip=UNASSIGNED_IPS["h1"],
            destination_ip=UNASSIGNED_IPS["h3"],
        )
        reverse = flow_packet(
            "udp",
            "direction",
            0,
            destination_port,
            source_port,
            source_name="h3",
            source_ip=UNASSIGNED_IPS["h3"],
            destination_ip=UNASSIGNED_IPS["h1"],
        )
        self.assertEqual(forward[IP].id, reverse[IP].id)
        self.assertEqual(forward[IP].len, reverse[IP].len)
        self.assertEqual(forward[IP].chksum, reverse[IP].chksum)
        self.assertEqual(forward[UDP].chksum, reverse[UDP].chksum)
        self.assertEqual(raw(forward[UDP].payload), raw(reverse[UDP].payload))

        before = self.registers.reset_all()
        captured = self.capture([forward], "h1")
        self.assert_batch_forwarding([forward], captured, UDP, "h1", "h3")
        forward_indices, _ = self.flow_update(
            before,
            self.registers.read_all(),
            "forward UDP flow",
        )

        before = self.registers.reset_all()
        captured = self.capture([reverse], "h3")
        self.assert_batch_forwarding([reverse], captured, UDP, "h3", "h1")
        reverse_indices, _ = self.flow_update(
            before,
            self.registers.read_all(),
            "reverse UDP flow",
        )
        self.assertNotEqual(forward_indices, reverse_indices)

        self.registers.reset_all()
        captured = self.capture([forward], "h1")
        self.assert_batch_forwarding([forward], captured, UDP, "h1", "h3")
        captured = self.capture([reverse], "h3")
        self.assert_batch_forwarding([reverse], captured, UDP, "h3", "h1")
        rows = self.registers.read_all()
        for position, row in enumerate(SKETCH_ROWS):
            expected = Counter((forward_indices[position], reverse_indices[position]))
            self.assertEqual(
                nonzero_cells(rows[row]),
                sorted(expected.items()),
                f"{row}: expected {sorted(expected.items())}",
            )
        self.assertEqual(sketch_estimate(rows, forward_indices), 1)
        self.assertEqual(sketch_estimate(rows, reverse_indices), 1)

    def test_udp_zero_checksum_is_preserved(self):
        packet = flow_packet("udp", "zero-checksum", 0)
        packet[UDP].chksum = 0
        packet = materialize(packet)
        self.assertEqual(packet[UDP].chksum, 0)

        self.registers.reset_all()
        captured = self.capture([packet])
        self.assert_batch_forwarding([packet], captured, UDP)
        self.assert_row_count(self.registers.read_all(), 1)

    def test_multiple_flow_estimates_and_heavy_hitters(self):
        indices = self.discover_flow_indices(
            [
                (source_port, destination_port)
                for _, source_port, destination_port, _ in MULTI_FLOW_COUNTS
            ]
        )
        for position, row in enumerate(SKETCH_ROWS):
            row_indices = {flow_indices[position] for flow_indices in indices.values()}
            self.assertEqual(len(row_indices), len(MULTI_FLOW_COUNTS), row)

        self.registers.reset_all()
        packets = [
            flow_packet(
                "udp",
                f"multi-{name}",
                sequence,
                source_port,
                destination_port,
            )
            for name, source_port, destination_port, count in MULTI_FLOW_COUNTS
            for sequence in range(count)
        ]
        captured = self.capture(packets)
        self.assert_batch_forwarding(packets, captured, UDP)
        rows = self.registers.read_all()
        self.assert_register_state(rows, MULTI_FLOW_COUNTS, indices)

        classifications = {}
        for name, source_port, destination_port, actual in MULTI_FLOW_COUNTS:
            flow_indices = indices[(source_port, destination_port)]
            estimate = sketch_estimate(rows, flow_indices)
            self.assertGreaterEqual(
                estimate,
                actual,
                f"flow {name}: estimate {estimate}, actual {actual}",
            )
            self.assertEqual(estimate, actual)
            classifications[name] = estimate >= HEAVY_HITTER_THRESHOLD
        self.assertEqual(
            classifications,
            {"a": True, "b": False, "c": False},
        )

    def test_heavy_hitter_threshold_boundary(self):
        source_port = 22000
        destination_port = 32000
        self.registers.reset_all()
        discovery = [
            flow_packet(
                "udp",
                "heavy-discover",
                0,
                source_port,
                destination_port,
            )
        ]
        captured = self.capture(discovery)
        self.assert_batch_forwarding(discovery, captured, UDP)
        indices = self.assert_row_count(self.registers.read_all(), 1)

        self.registers.reset_all()
        below_threshold = [
            flow_packet(
                "udp",
                "heavy-below",
                sequence,
                source_port,
                destination_port,
            )
            for sequence in range(HEAVY_HITTER_THRESHOLD - 1)
        ]
        captured = self.capture(below_threshold)
        self.assert_batch_forwarding(below_threshold, captured, UDP)
        rows = self.registers.read_all()
        self.assert_row_count(
            rows,
            HEAVY_HITTER_THRESHOLD - 1,
            indices,
        )
        self.assertFalse(
            sketch_estimate(rows, indices) >= HEAVY_HITTER_THRESHOLD
        )

        boundary = [
            flow_packet(
                "udp",
                "heavy-boundary",
                HEAVY_HITTER_THRESHOLD - 1,
                source_port,
                destination_port,
            )
        ]
        captured = self.capture(boundary)
        self.assert_batch_forwarding(boundary, captured, UDP)
        rows = self.registers.read_all()
        self.assert_row_count(rows, HEAVY_HITTER_THRESHOLD, indices)
        self.assertTrue(
            sketch_estimate(rows, indices) >= HEAVY_HITTER_THRESHOLD
        )

    def test_counters_saturate_without_wrapping(self):
        self.registers.reset_all()
        discovery = [flow_packet("udp", "saturation-discover", 0)]
        captured = self.capture(discovery)
        self.assert_batch_forwarding(discovery, captured, UDP)
        indices = self.assert_row_count(self.registers.read_all(), 1)

        self.registers.reset_all()
        for row, index in zip(SKETCH_ROWS, indices):
            self.registers.write_cell(row, index, COUNTER_MAX - 1)
        self.assert_row_count(
            self.registers.read_all(),
            COUNTER_MAX - 1,
            indices,
        )

        first = [flow_packet("udp", "saturation-first", 0)]
        captured = self.capture(first)
        self.assert_batch_forwarding(first, captured, UDP)
        self.assert_row_count(self.registers.read_all(), COUNTER_MAX, indices)

        second = [flow_packet("udp", "saturation-second", 1)]
        captured = self.capture(second)
        self.assert_batch_forwarding(second, captured, UDP)
        self.assert_row_count(self.registers.read_all(), COUNTER_MAX, indices)

    def test_single_row_collision_uses_minimum(self):
        (
            flow_a,
            indices_a,
            flow_b,
            indices_b,
            collision_row,
        ) = self.find_single_row_collision()
        self.assertEqual(
            sum(left == right for left, right in zip(indices_a, indices_b)),
            1,
        )

        flows = (
            ("collision-a", *flow_a, 10),
            ("collision-b", *flow_b, 5),
        )
        indices = {flow_a: indices_a, flow_b: indices_b}
        self.registers.reset_all()
        packets = [
            flow_packet(
                "udp",
                name,
                sequence,
                source_port,
                destination_port,
            )
            for name, source_port, destination_port, count in flows
            for sequence in range(count)
        ]
        captured = self.capture(packets)
        self.assert_batch_forwarding(packets, captured, UDP)
        rows = self.registers.read_all()
        self.assert_register_state(rows, flows, indices)

        shared_row = SKETCH_ROWS[collision_row]
        shared_index = indices_a[collision_row]
        self.assertEqual(rows[shared_row][shared_index], 15)
        estimate_a = sketch_estimate(rows, indices_a)
        estimate_b = sketch_estimate(rows, indices_b)
        self.assertEqual(estimate_a, 10)
        self.assertEqual(estimate_b, 5)
        self.assertGreaterEqual(estimate_a, 10)
        self.assertGreaterEqual(estimate_b, 5)

    def exercise_protocol(self, protocol):
        transport = TCP if protocol == "tcp" else UDP

        self.registers.reset_all()
        discovery = [flow_packet(protocol, "discover", 0)]
        captured = self.capture(discovery)
        self.assert_batch_forwarding(discovery, captured, transport)
        indices = self.assert_row_count(self.registers.read_all(), 1)

        self.registers.reset_all()
        packets = [flow_packet(protocol, "count", sequence) for sequence in range(20)]
        captured = self.capture(packets)
        self.assert_batch_forwarding(packets, captured, transport)
        self.assert_row_count(self.registers.read_all(), 20, indices)
        return indices

    def test_tcp_and_udp_single_flow_counts(self):
        tcp_indices = self.exercise_protocol("tcp")
        udp_indices = self.exercise_protocol("udp")
        self.assertNotEqual(tcp_indices, udp_indices)


if __name__ == "__main__":
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("integration tests must run as root on Linux")
    unittest.main(verbosity=2)
