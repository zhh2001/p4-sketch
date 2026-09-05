import os
import subprocess
import sys
import threading
import time
import unittest
from collections import Counter
from pathlib import Path

from scapy.compat import raw
from scapy.layers.inet import ICMP, IP, TCP, UDP, in4_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer
from scapy.utils import checksum

from bmv2_registers import SKETCH_ROWS, SketchRegisters


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "mininet"))

from run import HOSTS, running_network


SOURCE_IP = HOSTS["h1"]["ip"].split("/", maxsplit=1)[0]
DESTINATION_IP = "10.0.3.99"
SOURCE_PORT = 12000
DESTINATION_PORT = 23000
SWITCH_INTERFACES = tuple(f"s1-eth{port}" for port in (1, 2, 3))
COLLISION_SEARCH_LIMIT = 32

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


def flow_packet(
    protocol,
    phase,
    sequence,
    source_port=SOURCE_PORT,
    destination_port=DESTINATION_PORT,
):
    payload = (
        f"p4-sketch-{protocol}-{phase}-{sequence:03d}-".encode()
        + b"x" * 32
    )
    packet = (
        Ether(
            src=HOSTS["h1"]["mac"],
            dst=HOSTS["h1"]["switch_mac"],
        )
        / IP(
            src=SOURCE_IP,
            dst=DESTINATION_IP,
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


def barrier_packet(identifier):
    payload = f"p4-sketch-barrier-{identifier:04x}".encode() + b"b" * 24
    packet = (
        Ether(
            src=HOSTS["h1"]["mac"],
            dst=HOSTS["h1"]["switch_mac"],
        )
        / IP(
            src=SOURCE_IP,
            dst=HOSTS["h3"]["ip"].split("/", maxsplit=1)[0],
            ttl=64,
            id=0x7000 + identifier,
        )
        / ICMP(type="echo-request", id=identifier, seq=1)
        / Raw(payload)
    )
    return materialize(packet), payload


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


def is_barrier_reply(packet, identifier, payload):
    return (
        packet.sniffed_on == "s1-eth1"
        and Ether in packet
        and packet[Ether].src == HOSTS["h1"]["switch_mac"]
        and packet[Ether].dst == HOSTS["h1"]["mac"]
        and IP in packet
        and packet[IP].src == HOSTS["h3"]["ip"].split("/", maxsplit=1)[0]
        and packet[IP].dst == SOURCE_IP
        and ICMP in packet
        and packet[ICMP].type == 0
        and packet[ICMP].id == identifier
        and packet[ICMP].seq == 1
        and Raw in packet
        and raw(packet[Raw]) == payload
    )


def capture_batch(net, frames, identifier):
    sentinel, sentinel_payload = barrier_packet(identifier)
    ready = threading.Event()
    barrier_seen = threading.Event()

    def observe(packet):
        if is_barrier_reply(packet, identifier, sentinel_payload):
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
        send_frames(net.get("h1"), [*frames, sentinel])
        if not barrier_seen.wait(timeout=5):
            raise RuntimeError("packet-processing barrier was not observed")
    finally:
        if sniffer.running:
            captured = sniffer.stop()
        else:
            sniffer.join()
            captured = sniffer.results
    return list(captured)


def nonzero_cells(values):
    return [(index, value) for index, value in enumerate(values) if value != 0]


class SketchIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network_context = running_network(50)
        cls.net = cls.network_context.__enter__()
        cls.addClassCleanup(cls.network_context.__exit__, None, None, None)
        cls.registers = SketchRegisters()
        cls.barrier_identifier = 1

    def capture(self, frames):
        identifier = self.__class__.barrier_identifier
        self.__class__.barrier_identifier += 1
        return capture_batch(self.net, frames, identifier)

    def assert_forwarding(self, original, observed, transport):
        expected = original.copy()
        expected[Ether].src = HOSTS["h3"]["switch_mac"]
        expected[Ether].dst = HOSTS["h3"]["mac"]
        expected[IP].ttl -= 1
        del expected[IP].chksum
        expected = materialize(expected)

        self.assertEqual(raw(observed), raw(expected))
        self.assertEqual(observed[Ether].src, HOSTS["h3"]["switch_mac"])
        self.assertEqual(observed[Ether].dst, HOSTS["h3"]["mac"])
        self.assertEqual(observed[IP].src, original[IP].src)
        self.assertEqual(observed[IP].dst, original[IP].dst)
        self.assertEqual(observed[IP].proto, original[IP].proto)
        self.assertEqual(observed[IP].ttl, original[IP].ttl - 1)
        self.assertNotEqual(observed[IP].chksum, original[IP].chksum)
        self.assertEqual(checksum(raw(observed[IP])[:20]), 0)
        self.assertEqual(observed[transport].sport, original[transport].sport)
        self.assertEqual(observed[transport].dport, original[transport].dport)
        self.assertEqual(observed[transport].chksum, original[transport].chksum)
        self.assertEqual(raw(observed[transport].payload), raw(original[transport].payload))
        self.assertEqual(
            in4_chksum(observed[IP].proto, observed[IP], raw(observed[transport])),
            0,
        )
        if transport is TCP:
            self.assertEqual(observed[TCP].seq, original[TCP].seq)
            self.assertEqual(observed[TCP].ack, original[TCP].ack)
            self.assertEqual(observed[TCP].flags, original[TCP].flags)
            self.assertEqual(observed[TCP].window, original[TCP].window)
        else:
            self.assertNotEqual(original[UDP].chksum, 0)

    def assert_batch_forwarding(self, originals, captured, transport):
        expected_payloads = {raw(packet[transport].payload) for packet in originals}
        self.assertEqual(len(expected_payloads), len(originals))
        flow_packets = [
            packet
            for packet in captured
            if transport in packet
            and raw(packet[transport].payload) in expected_payloads
        ]
        self.assertEqual(len(flow_packets), 2 * len(originals))

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
                Counter({"s1-eth1": 1, "s1-eth3": 1}),
                f"payload {payload!r}: observed interfaces {interfaces}",
            )
            ingress = next(packet for packet in packets if packet.sniffed_on == "s1-eth1")
            egress = next(packet for packet in packets if packet.sniffed_on == "s1-eth3")
            original = originals_by_payload[payload]
            self.assertEqual(raw(ingress), raw(original))
            self.assert_forwarding(original, egress, transport)

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
        estimate = min(rows[row][index] for row, index in zip(SKETCH_ROWS, indices))
        self.assertEqual(estimate, expected_count)
        return tuple(indices)

    def wait_for_flow_update(self, previous, description):
        deadline = time.monotonic() + 2
        last_deltas = None
        while time.monotonic() < deadline:
            current = self.registers.read_all()
            deltas = {}
            for row in SKETCH_ROWS:
                deltas[row] = [
                    (index, after - before)
                    for index, (before, after) in enumerate(
                        zip(previous[row], current[row])
                    )
                    if after != before
                ]
            if all(
                len(deltas[row]) == 1 and deltas[row][0][1] == 1
                for row in SKETCH_ROWS
            ):
                indices = tuple(deltas[row][0][0] for row in SKETCH_ROWS)
                estimate = min(
                    current[row][index]
                    for row, index in zip(SKETCH_ROWS, indices)
                )
                self.assertGreaterEqual(estimate, 1)
                return indices, current
            if any(
                len(deltas[row]) > 1
                or any(increment < 0 or increment > 1 for _, increment in deltas[row])
                for row in SKETCH_ROWS
            ):
                self.fail(f"{description}: invalid register deltas {deltas}")
            last_deltas = deltas
            time.sleep(0.01)
        self.fail(f"{description}: register update timed out; deltas {last_deltas}")

    def observe_flow_indices(self, previous, source_port, destination_port, ordinal):
        packet = flow_packet(
            "udp",
            f"probe-{ordinal}",
            ordinal,
            source_port,
            destination_port,
        )
        send_frames(self.net.get("h1"), [packet])
        return self.wait_for_flow_update(
            previous,
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

    def test_multiple_flow_estimates_do_not_underestimate(self):
        flow_keys = [
            (source_port, destination_port)
            for _, source_port, destination_port, _ in MULTI_FLOW_COUNTS
        ]
        indices = self.discover_flow_indices(flow_keys)
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

        for name, source_port, destination_port, actual in MULTI_FLOW_COUNTS:
            flow_indices = indices[(source_port, destination_port)]
            estimate = min(
                rows[row][index]
                for row, index in zip(SKETCH_ROWS, flow_indices)
            )
            self.assertGreaterEqual(
                estimate,
                actual,
                f"flow {name}: estimate {estimate}, actual {actual}",
            )
            self.assertEqual(estimate, actual)

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
        estimate_a = min(
            rows[row][index] for row, index in zip(SKETCH_ROWS, indices_a)
        )
        estimate_b = min(
            rows[row][index] for row, index in zip(SKETCH_ROWS, indices_b)
        )
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
