#!/usr/bin/env python3

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Host, Switch
from mininet.topo import Topo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
P4INFO = PROJECT_ROOT / "build/count_min_sketch.p4info.txtpb"
DEVICE_CONFIG = PROJECT_ROOT / "build/count_min_sketch.json"
CONTROLLER = PROJECT_ROOT / "build/controller"
P4RUNTIME_PORT = 50051
THRIFT_PORT = 9090
DEVICE_ID = 1
ELECTION_ID = 1

OFFLOAD_OPTIONS = (
    "rx", "off",
    "tx", "off",
    "sg", "off",
    "tso", "off",
    "gso", "off",
    "gro", "off",
)

HOSTS = {
    "h1": {
        "ip": "10.0.1.1/24",
        "mac": "08:00:00:00:01:11",
        "gateway": "10.0.1.254",
        "switch_mac": "08:00:00:00:01:00",
        "port": 1,
    },
    "h2": {
        "ip": "10.0.2.1/24",
        "mac": "08:00:00:00:02:22",
        "gateway": "10.0.2.254",
        "switch_mac": "08:00:00:00:02:00",
        "port": 2,
    },
    "h3": {
        "ip": "10.0.3.1/24",
        "mac": "08:00:00:00:03:33",
        "gateway": "10.0.3.254",
        "switch_mac": "08:00:00:00:03:00",
        "port": 3,
    },
}


def run_host_command(host, command):
    stdout, stderr, status = host.pexec(command)
    if status != 0:
        detail = stderr.strip() or stdout.strip() or f"exit status {status}"
        raise RuntimeError(f"{host.name}: {' '.join(command)}: {detail}")


class SketchHost(Host):
    def config(self, **params):
        result = super().config(**params)
        interface = self.defaultIntf().name
        run_host_command(self, ["ethtool", "-K", interface, *OFFLOAD_OPTIONS])
        for setting in (
            "net.ipv6.conf.all.disable_ipv6=1",
            "net.ipv6.conf.default.disable_ipv6=1",
            "net.ipv6.conf.lo.disable_ipv6=1",
        ):
            run_host_command(self, ["sysctl", "-q", "-w", setting])
        return result


class BMv2Switch(Switch):
    def __init__(self, name, switch_binary, runtime_dir, **params):
        super().__init__(name, **params)
        self.switch_binary = switch_binary
        self.runtime_dir = Path(runtime_dir)
        self.process = None
        self.log_file = None

    def start(self, _controllers):
        ensure_ports_free((P4RUNTIME_PORT, THRIFT_PORT))
        data_ports = sorted(
            (port, interface)
            for port, interface in self.intfs.items()
            if port != 0
        )
        if [port for port, _ in data_ports] != [1, 2, 3]:
            raise RuntimeError("BMv2 data ports are not 1, 2, 3")

        for _, interface in data_ports:
            result = subprocess.run(
                ["ethtool", "-K", interface.name, *OFFLOAD_OPTIONS],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip()
                raise RuntimeError(f"{interface.name}: disable offloads: {detail}")

        command = [self.switch_binary]
        for port, interface in data_ports:
            command.extend(["-i", f"{port}@{interface.name}"])
        command.extend([
            "--device-id", str(DEVICE_ID),
            "--thrift-port", str(THRIFT_PORT),
            "--notifications-addr", f"ipc://{self.runtime_dir / 'notifications.ipc'}",
            "--no-p4",
            "--log-console",
            "-L", "warn",
            "--",
            "--grpc-server-addr", f"127.0.0.1:{P4RUNTIME_PORT}",
        ])

        info("*** Starting BMv2\n")
        self.log_file = (self.runtime_dir / "switch.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            text=True,
        )
        try:
            wait_for_ports(self.process, (P4RUNTIME_PORT, THRIFT_PORT), 5.0)
        except Exception:
            self._stop_process()
            self.log_file.flush()
            details = (self.runtime_dir / "switch.log").read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            if details:
                raise RuntimeError(f"BMv2 failed to start: {details}") from None
            raise

    def _stop_process(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        else:
            self.process.wait()
        self.process = None

    def stop(self, deleteIntfs=True):
        self._stop_process()
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None
        super().stop(deleteIntfs)


class SketchTopology(Topo):
    def build(self, switch_binary, runtime_dir):
        switch = self.addSwitch(
            "s1",
            cls=BMv2Switch,
            switch_binary=switch_binary,
            runtime_dir=runtime_dir,
        )
        for name, config in HOSTS.items():
            host = self.addHost(
                name,
                cls=SketchHost,
                ip=config["ip"],
                mac=config["mac"],
            )
            self.addLink(host, switch, port1=0, port2=config["port"])


def port_is_listening(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def ensure_ports_free(ports):
    busy = [str(port) for port in ports if port_is_listening(port)]
    if busy:
        raise RuntimeError(f"TCP port already in use: {', '.join(busy)}")


def wait_for_ports(process, ports, timeout):
    pending = set(ports)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"BMv2 exited with status {process.returncode}")
        pending = {port for port in pending if not port_is_listening(port)}
        if pending:
            time.sleep(0.05)
    if pending:
        listed = ", ".join(str(port) for port in sorted(pending))
        raise RuntimeError(f"BMv2 did not open TCP port(s) {listed}")


def configure_hosts(net):
    for name, config in HOSTS.items():
        host = net.get(name)
        interface = host.defaultIntf().name
        run_host_command(host, [
            "ip", "route", "replace", "default",
            "via", config["gateway"], "dev", interface,
        ])
        run_host_command(host, [
            "ip", "neigh", "replace", config["gateway"],
            "lladdr", config["switch_mac"], "nud", "permanent", "dev", interface,
        ])


def configure_pipeline(threshold):
    command = [
        str(CONTROLLER),
        "--p4runtime-addr", f"127.0.0.1:{P4RUNTIME_PORT}",
        "--device-id", str(DEVICE_ID),
        "--election-id", str(ELECTION_ID),
        "--p4info", str(P4INFO),
        "--device-config", str(DEVICE_CONFIG),
        "--threshold", str(threshold),
    ]
    try:
        subprocess.run(command, cwd=PROJECT_ROOT, check=True, timeout=15)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("controller timed out") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"controller exited with status {error.returncode}") from error


def run_network(threshold):
    if os.geteuid() != 0:
        raise RuntimeError("Mininet must run as root")
    switch_binary = shutil.which("simple_switch_grpc")
    if switch_binary is None:
        raise RuntimeError("simple_switch_grpc is not in PATH")
    for artifact in (P4INFO, DEVICE_CONFIG, CONTROLLER):
        if not artifact.is_file():
            raise RuntimeError(f"missing build artifact: {artifact.relative_to(PROJECT_ROOT)}")

    with tempfile.TemporaryDirectory(prefix="p4-sketch-") as runtime_dir:
        topology = SketchTopology(
            switch_binary=switch_binary,
            runtime_dir=runtime_dir,
        )
        net = Mininet(topo=topology, controller=None, build=False)
        try:
            net.build()
            net.start()
            configure_hosts(net)
            configure_pipeline(threshold)
            info("*** Network ready; ICMP is forwarded without sketch updates\n")
            CLI(net)
        finally:
            net.stop()


def main():
    parser = argparse.ArgumentParser(description="run the Count-Min Sketch Mininet topology")
    parser.add_argument("--threshold", type=int, default=50, help="heavy-hitter packet threshold")
    args = parser.parse_args()
    setLogLevel("info")
    try:
        run_network(args.threshold)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"run: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
