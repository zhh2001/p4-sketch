import re
import subprocess


SKETCH_ROWS = tuple(f"IngressImpl.sketch_row{row}" for row in range(3))
SKETCH_WIDTH = 256
COUNTER_MAX = 0xFFFFFFFF

_CLI_FAILURE = re.compile(r"(?:\bError:|\bInvalid register operation\b|\bException\b)")


class RegisterError(RuntimeError):
    pass


class SketchRegisters:
    def __init__(self, thrift_port=9090, cli="simple_switch_CLI", timeout=5):
        if not 1 <= thrift_port <= 65535:
            raise ValueError("Thrift port must be between 1 and 65535")
        if timeout <= 0:
            raise ValueError("CLI timeout must be positive")
        self.thrift_port = thrift_port
        self.cli = cli
        self.timeout = timeout

    def _run(self, command):
        try:
            result = subprocess.run(
                [self.cli, "--thrift-ip", "127.0.0.1", "--thrift-port", str(self.thrift_port)],
                input=f"{command}\n",
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RegisterError(f"simple_switch_CLI failed: {error}") from error
        output = result.stdout + result.stderr
        if result.returncode != 0 or _CLI_FAILURE.search(output):
            detail = " ".join(output.split()) or f"exit status {result.returncode}"
            raise RegisterError(f"simple_switch_CLI command {command!r} failed: {detail}")
        return output

    def read_row(self, row):
        _check_row(row)
        return parse_row(self._run(f"register_read {row}"), row)

    def read_cell(self, row, index):
        _check_row(row)
        _check_index(index)
        return parse_cell(self._run(f"register_read {row} {index}"), row, index)

    def read_all(self):
        return {row: self.read_row(row) for row in SKETCH_ROWS}

    def write_cell(self, row, index, value):
        _check_row(row)
        _check_index(index)
        if not 0 <= value <= COUNTER_MAX:
            raise ValueError(f"counter value must be between 0 and {COUNTER_MAX}")
        self._run(f"register_write {row} {index} {value}")

    def reset_all(self):
        for row in SKETCH_ROWS:
            self._run(f"register_reset {row}")
        rows = self.read_all()
        for row, values in rows.items():
            for index, value in enumerate(values):
                if value != 0:
                    raise RegisterError(
                        f"{row}[{index}]: expected 0 after reset, observed {value}"
                    )
        return rows


def parse_row(output, row):
    _check_row(row)
    match = re.search(
        rf"(?m)^(?:RuntimeCmd:\s*)*{re.escape(row)}=\s*([0-9]+(?:\s*,\s*[0-9]+)*)\s*$",
        output,
    )
    if match is None:
        raise RegisterError(f"{row}: register output not found")
    values = [int(value.strip()) for value in match.group(1).split(",")]
    if len(values) != SKETCH_WIDTH:
        raise RegisterError(
            f"{row}: expected {SKETCH_WIDTH} counters, observed {len(values)}"
        )
    for index, value in enumerate(values):
        if not 0 <= value <= COUNTER_MAX:
            raise RegisterError(f"{row}[{index}]: invalid counter value {value}")
    return values


def parse_cell(output, row, expected_index):
    _check_row(row)
    _check_index(expected_index)
    match = re.search(
        rf"(?m)^(?:RuntimeCmd:\s*)*{re.escape(row)}\[([0-9]+)\]=\s*([0-9]+)\s*$",
        output,
    )
    if match is None:
        raise RegisterError(f"{row}[{expected_index}]: register output not found")
    index = int(match.group(1))
    value = int(match.group(2))
    if index != expected_index:
        raise RegisterError(f"{row}: expected index {expected_index}, observed {index}")
    if not 0 <= value <= COUNTER_MAX:
        raise RegisterError(f"{row}[{index}]: invalid counter value {value}")
    return value


def _check_row(row):
    if row not in SKETCH_ROWS:
        raise ValueError(f"unknown sketch row: {row}")


def _check_index(index):
    if not 0 <= index < SKETCH_WIDTH:
        raise ValueError(f"register index must be between 0 and {SKETCH_WIDTH - 1}")
