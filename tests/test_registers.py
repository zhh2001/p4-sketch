import subprocess
import unittest
from unittest.mock import patch

from bmv2_registers import (
    COUNTER_MAX,
    SKETCH_ROWS,
    RegisterError,
    SketchRegisters,
    parse_cell,
    parse_row,
)


def cli_result(output="RuntimeCmd: "):
    return subprocess.CompletedProcess([], 0, output, "")


def row_output(row, values):
    return f"Obtaining JSON from switch...\nRuntimeCmd: {row}= {', '.join(map(str, values))}\n"


class RegisterParserTest(unittest.TestCase):
    def test_parse_row(self):
        values = [0] * 256
        values[17] = 42
        values[255] = COUNTER_MAX
        self.assertEqual(parse_row(row_output(SKETCH_ROWS[0], values), SKETCH_ROWS[0]), values)

    def test_parse_row_rejects_wrong_width(self):
        with self.assertRaisesRegex(RegisterError, "expected 256 counters, observed 2"):
            parse_row(row_output(SKETCH_ROWS[1], [0, 0]), SKETCH_ROWS[1])

    def test_parse_cell(self):
        output = f"RuntimeCmd: {SKETCH_ROWS[2]}[91]= 4294967294\nRuntimeCmd: "
        self.assertEqual(parse_cell(output, SKETCH_ROWS[2], 91), 0xFFFFFFFE)

    def test_parse_cell_rejects_wrong_index(self):
        output = f"RuntimeCmd: {SKETCH_ROWS[0]}[8]= 1\n"
        with self.assertRaisesRegex(RegisterError, "expected index 7, observed 8"):
            parse_cell(output, SKETCH_ROWS[0], 7)


class SketchRegistersTest(unittest.TestCase):
    @patch("bmv2_registers.subprocess.run")
    def test_reset_all_verifies_every_row(self, run):
        run.side_effect = [
            cli_result(),
            cli_result(),
            cli_result(),
            cli_result(row_output(SKETCH_ROWS[0], [0] * 256)),
            cli_result(row_output(SKETCH_ROWS[1], [0] * 256)),
            cli_result(row_output(SKETCH_ROWS[2], [0] * 256)),
        ]
        registers = SketchRegisters()
        rows = registers.reset_all()
        self.assertEqual(set(rows), set(SKETCH_ROWS))
        commands = [call.kwargs["input"].strip() for call in run.call_args_list]
        self.assertEqual(
            commands,
            [
                *(f"register_reset {row}" for row in SKETCH_ROWS),
                *(f"register_read {row}" for row in SKETCH_ROWS),
            ],
        )

    @patch("bmv2_registers.subprocess.run")
    def test_reset_all_reports_nonzero_cell(self, run):
        values = [0] * 256
        values[37] = 9
        run.side_effect = [
            cli_result(),
            cli_result(),
            cli_result(),
            cli_result(row_output(SKETCH_ROWS[0], [0] * 256)),
            cli_result(row_output(SKETCH_ROWS[1], values)),
            cli_result(row_output(SKETCH_ROWS[2], [0] * 256)),
        ]
        with self.assertRaisesRegex(
            RegisterError,
            rf"{SKETCH_ROWS[1]}\[37\]: expected 0 after reset, observed 9",
        ):
            SketchRegisters().reset_all()

    @patch("bmv2_registers.subprocess.run")
    def test_cli_error_is_not_accepted(self, run):
        run.return_value = cli_result("RuntimeCmd: Invalid register operation (INVALID_INDEX)\n")
        with self.assertRaisesRegex(RegisterError, "Invalid register operation"):
            SketchRegisters().write_cell(SKETCH_ROWS[0], 7, 1)

    @patch("bmv2_registers.subprocess.run")
    def test_read_and_write_cell_commands(self, run):
        run.side_effect = [
            cli_result(f"RuntimeCmd: {SKETCH_ROWS[0]}[7]= 5\n"),
            cli_result(),
        ]
        registers = SketchRegisters(thrift_port=9191)
        self.assertEqual(registers.read_cell(SKETCH_ROWS[0], 7), 5)
        registers.write_cell(SKETCH_ROWS[0], 7, COUNTER_MAX)
        commands = [call.kwargs["input"].strip() for call in run.call_args_list]
        self.assertEqual(
            commands,
            [
                f"register_read {SKETCH_ROWS[0]} 7",
                f"register_write {SKETCH_ROWS[0]} 7 {COUNTER_MAX}",
            ],
        )


if __name__ == "__main__":
    unittest.main()
