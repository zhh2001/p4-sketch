import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BMV2_JSON = ROOT / "build" / "count_min_sketch.json"
P4INFO = ROOT / "build" / "count_min_sketch.p4info.txtpb"


def textproto_blocks(text, field):
    pattern = re.compile(rf"(?m)^\s*{re.escape(field)}\s*\{{")
    blocks = []

    for match in pattern.finditer(text):
        depth = 0
        for offset in range(match.end() - 1, len(text)):
            if text[offset] == "{":
                depth += 1
            elif text[offset] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[match.start():offset + 1])
                    break
        else:
            raise ValueError(f"unterminated {field} block")

    return blocks


def named_textproto_block(blocks, name):
    for block in blocks:
        preambles = textproto_blocks(block, "preamble")
        if not preambles:
            continue
        match = re.search(r'(?m)^\s*name:\s*"([^"]+)"', preambles[0])
        if match and match.group(1) == name:
            return block
    raise AssertionError(f"P4Info object {name!r} is missing")


def integer_field(block, field):
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*(\d+)\s*$", block)
    if not match:
        raise AssertionError(f"field {field!r} is missing")
    return int(match.group(1))


def string_field(block, field):
    match = re.search(
        rf'(?m)^\s*{re.escape(field)}:\s*(?:"([^"]+)"|(\w+))\s*$', block
    )
    if not match:
        raise AssertionError(f"field {field!r} is missing")
    return match.group(1) or match.group(2)


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def contains_field(value, path):
    return any(
        node.get("type") == "field" and node.get("value") == list(path)
        for node in walk_dicts(value)
    )


def expression_operators(value):
    return {
        node["op"]
        for node in walk_dicts(value)
        if isinstance(node.get("op"), str)
    }


def integer_literals(value):
    literals = set()
    for node in walk_dicts(value):
        if node.get("type") != "hexstr":
            continue
        literals.add(int(node["value"], 0))
    return literals


class StructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for artifact in (BMV2_JSON, P4INFO):
            if not artifact.is_file():
                raise AssertionError(f"missing {artifact.relative_to(ROOT)}; run make build")

        cls.bmv2 = json.loads(BMV2_JSON.read_text(encoding="utf-8"))
        cls.p4info = P4INFO.read_text(encoding="utf-8")
        cls.ingress = next(
            pipeline
            for pipeline in cls.bmv2["pipelines"]
            if pipeline["name"] == "ingress"
        )

    def action_by_id(self, action_id):
        return next(
            action for action in self.bmv2["actions"] if action["id"] == action_id
        )

    def table_by_name(self, name):
        return next(table for table in self.ingress["tables"] if table["name"] == name)

    def field_width(self, path):
        header_types = {
            item["name"]: {field[0]: field[1] for field in item["fields"]}
            for item in self.bmv2["header_types"]
        }
        headers = {item["name"]: item["header_type"] for item in self.bmv2["headers"]}
        return header_types[headers[path[0]]][path[1]]

    def decode_transition(self, transition, widths):
        byte_widths = [(width + 7) // 8 for width in widths]
        raw = int(transition["value"], 0).to_bytes(sum(byte_widths), "big")
        values = []
        offset = 0
        for byte_width in byte_widths:
            values.append(int.from_bytes(raw[offset:offset + byte_width], "big"))
            offset += byte_width
        return values

    def test_p4info_forwarding_contract(self):
        table = named_textproto_block(
            textproto_blocks(self.p4info, "tables"),
            "IngressImpl.ipv4_lpm",
        )
        match_fields = textproto_blocks(table, "match_fields")
        self.assertEqual(len(match_fields), 1)
        self.assertEqual(string_field(match_fields[0], "name"), "hdr.ipv4.dst_addr")
        self.assertEqual(integer_field(match_fields[0], "id"), 1)
        self.assertEqual(integer_field(match_fields[0], "bitwidth"), 32)
        self.assertEqual(string_field(match_fields[0], "match_type"), "LPM")
        self.assertEqual(integer_field(table, "size"), 64)

        action = named_textproto_block(
            textproto_blocks(self.p4info, "actions"),
            "IngressImpl.ipv4_forward",
        )
        action_id = integer_field(textproto_blocks(action, "preamble")[0], "id")
        params = {
            string_field(param, "name"): (
                integer_field(param, "id"),
                integer_field(param, "bitwidth"),
            )
            for param in textproto_blocks(action, "params")
        }
        self.assertEqual(
            params,
            {
                "dst_mac": (1, 48),
                "src_mac": (2, 48),
                "port": (3, 9),
            },
        )
        action_refs = {
            integer_field(ref, "id") for ref in textproto_blocks(table, "action_refs")
        }
        self.assertIn(action_id, action_refs)

    def test_fragment_aware_transport_parser(self):
        parser = self.bmv2["parsers"][0]
        states = {state["name"]: state for state in parser["parse_states"]}
        ipv4 = states["parse_ipv4"]

        keys = ipv4["transition_key"]
        paths = [key["value"] for key in keys]
        self.assertEqual(paths[0:2], [["ipv4", "version"], ["ipv4", "ihl"]])
        self.assertEqual(paths[3:], [["ipv4", "frag_offset"], ["ipv4", "protocol"]])

        flag_key = paths[2]
        flag_sets = [
            operation
            for operation in ipv4["parser_ops"]
            if operation["op"] == "set"
            and operation["parameters"][0].get("value") == flag_key
        ]
        self.assertEqual(len(flag_sets), 1)
        flag_expression = flag_sets[0]["parameters"][1]
        self.assertTrue(contains_field(flag_expression, ("ipv4", "flags")))
        self.assertIn("&", expression_operators(flag_expression))
        self.assertIn(1, integer_literals(flag_expression))

        widths = [self.field_width(path) for path in paths]
        transitions = {item["next_state"]: item for item in ipv4["transitions"]}
        self.assertEqual(
            self.decode_transition(transitions["parse_tcp"], widths),
            [4, 5, 0, 0, 6],
        )
        self.assertEqual(
            self.decode_transition(transitions["parse_udp"], widths),
            [4, 5, 0, 0, 17],
        )
        default = next(item for item in ipv4["transitions"] if item["type"] == "default")
        self.assertIsNone(default["next_state"])

        for state_name, header_name in (("parse_tcp", "tcp"), ("parse_udp", "udp")):
            extracts = [
                operation["parameters"][0].get("value")
                for operation in states[state_name]["parser_ops"]
                if operation["op"] == "extract"
            ]
            self.assertIn(header_name, extracts)

    def test_ipv4_route_rewrite_and_miss_drop(self):
        route = self.table_by_name("IngressImpl.ipv4_lpm")
        self.assertEqual(route["match_type"], "lpm")
        self.assertEqual(
            route["key"],
            [{
                "match_type": "lpm",
                "name": "hdr.ipv4.dst_addr",
                "target": ["ipv4", "dst_addr"],
                "mask": None,
            }],
        )
        self.assertIn("IngressImpl.ipv4_forward", route["actions"])

        forward = next(
            action
            for action in self.bmv2["actions"]
            if action["name"] == "IngressImpl.ipv4_forward"
        )
        self.assertEqual(
            [(item["name"], item["bitwidth"]) for item in forward["runtime_data"]],
            [("dst_mac", 48), ("src_mac", 48), ("port", 9)],
        )
        assignments = {
            tuple(primitive["parameters"][0]["value"]): primitive["parameters"][1]
            for primitive in forward["primitives"]
            if primitive["op"] == "assign"
        }
        self.assertEqual(assignments[("ethernet", "dst_addr")], {
            "type": "runtime_data", "value": 0,
        })
        self.assertEqual(assignments[("ethernet", "src_addr")], {
            "type": "runtime_data", "value": 1,
        })
        self.assertEqual(assignments[("standard_metadata", "egress_spec")], {
            "type": "runtime_data", "value": 2,
        })

        default_action = self.action_by_id(route["default_entry"]["action_id"])
        self.assertEqual(default_action["name"], "IngressImpl.drop")
        self.assertTrue(any(
            primitive["op"] == "mark_to_drop"
            for primitive in default_action["primitives"]
        ))

    def test_ttl_decrement_follows_route_hit(self):
        route = self.table_by_name("IngressImpl.ipv4_lpm")
        next_tables = route["next_tables"]
        if "__HIT__" in next_tables:
            hit_next = next_tables["__HIT__"]
            self.assertIn("__MISS__", next_tables)
            self.assertIsNone(next_tables["__MISS__"])
        else:
            hit_next = next_tables["IngressImpl.ipv4_forward"]
            self.assertIsNone(next_tables["IngressImpl.drop"])

        self.assertIsNotNone(hit_next)
        hit_stage = self.table_by_name(hit_next)
        hit_action = self.action_by_id(hit_stage["default_entry"]["action_id"])
        ttl_assignments = [
            (action["name"], primitive)
            for action in self.bmv2["actions"]
            for primitive in action["primitives"]
            if primitive["op"] == "assign"
            and primitive["parameters"][0].get("value") == ["ipv4", "ttl"]
        ]
        self.assertEqual(len(ttl_assignments), 1)
        action_name, assignment = ttl_assignments[0]
        self.assertEqual(action_name, hit_action["name"])

        expression = assignment["parameters"][1]
        self.assertTrue(contains_field(expression, ("ipv4", "ttl")))
        operators = expression_operators(expression)
        literals = integer_literals(expression)
        self.assertTrue(
            ("-" in operators and 1 in literals)
            or ("+" in operators and 0xff in literals),
            "TTL assignment is not an eight-bit decrement",
        )

    def test_ipv4_checksum_verification_and_update(self):
        checksums = [
            item
            for item in self.bmv2["checksums"]
            if item["target"] == ["ipv4", "hdr_checksum"]
        ]
        verify = [item for item in checksums if item["verify"] and not item["update"]]
        update = [item for item in checksums if item["update"] and not item["verify"]]
        self.assertEqual(len(verify), 1)
        self.assertEqual(len(update), 1)

        calculations = {item["name"]: item for item in self.bmv2["calculations"]}
        expected_fields = [
            ["ipv4", name]
            for name in (
                "version", "ihl", "diffserv", "total_len", "identification",
                "flags", "frag_offset", "ttl", "protocol", "src_addr", "dst_addr",
            )
        ]
        for checksum in (verify[0], update[0]):
            calculation = calculations[checksum["calculation"]]
            self.assertEqual(calculation["algo"], "csum16")
            self.assertEqual(
                [item["value"] for item in calculation["input"]],
                expected_fields,
            )

        checksum_guards = [
            conditional
            for conditional in self.ingress["conditionals"]
            if contains_field(
                conditional["expression"],
                ("standard_metadata", "checksum_error"),
            )
        ]
        self.assertEqual(len(checksum_guards), 1)
        drop_stage = self.table_by_name(checksum_guards[0]["true_next"])
        drop_action = self.action_by_id(drop_stage["default_entry"]["action_id"])
        self.assertEqual(drop_action["name"], "IngressImpl.drop")


if __name__ == "__main__":
    unittest.main()
