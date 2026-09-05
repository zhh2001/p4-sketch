import ast
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


def field_path(value):
    if isinstance(value, dict) and value.get("type") == "field":
        return tuple(value["value"])
    return None


def field_paths(value):
    return {
        tuple(node["value"])
        for node in walk_dicts(value)
        if node.get("type") == "field"
    }


def literal_value(value):
    if not isinstance(value, dict) or value.get("type") != "hexstr":
        raise AssertionError(f"expected integer literal, got {value!r}")
    return int(value["value"], 0)


def operator_nodes(value, operator):
    return [node for node in walk_dicts(value) if node.get("op") == operator]


def expression_root(value):
    while (
        isinstance(value, dict)
        and value.get("type") == "expression"
        and isinstance(value.get("value"), dict)
    ):
        value = value["value"]
    return value


def metadata_path(path, name):
    return (
        path is not None
        and path[0] == "scalars"
        and path[-1].split(".")[-1] == name
    )


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

    def action_by_name(self, name):
        actions = [action for action in self.bmv2["actions"] if action["name"] == name]
        self.assertEqual(len(actions), 1, f"expected one BMv2 action named {name}")
        return actions[0]

    def conditional_by_name(self, name):
        return next(
            conditional
            for conditional in self.ingress["conditionals"]
            if conditional["name"] == name
        )

    def stage_successors(self, name):
        if name is None:
            return set()
        tables = {
            table["name"]: table for table in self.ingress["tables"]
        }
        conditionals = {
            conditional["name"]: conditional
            for conditional in self.ingress["conditionals"]
        }
        if name in conditionals:
            stage = conditionals[name]
            return {
                successor
                for successor in (stage["true_next"], stage["false_next"])
                if successor is not None
            }
        stage = tables[name]
        successors = set(stage["next_tables"].values())
        successors.add(stage["base_default_next"])
        successors.discard(None)
        return successors

    def reachable_stages(self, start):
        reachable = set()
        pending = [start] if start is not None else []
        while pending:
            name = pending.pop()
            if name in reachable:
                continue
            reachable.add(name)
            pending.extend(self.stage_successors(name) - reachable)
        return reachable

    def route_successors(self, route):
        if "__HIT__" in route["next_tables"]:
            return (
                route["next_tables"]["__HIT__"],
                route["next_tables"].get("__MISS__"),
            )
        return (
            route["next_tables"]["IngressImpl.ipv4_forward"],
            route["next_tables"]["IngressImpl.drop"],
        )

    def table_applying(self, action_name):
        tables = [
            table
            for table in self.ingress["tables"]
            if action_name in table["actions"]
        ]
        self.assertEqual(len(tables), 1, f"expected one table applying {action_name}")
        return tables[0]

    def ttl_assignment(self):
        assignments = [
            (action, primitive)
            for action in self.bmv2["actions"]
            for primitive in action["primitives"]
            if primitive["op"] == "assign"
            and field_path(primitive["parameters"][0]) == ("ipv4", "ttl")
        ]
        self.assertEqual(len(assignments), 1)
        return assignments[0]

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

    def test_p4info_sketch_contract(self):
        table = named_textproto_block(
            textproto_blocks(self.p4info, "tables"),
            "IngressImpl.sketch_config",
        )
        self.assertEqual(textproto_blocks(table, "match_fields"), [])

        action = named_textproto_block(
            textproto_blocks(self.p4info, "actions"),
            "IngressImpl.set_threshold",
        )
        action_id = integer_field(textproto_blocks(action, "preamble")[0], "id")
        params = textproto_blocks(action, "params")
        self.assertEqual(len(params), 1)
        self.assertEqual(string_field(params[0], "name"), "value")
        self.assertEqual(integer_field(params[0], "id"), 1)
        self.assertEqual(integer_field(params[0], "bitwidth"), 32)

        refs = textproto_blocks(table, "action_refs")
        self.assertEqual(len(refs), 1)
        self.assertEqual(integer_field(refs[0], "id"), action_id)
        self.assertEqual(string_field(refs[0], "annotations"), "@defaultonly")
        self.assertEqual(string_field(refs[0], "scope"), "DEFAULT_ONLY")
        self.assertNotRegex(table, r"(?m)^\s*const_default_action_id:")

        defaults = textproto_blocks(table, "initial_default_action")
        self.assertEqual(len(defaults), 1)
        self.assertEqual(integer_field(defaults[0], "action_id"), action_id)
        arguments = textproto_blocks(defaults[0], "arguments")
        self.assertEqual(len(arguments), 1)
        self.assertEqual(integer_field(arguments[0], "param_id"), 1)
        quoted_value = re.search(
            r'(?m)^\s*value:\s*("(?:\\.|[^"])*")\s*$', arguments[0]
        )
        self.assertIsNotNone(quoted_value)
        self.assertEqual(int.from_bytes(ast.literal_eval("b" + quoted_value[1]), "big"), 50)

        bmv2_table = self.table_by_name("IngressImpl.sketch_config")
        self.assertEqual(bmv2_table["key"], [])
        self.assertEqual(bmv2_table["actions"], ["IngressImpl.set_threshold"])
        threshold_action = self.action_by_name("IngressImpl.set_threshold")
        self.assertEqual(
            threshold_action["runtime_data"],
            [{"name": "value", "bitwidth": 32}],
        )
        self.assertEqual(len(threshold_action["primitives"]), 1)
        threshold_assignment = threshold_action["primitives"][0]
        self.assertEqual(threshold_assignment["op"], "assign")
        self.assertTrue(
            metadata_path(field_path(threshold_assignment["parameters"][0]), "threshold")
        )
        self.assertEqual(
            threshold_assignment["parameters"][1],
            {"type": "runtime_data", "value": 0},
        )
        self.assertEqual(
            bmv2_table["default_entry"]["action_id"], threshold_action["id"]
        )
        self.assertFalse(bmv2_table["default_entry"]["action_const"])
        self.assertFalse(bmv2_table["default_entry"]["action_entry_const"])
        self.assertEqual(
            [int(value, 0) for value in bmv2_table["default_entry"]["action_data"]],
            [50],
        )

        expected = {
            f"IngressImpl.sketch_row{row}": (256, 32) for row in range(3)
        }
        registers = {
            register["name"]: (register["size"], register["bitwidth"])
            for register in self.bmv2["register_arrays"]
        }
        self.assertEqual(registers, expected)

        p4info_registers = {
            string_field(textproto_blocks(block, "preamble")[0], "name"): (
                integer_field(block, "size"),
                integer_field(block, "bitwidth"),
            )
            for block in textproto_blocks(self.p4info, "registers")
        }
        self.assertEqual(p4info_registers, expected)

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

    def test_sketch_action_hashes_and_saturating_updates(self):
        action = self.action_by_name("IngressImpl.update_sketch")
        sketch_actions = [
            candidate
            for candidate in self.bmv2["actions"]
            if any(
                primitive["op"] in {
                    "modify_field_with_hash_based_offset",
                    "register_read",
                    "register_write",
                }
                for primitive in candidate["primitives"]
            )
        ]
        self.assertEqual(sketch_actions, [action])

        primitives = action["primitives"]
        hashes = [
            (offset, primitive)
            for offset, primitive in enumerate(primitives)
            if primitive["op"] == "modify_field_with_hash_based_offset"
        ]
        self.assertEqual(len(hashes), 3)
        calculations = {item["name"]: item for item in self.bmv2["calculations"]}
        crc32 = {item["name"] for item in self.bmv2["calculations"] if item["algo"] == "crc32"}
        referenced = {primitive["parameters"][2]["value"] for _, primitive in hashes}
        self.assertEqual(referenced, crc32)
        self.assertEqual(len(referenced), 3)

        expected_rows = [f"IngressImpl.sketch_row{row}" for row in range(3)]
        reads = {}
        writes = {}
        for offset, primitive in enumerate(primitives):
            if primitive["op"] not in {"register_read", "register_write"}:
                continue
            register = next(
                parameter["value"]
                for parameter in primitive["parameters"]
                if parameter["type"] == "register_array"
            )
            target = reads if primitive["op"] == "register_read" else writes
            self.assertNotIn(register, target)
            target[register] = (offset, primitive)
        self.assertEqual(set(reads), set(expected_rows))
        self.assertEqual(set(writes), set(expected_rows))

        index_to_row = {}
        for row in expected_rows:
            read_offset, read = reads[row]
            write_offset, write = writes[row]
            counter = field_path(read["parameters"][0])
            index = field_path(read["parameters"][2])
            self.assertEqual(field_path(write["parameters"][1]), index)
            self.assertEqual(field_path(write["parameters"][2]), counter)
            self.assertEqual(write_offset, read_offset + 3)

            guard = primitives[read_offset + 1]
            increment = primitives[read_offset + 2]
            self.assertEqual(guard["op"], "_jump_if_zero")
            comparisons = operator_nodes(guard["parameters"][0], "!=")
            self.assertEqual(len(comparisons), 1)
            self.assertEqual(field_path(comparisons[0]["left"]), counter)
            self.assertEqual(literal_value(comparisons[0]["right"]), 0xffffffff)
            self.assertEqual(literal_value(guard["parameters"][1]), write_offset)

            self.assertEqual(increment["op"], "assign")
            self.assertEqual(field_path(increment["parameters"][0]), counter)
            additions = operator_nodes(increment["parameters"][1], "+")
            self.assertEqual(len(additions), 1)
            self.assertEqual(field_path(additions[0]["left"]), counter)
            self.assertEqual(literal_value(additions[0]["right"]), 1)
            index_to_row[index] = int(row[-1])

        port_locals = {}
        for port in ("src_port", "dst_port"):
            sources = {("tcp", port), ("udp", port)}
            candidates = []
            for primitive in primitives:
                if primitive["op"] != "assign":
                    continue
                target = field_path(primitive["parameters"][0])
                if target is None or target[0] != "scalars":
                    continue
                assigned = {
                    field_path(candidate["parameters"][1])
                    for candidate in primitives
                    if candidate["op"] == "assign"
                    and field_path(candidate["parameters"][0]) == target
                }
                if assigned == sources:
                    candidates.append(target)
            self.assertEqual(len(set(candidates)), 1)
            port_locals[port] = candidates[0]

        port_assignments = {}
        for offset, primitive in enumerate(primitives):
            if primitive["op"] != "assign":
                continue
            target = field_path(primitive["parameters"][0])
            source = field_path(primitive["parameters"][1])
            for port, local in port_locals.items():
                if target == local and source in {("tcp", port), ("udp", port)}:
                    port_assignments[source] = offset
        self.assertEqual(
            list(port_assignments),
            [
                ("tcp", "src_port"),
                ("tcp", "dst_port"),
                ("udp", "src_port"),
                ("udp", "dst_port"),
            ],
        )
        tcp_offsets = [
            port_assignments[("tcp", "src_port")],
            port_assignments[("tcp", "dst_port")],
        ]
        udp_offsets = [
            port_assignments[("udp", "src_port")],
            port_assignments[("udp", "dst_port")],
        ]
        self.assertEqual(tcp_offsets[1], tcp_offsets[0] + 1)
        self.assertEqual(udp_offsets[1], udp_offsets[0] + 1)
        port_guard = primitives[tcp_offsets[0] - 1]
        self.assertEqual(port_guard["op"], "_jump_if_zero")
        self.assertEqual(
            field_paths(port_guard["parameters"][0]), {("tcp", "$valid$")}
        )
        self.assertEqual(literal_value(port_guard["parameters"][1]), udp_offsets[0])
        skip_udp = primitives[tcp_offsets[1] + 1]
        self.assertEqual(skip_udp["op"], "_jump")
        self.assertEqual(literal_value(skip_udp["parameters"][0]), udp_offsets[1] + 1)

        expected_inputs = {
            0: [0x11, ("ipv4", "src_addr"), ("ipv4", "dst_addr"),
                ("ipv4", "protocol"), "src_port", "dst_port"],
            1: [0x37, "dst_port", "src_port", ("ipv4", "protocol"),
                ("ipv4", "dst_addr"), ("ipv4", "src_addr")],
            2: [0x9d, ("ipv4", "protocol"), "src_port", "dst_port",
                ("ipv4", "src_addr"), ("ipv4", "dst_addr")],
        }
        observed_rows = set()
        for hash_offset, primitive in hashes:
            parameters = primitive["parameters"]
            row = index_to_row[field_path(parameters[0])]
            observed_rows.add(row)
            self.assertEqual(literal_value(parameters[1]), 0)
            self.assertEqual(literal_value(parameters[3]), 256)
            calculation = calculations[parameters[2]["value"]]
            self.assertEqual(calculation["algo"], "crc32")

            traced = []
            for item in calculation["input"]:
                scalar = tuple(item["value"])
                self.assertEqual(scalar[0], "scalars")
                definitions = [
                    candidate
                    for candidate in primitives[:hash_offset]
                    if candidate["op"] == "assign"
                    and field_path(candidate["parameters"][0]) == scalar
                ]
                self.assertEqual(len(definitions), 1)
                source = definitions[0]["parameters"][1]
                if source["type"] == "hexstr":
                    traced.append(literal_value(source))
                else:
                    path = field_path(source)
                    if path == port_locals["src_port"]:
                        traced.append("src_port")
                    elif path == port_locals["dst_port"]:
                        traced.append("dst_port")
                    else:
                        traced.append(path)
            self.assertEqual(traced, expected_inputs[row])
        self.assertEqual(observed_rows, {0, 1, 2})

        header_names = {"ethernet", "ipv4", "tcp", "udp"}
        header_writes = [
            primitive
            for primitive in primitives
            if primitive.get("parameters")
            and (
                (
                    field_path(primitive["parameters"][0]) is not None
                    and field_path(primitive["parameters"][0])[0] in header_names
                )
                or (
                    primitive["parameters"][0].get("type") == "header"
                    and primitive["parameters"][0].get("value") in header_names
                )
            )
        ]
        self.assertEqual(header_writes, [])

    def test_updated_minimum_and_heavy_classification(self):
        action = self.action_by_name("IngressImpl.update_sketch")
        primitives = action["primitives"]
        row_values = {}
        write_offsets = []
        for offset, primitive in enumerate(primitives):
            if primitive["op"] != "register_write":
                continue
            row = next(
                parameter["value"]
                for parameter in primitive["parameters"]
                if parameter["type"] == "register_array"
            )
            row_values[int(row[-1])] = field_path(primitive["parameters"][2])
            write_offsets.append(offset)

        estimates = [
            (offset, primitive)
            for offset, primitive in enumerate(primitives)
            if primitive["op"] == "assign"
            and metadata_path(field_path(primitive["parameters"][0]), "estimate")
        ]
        self.assertEqual(
            [field_path(primitive["parameters"][1]) for _, primitive in estimates],
            [row_values[0], row_values[1], row_values[2]],
        )
        self.assertLess(max(write_offsets), estimates[0][0])
        estimate = field_path(estimates[0][1]["parameters"][0])

        row1_guard = primitives[estimates[1][0] - 1]
        self.assertEqual(row1_guard["op"], "_jump_if_zero")
        row1_compare = operator_nodes(row1_guard["parameters"][0], "<")
        self.assertEqual(len(row1_compare), 1)
        self.assertEqual(field_path(row1_compare[0]["left"]), row_values[1])
        self.assertEqual(field_path(row1_compare[0]["right"]), row_values[0])
        self.assertEqual(
            literal_value(row1_guard["parameters"][1]), estimates[1][0] + 1
        )

        row2_guard = primitives[estimates[2][0] - 1]
        self.assertEqual(row2_guard["op"], "_jump_if_zero")
        row2_compare = operator_nodes(row2_guard["parameters"][0], "<")
        self.assertEqual(len(row2_compare), 1)
        self.assertEqual(field_path(row2_compare[0]["left"]), row_values[2])
        self.assertEqual(field_path(row2_compare[0]["right"]), estimate)
        self.assertEqual(
            literal_value(row2_guard["parameters"][1]), estimates[2][0] + 1
        )

        heavy = [
            (offset, primitive)
            for offset, primitive in enumerate(primitives)
            if primitive["op"] == "assign"
            and metadata_path(field_path(primitive["parameters"][0]), "is_heavy")
        ]
        self.assertEqual([literal_value(item[1]["parameters"][1]) for item in heavy], [1, 0])
        true_offset, true_assignment = heavy[0]
        false_offset, false_assignment = heavy[1]
        self.assertEqual(
            field_path(true_assignment["parameters"][0]),
            field_path(false_assignment["parameters"][0]),
        )
        guard = primitives[true_offset - 1]
        self.assertEqual(guard["op"], "_jump_if_zero")
        comparisons = operator_nodes(guard["parameters"][0], ">=")
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(field_path(comparisons[0]["left"]), estimate)
        threshold = field_path(comparisons[0]["right"])
        self.assertTrue(metadata_path(threshold, "threshold"))
        threshold_action = self.action_by_name("IngressImpl.set_threshold")
        self.assertEqual(len(threshold_action["primitives"]), 1)
        self.assertEqual(
            field_path(threshold_action["primitives"][0]["parameters"][0]),
            threshold,
        )
        self.assertLess(estimates[-1][0], true_offset - 1)
        self.assertEqual(literal_value(guard["parameters"][1]), false_offset)
        skip_false = primitives[true_offset + 1]
        self.assertEqual(skip_false["op"], "_jump")
        self.assertEqual(literal_value(skip_false["parameters"][0]), false_offset + 1)

    def test_ttl_decrement_follows_route_hit(self):
        route = self.table_by_name("IngressImpl.ipv4_lpm")
        hit_next, miss_next = self.route_successors(route)
        self.assertIsNotNone(hit_next)

        ttl_action, assignment = self.ttl_assignment()
        ttl_tables = [
            table
            for table in self.ingress["tables"]
            if ttl_action["id"] in table["action_ids"]
        ]
        self.assertEqual(len(ttl_tables), 1)
        ttl_table = ttl_tables[0]
        self.assertIn(ttl_table["name"], self.reachable_stages(hit_next))
        self.assertNotIn(ttl_table["name"], self.reachable_stages(miss_next))

        expression = assignment["parameters"][1]
        self.assertTrue(contains_field(expression, ("ipv4", "ttl")))
        operators = expression_operators(expression)
        literals = integer_literals(expression)
        self.assertTrue(
            ("-" in operators and 1 in literals)
            or ("+" in operators and 0xff in literals),
            "TTL assignment is not an eight-bit decrement",
        )

    def test_sketch_update_requires_forwarded_tcp_or_udp(self):
        route = self.table_by_name("IngressImpl.ipv4_lpm")
        hit_next, miss_next = self.route_successors(route)
        eligibility = self.conditional_by_name(hit_next)
        root = expression_root(eligibility["expression"])
        self.assertEqual(root["op"], "or")
        self.assertEqual(
            field_paths(eligibility["expression"]),
            {("tcp", "$valid$"), ("udp", "$valid$")},
        )

        config = self.table_by_name("IngressImpl.sketch_config")
        update = self.table_applying("IngressImpl.update_sketch")
        update_action = self.action_by_name("IngressImpl.update_sketch")
        self.assertEqual(update["actions"], ["IngressImpl.update_sketch"])
        self.assertEqual(update["action_ids"], [update_action["id"]])
        self.assertEqual(
            update["default_entry"]["action_id"], update_action["id"]
        )
        self.assertEqual(eligibility["true_next"], config["name"])
        self.assertEqual(self.stage_successors(config["name"]), {update["name"]})
        self.assertIn(update["name"], self.reachable_stages(hit_next))
        self.assertNotIn(update["name"], self.reachable_stages(eligibility["false_next"]))
        self.assertNotIn(update["name"], self.reachable_stages(miss_next))

        stages = (
            [table["name"] for table in self.ingress["tables"]]
            + [item["name"] for item in self.ingress["conditionals"]]
        )
        def predecessors(target):
            return {
                stage for stage in stages if target in self.stage_successors(stage)
            }

        self.assertEqual(predecessors(eligibility["name"]), {route["name"]})
        self.assertEqual(predecessors(config["name"]), {eligibility["name"]})
        self.assertEqual(predecessors(update["name"]), {config["name"]})

        ttl_action, _ = self.ttl_assignment()
        ttl_tables = [
            table
            for table in self.ingress["tables"]
            if ttl_action["id"] in table["action_ids"]
        ]
        self.assertEqual(len(ttl_tables), 1)
        ttl_table = ttl_tables[0]
        self.assertEqual(eligibility["false_next"], ttl_table["name"])
        self.assertEqual(self.stage_successors(update["name"]), {ttl_table["name"]})

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
