import ida_hexrays
import ida_name
import ida_idaapi
import ida_graph

from dataclasses import dataclass
from typing import Dict


def op_to_str(op: int) -> str:
    """Get the canonical name for an operation by ID."""

    # fmt: off
    match op:
        case ida_hexrays.cot_empty: return "empty"
        case ida_hexrays.cot_comma: return "comma"
        case ida_hexrays.cot_asg: return "asg"
        case ida_hexrays.cot_asgbor: return "asgbor"
        case ida_hexrays.cot_asgxor: return "asgxor"
        case ida_hexrays.cot_asgband: return "asgband"
        case ida_hexrays.cot_asgadd: return "asgadd"
        case ida_hexrays.cot_asgsub: return "asgsub"
        case ida_hexrays.cot_asgmul: return "asgmul"
        case ida_hexrays.cot_asgsshr: return "asgsshr"
        case ida_hexrays.cot_asgushr: return "asgushr"
        case ida_hexrays.cot_asgshl: return "asgshl"
        case ida_hexrays.cot_asgsdiv: return "asgsdiv"
        case ida_hexrays.cot_asgudiv: return "asgudiv"
        case ida_hexrays.cot_asgsmod: return "asgsmod"
        case ida_hexrays.cot_asgumod: return "asgumod"
        case ida_hexrays.cot_tern: return "tern"
        case ida_hexrays.cot_lor: return "lor"
        case ida_hexrays.cot_land: return "land"
        case ida_hexrays.cot_bor: return "bor"
        case ida_hexrays.cot_xor: return "xor"
        case ida_hexrays.cot_band: return "band"
        case ida_hexrays.cot_eq: return "eq"
        case ida_hexrays.cot_ne: return "ne"
        case ida_hexrays.cot_sge: return "sge"
        case ida_hexrays.cot_uge: return "uge"
        case ida_hexrays.cot_sle: return "sle"
        case ida_hexrays.cot_ule: return "ule"
        case ida_hexrays.cot_sgt: return "sgt"
        case ida_hexrays.cot_ugt: return "ugt"
        case ida_hexrays.cot_slt: return "slt"
        case ida_hexrays.cot_ult: return "ult"
        case ida_hexrays.cot_sshr: return "sshr"
        case ida_hexrays.cot_ushr: return "ushr"
        case ida_hexrays.cot_shl: return "shl"
        case ida_hexrays.cot_add: return "add"
        case ida_hexrays.cot_sub: return "sub"
        case ida_hexrays.cot_mul: return "mul"
        case ida_hexrays.cot_sdiv: return "sdiv"
        case ida_hexrays.cot_udiv: return "udiv"
        case ida_hexrays.cot_smod: return "smod"
        case ida_hexrays.cot_umod: return "umod"
        case ida_hexrays.cot_fadd: return "fadd"
        case ida_hexrays.cot_fsub: return "fsub"
        case ida_hexrays.cot_fmul: return "fmul"
        case ida_hexrays.cot_fdiv: return "fdiv"
        case ida_hexrays.cot_fneg: return "fneg"
        case ida_hexrays.cot_neg: return "neg"
        case ida_hexrays.cot_cast: return "cast"
        case ida_hexrays.cot_lnot: return "lnot"
        case ida_hexrays.cot_bnot: return "bnot"
        case ida_hexrays.cot_ptr: return "ptr"
        case ida_hexrays.cot_ref: return "ref"
        case ida_hexrays.cot_postinc: return "postinc"
        case ida_hexrays.cot_postdec: return "postdec"
        case ida_hexrays.cot_preinc: return "preinc"
        case ida_hexrays.cot_predec: return "predec"
        case ida_hexrays.cot_call: return "call"
        case ida_hexrays.cot_idx: return "idx"
        case ida_hexrays.cot_memref: return "memref"
        case ida_hexrays.cot_memptr: return "memptr"
        case ida_hexrays.cot_num: return "num"
        case ida_hexrays.cot_fnum: return "fnum"
        case ida_hexrays.cot_str: return "str"
        case ida_hexrays.cot_obj: return "obj"
        case ida_hexrays.cot_var: return "var"
        case ida_hexrays.cot_insn: return "insn"
        case ida_hexrays.cot_sizeof: return "sizeof"
        case ida_hexrays.cot_helper: return "helper"
        case ida_hexrays.cot_type: return "type"
        case ida_hexrays.cit_empty: return "empty"
        case ida_hexrays.cit_block: return "block"
        case ida_hexrays.cit_expr: return "expr"
        case ida_hexrays.cit_if: return "if"
        case ida_hexrays.cit_for: return "for"
        case ida_hexrays.cit_while: return "while"
        case ida_hexrays.cit_do: return "do"
        case ida_hexrays.cit_switch: return "switch"
        case ida_hexrays.cit_break: return "break"
        case ida_hexrays.cit_continue: return "continue"
        case ida_hexrays.cit_return: return "return"
        case ida_hexrays.cit_goto: return "goto"
        case ida_hexrays.cit_asm: return "asm"
        case _: return str(op)
    # fmt: on


def quote(text: str) -> str:
    return f'"{text}"'


@dataclass
class item_info_t:
    name: str
    ea: int
    props: Dict[str, str]

    def __init__(self, item):
        self.name = op_to_str(item.op)
        self.props = {}
        self.ea = item.ea

        match item.op:
            case ida_hexrays.cot_ptr:
                self.props["size"] = item.ptrsize
            case ida_hexrays.cot_memref:
                self.props["offset"] = item.m
            case ida_hexrays.cot_memptr:
                self.props["offset"] = item.m
                self.props["size"] = item.ptrsize
            case ida_hexrays.cot_num:
                self.props["value"] = f"{item.n._value:#x}"
            case ida_hexrays.cot_obj:
                # Repurposing the address field to point to the object's
                # address. IDA doesn't populate this field for object items
                # anyway, and it yields a more intuitive rendering.
                self.ea = item.obj_ea

                if name := ida_name.get_short_name(item.obj_ea):
                    self.props["name"] = quote(name)
            case ida_hexrays.cot_var:
                self.props["name"] = quote(item.v.getv().name)
            case ida_hexrays.cot_helper:
                self.props["name"] = quote(item.helper)
            case _:
                pass


class common_tree_visitor_t(ida_hexrays.ctree_visitor_t):
    depth: int

    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(
            self, ida_hexrays.CV_POST | ida_hexrays.CV_PARENTS
        )
        self.depth = -1

    def process(self, item) -> int:
        return 0

    def visit_insn(self, insn) -> int:  # pyright: ignore
        self.depth += 1
        self.process(insn)
        return 0

    def leave_insn(self, *args) -> int:
        self.depth -= 1
        return super().leave_insn(*args)

    def visit_expr(self, expr) -> int:  # pyright: ignore
        self.depth += 1
        self.process(expr)
        return 0

    def leave_expr(self, *args) -> int:
        self.depth -= 1
        return super().leave_expr(*args)


class dumping_tree_visitor_t(common_tree_visitor_t):
    def __init__(self):
        common_tree_visitor_t.__init__(self)

    def process(self, item):
        info = item_info_t(item)

        text = info.name
        if info.ea != ida_idaapi.BADADDR:
            text += f"@{info.ea:#x}"

        pairs = []
        for prop in info.props:
            pairs.append(f"{prop}={info.props[prop]}")
        if len(pairs):
            text += "<" + ", ".join(pairs) + ">"

        print("  " * self.depth + text)
        return 0


class graphing_tree_visitor_t(common_tree_visitor_t):
    graph: ida_graph.GraphViewer
    obj_to_node: Dict[int, int]

    def __init__(self, graph):
        common_tree_visitor_t.__init__(self)
        self.graph = graph
        self.obj_to_node = {}

    def add_item(self, item):
        node_id = self.graph.AddNode(item)
        self.obj_to_node[item.obj_id] = node_id

        return node_id

    def process(self, item) -> int:
        node = self.add_item(item)
        if len(self.parents) > 1:
            parent = self.obj_to_node[self.parents.back().obj_id]
            self.graph.AddEdge(parent, node)

        return 0
