from hexi_core.visitor import dumping_tree_visitor_t

import ida_hexrays


def print_tree(func):
    """Dump a function's pseudocode tree to the output window as text."""

    cfunc = ida_hexrays.decompile(func)

    visitor = dumping_tree_visitor_t()
    visitor.apply_to(cfunc.body, None)
