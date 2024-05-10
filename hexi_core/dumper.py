from hexi_core.visitor import dumping_tree_visitor_t

import ida_hexrays


def print_tree(root: ida_hexrays.citem_t):
    """Dump a function's pseudocode tree to the output window as text."""

    dumping_tree_visitor_t().apply_to(root, None)
