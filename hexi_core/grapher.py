import ida_idaapi
import ida_graph
import ida_hexrays
import ida_kernwin

from hexi_core.visitor import graphing_tree_visitor_t, item_info_t


class tree_graph_t(ida_graph.GraphViewer):
    def __init__(self, cfunc, close_open=False):
        ida_graph.GraphViewer.__init__(self, "Pseudocode tree", close_open)
        self.cfunc = cfunc

        self.Refresh()

    def OnRefresh(self):
        self.Clear()

        visitor = graphing_tree_visitor_t(self)
        visitor.apply_to(self.cfunc.body, None)

        return True

    def OnGetText(self, id):
        # TODO: Cache these so it can be shared with the double click handler?
        info = item_info_t(self[id])

        text = info.name
        if info.ea != ida_idaapi.BADADDR:
            text += f" @ {info.ea:#x}"

        text += "\n\n" if len(info.props) else ""
        for prop in info.props:
            text += f"{prop}: {info.props[prop]}\n"

        return text

    def OnDblClick(self, _):
        if not (hl := ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())):
            return True

        # Super sketchy "jump to highlighted address" logic...
        addr_text, _ = hl
        try:
            ida_kernwin.jumpto(int(addr_text, 16))
        except ValueError:
            pass

        return True

    def Show(self):
        if not ida_graph.GraphViewer.Show(self):
            return False

        return True


def show_tree(func):
    """View a function's pseudocode tree as a graph."""

    cfunc = ida_hexrays.decompile(func)
    tree_graph_t(cfunc).Show()
