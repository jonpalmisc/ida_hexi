from hexi_core import dumper, grapher

import ida_idaapi
import ida_kernwin
import ida_hexrays

from typing import Optional


def get_pseudo_tree(
    ctx: ida_kernwin.action_ctx_base_t, use_subtree: bool
) -> Optional[ida_hexrays.citem_t]:
    """
    Get the pseudocode tree for an entire function or a subtree depending on
    user preferences and the current UI context.
    """

    if ctx.widget_type != ida_kernwin.BWN_PSEUDOCODE:
        return None
    if not (vdui := ida_hexrays.get_widget_vdui(ctx.widget)):
        return None

    # Return entire tree if a subtree was not requested.
    if not use_subtree:
        return vdui.cfunc.body

    # Try to determine the currently-focused subtree.
    vdui.get_current_item(ida_hexrays.USE_KEYBOARD)
    if vdui.item.is_citem():
        return vdui.item.e

    return None


class dump_tree_handler_t(ida_kernwin.action_handler_t):
    use_subtree: bool

    def __init__(self, use_subtree: bool = False):
        ida_kernwin.action_handler_t.__init__(self)
        self.use_subtree = use_subtree

    def activate(self, ctx):  # pyright: ignore
        if tree := get_pseudo_tree(ctx, self.use_subtree):
            dumper.print_tree(tree)

        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if get_pseudo_tree(ctx, self.use_subtree)
            else ida_kernwin.AST_DISABLE
        )


class view_tree_handler_t(ida_kernwin.action_handler_t):
    use_subtree: bool

    def __init__(self, use_subtree: bool = False):
        ida_kernwin.action_handler_t.__init__(self)
        self.use_subtree = use_subtree

    def activate(self, ctx):  # pyright: ignore
        if tree := get_pseudo_tree(ctx, self.use_subtree):
            grapher.show_tree(tree)

        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if get_pseudo_tree(ctx, self.use_subtree)
            else ida_kernwin.AST_DISABLE
        )


##===----------------------------------------------------------------------===##


class hexi_ui_hooks_t(ida_kernwin.UI_Hooks):
    popup_actions = []

    def finish_populating_widget_popup(self, widget, popup):  # pyright: ignore
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        for action_id, action_name in self.popup_actions:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                action_id,
                f"&Hexi/{action_name}",
                ida_kernwin.SETMENU_APP,
            )


class hexi_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_DRAW | ida_idaapi.PLUGIN_HIDE
    help = ""
    comment = "Hex-Rays decompiler inspector"
    wanted_name = "hexi"
    wanted_hotkey = ""

    ui_hooks: hexi_ui_hooks_t

    def register_action(
        self,
        id: str,
        name: str,
        help: str,
        handler,
    ):
        """Register an action and add it to the popup menu all at once."""

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(id, name, handler, None, help)
        )
        self.ui_hooks.popup_actions.append((id, name))

    def init(self):
        self.ui_hooks = hexi_ui_hooks_t()

        self.register_action(
            "hexi:ViewPseudoTree",
            "View pseudocode ~t~ree",
            "View the pseudocode tree as a graph",
            view_tree_handler_t(),
        )
        self.register_action(
            "hexi:ViewPseudoSubtree",
            "View pseudocode ~s~ubtree",
            "View the selected pseudocode subtree as a graph",
            view_tree_handler_t(use_subtree=True),
        )
        self.register_action(
            "hexi:DumpPseudoTree",
            "Dump pseudocode tree",
            "Dump the pseudocode tree to the output window",
            dump_tree_handler_t(),
        )
        self.register_action(
            "hexi:DumpPseudoSubtree",
            "Dump pseudocode subtree",
            "Dump the selected pseudocode subtree to the output window",
            dump_tree_handler_t(use_subtree=True),
        )

        self.ui_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self):  # pyright: ignore
        print("Plugin cannot be run as a script!")

    def term(self):
        self.ui_hooks.unhook()


def PLUGIN_ENTRY():
    return hexi_plugin_t()
