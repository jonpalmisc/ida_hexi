from hexi_core import dumper, grapher

import ida_idaapi
import ida_kernwin

from typing import Optional


class dump_tree_handler_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):  # pyright: ignore
        dumper.print_tree(ctx.cur_func)
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE
            else ida_kernwin.AST_DISABLE
        )


class view_tree_handler_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):  # pyright: ignore
        grapher.show_tree(ctx.cur_func)
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE
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
                widget, popup, action_id, f"Hexi/{action_name}", ida_kernwin.SETMENU_APP
            )


class hexi_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_DRAW | ida_idaapi.PLUGIN_HIDE
    help = ""
    comment = "Hex-Rays decompiler introspection tools"
    wanted_name = "hexi"
    wanted_hotkey = ""

    ui_hooks: hexi_ui_hooks_t

    def register_action(
        self,
        id: str,
        name: str,
        handler,
        shortcut: Optional[str] = None,
    ):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(id, name, handler, shortcut)
        )
        self.ui_hooks.popup_actions.append((id, name))

    def init(self):
        self.ui_hooks = hexi_ui_hooks_t()

        self.register_action("hexi:dump_tree", "Dump tree", dump_tree_handler_t())
        self.register_action("hexi:view_tree", "View tree", view_tree_handler_t())

        self.ui_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self):  # pyright: ignore
        print("Plugin cannot be run as a script!")

    def term(self):
        self.ui_hooks.unhook()


def PLUGIN_ENTRY():
    return hexi_plugin_t()
