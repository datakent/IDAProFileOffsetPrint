#---------------------------------------------------------
# IDA Pro Plugin -> fileOffset
# print file offset from current position to output window
#
# Test: IDA Pro 9.0 and Python 3.9
# 2025-05-12
#---------------------------------------------------------

VERSION = '1.0.0'
AUTHOR = 'datakent'
PLUGIN_NAME = "fileOffset"

import idaapi

class fileOffset(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "print file offset"
    wanted_name = PLUGIN_NAME

    ACTION_NAME_PRINTOFFSET = "fileOffset:PrintFileOffset"

    def init(self):
        self.AddActions()
        self._init_hooks()
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.RemoveAllActions()
        self._hooks.unhook()

    def _init_hooks(self):
        self._hooks = Hooks()
        self._init_hexrays_hooks()
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    def AddActions(self):
        action_desc_poffset = idaapi.action_desc_t(
            self.ACTION_NAME_PRINTOFFSET,
             "Print File Offset",
             PrintFileOffsetHandler(),
             None,
             ""
        )

        idaapi.register_action(action_desc_poffset)

    def RemoveAllActions(self):
        idaapi.unregister_action(self.ACTION_NAME_PRINTOFFSET)


def PLUGIN_ENTRY():
    return fileOffset()


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup, fileOffset.ACTION_NAME_PRINTOFFSET, None)
        return 0

    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            idaapi.attach_action_to_popup(form, popup, fileOffset.ACTION_NAME_PRINTOFFSET, None)
        return 0


class PrintFileOffsetHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        print(f"{ea:X} -> 0x{get_file_offset(ea):X}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

#Other defs
def get_file_offset(ea):
    seg = idaapi.getseg(ea)
    if seg:
        seg_start = seg.start_ea
        file_offset = idaapi.get_fileregion_offset(seg_start) + (ea - seg_start)
        return file_offset
    return idaapi.BADADDR