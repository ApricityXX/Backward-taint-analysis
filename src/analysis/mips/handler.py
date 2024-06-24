# -*- coding: utf-8 -*-
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.knowledge_plugins.key_definitions.tag import SideEffectTag
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.code_location import CodeLocation
from analysis.utils import extract_format, writelog
from angr import SimState
from analysis import global_var as global_var


class Handler(FunctionHandler):
    def __init__(self):
        self._analysis = None

    def hook(self, rda):
        self._analysis = rda
        return self

    def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth, visited_blocks,
                              dependency_graph, src_ins_addr=None, codeloc=None):
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        global_var.set_value('is_local_function', True)
        global_var.set_value('need_args', False)
        global_var.set_value('sub_func', function)
        global_var.set_value('new_addr', codeloc.ins_addr + function.size - 0x8)
        global_var.set_value("have_return_value", function.has_return)
        return True, state, visited_blocks, dependency_graph

    def handle_sprintf(self, state, codeloc):
        # sprintf(dest,"whoami;ls %s",src)
        offset = self._analysis.project.arch.registers.get('a1')[0]
        format_def = state.register_definitions.get_objects_by_offset(offset).copy().pop()
        format_addr = format_def.data.data.copy().pop()
        sim_state: SimState = self._analysis.project.factory.blank_state()
        format_list = extract_format(sim_state, format_addr)
        reg_offset_list = list()
        if len(format_list) > 1:
            reg_offset_list.append(self._analysis.project.arch.registers.get('a2')[0])
        a2_offset = self._analysis.project.arch.registers.get('a2')[0]
        dest_def = state.register_definitions.get_objects_by_offset(a2_offset)
        writelog(f"handler def new_addresss {hex(dest_def.copy().pop().codeloc.ins_addr)}")
        global_var.set_value("new_offset_list", reg_offset_list)
        global_var.set_value("new_address", dest_def.copy().pop().codeloc.ins_addr)
        return True, state

    def handle_snprintf(self, state, codeloc):
        offset = self._analysis.project.arch.registers.get('a2')[0]
        format_def = state.register_definitions.get_objects_by_offset(offset).copy().pop()
        format_addr = format_def.data.data.copy().pop()
        sim_state: SimState = self._analysis.project.factory.blank_state()
        format_list = extract_format(sim_state, format_addr)
        reg_offset_list = list()
        if len(format_list) > 1:
            reg_offset_list.append(self._analysis.project.arch.registers.get('a3')[0])
        a3_offset = self._analysis.project.arch.registers.get('a3')[0]
        dest_def = state.register_definitions.get_objects_by_offset(a3_offset)
        writelog(f"handler def new_addresss {dest_def.copy().pop().codeloc.ins_addr}")
        global_var.set_value("new_offset_list", reg_offset_list)
        global_var.set_value("new_address", dest_def.copy().pop().codeloc.ins_addr)
        return True, state

    def handle_strcpy(self, state, codeloc):  # 效果成功
        # strcpy(dest,src)
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        src_ins_addr = state.current_codeloc.ins_addr
        dest_offset = self._analysis.project.arch.registers.get('a0')[0]
        src_offset = self._analysis.project.arch.registers.get('a1')[0]
        dest_def = state.register_definitions.get_objects_by_offset(dest_offset)
        src_def = state.register_definitions.get_objects_by_offset(src_offset)
        dest_sp_offset = dest_def.copy().pop().data.data.copy().pop()
        new_atom = MemoryLocation(dest_sp_offset, int(self._analysis.project.arch.bits / 8))
        new_codeloc = CodeLocation(src_ins_addr, 0, ins_addr=src_ins_addr)
        new_data = src_def.copy().pop().data
        new_tags = {SideEffectTag(metadata=function)}
        state.kill_and_add_definition(new_atom, new_codeloc, new_data, tags=new_tags)
        return True, state

    def handle_strncpy(self, state, codeloc):
        # strncpy(dest,src,size)
        # 与strcpy一致
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        src_ins_addr = state.current_codeloc.ins_addr
        dest_offset = self._analysis.project.arch.registers.get('a0')[0]
        src_offset = self._analysis.project.arch.registers.get('a1')[0]
        dest_def = state.register_definitions.get_objects_by_offset(dest_offset)
        src_def = state.register_definitions.get_objects_by_offset(src_offset)
        dest_sp_offset = dest_def.copy().pop().data.data.copy().pop()
        new_atom = MemoryLocation(dest_sp_offset, int(self._analysis.project.arch.bits / 8))
        new_codeloc = CodeLocation(src_ins_addr, 0, ins_addr=src_ins_addr)
        new_data = src_def.copy().pop().data
        new_tags = {SideEffectTag(metadata=function)}
        state.kill_and_add_definition(new_atom, new_codeloc, new_data, tags=new_tags)
        return True, state

    def handle_memcpy(self, state, codeloc):
        # memcpy(dest,src,size)
        # 与strcpy一致
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        src_ins_addr = state.current_codeloc.ins_addr
        dest_offset = self._analysis.project.arch.registers.get('a0')[0]
        src_offset = self._analysis.project.arch.registers.get('a1')[0]
        dest_def = state.register_definitions.get_objects_by_offset(dest_offset)
        src_def = state.register_definitions.get_objects_by_offset(src_offset)
        dest_sp_offset = dest_def.copy().pop().data.data.copy().pop()
        new_atom = MemoryLocation(dest_sp_offset, int(self._analysis.project.arch.bits / 8))
        new_codeloc = CodeLocation(src_ins_addr, 0, ins_addr=src_ins_addr)
        new_data = src_def.copy().pop().data
        new_tags = {SideEffectTag(metadata=function)}
        state.kill_and_add_definition(new_atom, new_codeloc, new_data, tags=new_tags)
        return True, state

    def handle___isoc99_scanf(self, state, codeloc):
        # scanf("%s",src)
        # codeloc->plt address
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        src_ins_addr = state.current_codeloc.ins_addr  # this_function_called_address
        offset = self._analysis.project.arch.registers.get('a0')[0]
        format_def = state.register_definitions.get_objects_by_offset(offset).copy().pop()
        format_addr = format_def.data.data.copy().pop()  # the source of a0
        sim_state: SimState = self._analysis.project.factory.blank_state()
        format_list = extract_format(sim_state, format_addr)
        reg_offset_list = list()
        if len(format_list) == 1:
            reg_offset_list.append(self._analysis.project.arch.registers.get('a1')[0])
        elif len(format_list) == 2:
            reg_offset_list.append(self._analysis.project.arch.registers.get('a1')[0])
            reg_offset_list.append(self._analysis.project.arch.registers.get('a2')[0])
        elif len(format_list) >= 3:
            reg_offset_list.append(self._analysis.project.arch.registers.get('a1')[0])
            reg_offset_list.append(self._analysis.project.arch.registers.get('a2')[0])
            reg_offset_list.append(self._analysis.project.arch.registers.get('a3')[0])
        # 设置添加定义所需的变量
        for reg_offset in reg_offset_list:
            defs = state.register_definitions.get_objects_by_offset(reg_offset)  # the source of a1
            # 构造定义
            sp_offset = defs.copy().pop().data.data.copy().pop()  # the source address of a1
            new_atom = MemoryLocation(sp_offset, int(self._analysis.project.arch.bits / 8))
            new_codeloc = CodeLocation(src_ins_addr, 0, ins_addr=src_ins_addr)
            new_data = DataSet(Undefined(), self._analysis.project.arch.bits)
            new_tags = {SideEffectTag(metadata=function)}
            state.kill_and_add_definition(new_atom, new_codeloc, new_data, tags=new_tags)
        return True, state

    def handle_GetValue(self, state, codeloc):
        # GetValue("lan.ip",lan_ip)
        # GetValue获取的属于外部数据
        function = self._analysis.project.kb.functions.function(addr=codeloc.ins_addr)
        src_ins_addr = state.current_codeloc.ins_addr
        offset = self._analysis.project.arch.registers.get('a1')[0]
        defs = state.register_definitions.get_objects_by_offset(offset)
        sp_offset = defs.copy().pop().data.data.copy().pop()
        new_atom = MemoryLocation(sp_offset, int(self._analysis.project.arch.bits / 8))
        new_codeloc = CodeLocation(src_ins_addr, 0, ins_addr=src_ins_addr)
        new_data = DataSet(Undefined(), self._analysis.project.arch.bits)
        new_tags = {SideEffectTag(metadata=function)}
        state.kill_and_add_definition(new_atom, new_codeloc, new_data, tags=new_tags)
        return True, state

    def handle_printf(self, state, codeloc):
        global_var.set_value('is_local_function', False)
        return True, state
