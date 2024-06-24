#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import Tuple
from analysis.utils import extract_format
import angr.analyses.reaching_definitions.dep_graph as dep_graph


class InitOffset:
    def __init__(self, proj, vuln_name: str, func_pred, call_addr):
        """
        初次分析前获取MIPS32架构所需对应的寄存器偏移或栈偏移
        :param proj: angr的Project
        :param vuln_name: 漏洞函数名称
        :param func_pred: 函数所在地址
        :param call_addr: 调用地址
        """
        self._proj = proj
        self._name = vuln_name
        self._func_pred = func_pred
        self._addr = call_addr

    def __call__(self):
        # MIPS架构传参寄存器:a0-a3
        offset = list()
        handler = '_handler_' + self._name
        if hasattr(self, handler):
            offset = getattr(self, handler)()
            return offset
        else:
            return offset

    def _handler_sprintf(self):
        offset_list = list()
        tmp_offset = self._proj.arch.registers.get('a1')[0]
        current_rd = self._proj.analyses.ReachingDefinitions(subject=self._func_pred,
                                                             func_graph=self._func_pred.graph,
                                                             cc=self._func_pred.calling_convention,
                                                             observation_points=[
                                                                 ("insn", self._addr, 0)],
                                                             dep_graph=dep_graph.DepGraph()
                                                             )
        current_defs = current_rd.one_result.register_definitions.get_objects_by_offset(tmp_offset)
        format_string_addr = current_defs.copy().pop().data.data.copy().pop()
        # 获取格式化字符串个数
        state = self._proj.factory.blank_state()
        format_result = extract_format(state, format_string_addr)
        # 依据格式化字符串个数返回相应的偏移
        if len(format_result) == 0:
            return offset_list
        elif len(format_result) == 1:
            offset_list.append(self._proj.arch.registers.get('a2')[0])
            return offset_list
        elif len(format_result) >= 2:
            offset_list.append(self._proj.arch.registers.get('a2')[0])
            offset_list.append(self._proj.arch.registers.get('a3')[0])
            return offset_list
        else:
            return offset_list

    def _handler_doSystemCmd(self):
        offset_list = list()
        tmp_offset = self._proj.arch.registers.get('a0')[0]
        current_rd = self._proj.analyses.ReachingDefinitions(subject=self._func_pred,
                                                             func_graph=self._func_pred.graph,
                                                             cc=self._func_pred.calling_convention,
                                                             observation_points=[("insn", self._addr, 0)],
                                                             dep_graph=dep_graph.DepGraph()
                                                             )
        current_defs = current_rd.one_result.register_definitions.get_objects_by_offset(tmp_offset)
        # 需要考虑 doSystemCmd(buf)的情况
        if str(current_defs.copy().pop().data.data.copy().pop()) != '<Undefined>':
            format_string_addr = current_defs.copy().pop().data.data.copy().pop()
            state = self._proj.factory.blank_state()
            format_result = extract_format(state, format_string_addr)
            if len(format_result) == 0:
                return offset_list
            elif len(format_result) == 1:
                offset_list.append(self._proj.arch.registers.get('a1')[0])
                return offset_list
            elif len(format_result) == 2:
                offset_list.append(self._proj.arch.registers.get('a1')[0])
                offset_list.append(self._proj.arch.registers.get('a2')[0])
                return offset_list
            elif len(format_result) >= 3:
                offset_list.append(self._proj.arch.registers.get('a1')[0])
                offset_list.append(self._proj.arch.registers.get('a2')[0])
                offset_list.append(self._proj.arch.registers.get('a3')[0])
                return offset_list
            else:
                return offset_list
        else:
            offset_list.append(self._proj.arch.registers.get('a0')[0])
            return offset_list

    def _handler_system(self):
        offset_list = list()
        offset_list.append(self._proj.arch.registers.get('a0')[0])
        return offset_list

    def _handler_strcpy(self):
        offset_list = list()
        offset_list.append(self._proj.arch.registers.get('a1')[0])
        return offset_list


class UpdateOffset:
    def __init__(self, proj, block, operand: str, insn_name, func_addr):
        """
        MIPS32架构更新分析过程中的偏移量
        :param proj: angr的Project
        :param block: 基本块
        :param operand: 操作数
        :param insn_name: 指令名称
        :param func_addr: 当前正在分析的函数地址
        """
        self._proj = proj
        self._block = block
        self._operand = operand
        self._insn_name = insn_name
        self._func_addr = func_addr

    def __call__(self) -> Tuple[int, bool]:
        # 依据指令的语义处理指令，
        # 获取对应的偏移，
        # 并且确定是栈偏移还是寄存器偏移
        # False：寄存器偏移；True：栈偏移
        handler = '_handler_' + self._insn_name
        if hasattr(self, handler):
            new_offset, stack = getattr(self, handler)()
            return new_offset, stack
        else:
            return -9999, False

    def _handler_move(self) -> Tuple[int, bool]:
        target_op = self._operand.split(', $')[1]
        target_offset = self._proj.arch.registers.get(target_op)[0]
        return target_offset, False

    def _handler_lw(self) -> Tuple[int, bool]:
        target_offset = int(self._operand.split(', ')[1].split('($')[0], 16)
        stack_size = self._stack_frame_size()
        return target_offset - stack_size, True

    def _handler_sw(self) -> Tuple[int, bool]:
        target_op = self._operand.split(', ')[0].split('$')[1]
        target_offset = self._proj.arch.registers.get(target_op)[0]
        return target_offset, False

    def _handler_addiu(self):
        target_op = self._operand.split(', ')[1].split('$')[1]
        if target_op == 'fp':
            stack_size = self._stack_frame_size()
            target_offset = int(self._operand.split(', ')[2], 16)
            return target_offset - stack_size, True
        else:
            target_offset = self._proj.arch.registers.get(target_op)[0]
            return target_offset, False

    def _stack_frame_size(self) -> int:
        # 在函数开头做一次符号执行获取栈帧大小
        begin_state = self._proj.factory.entry_state(addr=self._func_addr)
        suc_state = begin_state.step()
        next_state = suc_state.all_successors[0]
        begin_sp = begin_state.regs.sp
        next_sp = next_state.regs.sp
        begin_sp = int(str(begin_sp).split(' ')[1].split('>')[0], 16)
        next_sp = int(str(next_sp).split(' ')[1].split('>')[0], 16)
        return begin_sp - next_sp
