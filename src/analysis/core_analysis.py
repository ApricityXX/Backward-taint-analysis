# -*- coding: utf-8 -*-
from .mips.offset import UpdateOffset as MIPS32_UpdateOffset
from .mips.offset import InitOffset as MIPS32_InitOffset
from .mips.handler import Handler as MIPS32Handler

from typing import Tuple
import angr.analyses.reaching_definitions.dep_graph as dep_graph

from analysis import utils, global_var
import logging

from .utils import writelog


class DefinitionExplore:
    def __init__(self, project, cfg):
        """
        初始化可达定义分析所需的数据
        :param project: angr的Project
        :param cfg:待分析文件的CFG图
        """
        self._proj = project
        self._cfg = cfg
        self._break_count = 30
        self._break_address = None
        self._hit_point = []
        # 获取架构信息
        self._archinfo = project.arch
        # 存储用于进行过滤操作的信息
        self.call_addr = 0
        self.func_addr = 0
        self.current_vuln_name = ''
        # 设置handler和InitOffset
        if 'MIPS32' in self._archinfo.name:
            self._handler = MIPS32Handler()
            self._init_offset = MIPS32_InitOffset

    def explore(self, sub_func, call_addr, name: str, handler: str):
        """
        为主分析逻辑提供一个外部接口
        :param sub_func:当前分析的函数
        :param call_addr:观测点地址
        :param name:危险函数名
        :param handler:是否使用handler
        """
        offset_list = self._init_offset(self._proj, name, sub_func, call_addr).__call__()
        if handler == "handler":
            utils.addPath(currentName=name, currentAddress=0, nextName=sub_func.name, nextAddress=call_addr,
                          binary=self._proj.filename, name=self.current_vuln_name)
            for offset in offset_list:
                self._explore_handler(offset, sub_func, call_addr, False)

    def _explore_handler(self, tmp_offset, sub_func, observation_addr, stack):
        writelog(f"Handler Header: {tmp_offset}, \n-----------------------------------------\n"
                 f"{sub_func}, \n-----------------------------------------\n"
                 f"{hex(observation_addr)}, \n-----------------------------------------\n"
                 f"{stack}")
        if tmp_offset == -9999:
            return
        # 有Handler情况下递归进行分析
        try:
            rd = self._proj.analyses.ReachingDefinitions(subject=sub_func,
                                                         func_graph=sub_func.graph,
                                                         cc=sub_func.calling_convention,
                                                         observation_points=[("insn", observation_addr, 0)],
                                                         dep_graph=dep_graph.DepGraph(),
                                                         function_handler=self._handler
                                                         )
            tmpFuncName = sub_func.name
            tmpAddress = observation_addr
            # if it is local function
            if tmp_offset == 16 and global_var.get_value('is_local_function'):
                global_var.set_value('is_local_function', False)
                last_addr = None
                tmp_addr = 0
                for addr in range(observation_addr - 4, sub_func.addr, -int(self._archinfo.bits / 8)):
                    register = self._proj.factory.block(addr).capstone.insns[0]
                    if "v0" in register.op_str:
                        break
                    if 'j' in register.mnemonic:
                        if '$' in register.op_str:
                            break
                        last_addr = int(register.op_str, 16)
                        tmp_addr = addr
                        break
                if last_addr is not None:
                    new_offset = 16
                    stack = False
                    writelog(f"my function new address0: {hex(tmp_addr)}")
                    utils.addPath(currentName=sub_func.name, currentAddress=tmpAddress,
                                  nextName=tmpFuncName, nextAddress=tmp_addr,
                                  binary=self._proj.filename, name=self.current_vuln_name)
                    function = self._proj.kb.functions.function(addr=last_addr)
                    new_addr = function.size + function.addr - int(self._archinfo.bits / 8)
                    writelog(f"new address1: {hex(new_addr)}")
                    utils.addPath(currentName=tmpFuncName, currentAddress=tmp_addr,
                                  nextName=function.name, nextAddress=new_addr,
                                  binary=self._proj.filename, name=self.current_vuln_name)

                    self._explore_handler(new_offset, function, new_addr, stack)
                    return
            # 依据传入的类型判断求栈定义还是寄存器定义
            if stack:
                begin_state = self._proj.factory.entry_state(addr=sub_func.addr)
                begin_sp = begin_state.regs.sp
                begin_sp = int(str(begin_sp).split(' ')[1].split('>')[0], 16)
                begin_state.inspect.b("mem_write", action=self.breakpoint_action)
                print("=====================\n target breakpoint address:", hex(begin_sp + tmp_offset))
                self._break_address = begin_sp + tmp_offset
                simgr = self._proj.factory.simulation_manager(begin_state)
                while len(simgr.active) and self._break_count > 0:
                    simgr.step()
                if len(self._hit_point) > 0:
                    new_func_name = self._hit_point.pop()
                    new_addr = self._hit_point.pop()
                    self._hit_point.clear()
                    self._break_count = 30
                    writelog(f"new breakpoint hit: {hex(new_addr)}")
                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                  nextName=new_func_name, nextAddress=new_addr,
                                  binary=self._proj.filename, name=self.current_vuln_name)
                    offset, stack = self._get_offset(addr=new_addr, func_addr=sub_func.addr)
                    self._explore_handler(offset, sub_func, new_addr, stack)
                    return
                current_def_set = rd.one_result.stack_definitions.get_objects_by_offset(tmp_offset)
            else:
                current_def_set = rd.one_result.register_definitions.get_objects_by_offset(tmp_offset)
            copy_def_set = current_def_set.copy()
            writelog(f"def1: {copy_def_set}")
            # 判断是否需要函数过程间分析
            if self._inter_function(copy_def_set, stack, tmp_offset, sub_func, observation_addr):
                # 函数过程间分析
                # 通过CFG图获取当前分析函数的所有前驱
                current_node = self._cfg.model.get_any_node(sub_func.addr)
                preds_node_list = current_node.predecessors
                # 遍历所有的前驱
                for pred_node in preds_node_list:
                    pred_func_addr = pred_node.function_address
                    pred_func = self._cfg.functions.get_by_addr(pred_func_addr)
                    new_addr = self._proj.factory.block(pred_node.addr).instruction_addrs[-1]
                    global_var.set_value("need_agrs", True)
                    writelog(f"new address2: {hex(new_addr)}")
                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                  nextName=pred_func.name, nextAddress=new_addr,
                                  binary=self._proj.filename, name=self.current_vuln_name)
                    self._explore_handler(tmp_offset, pred_func, new_addr, False)

            # 不进行函数过程间分析的情况
            else:
                for cu_def in copy_def_set:
                    if cu_def.codeloc.ins_addr is None:
                        writelog(f"def2: {cu_def}")
                        writelog(f"def2 ins_addr: None")
                        new_offset_list = global_var.get_value("new_offset_list")
                        writelog(f"new offset list is {new_offset_list}")
                        new_address = global_var.get_value("new_address")
                        writelog(f"new address is {new_address}")
                        if new_offset_list is None:
                            return
                        for new_offset in new_offset_list:
                            utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                          nextName=tmpFuncName, nextAddress=new_address,
                                          binary=self._proj.filename, name=self.current_vuln_name)
                            offset, stack = self._get_offset(addr=new_address, func_addr=sub_func.addr)
                            self._explore_handler(new_offset, sub_func, new_address, stack)
                        return
                    # 栈定义
                    if 'Mem' in str(cu_def.atom):
                        # 如果定义被标记为SideEffectTag,
                        # 说明该定义属于FunctionHandler自定义添加，需进一步分析
                        if len(cu_def.tags) != 0 and 'SideEffectTag' in str(cu_def.tags.copy().pop()):
                            for cu_data in cu_def.data.data.copy():
                                if str(cu_data) != '<Undefined>':
                                    if type(cu_data) == int:

                                        writelog(f"new address3: {hex(copy_def_set.copy().pop().codeloc.ins_addr)}")

                                        utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                      nextName=f"CONST_DATA:{hex(cu_data)}|{tmpFuncName}",
                                                      nextAddress=copy_def_set.copy().pop().codeloc.ins_addr,
                                                      binary=self._proj.filename, name=self.current_vuln_name)
                                    else:
                                        new_offset = cu_data.offset
                                        new_addr = cu_def.codeloc.ins_addr

                                        writelog(f"new address4: {hex(new_addr)}")

                                        utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                      nextName=sub_func.name, nextAddress=new_addr,
                                                      binary=self._proj.filename, name=self.current_vuln_name)
                                        self._explore_handler(new_offset, sub_func, new_addr, True)
                                writelog(f"def22: {cu_def}")
                                writelog(f"def22 ins_addr: None")
                                new_offset_list = global_var.get_value("new_offset_list")
                                writelog(f"new offset list2 is {new_offset_list}")
                                new_address = global_var.get_value("new_address")
                                writelog(f"new address2 is {new_address}")
                                if new_offset_list is None:
                                    return
                                for new_offset in new_offset_list:
                                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                  nextName=tmpFuncName, nextAddress=new_address,
                                                  binary=self._proj.filename, name=self.current_vuln_name)
                                    offset, stack = self._get_offset(addr=new_address, func_addr=sub_func.addr)
                                    self._explore_handler(new_offset, sub_func, new_address, stack)
                                return
                        else:
                            new_addr = cu_def.codeloc.ins_addr
                            new_offset, is_stack = self._get_offset(new_addr, sub_func.addr)
                            writelog(f"new address6: {hex(new_addr)}")
                            utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                          nextName=sub_func.name, nextAddress=new_addr,
                                          binary=self._proj.filename, name=self.current_vuln_name)
                            self._explore_handler(new_offset, sub_func, new_addr, is_stack)
                    # 寄存器定义
                    elif 'Reg' in str(cu_def.atom):
                        data = cu_def.data.data.copy().pop()
                        if type(data) is int:
                            main_obj = self._proj.loader.main_object
                            if main_obj.max_addr >= data >= main_obj.min_addr:
                                print("\033[31mFind ADDR:{}\033[0m".format(hex(data)))
                                data_symbol = self._proj.loader.find_symbol(data)
                                if data_symbol is not None:
                                    print("\033[31mThis is a Function:{}".format(data_symbol.name))

                                writelog(f"new address7: {hex(copy_def_set.copy().pop().codeloc.ins_addr)}")

                                utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                              nextName=f"CONST_DATA:{hex(data)}" + "|" + tmpFuncName,
                                              nextAddress=copy_def_set.copy().pop().codeloc.ins_addr,
                                              binary=self._proj.filename, name=self.current_vuln_name)
                            else:
                                print("\033[31mFind VALUE:{}\033[0m".format(hex(data)))
                        else:
                            # 找到结果
                            if len(cu_def.tags) != 0 and 'ReturnValueTag' in str(cu_def.tags.copy().pop()):
                                func_addr = cu_def.tags.copy().pop().function
                                func_symbol = self._proj.loader.find_symbol(func_addr)
                                if func_symbol.name not in utils.functions_list:
                                    new_addr = cu_def.codeloc.ins_addr
                                    new_offset, stack = self._get_offset(new_addr, sub_func.addr)
                                    writelog(f"new address8: {hex(new_addr)}")
                                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                  nextName=sub_func.name, nextAddress=new_addr,
                                                  binary=self._proj.filename, name=self.current_vuln_name)
                                    self._explore_handler(new_offset, sub_func, new_addr, stack)
                                if func_symbol is not None:
                                    writelog(f"new address9: {hex(cu_def.codeloc.ins_addr)}")
                                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                  nextName=func_symbol.name, nextAddress=cu_def.codeloc.ins_addr,
                                                  binary=self._proj.filename, name=self.current_vuln_name)
                                else:
                                    writelog(f"new address10: {hex(cu_def.codeloc.ins_addr)}")
                                    name = self._proj.loader.find_plt_stub_name(func_addr)
                                    utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                                  nextName=name, nextAddress=cu_def.codeloc.ins_addr,
                                                  binary=self._proj.filename, name=self.current_vuln_name)
                                return
                            # 未找到，继续递归分析
                            else:
                                new_addr = cu_def.codeloc.ins_addr
                                print(f"ERROR address: {hex(new_addr)}")
                                new_offset, stack = self._get_offset(new_addr, sub_func.addr)

                                writelog(f"new address11: {hex(new_addr)}")

                                utils.addPath(currentName=tmpFuncName, currentAddress=tmpAddress,
                                              nextName=sub_func.name, nextAddress=new_addr,
                                              binary=self._proj.filename, name=self.current_vuln_name)
                                self._explore_handler(new_offset, sub_func, new_addr, stack)
        except Exception as e:
            logging.exception(e)
            print("\033[31mERROR:{}\033[0m".format(e))
            return

    def _inter_function(self, def_set: set, stack: bool, offset, sub_func, observation_addr) -> bool:
        # 判断是否符合需要跨函分析(函数过程间分析)
        if len(def_set) == 0:
            # 对不同架构获取相应的函数调用传参寄存器
            param_reg_list = list()
            if 'MIPS32' in self._archinfo.name:
                param_reg_list.append(self._proj.arch.registers.get('a0')[0])
                param_reg_list.append(self._proj.arch.registers.get('a1')[0])
                param_reg_list.append(self._proj.arch.registers.get('a2')[0])
                param_reg_list.append(self._proj.arch.registers.get('a3')[0])
            # 如果当前分析的寄存器属于传参寄存器
            if offset in param_reg_list:
                # 判断观测点的指令是否在当前分析函数的第一个基本块中
                sub_func_addr = sub_func.addr
                block = self._proj.factory.block(sub_func_addr)
                if observation_addr in block.instruction_addrs:
                    # 上述条件全都符合时，允许进行跨函数分析
                    writelog("\n_inter_function     OK\n")
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def _get_offset(self, addr, func_addr) -> Tuple[int, bool]:
        # 依据指令更新偏移
        # 并给出当前分析的是寄存器还是栈偏移
        cu_block = self._proj.factory.block(addr=addr)
        # 获取指令操作数和指令名称
        op_str = cu_block.capstone.insns[0].insn.op_str
        insn_name = cu_block.capstone.insns[0].insn.insn_name()
        if 'MIPS32' in self._archinfo.name:
            offset, stack = MIPS32_UpdateOffset(self._proj, cu_block, op_str, insn_name, func_addr).__call__()
            return offset, stack

    def breakpoint_action(self, state):
        self._break_count -= 1
        if self._break_count == 0:
            return
        print('Write', state.inspect.mem_write_expr, 'from', state.inspect.mem_write_address, hex(state.addr))
        if state.solver.eval(state.inspect.mem_write_address) != self._break_address:
            return
        function = None
        for f in self._cfg.functions.values():
            if len(f.endpoints) == 0:
                continue
            if f.startpoint.addr <= state.addr < (f.startpoint.addr + f.size):
                function = f
                break
        if function is None:
            return
        self._hit_point.append(state.addr)
        self._hit_point.append(function.name)
