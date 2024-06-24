#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import pygraphviz
from angr import SimState

functions_list = ["system", "__isoc99_scanf", "sprintf", "handle_strcpy",
                  "strncpy", "memcpy", "GetValue", "malloc"]


def extract_format(state: SimState, format_addr: int) -> list:
    """
    提取ELF文件对应内存地址的字符串中格式化字符串
    :param state: angr的SimState，空白的状态，用于提取格式化字符串
    :param format_addr: 格式化字符串所在的地址
    :return: 返回提取出来的格式化字符串
    """
    length = 0x50
    read_string_bv = state.memory.load(format_addr, size=length)
    target_string = state.solver.eval(read_string_bv, cast_to=bytes)
    target_string = target_string.decode().split('\x00')[0]
    pattern = re.compile(r'%[a-zA-Z]{1,4}')
    format_result = pattern.findall(str(target_string))
    # 返回格式化字符串列表
    return format_result


def addPath(currentName, currentAddress, nextName, nextAddress, binary, name):
    print(currentName, hex(currentAddress), nextName, hex(nextAddress), binary, name)
    pathInfoGraph = pygraphviz.AGraph(f"./results/{binary.split('/')[-1]}_{name}.dot")
    pathInfoGraph.add_node(f"{nextName}|{hex(nextAddress)}", style="rounded")
    pathInfoGraph.add_edge(f"{nextName}|{hex(nextAddress)}", f"{currentName}|{hex(currentAddress)}", color='green')
    pathInfoGraph.write(f"./results/{binary.split('/')[-1]}_{name}.dot")


def writelog(loginfo):
    with open("log.txt", "a") as f:
        f.write("\n---------------------------------------------------------------"
                "\n---------------------------------------------------------------\n")
        f.write(loginfo)
        f.write("\n")
