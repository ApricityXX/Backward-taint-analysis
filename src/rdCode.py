# -*- coding: utf-8 -*-
import argparse
import logging
import os
import sys
from datetime import datetime

import angr

import pygraphviz as pgv
from analysis import global_var
from analysis.core_analysis import DefinitionExplore
from analysis.search_vuln_info import GetVulnInfo

sys.setrecursionlimit(500)
logging.getLogger('angr').setLevel('CRITICAL')


def argsparse():
    # 设置输入的参数
    parser = argparse.ArgumentParser(description="Definition Analysis",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    # 添加待分析二进制文件路径
    parser.add_argument("-i", "--input", required=True,
                        help="Enter the file to be analyzed.")
    args = parser.parse_args()
    return args


def main():
    with open('log.txt', "w") as f:
        f.seek(0)
        f.truncate()  # 清空文件
    os.makedirs("results", exist_ok=True)
    starttime = datetime.now()
    # 获取待分析文件路径
    args = argsparse()
    binary = args.input

    # 初始化angr.Porject
    proj = angr.Project(binary)

    # 初始化CFG图
    bin_cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True,
                                    # Try to resolve indirect jumps. This is necessary to resolve jump targets from jump tables, etc.
                                    cross_references=True,
                                    # Whether CFGFast should collect "cross-references" from the entire program or not.
                                    force_complete_scan=False,
                                    # Perform a complete scan on the binary and maximize the number of identified code blocks.
                                    normalize=True,
                                    # Normalize the CFG as well as all function graphs after CFG recovery.
                                    symbols=True
                                    )  # Get function beginnings from symbols in the binary.

    endtime0 = datetime.now()
    print("CFG Object cost time:", endtime0 - starttime)

    # 获取引用危险函数的函数地址和引用危险函数的CFG图节点
    vuln_info = GetVulnInfo(proj, bin_cfg.copy()).__call__()

    # 将所有获得的引用危险函数的函数地址、CFG图等信息进行整理
    FUNC_PREDECESSORS = dict()
    ALL_FUNC_PREDECESSORS = dict()
    for name, tmp_list in vuln_info.items():
        vuln_node_preds = tmp_list[0]
        vuln_func_preds = tmp_list[1]
        for func_addr in vuln_func_preds:
            FUNC_PREDECESSORS[str(func_addr)] = []
        for x in vuln_node_preds:
            FUNC_PREDECESSORS[str(x.function_address)].append(x)
        ALL_FUNC_PREDECESSORS[name] = FUNC_PREDECESSORS.copy()
        FUNC_PREDECESSORS.clear()

    # 初始化主分析类
    de_explore = DefinitionExplore(proj, bin_cfg.copy())

    global_var._init()
    # 有FunctionHandler分析过程
    for name, func_predecessors in ALL_FUNC_PREDECESSORS.items():
        de_explore.current_vuln_name = name
        pathInfoGraph = pgv.AGraph(directed=True, splines="spline")
        pathInfoGraph.add_node(f"{name}|{hex(0)}", style="rounded")
        pathInfoGraph.write(f"./results/{binary.split('/')[-1]}_{name}.dot")
        for func_preds_addr, xrefs in func_predecessors.items():
            func_preds_addr = int(func_preds_addr)

            if not xrefs:
                continue
            for xref in xrefs:
                try:
                    # 获取初始观察点
                    call_to_xref_address = proj.factory.block(xref.addr).instruction_addrs[-1]
                    func_pred = bin_cfg.functions.get_by_addr(func_preds_addr)
                    print(hex(call_to_xref_address))
                    # MIPS架构分析
                    if 'MIPS' in proj.arch.name:
                        de_explore.explore(func_pred, call_to_xref_address, name, "handler")

                except Exception as e:
                    logging.exception(e)
                    print("\033[31mERROR:{}\033[0m".format(e))

        pathInfoGraph = pgv.AGraph(f"./results/{binary.split('/')[-1]}_{name}.dot")
        pathInfoGraph.draw(f"./results/{binary.split('/')[-1]}_{name}.png", prog="dot", format="png")

    print("\033[34mEnd Of Analysis\033[0m")
    endtime = datetime.now()

    print("total time:", endtime - starttime)


if __name__ == '__main__':
    main()
