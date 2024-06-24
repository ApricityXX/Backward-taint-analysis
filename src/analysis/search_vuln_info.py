#!/usr/bin/env python
# -*- coding: utf-8 -*-

class GetVulnInfo:
    def __init__(self, project, cfg):
        """
        初始化获取漏洞点信息所需的数据
        :param project: angr的Project
        :param cfg: 控制流图(CFG)
        """
        self._proj = project
        self._bin_cfg = cfg
        # 获取架构信息
        self._arch = project.arch.name
        # 外部的高危函数(如libc中)
        self._external_vuln_func = ['system']

    def __call__(self):
        """
        获取危险函数节点和所在函数地址的信息
        :return: 由危险函数构成的节点和函数地址字典
        """
        vuln = self._get_Info()
        return vuln

    def _get_Info(self) -> dict:
        vuln_plt = dict()
        vuln_info = dict()
        # main_obj = self._proj.loader.main_object  # 存储二进制文件一些信息，https://docs.angr.io/projects/cle/en/stable/_modules/cle/loader.html
        for name in self._external_vuln_func:
            symbol = self._proj.loader.find_symbol(name)  # 返回cle.backends.Symbol对象
            if symbol is not None:
                vuln_plt[name] = symbol.rebased_addr
        for name, addr in vuln_plt.items():
            current_node = self._bin_cfg.model.get_any_node(addr)
            # Get an arbitrary CFGNode (without considering their contexts) from our graph. https://docs.angr.io/en/latest/api.html#angr.knowledge_plugins.cfg.cfg_model.CFGModel
            if current_node is None:
                break
            vuln_node_preds = current_node.predecessors
            for node in vuln_node_preds:
                print("node_preds:", node)
            vuln_func_preds = list(
                set(x.function_address for x in vuln_node_preds))  # get all of the function appeared address
            vuln_info[name] = [vuln_node_preds.copy(), vuln_func_preds.copy()]
            vuln_node_preds.clear()
            vuln_func_preds.clear()
            return vuln_info
