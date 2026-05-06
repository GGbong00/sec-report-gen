# -*- coding: utf-8 -*-
"""
XML 数据导出生成器 - 生成结构化 XML 格式的安全报告数据

XML Data Export Generator - Generate structured XML format security report data
"""

import os
from typing import Dict, List, Any
from xml.etree.ElementTree import Element, SubElement, tostring, ElementTree
from xml.dom import minidom

from . import BaseGenerator, get_risk_level_text


class XMLGenerator(BaseGenerator):
    """XML 格式数据导出生成器"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        root = self._build_xml(project_info, vulnerabilities)
        xml_str = self._prettify(root)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(xml_str)

        return output_path

    def _build_xml(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Element:
        """构建 XML 树结构"""
        root = Element("SecReport")
        root.set("lang", self.lang)
        root.set("version", "1.0")

        # 项目信息节点
        project_node = SubElement(root, "ProjectInfo")

        self._add_text_element(project_node, "Name", project_info.get("name", self._t("unknown")))
        self._add_text_element(project_node, "Client", project_info.get("client", self._t("unknown")))
        self._add_text_element(project_node, "Tester", project_info.get("tester", self._t("unknown")))
        self._add_text_element(project_node, "Date", project_info.get("date", ""))
        self._add_text_element(project_node, "Classification", project_info.get("classification", self._t("unknown")))
        self._add_text_element(project_node, "Version", project_info.get("version", "1.0"))

        # 测试范围
        scope = project_info.get("scope", [])
        if isinstance(scope, str):
            scope = [scope]
        scope_node = SubElement(project_node, "Scope")
        for item in scope:
            self._add_text_element(scope_node, "Item", item)

        # 测试方法
        method = project_info.get("method", [])
        if isinstance(method, str):
            method = [method]
        method_node = SubElement(project_node, "Methodology")
        for item in method:
            self._add_text_element(method_node, "Item", item)

        # 测试工具
        tools = project_info.get("tools", [])
        if isinstance(tools, str):
            tools = [tools]
        tools_node = SubElement(project_node, "Tools")
        for item in tools:
            self._add_text_element(tools_node, "Tool", item)

        # 漏洞列表节点
        vulns_node = SubElement(root, "Vulnerabilities")
        vulns_node.set("total", str(len(vulnerabilities)))

        for idx, vuln in enumerate(vulnerabilities, 1):
            vuln_node = SubElement(vulns_node, "Vulnerability")
            vuln_node.set("id", str(idx).zfill(4))

            risk_level = str(vuln.get("risk_level", "info")).lower()

            self._add_text_element(vuln_node, "CVE_ID", vuln.get("cve_id", ""))
            self._add_text_element(vuln_node, "Name", vuln.get("name", self._t("unknown")))
            self._add_text_element(vuln_node, "RiskLevel", risk_level)
            self._add_text_element(vuln_node, "RiskLevelText", self._risk_text(risk_level))
            self._add_text_element(vuln_node, "Target", vuln.get("target", ""))
            self._add_text_element(vuln_node, "Port", str(vuln.get("port", "")))
            self._add_text_element(vuln_node, "Protocol", vuln.get("protocol", ""))
            self._add_text_element(vuln_node, "Description", vuln.get("description", ""))
            self._add_text_element(vuln_node, "Impact", vuln.get("impact", ""))
            self._add_text_element(vuln_node, "Remediation", vuln.get("remediation", ""))
            self._add_text_element(vuln_node, "Source", vuln.get("source", ""))

            # 复现步骤
            reproduce_steps = vuln.get("reproduce_steps", [])
            if isinstance(reproduce_steps, str):
                reproduce_steps = [reproduce_steps]
            steps_node = SubElement(vuln_node, "ReproduceSteps")
            for step_idx, step in enumerate(reproduce_steps, 1):
                step_node = SubElement(steps_node, "Step")
                step_node.set("order", str(step_idx))
                step_node.text = str(step)

        return root

    def _add_text_element(self, parent: Element, tag: str, text: str):
        """添加文本子元素"""
        elem = SubElement(parent, tag)
        elem.text = str(text) if text else ""
        return elem

    def _prettify(self, elem: Element) -> str:
        """将 XML 元素格式化为美化的字符串"""
        rough_string = tostring(elem, encoding="unicode")
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ", encoding=None)
        # 移除多余的空行
        lines = [line for line in pretty_xml.split("\n") if line.strip()]
        return "\n".join(lines) + "\n"
