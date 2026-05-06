# -*- coding: utf-8 -*-
"""
TXT 文本报告生成器 - 生成纯文本格式的安全测试报告

TXT Text Report Generator - Generate plain text format security assessment reports
"""

import os
from typing import Dict, List, Any

from . import (
    BaseGenerator,
    count_by_level,
    get_overall_risk_level,
    get_risk_color,
)


class TXTGenerator(BaseGenerator):
    """TXT 纯文本格式报告生成器"""

    # 风险等级符号
    RISK_SYMBOLS = {
        "critical": "[!!!]",
        "high": "[!! ]",
        "medium": "[!  ]",
        "low": "[   ]",
        "info": "[   ]",
    }

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        lines = self._build_report(project_info, vulnerabilities)
        content = "\n".join(lines)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path

    def _separator(self, char: str = "=", width: int = 72) -> str:
        """生成分隔线"""
        return char * width

    def _sub_separator(self, char: str = "-", width: int = 72) -> str:
        """生成子分隔线"""
        return char * width

    def _build_report(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """构建报告文本行"""
        lines = []
        w = 72  # 行宽

        # ========== 封面 ==========
        lines.append(self._separator("=", w))
        lines.append("")
        lines.append(self._center_text(self._t("cover_title"), w))
        lines.append(self._center_text(self._t("cover_subtitle"), w))
        lines.append("")
        lines.append(self._separator("-", w))
        lines.append("")

        cover_items = [
            (self._t("cover_project"), project_info.get("name", self._t("unknown"))),
            (self._t("cover_client"), project_info.get("client", self._t("unknown"))),
            (self._t("cover_tester"), project_info.get("tester", self._t("unknown"))),
            (self._t("cover_date"), project_info.get("date", "")),
            (self._t("cover_classification"), project_info.get("classification", self._t("unknown"))),
        ]

        for label, value in cover_items:
            lines.append(f"  {label}: {value}")

        lines.append("")
        lines.append(self._separator("=", w))
        lines.append("")

        # ========== 第一章：项目概述 ==========
        lines.append(self._t("ch1_title"))
        lines.append(self._separator("-", w))
        lines.append("")

        lines.append(f"  {self._t('ch1_test_objective')}:")
        lines.append(f"    {self._t('ch1_test_objective_desc')}")
        lines.append("")

        lines.append(f"  {self._t('ch1_test_scope')}:")
        scope = project_info.get("scope", [])
        if isinstance(scope, str):
            scope = [scope]
        for item in scope:
            lines.append(f"    - {item}")
        if not scope:
            lines.append(f"    {self._t('ch1_test_scope_desc')}")
        lines.append("")

        lines.append(f"  {self._t('ch1_test_method')}:")
        method = project_info.get("method", [])
        if isinstance(method, str):
            method = [method]
        for item in method:
            lines.append(f"    - {item}")
        if not method:
            lines.append(f"    {self._t('ch1_test_method_desc')}")
        lines.append("")

        lines.append(f"  {self._t('ch1_test_tools')}:")
        tools = project_info.get("tools", [])
        if isinstance(tools, str):
            tools = [tools]
        for item in tools:
            lines.append(f"    - {item}")
        if not tools:
            lines.append(f"    {self._t('ch1_test_tools_desc')}")
        lines.append("")

        # ========== 第二章：风险统计概览 ==========
        lines.append(self._t("ch2_title"))
        lines.append(self._separator("-", w))
        lines.append("")
        lines.append(f"  {self._t('ch2_desc')}")
        lines.append("")

        counts = count_by_level(vulnerabilities)
        total = sum(counts.values())

        level_items = [
            ("critical", self._t("ch2_critical")),
            ("high", self._t("ch2_high")),
            ("medium", self._t("ch2_medium")),
            ("low", self._t("ch2_low")),
            ("info", self._t("ch2_info")),
        ]

        # 统计表
        header = f"  {'Risk Level':<20} {'Count':>8} {'Percentage':>12}"
        lines.append(header)
        lines.append(f"  {'-' * 42}")

        for level_key, level_name in level_items:
            count = counts[level_key]
            pct = f"{count / total * 100:.1f}%" if total > 0 else "0.0%"
            symbol = self.RISK_SYMBOLS.get(level_key, "[   ]")
            lines.append(f"  {symbol} {level_name:<16} {count:>8} {pct:>12}")

        lines.append(f"  {'-' * 42}")
        lines.append(f"  {'':>4}{'Total':<16} {total:>8} {'100.0%':>12}")
        lines.append("")

        # 简易柱状图
        max_count = max(counts.values()) if counts.values() else 1
        lines.append("  " + self._t("ch2_title") + ":")
        for level_key, level_name in level_items:
            count = counts[level_key]
            bar_len = int(count / max_count * 30) if max_count > 0 else 0
            bar = "#" * bar_len
            lines.append(f"    {level_name:<8} | {bar:<30} {count}")
        lines.append("")

        # ========== 第三章：漏洞详情 ==========
        lines.append(self._t("ch3_title"))
        lines.append(self._separator("-", w))
        lines.append("")

        if not vulnerabilities:
            lines.append(f"  {self._t('html_no_vulns')}")
            lines.append("")
        else:
            for idx, vuln in enumerate(vulnerabilities, 1):
                risk_level = str(vuln.get("risk_level", "info")).lower()
                risk_text = self._risk_text(risk_level)
                symbol = self.RISK_SYMBOLS.get(risk_level, "[   ]")

                lines.append(f"  {symbol} [{risk_text}] {idx}. {vuln.get('name', self._t('unknown'))}")
                lines.append(f"  {'~' * 60}")

                info_lines = [
                    (self._t("ch3_cve_id"), vuln.get("cve_id", self._t("na"))),
                    (self._t("ch3_target"), vuln.get("target", self._t("na"))),
                    (self._t("ch3_port"), str(vuln.get("port", self._t("na")))),
                    (self._t("ch3_protocol"), vuln.get("protocol", self._t("na"))),
                    (self._t("ch3_source"), vuln.get("source", self._t("na"))),
                ]
                for label, value in info_lines:
                    lines.append(f"    {label}: {value}")

                lines.append("")
                lines.append(f"    >> {self._t('ch3_description')}:")
                lines.append(f"       {vuln.get('description', self._t('na'))}")
                lines.append("")

                lines.append(f"    >> {self._t('ch3_impact')}:")
                lines.append(f"       {vuln.get('impact', self._t('na'))}")
                lines.append("")

                reproduce_steps = vuln.get("reproduce_steps", "")
                if reproduce_steps:
                    lines.append(f"    >> {self._t('ch3_reproduce')}:")
                    if isinstance(reproduce_steps, list):
                        for step_i, step in enumerate(reproduce_steps, 1):
                            lines.append(f"       {step_i}. {step}")
                    else:
                        lines.append(f"       {reproduce_steps}")
                    lines.append("")

                lines.append(f"    >> {self._t('ch3_remediation')}:")
                lines.append(f"       {vuln.get('remediation', self._t('na'))}")
                lines.append("")
                lines.append("")

        # ========== 第四章：综合风险评估 ==========
        lines.append(self._t("ch4_title"))
        lines.append(self._separator("-", w))
        lines.append("")

        overall = get_overall_risk_level(counts)
        overall_text = self._risk_text(overall)
        overall_symbol = self.RISK_SYMBOLS.get(overall, "[   ]")

        lines.append(f"  {self._t('ch4_overall_risk')}: {overall_symbol} {overall_text}")
        lines.append("")
        lines.append(f"  {self._t('ch4_risk_summary')}:")
        lines.append(f"    {self._t('ch4_risk_summary_desc')}")
        lines.append("")

        risk_descriptions = [
            ("critical", self._t("ch4_critical_desc")),
            ("high", self._t("ch4_high_desc")),
            ("medium", self._t("ch4_medium_desc")),
            ("low", self._t("ch4_low_desc")),
            ("info", self._t("ch4_info_desc")),
        ]

        for level_key, desc in risk_descriptions:
            if counts[level_key] > 0:
                level_name = self._risk_text(level_key)
                count = counts[level_key]
                lines.append(f"    [{level_name}] ({count})")
                lines.append(f"      {desc}")
                lines.append("")

        lines.append(f"  {self._t('ch4_recommendation')}:")
        lines.append(f"    {self._t('ch4_recommendation_desc')}")
        lines.append("")

        # ========== 第五章：修复优先级建议 ==========
        lines.append(self._t("ch5_title"))
        lines.append(self._separator("-", w))
        lines.append("")
        lines.append(f"  {self._t('ch5_desc')}")
        lines.append("")

        priorities = [
            (self._t("ch5_p1"), self._t("ch2_critical"), counts["critical"], self._t("ch5_p1_desc")),
            (self._t("ch5_p2"), self._t("ch2_high"), counts["high"], self._t("ch5_p2_desc")),
            (self._t("ch5_p3"), self._t("ch2_medium"), counts["medium"], self._t("ch5_p3_desc")),
            (self._t("ch5_p4"), f"{self._t('ch2_low')}/{self._t('ch2_info')}",
             counts["low"] + counts["info"], self._t("ch5_p4_desc")),
        ]

        for priority, level, count, suggestion in priorities:
            lines.append(f"  {priority}")
            lines.append(f"    {self._t('ch5_level')}: {level} | {self._t('ch5_count')}: {count}")
            lines.append(f"    {self._t('ch5_suggestion')}: {suggestion}")
            lines.append("")

        # ========== 附录 ==========
        lines.append(self._t("appendix_title"))
        lines.append(self._separator("-", w))
        lines.append("")

        if vulnerabilities:
            for idx, vuln in enumerate(vulnerabilities, 1):
                risk_level = str(vuln.get("risk_level", "info")).lower()
                risk_text = self._risk_text(risk_level)
                lines.append(
                    f"  {idx:>4}. [{risk_text}] {vuln.get('cve_id', self._t('na')):<20} "
                    f"{vuln.get('name', self._t('unknown'))}"
                )
            lines.append("")
        else:
            lines.append(f"  {self._t('html_no_vulns')}")
            lines.append("")

        # 页脚
        lines.append(self._separator("=", w))
        lines.append(f"  {self._t('html_generated_by')}")
        lines.append(f"  {project_info.get('date', '')}")
        lines.append(self._separator("=", w))

        return lines

    def _center_text(self, text: str, width: int) -> str:
        """将文本居中"""
        # 处理中文字符宽度（中文占2个字符宽度）
        text_width = self._get_display_width(text)
        padding = max(0, (width - text_width) // 2)
        return " " * padding + text

    def _get_display_width(self, text: str) -> int:
        """计算文本的显示宽度（中文字符算2个宽度）"""
        width = 0
        for char in text:
            if ord(char) > 127:
                width += 2
            else:
                width += 1
        return width
