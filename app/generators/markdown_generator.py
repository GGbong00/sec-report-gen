# -*- coding: utf-8 -*-
"""
Markdown 报告生成器 - 生成标准 Markdown 格式的安全测试报告

Markdown Report Generator - Generate standard Markdown format security assessment reports
"""

import os
from typing import Dict, List, Any

from . import (
    BaseGenerator,
    count_by_level,
    get_overall_risk_level,
    get_risk_color,
)


class MarkdownGenerator(BaseGenerator):
    """Markdown 格式报告生成器"""

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

    def _build_report(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """构建 Markdown 报告"""
        lines = []

        # ========== 封面 ==========
        lines.append(f"# {self._t('cover_title')}")
        lines.append("")
        lines.append(f"### {self._t('cover_subtitle')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 项目信息表格
        lines.append(f"| | |")
        lines.append(f"|---|---|")
        cover_items = [
            (self._t("cover_project"), project_info.get("name", self._t("unknown"))),
            (self._t("cover_client"), project_info.get("client", self._t("unknown"))),
            (self._t("cover_tester"), project_info.get("tester", self._t("unknown"))),
            (self._t("cover_date"), project_info.get("date", "")),
            (self._t("cover_classification"), project_info.get("classification", self._t("unknown"))),
        ]
        for label, value in cover_items:
            lines.append(f"| **{label}** | {value} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 目录 ==========
        lines.append(f"## {self._t('toc_title')}")
        lines.append("")
        toc_items = [
            self._t("ch1_title"),
            self._t("ch2_title"),
            self._t("ch3_title"),
            self._t("ch4_title"),
            self._t("ch5_title"),
            self._t("appendix_title"),
        ]
        for i, item in enumerate(toc_items, 1):
            lines.append(f"{i}. {item}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 第一章：项目概述 ==========
        lines.append(f"## {self._t('ch1_title')}")
        lines.append("")

        lines.append(f"### {self._t('ch1_test_objective')}")
        lines.append("")
        lines.append(self._t("ch1_test_objective_desc"))
        lines.append("")

        lines.append(f"### {self._t('ch1_test_scope')}")
        lines.append("")
        scope = project_info.get("scope", [])
        if isinstance(scope, str):
            scope = [scope]
        for item in scope:
            lines.append(f"- {item}")
        if not scope:
            lines.append(self._t("ch1_test_scope_desc"))
        lines.append("")

        lines.append(f"### {self._t('ch1_test_method')}")
        lines.append("")
        method = project_info.get("method", [])
        if isinstance(method, str):
            method = [method]
        for item in method:
            lines.append(f"- {item}")
        if not method:
            lines.append(self._t("ch1_test_method_desc"))
        lines.append("")

        lines.append(f"### {self._t('ch1_test_tools')}")
        lines.append("")
        tools = project_info.get("tools", [])
        if isinstance(tools, str):
            tools = [tools]
        for item in tools:
            lines.append(f"- {item}")
        if not tools:
            lines.append(self._t("ch1_test_tools_desc"))
        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 第二章：风险统计概览 ==========
        lines.append(f"## {self._t('ch2_title')}")
        lines.append("")
        lines.append(self._t("ch2_desc"))
        lines.append("")

        counts = count_by_level(vulnerabilities)
        total = sum(counts.values())

        # 统计卡片
        lines.append(f"| {self._t('ch2_critical')} | {self._t('ch2_high')} | {self._t('ch2_medium')} | {self._t('ch2_low')} | {self._t('ch2_info')} | {self._t('ch2_total')} |")
        lines.append(f"|:---:|:---:|:---:|:---:|:---:|:---:|")
        lines.append(
            f"| **{counts['critical']}** | **{counts['high']}** | **{counts['medium']}** "
            f"| **{counts['low']}** | **{counts['info']}** | **{total}** |"
        )
        lines.append("")

        # 统计表
        lines.append(f"| {self._t('ch2_level')} | {self._t('ch2_count')} | {self._t('ch2_percentage')} |")
        lines.append(f"|:---|:---:|:---:|")

        level_items = [
            ("critical", self._t("ch2_critical")),
            ("high", self._t("ch2_high")),
            ("medium", self._t("ch2_medium")),
            ("low", self._t("ch2_low")),
            ("info", self._t("ch2_info")),
        ]

        for level_key, level_name in level_items:
            count = counts[level_key]
            pct = f"{count / total * 100:.1f}%" if total > 0 else "0.0%"
            lines.append(f"| {level_name} | {count} | {pct} |")

        lines.append(f"| **{self._t('ch2_total')}** | **{total}** | **100.0%** |")
        lines.append("")

        # 柱状图（使用 Unicode 方块字符）
        max_count = max(counts.values()) if counts.values() else 1
        lines.append(f"### {self._t('ch2_title')}")
        lines.append("")
        lines.append("```")
        for level_key, level_name in level_items:
            count = counts[level_key]
            bar_len = int(count / max_count * 30) if max_count > 0 else 0
            bar = "\u2588" * bar_len + "\u2591" * (30 - bar_len)
            lines.append(f"  {level_name:<8} | {bar} {count}")
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 第三章：漏洞详情 ==========
        lines.append(f"## {self._t('ch3_title')}")
        lines.append("")

        if not vulnerabilities:
            lines.append(f"> {self._t('html_no_vulns')}")
            lines.append("")
        else:
            for idx, vuln in enumerate(vulnerabilities, 1):
                risk_level = str(vuln.get("risk_level", "info")).lower()
                risk_text = self._risk_text(risk_level)
                vuln_name = vuln.get("name", self._t("unknown"))

                lines.append(f"### {idx}. {vuln_name}")
                lines.append("")
                lines.append(f"**{self._t('ch3_risk_level')}:** {risk_text}  ")
                lines.append(f"**{self._t('ch3_cve_id')}:** {vuln.get('cve_id', self._t('na'))}  ")
                lines.append(f"**{self._t('ch3_target')}:** {vuln.get('target', self._t('na'))}  ")
                lines.append(f"**{self._t('ch3_port')}:** {vuln.get('port', self._t('na'))}  ")
                lines.append(f"**{self._t('ch3_protocol')}:** {vuln.get('protocol', self._t('na'))}  ")
                lines.append(f"**{self._t('ch3_source')}:** {vuln.get('source', self._t('na'))}")
                lines.append("")

                # 信息表格
                lines.append(f"| Field | Value |")
                lines.append(f"|:---|:---|")
                info_rows = [
                    (self._t("ch3_vuln_id"), str(idx).zfill(4)),
                    (self._t("ch3_cve_id"), vuln.get("cve_id", self._t("na"))),
                    (self._t("ch3_vuln_name"), vuln_name),
                    (self._t("ch3_risk_level"), risk_text),
                    (self._t("ch3_target"), vuln.get("target", self._t("na"))),
                    (self._t("ch3_port"), str(vuln.get("port", self._t("na")))),
                    (self._t("ch3_protocol"), vuln.get("protocol", self._t("na"))),
                ]
                for label, value in info_rows:
                    lines.append(f"| {label} | {value} |")
                lines.append("")

                # 描述
                lines.append(f"#### {self._t('ch3_description')}")
                lines.append("")
                lines.append(vuln.get("description", self._t("na")))
                lines.append("")

                # 影响分析
                lines.append(f"#### {self._t('ch3_impact')}")
                lines.append("")
                lines.append(vuln.get("impact", self._t("na")))
                lines.append("")

                # 复现步骤
                reproduce_steps = vuln.get("reproduce_steps", "")
                if reproduce_steps:
                    lines.append(f"#### {self._t('ch3_reproduce')}")
                    lines.append("")
                    if isinstance(reproduce_steps, list):
                        lines.append("```bash")
                        for step_i, step in enumerate(reproduce_steps, 1):
                            lines.append(f"# Step {step_i}")
                            lines.append(str(step))
                            if step_i < len(reproduce_steps):
                                lines.append("")
                        lines.append("```")
                    else:
                        lines.append("```")
                        lines.append(str(reproduce_steps))
                        lines.append("```")
                    lines.append("")

                # 修复建议
                lines.append(f"#### {self._t('ch3_remediation')}")
                lines.append("")
                lines.append(vuln.get("remediation", self._t("na")))
                lines.append("")
                lines.append("---")
                lines.append("")

        # ========== 第四章：综合风险评估 ==========
        lines.append(f"## {self._t('ch4_title')}")
        lines.append("")

        overall = get_overall_risk_level(counts)
        overall_text = self._risk_text(overall)

        lines.append(f"### {self._t('ch4_overall_risk')}")
        lines.append("")
        lines.append(f"> ### {overall_text}")
        lines.append("")

        lines.append(f"### {self._t('ch4_risk_summary')}")
        lines.append("")
        lines.append(self._t("ch4_risk_summary_desc"))
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
                lines.append(f"#### {level_name} ({count})")
                lines.append("")
                lines.append(desc)
                lines.append("")

        lines.append(f"### {self._t('ch4_recommendation')}")
        lines.append("")
        lines.append(self._t("ch4_recommendation_desc"))
        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 第五章：修复优先级建议 ==========
        lines.append(f"## {self._t('ch5_title')}")
        lines.append("")
        lines.append(self._t("ch5_desc"))
        lines.append("")

        lines.append(f"| {self._t('ch5_priority')} | {self._t('ch5_level')} | {self._t('ch5_count')} | {self._t('ch5_suggestion')} |")
        lines.append(f"|:---|:---:|:---:|:---|")

        priorities = [
            (self._t("ch5_p1"), self._t("ch2_critical"), counts["critical"], self._t("ch5_p1_desc")),
            (self._t("ch5_p2"), self._t("ch2_high"), counts["high"], self._t("ch5_p2_desc")),
            (self._t("ch5_p3"), self._t("ch2_medium"), counts["medium"], self._t("ch5_p3_desc")),
            (self._t("ch5_p4"), f"{self._t('ch2_low')}/{self._t('ch2_info')}",
             counts["low"] + counts["info"], self._t("ch5_p4_desc")),
        ]

        for priority, level, count, suggestion in priorities:
            lines.append(f"| **{priority}** | {level} | {count} | {suggestion} |")

        lines.append("")
        lines.append("---")
        lines.append("")

        # ========== 附录 ==========
        lines.append(f"## {self._t('appendix_title')}")
        lines.append("")

        if vulnerabilities:
            lines.append(
                f"| {self._t('appendix_index')} | {self._t('appendix_cve')} | "
                f"{self._t('appendix_name')} | {self._t('appendix_level')} | "
                f"{self._t('appendix_target')} | {self._t('appendix_port')} | "
                f"{self._t('appendix_protocol')} | {self._t('appendix_source')} |"
            )
            lines.append(f"|:---:|:---|:---|:---:|:---|:---:|:---:|:---|")

            for idx, vuln in enumerate(vulnerabilities, 1):
                risk_level = str(vuln.get("risk_level", "info")).lower()
                risk_text = self._risk_text(risk_level)
                lines.append(
                    f"| {idx} | {vuln.get('cve_id', self._t('na'))} | "
                    f"{vuln.get('name', self._t('unknown'))} | {risk_text} | "
                    f"{vuln.get('target', self._t('na'))} | {vuln.get('port', self._t('na'))} | "
                    f"{vuln.get('protocol', self._t('na'))} | {vuln.get('source', self._t('na'))} |"
                )
            lines.append("")
        else:
            lines.append(f"> {self._t('html_no_vulns')}")
            lines.append("")

        # 页脚
        lines.append("---")
        lines.append("")
        lines.append(f"*{self._t('html_generated_by')}*")
        lines.append(f"*{project_info.get('date', '')}*")
        lines.append("")

        return lines
