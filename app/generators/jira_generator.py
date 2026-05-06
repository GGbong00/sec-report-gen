# -*- coding: utf-8 -*-
"""
Jira CSV 导入格式生成器
生成兼容 Jira 导入的 CSV 文件

Jira CSV Import Format Generator
Generate CSV files compatible with Jira import
"""

import os
import csv
from typing import Dict, List, Any
from datetime import datetime, timedelta

from . import BaseGenerator


# 严重程度到 Jira Priority 的映射
_SEVERITY_TO_JIRA_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraGenerator(BaseGenerator):
    """Jira CSV 导入格式生成器"""

    # CSV 列定义
    COLUMNS = [
        "Summary",
        "Description",
        "Issue Type",
        "Priority",
        "Labels",
        "Assignee",
        "Due Date",
        "Status",
    ]

    def _sanitize_csv_value(self, value):
        """防止 CSV 公式注入"""
        if value and isinstance(value, str) and value[0] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + value
        return value

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang

        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True,
        )

        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.COLUMNS)
            writer.writeheader()

            for idx, vuln in enumerate(vulnerabilities, 1):
                row = self._build_row(vuln, idx)
                row = {k: self._sanitize_csv_value(str(v)) for k, v in row.items()}
                writer.writerow(row)

        return output_path

    def _build_row(self, vuln: Dict[str, Any], index: int) -> Dict[str, str]:
        """构建单条漏洞的 CSV 行数据"""
        risk_level = str(vuln.get("risk_level", "info")).lower()
        priority = _SEVERITY_TO_JIRA_PRIORITY.get(risk_level, "Lowest")

        # 标题 / Summary
        cve_id = vuln.get("cve_id", "")
        vuln_name = vuln.get("name", "Unknown Vulnerability")
        summary = f"[SEC-{index:04d}] {vuln_name}"
        if cve_id and cve_id != self._t("na"):
            summary += f" ({cve_id})"

        # 描述 / Description
        description_parts = []

        vuln_desc = vuln.get("description", "")
        if vuln_desc:
            description_parts.append(vuln_desc)

        impact = vuln.get("impact", "")
        if impact:
            impact_label = (
                self._t("ch3_impact")
                if self._t("ch3_impact") != "ch3_impact"
                else "Impact"
            )
            description_parts.append(f"\n{impact_label}:\n{impact}")

        reproduce_steps = vuln.get("reproduce_steps", [])
        if isinstance(reproduce_steps, str):
            reproduce_steps = [reproduce_steps]
        if reproduce_steps:
            steps_label = (
                self._t("ch3_reproduce")
                if self._t("ch3_reproduce") != "ch3_reproduce"
                else "Reproduction Steps"
            )
            steps_text = "\n".join(
                f"{i+1}. {step}" for i, step in enumerate(reproduce_steps)
            )
            description_parts.append(f"\n{steps_label}:\n{steps_text}")

        remediation = vuln.get("remediation", "")
        if remediation:
            remediation_label = (
                self._t("ch3_remediation")
                if self._t("ch3_remediation") != "ch3_remediation"
                else "Remediation"
            )
            description_parts.append(f"\n{remediation_label}:\n{remediation}")

        # 附加元数据
        target = vuln.get("target", "")
        port = str(vuln.get("port", ""))
        source = vuln.get("source", "")
        protocol = vuln.get("protocol", "")

        meta_parts = []
        if target:
            meta_parts.append(f"Target: {target}")
        if port and port != self._t("na"):
            meta_parts.append(f"Port: {port}")
        if protocol:
            meta_parts.append(f"Protocol: {protocol}")
        if source:
            meta_parts.append(f"Source: {source}")
        if cve_id and cve_id != self._t("na"):
            meta_parts.append(f"CVE: {cve_id}")

        if meta_parts:
            description_parts.append(f"\n---\n" + "\n".join(meta_parts))

        description = "\n".join(description_parts) if description_parts else "No description provided."

        # 根据严重程度计算截止日期
        due_date = self._calculate_due_date(risk_level)

        return {
            "Summary": summary,
            "Description": description,
            "Issue Type": "Bug",
            "Priority": priority,
            "Labels": "security",
            "Assignee": "",
            "Due Date": due_date,
            "Status": "Open",
        }

    def _calculate_due_date(self, risk_level: str) -> str:
        """根据风险等级计算建议修复截止日期"""
        today = datetime.now()
        deltas = {
            "critical": timedelta(days=1),
            "high": timedelta(days=7),
            "medium": timedelta(days=30),
            "low": timedelta(days=90),
            "info": timedelta(days=180),
        }
        delta = deltas.get(risk_level, timedelta(days=30))
        due = today + delta
        return due.strftime("%Y-%m-%d")
