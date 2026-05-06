# -*- coding: utf-8 -*-
"""
JSON 数据导出生成器 - 生成格式化 JSON 格式的安全报告数据

JSON Data Export Generator - Generate formatted JSON format security report data
"""

import os
import json
from typing import Dict, List, Any

from . import (
    BaseGenerator,
    count_by_level,
    get_overall_risk_level,
    get_risk_level_text,
)


class JSONGenerator(BaseGenerator):
    """JSON 格式数据导出生成器"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        data = self._build_json(project_info, vulnerabilities)
        json_str = json.dumps(data, ensure_ascii=False, indent=2)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
            f.write("\n")

        return output_path

    def _build_json(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """构建 JSON 数据结构"""
        counts = count_by_level(vulnerabilities)
        total = sum(counts.values())
        overall = get_overall_risk_level(counts)

        # 处理 scope/method/tools 为列表
        scope = project_info.get("scope", [])
        if isinstance(scope, str):
            scope = [scope]

        method = project_info.get("method", [])
        if isinstance(method, str):
            method = [method]

        tools = project_info.get("tools", [])
        if isinstance(tools, str):
            tools = [tools]

        # 项目信息
        project_data = {
            "name": project_info.get("name", self._t("unknown")),
            "client": project_info.get("client", self._t("unknown")),
            "tester": project_info.get("tester", self._t("unknown")),
            "date": project_info.get("date", ""),
            "classification": project_info.get("classification", self._t("unknown")),
            "version": project_info.get("version", "1.0"),
            "scope": scope,
            "methodology": method,
            "tools": tools,
        }

        # 漏洞列表
        vuln_list = []
        for idx, vuln in enumerate(vulnerabilities, 1):
            risk_level = str(vuln.get("risk_level", "info")).lower()

            reproduce_steps = vuln.get("reproduce_steps", [])
            if isinstance(reproduce_steps, str):
                reproduce_steps = [reproduce_steps]

            vuln_data = {
                "id": str(idx).zfill(4),
                "cve_id": vuln.get("cve_id", ""),
                "name": vuln.get("name", self._t("unknown")),
                "risk_level": risk_level,
                "risk_level_text": self._risk_text(risk_level),
                "target": vuln.get("target", ""),
                "port": str(vuln.get("port", "")),
                "protocol": vuln.get("protocol", ""),
                "description": vuln.get("description", ""),
                "impact": vuln.get("impact", ""),
                "reproduce_steps": reproduce_steps,
                "remediation": vuln.get("remediation", ""),
                "source": vuln.get("source", ""),
            }
            vuln_list.append(vuln_data)

        # 统计信息
        statistics = {
            "total": total,
            "by_level": {
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "info": counts["info"],
            },
            "overall_risk_level": overall,
            "overall_risk_level_text": self._risk_text(overall),
        }

        # 按目标统计
        target_stats: Dict[str, int] = {}
        for vuln in vulnerabilities:
            target = vuln.get("target", self._t("unknown"))
            target_stats[target] = target_stats.get(target, 0) + 1
        statistics["by_target"] = target_stats

        return {
            "report_version": "1.0",
            "lang": self.lang,
            "project_info": project_data,
            "statistics": statistics,
            "vulnerabilities": vuln_list,
        }
