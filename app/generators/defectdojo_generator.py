# -*- coding: utf-8 -*-
"""
DefectDojo JSON 导入格式生成器
生成符合 DefectDojo Import Format 的 JSON 文件

DefectDojo JSON Import Format Generator
Generate JSON files compatible with DefectDojo import format
"""

import os
import json
from typing import Dict, List, Any

from . import BaseGenerator


# 严重程度到 DefectDojo numerical_severity 的映射
_SEVERITY_TO_NUMERICAL = {
    "critical": "S0",
    "high": "S1",
    "medium": "S2",
    "low": "S3",
    "info": "S4",
}

# 严重程度标准化映射（统一大小写处理）
_SEVERITY_NORMALIZE = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}


class DefectDojoGenerator(BaseGenerator):
    """DefectDojo JSON 导入格式生成器"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        data = self._build_defectdojo(project_info, vulnerabilities)
        json_str = json.dumps(data, ensure_ascii=False, indent=2)

        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True,
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
            f.write("\n")

        return output_path

    def _build_defectdojo(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """构建 DefectDojo JSON 导入数据结构"""
        findings = []

        for vuln in vulnerabilities:
            risk_level = str(vuln.get("risk_level", "info")).lower()
            severity = _SEVERITY_NORMALIZE.get(risk_level, "Info")
            numerical_severity = _SEVERITY_TO_NUMERICAL.get(risk_level, "S4")

            # 构建描述
            description_parts = []
            desc = vuln.get("description", "")
            if desc:
                description_parts.append(desc)

            impact = vuln.get("impact", "")
            if impact:
                description_parts.append(
                    f"\n\n{self._t('ch3_impact') if self._t('ch3_impact') != 'ch3_impact' else 'Impact'}:\n{impact}"
                )

            reproduce_steps = vuln.get("reproduce_steps", [])
            if isinstance(reproduce_steps, str):
                reproduce_steps = [reproduce_steps]
            if reproduce_steps:
                steps_text = "\n".join(
                    f"{i+1}. {step}" for i, step in enumerate(reproduce_steps)
                )
                description_parts.append(
                    f"\n\n{self._t('ch3_reproduce') if self._t('ch3_reproduce') != 'ch3_reproduce' else 'Reproduction Steps'}:\n{steps_text}"
                )

            description = "\n".join(description_parts) if description_parts else "No description provided."

            # 修复建议 / Mitigation
            mitigation = vuln.get("remediation", "")
            if not mitigation:
                mitigation = "No remediation provided."

            # 构建标题
            cve_id = vuln.get("cve_id", "")
            vuln_name = vuln.get("name", "Unknown Vulnerability")
            title = f"[{severity}] {vuln_name}"
            if cve_id and cve_id != self._t("na"):
                title += f" ({cve_id})"

            # 构建端点信息
            target = vuln.get("target", "")
            port = str(vuln.get("port", ""))
            protocol = vuln.get("protocol", "")
            endpoints = []

            if target:
                url = target
                if port and port != self._t("na"):
                    url = f"{protocol}://{target}:{port}" if protocol else f"{target}:{port}"
                elif protocol:
                    url = f"{protocol}://{target}"
                endpoints.append({"url": url})

            # 构建引用
            references = []
            if cve_id and cve_id != self._t("na"):
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

            source = vuln.get("source", "")
            if source:
                references.append(source)

            finding = {
                "title": title,
                "severity": severity,
                "description": description,
                "mitigation": mitigation,
                "impact": impact if impact else "",
                "references": references,
                "endpoints": endpoints,
                "active": True,
                "verified": False,
                "false_p": False,
                "duplicate": False,
                "out_of_scope": False,
                "under_defect_review": False,
                "numerical_severity": numerical_severity,
            }

            # 添加可选字段
            if cve_id and cve_id != self._t("na"):
                finding["cve"] = cve_id

            findings.append(finding)

        return {"findings": findings}
