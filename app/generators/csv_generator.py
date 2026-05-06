# -*- coding: utf-8 -*-
"""
CSV 数据导出生成器 - 生成 UTF-8 BOM 编码的 CSV 文件

CSV Data Export Generator - Generate UTF-8 BOM encoded CSV files
"""

import os
import csv
from typing import Dict, List, Any

from . import BaseGenerator


class CSVGenerator(BaseGenerator):
    """CSV 格式数据导出生成器"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)

            # 写入表头
            headers = [
                self._t("appendix_index"),
                self._t("appendix_cve"),
                self._t("appendix_name"),
                self._t("appendix_level"),
                self._t("appendix_target"),
                self._t("appendix_port"),
                self._t("appendix_protocol"),
                self._t("appendix_desc"),
                self._t("appendix_remediation"),
                self._t("appendix_source"),
            ]
            writer.writerow(headers)

            # 写入数据行
            for idx, vuln in enumerate(vulnerabilities, 1):
                risk_level = str(vuln.get("risk_level", "info")).lower()
                row = [
                    idx,
                    vuln.get("cve_id", self._t("na")),
                    vuln.get("name", self._t("unknown")),
                    self._risk_text(risk_level),
                    vuln.get("target", self._t("na")),
                    str(vuln.get("port", self._t("na"))),
                    vuln.get("protocol", self._t("na")),
                    vuln.get("description", self._t("na")),
                    vuln.get("remediation", self._t("na")),
                    vuln.get("source", self._t("na")),
                ]
                writer.writerow(row)

        return output_path
