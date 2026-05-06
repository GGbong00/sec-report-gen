"""
Nessus 报告解析器

支持 Nessus v2 报告格式，可解析 CSV 和 JSON 两种输出格式。
"""

import csv
import io
import json
import logging
import os
from typing import Dict, List, Optional

from . import BaseParser

logger = logging.getLogger(__name__)


class NessusParser(BaseParser):
    """Nessus 报告解析器（支持 CSV 和 JSON 格式）"""

    # Nessus 严重程度数值到标准严重程度的映射
    SEVERITY_MAP = {
        0: 'info',
        1: 'low',
        2: 'medium',
        3: 'high',
        4: 'critical',
        '0': 'info',
        '1': 'low',
        '2': 'medium',
        '3': 'high',
        '4': 'critical',
        'None': 'info',
        'none': 'info',
        'Informational': 'info',
        'informational': 'info',
        'Low': 'low',
        'low': 'low',
        'Medium': 'medium',
        'medium': 'medium',
        'High': 'high',
        'high': 'high',
        'Critical': 'critical',
        'critical': 'critical',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 Nessus 报告文件，自动根据扩展名选择解析方式。

        Args:
            file_path: Nessus 报告文件路径

        Returns:
            漏洞字典列表
        """
        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext == '.csv':
                return self._parse_csv(file_path)
            elif ext == '.json':
                return self._parse_json(file_path)
            else:
                # 尝试先按 JSON 解析，再按 CSV 解析
                content = self._read_file(file_path)
                if content and (content.strip().startswith('{') or content.strip().startswith('[')):
                    return self._parse_json(file_path)
                else:
                    return self._parse_csv(file_path)
        except Exception as e:
            logger.error(f"解析 Nessus 报告文件失败: {e}")
            return []

    def _parse_csv(self, file_path: str) -> List[Dict]:
        """
        解析 Nessus CSV 格式报告。

        Nessus CSV 报告通常包含以下列：
        Plugin ID, CVE, CVSS, Risk, Host, Protocol, Port, Name,
        Synopsis, Description, Solution, See Also, Plugin Output

        Args:
            file_path: CSV 文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []
        encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1', 'iso-8859-1']

        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    content = f.read()
                break
            except Exception:
                continue
        else:
            logger.error(f"无法读取 Nessus CSV 文件: {file_path}")
            return []

        try:
            # 使用 csv reader 解析
            reader = csv.DictReader(io.StringIO(content))
            fieldnames = reader.fieldnames

            if not fieldnames:
                logger.warning("Nessus CSV 文件为空或格式不正确")
                return []

            # 标准化列名映射（Nessus CSV 列名可能有变化）
            col_map = {}
            for col in fieldnames:
                col_lower = col.strip().lower()
                if 'plugin' in col_lower and 'id' in col_lower:
                    col_map['plugin_id'] = col
                elif col_lower == 'cve' or col_lower == 'CVE':
                    col_map['cve'] = col
                elif col_lower in ('risk', 'severity', 'risk factor', 'risk_factor'):
                    col_map['severity'] = col
                elif col_lower in ('host', 'host_ip', 'ip', 'hostname'):
                    col_map['host'] = col
                elif col_lower == 'port':
                    col_map['port'] = col
                elif col_lower == 'protocol':
                    col_map['protocol'] = col
                elif col_lower in ('name', 'plugin_name', 'title'):
                    col_map['name'] = col
                elif col_lower == 'synopsis':
                    col_map['synopsis'] = col
                elif col_lower == 'description':
                    col_map['description'] = col
                elif col_lower == 'solution':
                    col_map['solution'] = col
                elif col_lower in ('see also', 'see_also', 'reference', 'references'):
                    col_map['references'] = col
                elif col_lower in ('plugin output', 'plugin_output', 'output'):
                    col_map['output'] = col
                elif col_lower in ('cvss', 'cvss_score', 'cvss base score', 'cvss_base_score'):
                    col_map['cvss'] = col

            for row in reader:
                vuln = self._parse_csv_row(row, col_map)
                if vuln:
                    vulnerabilities.append(vuln)

        except csv.Error as e:
            logger.error(f"解析 Nessus CSV 文件时发生 CSV 错误: {e}")
            return []
        except Exception as e:
            logger.error(f"解析 Nessus CSV 文件时发生错误: {e}")
            return []

        logger.info(f"Nessus CSV 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_csv_row(self, row: dict, col_map: dict) -> Optional[Dict]:
        """
        解析单行 CSV 数据。

        Args:
            row: CSV 行数据字典
            col_map: 列名映射

        Returns:
            漏洞字典，数据无效时返回 None
        """
        def get_val(key):
            col = col_map.get(key)
            if col and col in row:
                return row[col].strip()
            return ''

        plugin_id = get_val('plugin_id')
        name = get_val('name')
        severity_raw = get_val('severity')
        host = get_val('host')
        port = get_val('port')
        protocol = get_val('protocol')
        cve = get_val('cve')
        synopsis = get_val('synopsis')
        description = get_val('description')
        solution = get_val('solution')
        references = get_val('references')
        output = get_val('output')
        cvss = get_val('cvss')

        # 跳过空行或无名称的记录
        if not name and not plugin_id:
            return None

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(severity_raw, 'info')
        if severity == 'info' and severity_raw:
            severity = self._normalize_severity(severity_raw)

        # 构建描述
        desc_parts = []
        if synopsis:
            desc_parts.append(f"概要: {synopsis}")
        if description:
            desc_parts.append(f"描述: {description}")
        if output:
            desc_parts.append(f"输出: {output}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 构建标题
        title = name if name else f"Plugin {plugin_id}"

        # 处理 CVE（可能有多个，用逗号分隔）
        cve_list = []
        if cve:
            for c in cve.replace(';', ',').split(','):
                c = c.strip()
                if c.upper().startswith('CVE-'):
                    cve_list.append(c)

        return {
            'title': title,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': protocol,
            'url': '',
            'description': description_text,
            'solution': solution,
            'cve': ', '.join(cve_list) if cve_list else '',
            'extra': {
                'scanner': 'nessus',
                'plugin_id': plugin_id,
                'cvss': cvss,
                'references': references,
                'raw_severity': severity_raw,
            },
        }

    def _parse_json(self, file_path: str) -> List[Dict]:
        """
        解析 Nessus JSON 格式报告（v2 格式）。

        Nessus v2 JSON 报告结构：
        {
            "Report": [
                {
                    "ReportHost": {
                        "name": "host_ip",
                        "HostProperties": { ... },
                        "ReportItem": [
                            {
                                "pluginID": "...",
                                "pluginName": "...",
                                "severity": 0-4,
                                "host": "...",
                                "port": "...",
                                "protocol": "...",
                                "cve": "...",
                                "synopsis": "...",
                                "description": "...",
                                "solution": "...",
                                ...
                            }
                        ]
                    }
                }
            ]
        }

        Args:
            file_path: JSON 文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []

        try:
            content = self._read_file(file_path)
            if not content:
                logger.error(f"无法读取 Nessus JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 Nessus JSON 文件失败 (JSON格式错误): {e}")
            return []
        except Exception as e:
            logger.error(f"读取 Nessus JSON 文件时发生错误: {e}")
            return []

        try:
            # Nessus v2 格式：顶层有 "Report" 键
            reports = data.get('Report', [])
            if not reports and isinstance(data, list):
                # 可能直接是 Report 数组
                reports = data
            if not reports and 'NessusClientData_v2' in data:
                reports = data['NessusClientData_v2'].get('Report', [])

            for report in reports:
                if not isinstance(report, dict):
                    continue

                # 获取报告主机
                report_hosts = report.get('ReportHost', [])
                if isinstance(report_hosts, dict):
                    report_hosts = [report_hosts]

                for host_data in report_hosts:
                    if not isinstance(host_data, dict):
                        continue

                    host_name = host_data.get('name', '')

                    # 获取主机属性
                    host_properties = host_data.get('HostProperties', {})
                    host_props_dict = {}
                    if isinstance(host_properties, dict):
                        for prop in host_properties.get('tag', []):
                            if isinstance(prop, dict):
                                host_props_dict[prop.get('name', '')] = prop.get('content', '')

                    # 获取报告项
                    report_items = host_data.get('ReportItem', [])
                    if isinstance(report_items, dict):
                        report_items = [report_items]

                    for item in report_items:
                        if not isinstance(item, dict):
                            continue

                        vuln = self._parse_json_item(item, host_name, host_props_dict)
                        if vuln:
                            vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 Nessus JSON 数据时发生错误: {e}")
            return []

        logger.info(f"Nessus JSON 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_json_item(self, item: dict, host_name: str,
                         host_props: dict) -> Optional[Dict]:
        """
        解析单个 Nessus JSON 报告项。

        Args:
            item: 报告项字典
            host_name: 主机名/IP
            host_props: 主机属性字典

        Returns:
            漏洞字典，数据无效时返回 None
        """
        plugin_id = str(item.get('pluginID', item.get('plugin_id', '')))
        plugin_name = item.get('pluginName', item.get('plugin_name', ''))
        severity_raw = item.get('severity', 0)
        host = item.get('host', host_name)
        port = str(item.get('port', ''))
        protocol = item.get('protocol', '')
        cve = item.get('cve', '')
        synopsis = item.get('synopsis', '')
        description = item.get('description', '')
        solution = item.get('solution', '')
        see_also = item.get('see_also', item.get('seeAlso', ''))
        plugin_output = item.get('plugin_output', item.get('pluginOutput', ''))
        cvss_vector = item.get('cvss_vector', item.get('cvssVector', ''))
        cvss_base_score = item.get('cvss_base_score', item.get('cvssBaseScore', ''))
        cvss_temporal_score = item.get('cvss_temporal_score', item.get('cvssTemporalScore', ''))
        risk_factor = item.get('risk_factor', item.get('riskFactor', ''))

        # 跳过无名称的记录
        if not plugin_name and not plugin_id:
            return None

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(severity_raw, 'info')
        if severity == 'info' and risk_factor:
            severity = self.SEVERITY_MAP.get(risk_factor, 'info')
        if severity == 'info' and severity_raw:
            severity = self._normalize_severity(str(severity_raw))

        # 构建描述
        desc_parts = []
        if synopsis:
            desc_parts.append(f"概要: {synopsis}")
        if description:
            desc_parts.append(f"描述: {description}")
        if plugin_output:
            # 截断过长的输出
            output_text = plugin_output if len(plugin_output) <= 2000 else plugin_output[:2000] + '...(已截断)'
            desc_parts.append(f"输出: {output_text}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 处理 CVE
        cve_list = []
        if cve:
            if isinstance(cve, str):
                for c in cve.replace(';', ',').split(','):
                    c = c.strip()
                    if c.upper().startswith('CVE-'):
                        cve_list.append(c)
            elif isinstance(cve, list):
                for c in cve:
                    c = str(c).strip()
                    if c.upper().startswith('CVE-'):
                        cve_list.append(c)

        # 处理参考链接
        references = ''
        if see_also:
            if isinstance(see_also, str):
                references = see_also
            elif isinstance(see_also, list):
                references = '\n'.join(str(r) for r in see_also)

        # 构建标题
        title = plugin_name if plugin_name else f"Plugin {plugin_id}"

        return {
            'title': title,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': protocol,
            'url': '',
            'description': description_text,
            'solution': solution,
            'cve': ', '.join(cve_list) if cve_list else '',
            'extra': {
                'scanner': 'nessus',
                'plugin_id': plugin_id,
                'cvss_vector': cvss_vector,
                'cvss_base_score': str(cvss_base_score),
                'cvss_temporal_score': str(cvss_temporal_score),
                'references': references,
                'raw_severity': str(severity_raw),
                'risk_factor': risk_factor,
                'host_properties': host_props,
            },
        }
