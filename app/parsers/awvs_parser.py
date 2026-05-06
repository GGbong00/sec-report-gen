"""
AWVS (Acunetix) 报告解析器

支持 AWVS 生成的 XML 和 JSON 两种格式的扫描报告。
"""

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from html import unescape

from . import BaseParser

logger = logging.getLogger(__name__)


class AwvsParser(BaseParser):
    """AWVS 报告解析器（支持 XML 和 JSON 格式）"""

    # AWVS 严重程度到标准严重程度的映射
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'information': 'info',
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
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 AWVS 报告文件，自动根据扩展名选择解析方式。

        Args:
            file_path: AWVS 报告文件路径

        Returns:
            漏洞字典列表
        """
        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext == '.xml':
                return self._parse_xml(file_path)
            elif ext == '.json':
                return self._parse_json(file_path)
            else:
                # 尝试按 JSON 解析，再按 XML 解析
                content = self._read_file(file_path)
                if content and (content.strip().startswith('{') or content.strip().startswith('[')):
                    return self._parse_json(file_path)
                else:
                    return self._parse_xml(file_path)
        except Exception as e:
            logger.error(f"解析 AWVS 报告文件失败: {e}")
            return []

    def _parse_xml(self, file_path: str) -> List[Dict]:
        """
        解析 AWVS XML 格式报告。

        AWVS XML 报告结构：
        <Scan>
            <Report>
                <ReportItem>
                    <VulnId>...</VulnId>
                    <Name>...</Name>
                    <Severity>...</Severity>
                    <Affects>...</Affects>
                    <URL>...</URL>
                    <Description>...</Description>
                    <Recommendation>...</Recommendation>
                    <Details>...</Details>
                    <Classification>...</Classification>
                    <CVE>...</CVE>
                    <CWE>...</CWE>
                    <TechnicalDetails>...</TechnicalDetails>
                </ReportItem>
            </Report>
        </Scan>

        Args:
            file_path: XML 文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"解析 AWVS XML 文件失败 (XML格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"AWVS XML 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"解析 AWVS XML 文件时发生未知错误: {e}")
            return []

        try:
            # 查找所有 ReportItem 节点
            report_items = root.findall('.//ReportItem')
            if not report_items:
                # 尝试其他可能的节点名
                report_items = root.findall('.//Vulnerability')
                if not report_items:
                    report_items = root.findall('.//vulnerability')
                if not report_items:
                    report_items = root.findall('.//item')

            if not report_items:
                logger.warning("AWVS XML 中未找到 ReportItem/Vulnerability 节点")
                return []

            for item in report_items:
                vuln = self._parse_xml_item(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 AWVS XML ReportItem 节点时发生错误: {e}")
            return []

        logger.info(f"AWVS XML 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_xml_item(self, item) -> Optional[Dict]:
        """
        解析单个 XML 漏洞条目。

        Args:
            item: XML 漏洞节点

        Returns:
            漏洞字典，解析失败返回 None
        """
        def get_text(tag):
            """获取 XML 标签的文本内容"""
            node = item.find(tag)
            if node is not None and node.text:
                return unescape(node.text.strip())
            return ''

        def get_text_multi(tags):
            """尝试多个标签名，返回第一个有内容的"""
            for tag in tags:
                text = get_text(tag)
                if text:
                    return text
            return ''

        vuln_id = get_text('VulnId') or get_text('vuln_id') or get_text('ID') or get_text('id')
        name = get_text('Name') or get_text('name') or get_text('Title') or get_text('title')
        severity_raw = get_text('Severity') or get_text('severity')
        url = get_text('URL') or get_text('url') or get_text('Affects') or get_text('affects')
        description = get_text('Description') or get_text('description')
        recommendation = get_text('Recommendation') or get_text('recommendation') or \
                         get_text('Remediation') or get_text('remediation')
        details = get_text('Details') or get_text('details') or get_text('TechnicalDetails')
        classification = get_text('Classification') or get_text('classification')
        cve = get_text('CVE') or get_text('cve')
        cwe = get_text('CWE') or get_text('cwe')

        # 跳过无名称的记录
        if not name:
            return None

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(severity_raw.lower(), self._normalize_severity(severity_raw))

        # 提取主机和端口
        host = ''
        port = ''
        if url:
            # 从 URL 提取主机和端口
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', url)
            if url_match:
                host = url_match.group(2)
                port = url_match.group(3) or ''

        # 提取 CVE
        cve_list = []
        if cve:
            for c in re.findall(r'(CVE-\d{4}-\d+)', cve, re.IGNORECASE):
                cve_list.append(c.upper())

        # 构建描述
        desc_parts = []
        if description:
            desc_parts.append(description)
        if details:
            desc_parts.append(f"技术详情:\n{details}")
        if classification:
            desc_parts.append(f"分类: {classification}")
        if cwe:
            desc_parts.append(f"CWE: {cwe}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 构建标题
        title = name
        if vuln_id:
            title = f"[{vuln_id}] {name}"

        return {
            'title': title,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': '',
            'url': url,
            'description': description_text,
            'solution': recommendation,
            'cve': ', '.join(sorted(set(cve_list))) if cve_list else '',
            'extra': {
                'scanner': 'awvs',
                'vuln_id': vuln_id,
                'cwe': cwe,
                'classification': classification,
                'details': details,
                'raw_severity': severity_raw,
            },
        }

    def _parse_json(self, file_path: str) -> List[Dict]:
        """
        解析 AWVS JSON 格式报告。

        AWVS JSON 报告通常包含 vulnerabilities 数组：
        {
            "vulnerabilities": [
                {
                    "vt_id": "...",
                    "vuln_id": "...",
                    "name": "...",
                    "severity": "...",
                    "affects_url": "...",
                    "description": "...",
                    "recommendation": "...",
                    "details": { ... },
                    "cve": "...",
                    "cwe": "...",
                    ...
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
                logger.error(f"无法读取 AWVS JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 AWVS JSON 文件失败 (JSON格式错误): {e}")
            return []
        except Exception as e:
            logger.error(f"读取 AWVS JSON 文件时发生错误: {e}")
            return []

        try:
            # 获取漏洞列表
            vuln_list = data.get('vulnerabilities', [])
            if not vuln_list:
                # 尝试其他可能的键名
                vuln_list = data.get('results', [])
                if not vuln_list:
                    vuln_list = data.get('issues', [])
                if not vuln_list:
                    vuln_list = data.get('data', [])
                if not vuln_list and isinstance(data, list):
                    vuln_list = data

            if not isinstance(vuln_list, list):
                logger.warning("AWVS JSON 中未找到有效的漏洞数组")
                return []

            for item in vuln_list:
                if not isinstance(item, dict):
                    continue
                vuln = self._parse_json_item(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 AWVS JSON 漏洞数据时发生错误: {e}")
            return []

        logger.info(f"AWVS JSON 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_json_item(self, item: dict) -> Optional[Dict]:
        """
        解析单个 JSON 漏洞条目。

        Args:
            item: 漏洞字典

        Returns:
            漏洞字典，解析失败返回 None
        """
        vuln_id = str(item.get('vuln_id', item.get('vt_id', item.get('id', ''))))
        name = item.get('name', item.get('title', ''))
        severity_raw = item.get('severity', item.get('risk', ''))
        url = item.get('affects_url', item.get('url', item.get('target', '')))
        description = item.get('description', item.get('desc', ''))
        recommendation = item.get('recommendation', item.get('remediation', item.get('solution', '')))
        details = item.get('details', item.get('detail', {}))
        cve = item.get('cve', '')
        cwe = item.get('cwe', '')
        classification = item.get('classification', item.get('type', ''))

        # 跳过无名称的记录
        if not name:
            return None

        # 映射严重程度
        severity_raw_str = str(severity_raw).lower()
        severity = self.SEVERITY_MAP.get(severity_raw_str, self._normalize_severity(str(severity_raw)))

        # 提取主机和端口
        host = ''
        port = ''
        if url:
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', str(url))
            if url_match:
                host = url_match.group(2)
                port = url_match.group(3) or ''

        # 处理 details（可能是字符串或字典）
        details_text = ''
        if isinstance(details, dict):
            details_parts = []
            for key, value in details.items():
                details_parts.append(f"{key}: {value}")
            details_text = '\n'.join(details_parts)
        elif isinstance(details, str):
            details_text = details

        # 提取 CVE
        cve_list = []
        if cve:
            if isinstance(cve, str):
                for c in re.findall(r'(CVE-\d{4}-\d+)', cve, re.IGNORECASE):
                    cve_list.append(c.upper())
            elif isinstance(cve, list):
                for c in cve:
                    for match in re.findall(r'(CVE-\d{4}-\d+)', str(c), re.IGNORECASE):
                        cve_list.append(match.upper())

        # 构建描述
        desc_parts = []
        if description:
            desc_parts.append(str(description))
        if details_text:
            desc_parts.append(f"技术详情:\n{details_text}")
        if classification:
            desc_parts.append(f"分类: {classification}")
        if cwe:
            desc_parts.append(f"CWE: {cwe}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 构建标题
        title = name
        if vuln_id:
            title = f"[{vuln_id}] {name}"

        return {
            'title': title,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': '',
            'url': str(url) if url else '',
            'description': description_text,
            'solution': str(recommendation) if recommendation else '',
            'cve': ', '.join(sorted(set(cve_list))) if cve_list else '',
            'extra': {
                'scanner': 'awvs',
                'vuln_id': vuln_id,
                'cwe': str(cwe) if cwe else '',
                'classification': str(classification) if classification else '',
                'details': details_text,
                'raw_severity': str(severity_raw),
            },
        }
