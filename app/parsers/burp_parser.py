"""
Burp Suite XML 报告解析器

解析 Burp Suite Professional 生成的 XML 格式扫描报告。
"""

import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from html import unescape

from . import BaseParser

logger = logging.getLogger(__name__)


class BurpParser(BaseParser):
    """Burp Suite XML 报告解析器"""

    # Burp 严重程度到标准严重程度的映射
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'information': 'info',
        'info': 'info',
    }

    # Burp 置信度映射
    CONFIDENCE_MAP = {
        'certain': 'certain',
        'firm': 'firm',
        'tentative': 'tentative',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 Burp Suite XML 报告文件。

        Burp XML 报告结构：
        <issues>
            <issue>
                <type>...</type>
                <name>...</name>
                <host>...</host>
                <path>...</path>
                <location>...</location>
                <severity>...</severity>
                <confidence>...</confidence>
                <issueBackground>...</issueBackground>
                <remediationBackground>...</remediationBackground>
                <vulnerabilityClassifications>...</vulnerabilityClassifications>
                <references>...</references>
                <detail>...</detail>
                <requestresponse>
                    <request>...</request>
                    <response>...</response>
                </requestresponse>
            </issue>
        </issues>

        Args:
            file_path: Burp XML 报告文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"解析 Burp XML 文件失败 (XML格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Burp XML 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"解析 Burp XML 文件时发生未知错误: {e}")
            return []

        try:
            # 查找 issues 节点
            issues_node = root.find('issues')
            if issues_node is None:
                # 尝试直接在根节点查找 issue
                issues = root.findall('issue')
                if not issues:
                    logger.warning("Burp XML 中未找到 issues 或 issue 节点")
                    return []
            else:
                issues = issues_node.findall('issue')

            for issue_node in issues:
                vuln = self._parse_issue(issue_node)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 Burp issue 节点时发生错误: {e}")
            return []

        logger.info(f"Burp 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_issue(self, issue_node) -> Optional[Dict]:
        """
        解析单个 issue 节点。

        Args:
            issue_node: XML issue 节点

        Returns:
            漏洞字典，解析失败返回 None
        """
        def get_text(tag):
            """获取 XML 标签的文本内容"""
            node = issue_node.find(tag)
            if node is not None and node.text:
                return unescape(node.text.strip())
            return ''

        name = get_text('name')
        issue_type = get_text('type')
        host = get_text('host')
        path = get_text('path')
        location = get_text('location')
        severity_raw = get_text('severity')
        confidence_raw = get_text('confidence')
        issue_background = get_text('issueBackground')
        vulnerability_background = get_text('vulnerabilityBackground')
        remediation_background = get_text('remediationBackground')
        remediation_detail = get_text('remediationDetail')
        vulnerability_classifications = get_text('vulnerabilityClassifications')
        references_text = get_text('references')
        detail = get_text('detail')

        # 跳过无名称的记录
        if not name:
            return None

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(severity_raw.lower(), 'info')

        # 映射置信度
        confidence = self.CONFIDENCE_MAP.get(confidence_raw.lower(), confidence_raw)

        # 构建完整 URL
        url = ''
        if host and path:
            if path.startswith('/'):
                url = f"{host}{path}"
            else:
                url = f"{host}/{path}"
        elif host:
            url = host
        elif location:
            url = location

        # 构建描述
        desc_parts = []
        if issue_background:
            desc_parts.append(issue_background)
        if vulnerability_background:
            desc_parts.append(vulnerability_background)
        if detail:
            desc_parts.append(f"详情:\n{detail}")
        if vulnerability_classifications:
            desc_parts.append(f"分类: {vulnerability_classifications}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 构建修复建议
        solution_parts = []
        if remediation_background:
            solution_parts.append(remediation_background)
        if remediation_detail:
            solution_parts.append(remediation_detail)
        solution_text = '\n\n'.join(solution_parts) if solution_parts else ''

        # 提取参考链接
        ref_list = []
        if references_text:
            # Burp 的 references 可能包含多个链接，用换行分隔
            for line in references_text.split('\n'):
                line = line.strip()
                if line and ('http://' in line or 'https://' in line):
                    ref_list.append(line)
                elif line:
                    ref_list.append(line)

        # 提取 CVE
        cve_list = []
        all_text = f"{vulnerability_classifications} {references_text} {detail}"
        cve_matches = re.findall(r'(CVE-\d{4}-\d+)', all_text, re.IGNORECASE)
        cve_list = list(set(cve_matches))

        # 提取端口号
        port = ''
        if host:
            port_match = re.search(r':(\d+)', host)
            if port_match:
                port = port_match.group(1)

        # 提取请求/响应信息
        request_response_list = []
        for rr_node in issue_node.findall('.//requestresponse'):
            rr_data = {}
            req_node = rr_node.find('request')
            if req_node is not None and req_node.text:
                rr_data['request'] = req_node.text.strip()
            resp_node = rr_node.find('response')
            if resp_node is not None and resp_node.text:
                rr_data['response'] = resp_node.text.strip()
            if rr_data:
                request_response_list.append(rr_data)

        return {
            'title': name,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': '',
            'url': url,
            'description': description_text,
            'solution': solution_text,
            'cve': ', '.join(sorted(cve_list)) if cve_list else '',
            'extra': {
                'scanner': 'burp',
                'type': issue_type,
                'confidence': confidence,
                'path': path,
                'location': location,
                'references': ref_list,
                'request_response': request_response_list,
                'raw_severity': severity_raw,
            },
        }
