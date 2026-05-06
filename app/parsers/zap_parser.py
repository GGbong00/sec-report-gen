"""
OWASP ZAP 报告解析器

支持 OWASP ZAP 生成的 XML 和 JSON 两种格式的扫描报告。
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


class ZapParser(BaseParser):
    """OWASP ZAP 报告解析器（支持 XML 和 JSON 格式）"""

    # ZAP riskcode 到标准严重程度的映射
    RISKCODE_MAP = {
        '0': 'info',
        '1': 'low',
        '2': 'medium',
        '3': 'high',
        0: 'info',
        1: 'low',
        2: 'medium',
        3: 'high',
    }

    # ZAP confidence 映射
    CONFIDENCE_MAP = {
        '0': 'false_positive',
        '1': 'low',
        '2': 'medium',
        '3': 'high',
        0: 'false_positive',
        1: 'low',
        2: 'medium',
        3: 'high',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 ZAP 报告文件，自动根据扩展名选择解析方式。

        Args:
            file_path: ZAP 报告文件路径

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
            logger.error(f"解析 ZAP 报告文件失败: {e}")
            return []

    def _parse_xml(self, file_path: str) -> List[Dict]:
        """
        解析 ZAP XML 格式报告。

        ZAP XML 报告结构：
        <OWASPZAPReport>
            <site>
                <name>...</name>
                <host>...</host>
                <port>...</port>
                <ssl>...</ssl>
                <alerts>
                    <alert>
                        <alertid>...</alertid>
                        <name>...</name>
                        <riskcode>...</riskcode>
                        <confidence>...</confidence>
                        <riskdesc>...</riskdesc>
                        <desc>...</desc>
                        <instances>
                            <instance>
                                <uri>...</uri>
                                <method>...</method>
                                <param>...</param>
                            </instance>
                        </instances>
                        <count>...</count>
                        <solution>...</solution>
                        <reference>...</reference>
                        <cweid>...</cweid>
                        <wascid>...</wascid>
                        <sourceid>...</sourceid>
                    </alert>
                </alerts>
            </site>
        </OWASPZAPReport>

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
            logger.error(f"解析 ZAP XML 文件失败 (XML格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"ZAP XML 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"解析 ZAP XML 文件时发生未知错误: {e}")
            return []

        try:
            # 查找所有 alert 节点
            alerts = root.findall('.//alert')
            if not alerts:
                logger.warning("ZAP XML 中未找到 alert 节点")
                return []

            for alert_node in alerts:
                vuln = self._parse_xml_alert(alert_node)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 ZAP XML alert 节点时发生错误: {e}")
            return []

        logger.info(f"ZAP XML 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_xml_alert(self, alert_node) -> Optional[Dict]:
        """
        解析单个 XML alert 节点。

        Args:
            alert_node: XML alert 节点

        Returns:
            漏洞字典，解析失败返回 None
        """
        def get_text(tag):
            """获取 XML 标签的文本内容"""
            node = alert_node.find(tag)
            if node is not None and node.text:
                return unescape(node.text.strip())
            return ''

        alert_id = get_text('alertid')
        name = get_text('name')
        riskcode = get_text('riskcode')
        confidence = get_text('confidence')
        riskdesc = get_text('riskdesc')
        description = get_text('desc')
        solution = get_text('solution')
        reference = get_text('reference')
        cweid = get_text('cweid')
        wascid = get_text('wascid')
        sourceid = get_text('sourceid')
        count = get_text('count')

        # 跳过无名称的记录
        if not name:
            return None

        # 映射严重程度
        severity = self.RISKCODE_MAP.get(riskcode, 'info')

        # 映射置信度
        confidence_text = self.CONFIDENCE_MAP.get(confidence, confidence)

        # 提取 URL（从 instances 中获取）
        urls = []
        instances_node = alert_node.find('instances')
        if instances_node is not None:
            for instance in instances_node.findall('instance'):
                uri_node = instance.find('uri')
                method_node = instance.find('method')
                param_node = instance.find('param')
                if uri_node is not None and uri_node.text:
                    uri = uri_node.text.strip()
                    method = method_node.text.strip() if method_node is not None and method_node.text else ''
                    param = param_node.text.strip() if param_node is not None and param_node.text else ''
                    url_entry = uri
                    if method:
                        url_entry = f"{method} {uri}"
                    if param:
                        url_entry += f" (param: {param})"
                    urls.append(url_entry)
        else:
            # 尝试从 url 节点获取
            url_node = alert_node.find('url')
            if url_node is not None and url_node.text:
                urls.append(url_node.text.strip())

        # 获取站点信息
        site_name = ''
        site_node = alert_node
        parent = alert_node
        while parent is not None:
            site_tag = parent.find('name')
            if site_tag is not None and site_tag.text and ('http' in site_tag.text.lower()):
                site_name = site_tag.text.strip()
                break
            parent = parent.getparent() if hasattr(parent, 'getparent') else None

        # 提取主机和端口
        host = ''
        port = ''
        primary_url = urls[0] if urls else site_name
        if primary_url:
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', primary_url)
            if url_match:
                host = url_match.group(2)
                port = url_match.group(3) or ''
                if not port:
                    port = '443' if 'https' in primary_url.lower() else '80'

        # 构建描述
        desc_parts = []
        if riskdesc:
            desc_parts.append(f"风险: {riskdesc}")
        if description:
            desc_parts.append(description)
        if urls:
            desc_parts.append(f"受影响 URL ({len(urls)}):\n" + '\n'.join(urls[:20]))
        if cweid:
            desc_parts.append(f"CWE: {cweid}")
        if wascid:
            desc_parts.append(f"WASC: {wascid}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 处理参考链接
        ref_list = []
        if reference:
            for line in reference.split('\n'):
                line = line.strip()
                if line:
                    ref_list.append(line)

        return {
            'title': name,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': 'https' if ('https' in (urls[0] if urls else site_name).lower()) else 'http',
            'url': primary_url,
            'description': description_text,
            'solution': solution,
            'cve': '',
            'extra': {
                'scanner': 'zap',
                'alert_id': alert_id,
                'riskcode': riskcode,
                'confidence': confidence_text,
                'cweid': cweid,
                'wascid': wascid,
                'sourceid': sourceid,
                'count': count,
                'references': ref_list,
                'all_urls': urls,
                'site': site_name,
            },
        }

    def _parse_json(self, file_path: str) -> List[Dict]:
        """
        解析 ZAP JSON 格式报告。

        ZAP JSON 报告结构：
        {
            "site": [
                {
                    "@name": "http://example.com",
                    "@host": "example.com",
                    "@port": "80",
                    "@ssl": "false",
                    "alerts": [
                        {
                            "alertid": "1",
                            "name": "...",
                            "riskcode": "3",
                            "confidence": "2",
                            "riskdesc": "High (Medium)",
                            "desc": "...",
                            "instances": [
                                {
                                    "uri": "...",
                                    "method": "...",
                                    "param": "..."
                                }
                            ],
                            "count": "1",
                            "solution": "...",
                            "reference": "...",
                            "cweid": "...",
                            "wascid": "..."
                        }
                    ]
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
                logger.error(f"无法读取 ZAP JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 ZAP JSON 文件失败 (JSON格式错误): {e}")
            return []
        except Exception as e:
            logger.error(f"读取 ZAP JSON 文件时发生错误: {e}")
            return []

        try:
            # 获取站点列表
            sites = data.get('site', [])
            if not sites and isinstance(data, list):
                sites = data

            if not isinstance(sites, list):
                logger.warning("ZAP JSON 中未找到有效的 site 数组")
                return []

            for site in sites:
                if not isinstance(site, dict):
                    continue

                site_name = site.get('@name', site.get('name', ''))
                site_host = site.get('@host', site.get('host', ''))
                site_port = site.get('@port', site.get('port', ''))
                site_ssl = site.get('@ssl', site.get('ssl', ''))

                # 获取告警列表
                alerts = site.get('alerts', [])
                if isinstance(alerts, dict):
                    alerts = [alerts]

                for alert in alerts:
                    if not isinstance(alert, dict):
                        continue
                    vuln = self._parse_json_alert(alert, site_name, site_host, site_port, site_ssl)
                    if vuln:
                        vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 ZAP JSON 数据时发生错误: {e}")
            return []

        logger.info(f"ZAP JSON 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_json_alert(self, alert: dict, site_name: str, site_host: str,
                          site_port: str, site_ssl: str) -> Optional[Dict]:
        """
        解析单个 JSON alert 条目。

        Args:
            alert: alert 字典
            site_name: 站点名称
            site_host: 站点主机
            site_port: 站点端口
            site_ssl: 是否 SSL

        Returns:
            漏洞字典，解析失败返回 None
        """
        alert_id = str(alert.get('alertid', alert.get('id', '')))
        name = alert.get('name', alert.get('title', ''))
        riskcode = str(alert.get('riskcode', '0'))
        confidence = str(alert.get('confidence', ''))
        riskdesc = alert.get('riskdesc', '')
        description = alert.get('desc', alert.get('description', ''))
        solution = alert.get('solution', alert.get('remediation', ''))
        reference = alert.get('reference', '')
        cweid = str(alert.get('cweid', ''))
        wascid = str(alert.get('wascid', ''))
        sourceid = str(alert.get('sourceid', ''))
        count = str(alert.get('count', ''))

        # 跳过无名称的记录
        if not name:
            return None

        # 映射严重程度
        severity = self.RISKCODE_MAP.get(riskcode, 'info')

        # 映射置信度
        confidence_text = self.CONFIDENCE_MAP.get(confidence, confidence)

        # 提取 URL
        urls = []
        instances = alert.get('instances', [])
        if isinstance(instances, list):
            for instance in instances:
                if isinstance(instance, dict):
                    uri = instance.get('uri', '')
                    method = instance.get('method', '')
                    param = instance.get('param', '')
                    if uri:
                        url_entry = uri
                        if method:
                            url_entry = f"{method} {uri}"
                        if param:
                            url_entry += f" (param: {param})"
                        urls.append(url_entry)
        elif isinstance(instances, dict):
            uri = instances.get('uri', '')
            if uri:
                urls.append(uri)

        if not urls:
            url_text = alert.get('url', site_name)
            if url_text:
                urls.append(url_text)

        # 提取主机和端口
        host = site_host
        port = site_port
        primary_url = urls[0] if urls else site_name
        if primary_url and not host:
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', primary_url)
            if url_match:
                host = url_match.group(2)
                port = url_match.group(3) or port

        # 构建描述
        desc_parts = []
        if riskdesc:
            desc_parts.append(f"风险: {riskdesc}")
        if description:
            desc_parts.append(str(description))
        if urls:
            desc_parts.append(f"受影响 URL ({len(urls)}):\n" + '\n'.join(urls[:20]))
        if cweid:
            desc_parts.append(f"CWE: {cweid}")
        if wascid:
            desc_parts.append(f"WASC: {wascid}")
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 处理参考链接
        ref_list = []
        if reference:
            if isinstance(reference, str):
                for line in reference.split('\n'):
                    line = line.strip()
                    if line:
                        ref_list.append(line)
            elif isinstance(reference, list):
                ref_list = [str(r) for r in reference]

        return {
            'title': name,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': 'https' if site_ssl.lower() == 'true' else 'http',
            'url': primary_url,
            'description': description_text,
            'solution': str(solution) if solution else '',
            'cve': '',
            'extra': {
                'scanner': 'zap',
                'alert_id': alert_id,
                'riskcode': riskcode,
                'confidence': confidence_text,
                'cweid': cweid,
                'wascid': wascid,
                'sourceid': sourceid,
                'count': count,
                'references': ref_list,
                'all_urls': urls,
                'site': site_name,
            },
        }
