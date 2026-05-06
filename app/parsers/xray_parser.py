"""
Xray 漏洞扫描报告解析器

解析长亭 Xray 安全评估工具生成的 JSON 格式报告。
"""

import json
import logging
import os
import re
from typing import Dict, List, Optional

from . import BaseParser

logger = logging.getLogger(__name__)


class XrayParser(BaseParser):
    """Xray JSON 报告解析器"""

    # Xray 严重程度到标准严重程度的映射
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'warning': 'medium',
        'fatal': 'critical',
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
        解析 Xray JSON 报告文件。

        Xray JSON 报告结构：
        {
            "vulns": [
                {
                    "vuln_class": "...",
                    "target_url": "...",
                    "specific_url": "...",
                    "severity": "...",
                    "transport": "https",
                    "plugin": "...",
                    "detail": {
                        "request": "...",
                        "response": "...",
                        "payload": "...",
                        "param": { ... },
                        "screenshot": "...",
                        "compiler": "..."
                    },
                    "create_time": "...",
                    "reverse": { ... }
                }
            ],
            "stats": { ... }
        }

        也支持直接传入 vulns 数组。

        Args:
            file_path: Xray JSON 报告文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []

        try:
            content = self._read_file(file_path)
            if not content:
                logger.error(f"无法读取 Xray JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 Xray JSON 文件失败 (JSON格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Xray JSON 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"读取 Xray JSON 文件时发生错误: {e}")
            return []

        try:
            # 获取漏洞列表
            vuln_list = data.get('vulns', [])
            if not vuln_list and isinstance(data, list):
                vuln_list = data
            if not vuln_list:
                logger.warning("Xray JSON 中未找到 vulns 数组")
                return []

            if not isinstance(vuln_list, list):
                logger.warning("Xray JSON 中 vulns 字段不是数组")
                return []

            for item in vuln_list:
                if not isinstance(item, dict):
                    continue
                vuln = self._parse_vuln(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 Xray JSON 漏洞数据时发生错误: {e}")
            return []

        logger.info(f"Xray 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_vuln(self, item: dict) -> Optional[Dict]:
        """
        解析单个 Xray 漏洞条目。

        Args:
            item: 漏洞字典

        Returns:
            漏洞字典，解析失败返回 None
        """
        vuln_class = item.get('vuln_class', item.get('type', ''))
        target_url = item.get('target_url', item.get('url', ''))
        specific_url = item.get('specific_url', item.get('url', ''))
        severity_raw = item.get('severity', 'info')
        transport = item.get('transport', '')
        plugin = item.get('plugin', '')
        create_time = item.get('create_time', item.get('time', ''))
        reverse = item.get('reverse', {})

        # 获取详情
        detail = item.get('detail', {})
        if not isinstance(detail, dict):
            detail = {}

        request = detail.get('request', '')
        response = detail.get('response', '')
        payload = detail.get('payload', '')
        param = detail.get('param', {})
        screenshot = detail.get('screenshot', '')
        compiler = detail.get('compiler', '')

        # 跳过无类型和 URL 的记录
        if not vuln_class and not target_url:
            return None

        # 映射严重程度
        severity_raw_str = str(severity_raw).lower()
        severity = self.SEVERITY_MAP.get(severity_raw_str, self._normalize_severity(str(severity_raw)))

        # 构建标题
        title = vuln_class if vuln_class else plugin
        if not title:
            title = 'Unknown Vulnerability'

        # 提取主机和端口
        host = ''
        port = ''
        url_for_parsing = specific_url or target_url
        if url_for_parsing:
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', url_for_parsing)
            if url_match:
                host = url_match.group(2)
                port = url_match.group(3) or ''
                if not port:
                    port = '443' if 'https' in url_for_parsing.lower() else '80'

        # 构建描述
        desc_parts = []
        if vuln_class:
            desc_parts.append(f"漏洞类型: {vuln_class}")
        if plugin:
            desc_parts.append(f"插件: {plugin}")
        if target_url:
            desc_parts.append(f"目标 URL: {target_url}")
        if specific_url and specific_url != target_url:
            desc_parts.append(f"具体 URL: {specific_url}")
        if transport:
            desc_parts.append(f"传输协议: {transport}")
        if payload:
            desc_parts.append(f"Payload: {payload}")
        if param and isinstance(param, dict):
            param_parts = []
            for key, value in param.items():
                param_parts.append(f"  {key}: {value}")
            if param_parts:
                desc_parts.append("参数:\n" + '\n'.join(param_parts))
        if create_time:
            desc_parts.append(f"发现时间: {create_time}")
        description_text = '\n'.join(desc_parts) if desc_parts else ''

        # 构建修复建议（基于漏洞类型）
        solution = self._get_solution_by_vuln_class(vuln_class)

        # 提取 CVE
        cve_list = []
        all_text = f"{vuln_class} {plugin} {str(detail)}"
        cve_matches = re.findall(r'(CVE-\d{4}-\d+)', all_text, re.IGNORECASE)
        cve_list = list(set(c.upper() for c in cve_matches))

        return {
            'title': title,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': transport,
            'url': specific_url or target_url,
            'description': description_text,
            'solution': solution,
            'cve': ', '.join(sorted(cve_list)) if cve_list else '',
            'extra': {
                'scanner': 'xray',
                'vuln_class': vuln_class,
                'target_url': target_url,
                'plugin': plugin,
                'transport': transport,
                'create_time': create_time,
                'payload': payload,
                'param': param,
                'screenshot': screenshot,
                'compiler': compiler,
                'reverse': reverse,
                'request': request[:2000] if request else '',
                'response': response[:2000] if response else '',
                'raw_severity': str(severity_raw),
            },
        }

    def _get_solution_by_vuln_class(self, vuln_class: str) -> str:
        """
        根据漏洞类型返回修复建议。

        Args:
            vuln_class: 漏洞类型

        Returns:
            修复建议字符串
        """
        if not vuln_class:
            return ''

        vuln_lower = vuln_class.lower()
        solutions = {
            'xss': '对所有用户输入进行严格的输入验证和输出编码，使用 Content-Security-Policy 头部限制脚本执行。',
            'sql injection': '使用参数化查询（预编译语句）替代字符串拼接，对所有用户输入进行验证和过滤。',
            'ssrf': '限制服务端请求的目标地址范围，禁止请求内网地址和敏感端口，使用白名单机制。',
            'xxe': '禁用外部实体解析，使用安全的 XML 解析库，避免将用户输入直接用于 XML 解析。',
            'rce': '严格限制命令执行，避免将用户输入传递给系统命令，使用白名单机制。',
            'information disclosure': '检查并修复信息泄露点，移除调试信息，配置适当的错误处理。',
            'directory traversal': '对文件路径输入进行严格验证，使用白名单机制，避免直接拼接用户输入到文件路径。',
            'csrf': '使用 CSRF Token 进行验证，设置 SameSite Cookie 属性，验证 Referer/Origin 头。',
            'jsonp hijacking': '避免使用 JSONP 传输敏感数据，使用 CORS 替代 JSONP。',
            'crlf injection': '对用户输入中的换行符进行过滤和编码。',
            'redirect': '对重定向目标进行白名单验证，避免开放重定向。',
            'unauthorized': '检查并修复权限控制逻辑，确保所有敏感操作都有适当的权限验证。',
            'file upload': '限制上传文件类型和大小，使用随机文件名，将上传目录配置为不可执行。',
            'ssti': '对模板输入进行严格验证，避免将用户输入直接传入模板引擎。',
            'deserialization': '避免反序列化不可信数据，使用安全的序列化格式如 JSON。',
        }

        for key, solution in solutions.items():
            if key in vuln_lower:
                return solution

        return '请根据漏洞类型进行相应的安全修复，参考相关安全文档和最佳实践。'
