"""
Nuclei 漏洞扫描报告解析器

解析 ProjectDiscovery Nuclei 生成的 JSON 格式扫描结果。
"""

import json
import logging
import os
import re
from typing import Dict, List, Optional

from . import BaseParser

logger = logging.getLogger(__name__)


class NucleiParser(BaseParser):
    """Nuclei JSON 报告解析器"""

    # Nuclei 严重程度到标准严重程度的映射
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'warning': 'medium',
        'unknown': 'info',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 Nuclei JSON 报告文件。

        Nuclei JSON 报告通常是结果数组，每条记录结构：
        {
            "template-id": "...",
            "template-url": "...",
            "info": {
                "name": "...",
                "author": "...",
                "severity": "...",
                "description": "...",
                "reference": ["..."],
                "tags": ["..."],
                "classification": {
                    "cve-id": "...",
                    "cwe-id": "...",
                    "cvss-metrics": "...",
                    "cvss-score": "..."
                }
            },
            "type": "...",
            "host": "...",
            "matched-at": "...",
            "extracted-results": ["..."],
            "request": "...",
            "response": "...",
            "curl-command": "...",
            "matcher-name": "...",
            "timestamp": "..."
        }

        Args:
            file_path: Nuclei JSON 报告文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []

        try:
            content = self._read_file(file_path)
            if not content:
                logger.error(f"无法读取 Nuclei JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 Nuclei JSON 文件失败 (JSON格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Nuclei JSON 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"读取 Nuclei JSON 文件时发生错误: {e}")
            return []

        try:
            # Nuclei 输出通常是 JSON 数组
            if isinstance(data, list):
                results = data
            elif isinstance(data, dict):
                # 可能包裹在某个键下
                results = data.get('results', data.get('data', data.get('vulnerabilities', [])))
                if not results:
                    # 单条结果
                    if 'template-id' in data or 'template_id' in data or 'info' in data:
                        results = [data]
                    else:
                        results = []
            else:
                results = []

            if not results:
                logger.warning("Nuclei JSON 中未找到有效的结果数据")
                return []

            for item in results:
                if not isinstance(item, dict):
                    continue
                vuln = self._parse_result(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 Nuclei JSON 结果数据时发生错误: {e}")
            return []

        logger.info(f"Nuclei 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_result(self, item: dict) -> Optional[Dict]:
        """
        解析单个 Nuclei 结果条目。

        Args:
            item: 结果字典

        Returns:
            漏洞字典，解析失败返回 None
        """
        # 获取基本信息
        template_id = item.get('template-id', item.get('template_id', ''))
        template_url = item.get('template-url', item.get('template_url', ''))
        result_type = item.get('type', '')
        host = item.get('host', '')
        matched_at = item.get('matched-at', item.get('matched_at', ''))
        timestamp = item.get('timestamp', '')
        matcher_name = item.get('matcher-name', item.get('matcher_name', ''))
        curl_command = item.get('curl-command', item.get('curl_command', ''))

        # 获取请求和响应
        request = item.get('request', '')
        response = item.get('response', '')

        # 获取提取结果
        extracted_results = item.get('extracted-results', item.get('extracted_results', []))
        if isinstance(extracted_results, str):
            extracted_results = [extracted_results]

        # 获取 info 字段
        info = item.get('info', {})
        if not isinstance(info, dict):
            info = {}

        name = info.get('name', '')
        author = info.get('author', '')
        severity_raw = info.get('severity', 'info')
        description = info.get('description', '')
        remediation = info.get('remediation', '')
        reference = info.get('reference', [])
        tags = info.get('tags', [])
        metadata = info.get('metadata', {})

        # 获取分类信息
        classification = info.get('classification', {})
        if not isinstance(classification, dict):
            classification = {}

        cve_id = classification.get('cve-id', classification.get('cve_id', ''))
        cwe_id = classification.get('cwe-id', classification.get('cwe_id', ''))
        cvss_metrics = classification.get('cvss-metrics', classification.get('cvss_metrics', ''))
        cvss_score = classification.get('cvss-score', classification.get('cvss_score', ''))

        # 跳过无名称的记录
        if not name and not template_id:
            return None

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(severity_raw.lower(), self._normalize_severity(str(severity_raw)))

        # 构建标题
        title = name if name else template_id
        if template_id and name:
            title = f"[{template_id}] {name}"

        # 提取主机和端口
        host_for_record = host or matched_at
        parsed_host = ''
        port = ''
        if host_for_record:
            url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', host_for_record)
            if url_match:
                parsed_host = url_match.group(2)
                port = url_match.group(3) or ''
                if not port:
                    port = '443' if 'https' in host_for_record.lower() else '80'

        # 构建描述
        desc_parts = []
        if description:
            desc_parts.append(str(description))
        if matched_at:
            desc_parts.append(f"匹配位置: {matched_at}")
        if result_type:
            desc_parts.append(f"类型: {result_type}")
        if matcher_name:
            desc_parts.append(f"匹配器: {matcher_name}")
        if extracted_results:
            desc_parts.append(f"提取结果:\n" + '\n'.join(str(r) for r in extracted_results[:10]))
        if cwe_id:
            desc_parts.append(f"CWE: {cwe_id}")
        if cvss_metrics:
            desc_parts.append(f"CVSS: {cvss_metrics} (score: {cvss_score})")
        if tags:
            desc_parts.append(f"标签: {', '.join(str(t) for t in tags)}")
        if metadata and isinstance(metadata, dict):
            meta_parts = []
            for key, value in metadata.items():
                meta_parts.append(f"  {key}: {value}")
            if meta_parts:
                desc_parts.append("元数据:\n" + '\n'.join(meta_parts))
        description_text = '\n\n'.join(desc_parts) if desc_parts else ''

        # 处理 CVE
        cve_list = []
        if cve_id:
            if isinstance(cve_id, str):
                for c in re.findall(r'(CVE-\d{4}-\d+)', cve_id, re.IGNORECASE):
                    cve_list.append(c.upper())
            elif isinstance(cve_id, list):
                for c in cve_id:
                    for match in re.findall(r'(CVE-\d{4}-\d+)', str(c), re.IGNORECASE):
                        cve_list.append(match.upper())

        # 处理参考链接
        ref_list = []
        if isinstance(reference, list):
            ref_list = [str(r) for r in reference]
        elif isinstance(reference, str):
            ref_list = [r.strip() for r in reference.split('\n') if r.strip()]

        # 处理 CWE
        cwe_list = []
        if cwe_id:
            if isinstance(cwe_id, str):
                for c in re.findall(r'(CWE-\d+)', cwe_id, re.IGNORECASE):
                    cwe_list.append(c.upper())
            elif isinstance(cwe_id, list):
                for c in cwe_id:
                    for match in re.findall(r'(CWE-\d+)', str(c), re.IGNORECASE):
                        cwe_list.append(match.upper())

        return {
            'title': title,
            'severity': severity,
            'host': parsed_host,
            'port': port,
            'protocol': 'https' if 'https' in (matched_at or host).lower() else 'http',
            'url': matched_at or host,
            'description': description_text,
            'solution': str(remediation) if remediation else '',
            'cve': ', '.join(sorted(set(cve_list))) if cve_list else '',
            'extra': {
                'scanner': 'nuclei',
                'template_id': template_id,
                'template_url': template_url,
                'type': result_type,
                'confidence': '',
                'cwe': ', '.join(sorted(set(cwe_list))) if cwe_list else '',
                'cvss_metrics': cvss_metrics,
                'cvss_score': cvss_score,
                'author': author,
                'tags': tags,
                'matcher_name': matcher_name,
                'curl_command': curl_command,
                'extracted_results': extracted_results,
                'references': ref_list,
                'timestamp': timestamp,
                'request': request[:2000] if request else '',
                'response': response[:2000] if response else '',
                'raw_severity': str(severity_raw),
            },
        }
