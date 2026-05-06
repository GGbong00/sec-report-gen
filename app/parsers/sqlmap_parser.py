"""
Sqlmap 漏洞扫描报告解析器

支持 Sqlmap 生成的 JSON 和 CSV 两种格式的扫描结果。
"""

import csv
import io
import json
import logging
import os
import re
from typing import Dict, List, Optional

from . import BaseParser

logger = logging.getLogger(__name__)


class SqlmapParser(BaseParser):
    """Sqlmap 报告解析器（支持 JSON 和 CSV 格式）"""

    # Sqlmap 严重程度到标准严重程度的映射
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        1: 'high',
        2: 'medium',
        3: 'low',
        '1': 'high',
        '2': 'medium',
        '3': 'low',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 Sqlmap 报告文件，自动根据扩展名选择解析方式。

        Args:
            file_path: Sqlmap 报告文件路径

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
                # 尝试按 JSON 解析，再按 CSV 解析
                content = self._read_file(file_path)
                if content and (content.strip().startswith('{') or content.strip().startswith('[')):
                    return self._parse_json(file_path)
                else:
                    return self._parse_csv(file_path)
        except Exception as e:
            logger.error(f"解析 Sqlmap 报告文件失败: {e}")
            return []

    def _parse_json(self, file_path: str) -> List[Dict]:
        """
        解析 Sqlmap JSON 格式报告。

        Sqlmap JSON 报告结构：
        {
            "data": [
                {
                    "url": "...",
                    "query": "...",
                    "parameter": "...",
                    "type": "...",
                    "title": "...",
                    "payload": "...",
                    "dbms": "...",
                    "technique": "...",
                    "backend": "...",
                    "os": "...",
                    "timestamp": "...",
                    "code": 200,
                    "level": 1,
                    "risk": 1,
                    "confidence": 1
                }
            ],
            "errors": [],
            "success": true,
            "log": "..."
        }

        也支持直接传入 data 数组。

        Args:
            file_path: JSON 文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []

        try:
            content = self._read_file(file_path)
            if not content:
                logger.error(f"无法读取 Sqlmap JSON 文件: {file_path}")
                return []

            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"解析 Sqlmap JSON 文件失败 (JSON格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Sqlmap JSON 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"读取 Sqlmap JSON 文件时发生错误: {e}")
            return []

        try:
            # 获取数据列表
            if isinstance(data, list):
                results = data
            elif isinstance(data, dict):
                results = data.get('data', [])
                if not results and isinstance(data, dict):
                    # 可能直接是单条结果
                    if 'url' in data and 'parameter' in data:
                        results = [data]
            else:
                results = []

            if not isinstance(results, list):
                logger.warning("Sqlmap JSON 中未找到有效的 data 数组")
                return []

            for item in results:
                if not isinstance(item, dict):
                    continue
                vuln = self._parse_json_item(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"解析 Sqlmap JSON 数据时发生错误: {e}")
            return []

        logger.info(f"Sqlmap JSON 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
        return vulnerabilities

    def _parse_json_item(self, item: dict) -> Optional[Dict]:
        """
        解析单个 Sqlmap JSON 结果条目。

        Args:
            item: 结果字典

        Returns:
            漏洞字典，解析失败返回 None
        """
        url = item.get('url', '')
        query = item.get('query', '')
        parameter = item.get('parameter', item.get('param', ''))
        inject_type = item.get('type', '')
        title = item.get('title', '')
        payload = item.get('payload', '')
        dbms = item.get('dbms', '')
        technique = item.get('technique', '')
        backend = item.get('backend', '')
        os_type = item.get('os', '')
        timestamp = item.get('timestamp', '')
        code = item.get('code', '')
        level = item.get('level', '')
        risk = item.get('risk', '')
        confidence = item.get('confidence', '')

        # 跳过无 URL 的记录
        if not url:
            return None

        # 构建标题
        if title:
            title_text = title
        elif inject_type:
            title_text = f"SQL Injection ({inject_type})"
        else:
            title_text = "SQL Injection"

        if parameter:
            title_text += f" - {parameter}"

        # 映射严重程度（基于 risk）
        severity = self.SEVERITY_MAP.get(risk, 'high')
        if severity == 'info':
            severity = 'high'  # SQL 注入默认为高危

        # 提取主机和端口
        host = ''
        port = ''
        url_match = re.match(r'(https?://)?([^/:]+)(?::(\d+))?(.*)', url)
        if url_match:
            host = url_match.group(2)
            port = url_match.group(3) or ''
            if not port:
                port = '443' if 'https' in url.lower() else '80'

        # 构建描述
        desc_parts = []
        if title:
            desc_parts.append(f"标题: {title}")
        if inject_type:
            desc_parts.append(f"注入类型: {inject_type}")
        if parameter:
            desc_parts.append(f"注入参数: {parameter}")
        if payload:
            desc_parts.append(f"Payload: {payload}")
        if query:
            desc_parts.append(f"查询: {query}")
        if dbms:
            desc_parts.append(f"数据库: {dbms}")
        if technique:
            desc_parts.append(f"技术: {technique}")
        if backend:
            desc_parts.append(f"后端: {backend}")
        if os_type:
            desc_parts.append(f"操作系统: {os_type}")
        if code:
            desc_parts.append(f"HTTP 状态码: {code}")
        if level:
            desc_parts.append(f"级别: {level}")
        if confidence:
            desc_parts.append(f"置信度: {confidence}")
        if timestamp:
            desc_parts.append(f"时间: {timestamp}")
        description_text = '\n'.join(desc_parts) if desc_parts else ''

        # 构建修复建议
        solution_parts = [
            "1. 使用参数化查询（预编译语句）替代字符串拼接",
            "2. 对所有用户输入进行严格的输入验证和过滤",
            "3. 使用 ORM 框架避免直接拼接 SQL",
            "4. 遵循最小权限原则，限制数据库账户权限",
        ]
        if dbms:
            solution_parts.append(f"5. 针对 {dbms} 数据库使用特定的安全配置")
        solution_text = '\n'.join(solution_parts)

        return {
            'title': title_text,
            'severity': severity,
            'host': host,
            'port': port,
            'protocol': 'https' if 'https' in url.lower() else 'http',
            'url': url,
            'description': description_text,
            'solution': solution_text,
            'cve': '',
            'extra': {
                'scanner': 'sqlmap',
                'parameter': parameter,
                'type': inject_type,
                'payload': payload,
                'query': query,
                'dbms': dbms,
                'technique': technique,
                'backend': backend,
                'os': os_type,
                'code': str(code) if code else '',
                'level': str(level) if level else '',
                'risk': str(risk) if risk else '',
                'confidence': str(confidence) if confidence else '',
                'timestamp': timestamp,
            },
        }

    def _parse_csv(self, file_path: str) -> List[Dict]:
        """
        解析 Sqlmap CSV 格式报告。

        Sqlmap CSV 报告通常包含以下列：
        url, query, parameter, type, title, payload, dbms, technique, ...

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
            logger.error(f"无法读取 Sqlmap CSV 文件: {file_path}")
            return []

        try:
            reader = csv.DictReader(io.StringIO(content))
            fieldnames = reader.fieldnames

            if not fieldnames:
                logger.warning("Sqlmap CSV 文件为空或格式不正确")
                return []

            # 标准化列名映射
            col_map = {}
            for col in fieldnames:
                col_lower = col.strip().lower().replace(' ', '_')
                if col_lower in ('url', 'target_url', 'target'):
                    col_map['url'] = col
                elif col_lower in ('query', 'sql_query'):
                    col_map['query'] = col
                elif col_lower in ('parameter', 'param', 'inject_parameter'):
                    col_map['parameter'] = col
                elif col_lower in ('type', 'inject_type', 'injection_type'):
                    col_map['type'] = col
                elif col_lower in ('title', 'name', 'vulnerability'):
                    col_map['title'] = col
                elif col_lower in ('payload', 'inject_payload'):
                    col_map['payload'] = col
                elif col_lower in ('dbms', 'database', 'db'):
                    col_map['dbms'] = col
                elif col_lower in ('technique', 'method'):
                    col_map['technique'] = col
                elif col_lower in ('backend',):
                    col_map['backend'] = col
                elif col_lower in ('os', 'operating_system'):
                    col_map['os'] = col
                elif col_lower in ('timestamp', 'time', 'date'):
                    col_map['timestamp'] = col
                elif col_lower in ('code', 'status_code', 'http_code'):
                    col_map['code'] = col
                elif col_lower in ('level',):
                    col_map['level'] = col
                elif col_lower in ('risk', 'risk_level'):
                    col_map['risk'] = col
                elif col_lower in ('confidence',):
                    col_map['confidence'] = col

            for row in reader:
                vuln = self._parse_csv_row(row, col_map)
                if vuln:
                    vulnerabilities.append(vuln)

        except csv.Error as e:
            logger.error(f"解析 Sqlmap CSV 文件时发生 CSV 错误: {e}")
            return []
        except Exception as e:
            logger.error(f"解析 Sqlmap CSV 文件时发生错误: {e}")
            return []

        logger.info(f"Sqlmap CSV 解析完成，共提取 {len(vulnerabilities)} 条漏洞记录")
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

        url = get_val('url')
        query = get_val('query')
        parameter = get_val('parameter')
        inject_type = get_val('type')
        title = get_val('title')
        payload = get_val('payload')
        dbms = get_val('dbms')
        technique = get_val('technique')
        backend = get_val('backend')
        os_type = get_val('os')
        timestamp = get_val('timestamp')
        code = get_val('code')
        level = get_val('level')
        risk = get_val('risk')
        confidence = get_val('confidence')

        if not url:
            return None

        # 构建与 JSON 解析相同格式的字典
        item = {
            'url': url,
            'query': query,
            'parameter': parameter,
            'type': inject_type,
            'title': title,
            'payload': payload,
            'dbms': dbms,
            'technique': technique,
            'backend': backend,
            'os': os_type,
            'timestamp': timestamp,
            'code': code,
            'level': level,
            'risk': risk,
            'confidence': confidence,
        }

        return self._parse_json_item(item)
