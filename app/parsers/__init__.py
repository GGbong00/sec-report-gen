"""
扫描器报告解析器包

提供多种安全扫描器报告的统一解析接口，将不同格式的扫描报告
转换为统一的 Vulnerability 字典列表。
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """所有扫描器解析器的抽象基类"""

    @abstractmethod
    def parse(self, file_path: str) -> List[Dict]:
        """
        解析扫描器报告文件，返回统一的漏洞字典列表。

        Args:
            file_path: 报告文件的绝对路径

        Returns:
            漏洞字典列表，每个字典包含以下标准字段：
            - title: 漏洞标题/名称
            - severity: 严重程度 (critical/high/medium/low/info)
            - host: 目标主机/IP
            - port: 端口号 (可选)
            - protocol: 协议 (可选)
            - url: 相关URL (可选)
            - description: 漏洞描述 (可选)
            - solution: 修复建议 (可选)
            - cve: CVE编号 (可选)
            - extra: 其他附加信息字典 (可选)
        """
        raise NotImplementedError("子类必须实现 parse 方法")

    @staticmethod
    def _read_file(file_path: str) -> Optional[str]:
        """
        读取文件内容并返回文本。

        Args:
            file_path: 文件路径

        Returns:
            文件文本内容，读取失败返回 None
        """
        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                logger.error(f"文件过大: {file_path} ({file_size} bytes), 超过限制 {MAX_FILE_SIZE} bytes")
                return None
        except OSError:
            pass
        encodings = ['utf-8', 'gbk', 'gb2312', 'gb18030', 'latin-1', 'iso-8859-1']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, UnicodeError):
                continue
            except Exception as e:
                logger.error(f"读取文件 {file_path} 失败: {e}")
                return None
        logger.error(f"无法用任何编码读取文件 {file_path}")
        return None

    @staticmethod
    def _read_file_bytes(file_path: str) -> Optional[bytes]:
        """
        以二进制模式读取文件内容。

        Args:
            file_path: 文件路径

        Returns:
            文件二进制内容，读取失败返回 None
        """
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"以二进制模式读取文件 {file_path} 失败: {e}")
            return None

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """
        将各种严重程度描述统一为标准值。

        Args:
            severity: 原始严重程度字符串

        Returns:
            标准化后的严重程度: critical/high/medium/low/info
        """
        if not severity:
            return 'info'
        severity_lower = severity.strip().lower()
        mapping = {
            'critical': 'critical',
            '严重': 'critical',
            '紧急': 'critical',
            '高危': 'high',
            'high': 'high',
            '重要': 'high',
            '中危': 'medium',
            'medium': 'medium',
            '中等': 'medium',
            '一般': 'medium',
            'warning': 'medium',
            '低危': 'low',
            'low': 'low',
            '次要': 'low',
            '提示': 'info',
            '信息': 'info',
            'info': 'info',
            'information': 'info',
            'informational': 'info',
            'note': 'info',
            'open': 'info',
            'filtered': 'low',
            'open|filtered': 'medium',
            'closed': 'info',
        }
        return mapping.get(severity_lower, 'info')


class ParserFactory:
    """解析器工厂，根据扫描器类型返回对应的解析器实例"""

    _parsers = {}

    @classmethod
    def register(cls, scanner_type: str, parser_class):
        """
        注册解析器。

        Args:
            scanner_type: 扫描器类型标识
            parser_class: 解析器类
        """
        cls._parsers[scanner_type.lower()] = parser_class

    @classmethod
    def get_parser(cls, scanner_type: str) -> Optional[BaseParser]:
        """
        根据扫描器类型获取解析器实例。

        Args:
            scanner_type: 扫描器类型标识

        Returns:
            对应的解析器实例，未找到返回 None
        """
        parser_class = cls._parsers.get(scanner_type.lower())
        if parser_class:
            return parser_class()
        logger.warning(f"未找到扫描器类型 '{scanner_type}' 对应的解析器")
        return None

    @classmethod
    def get_supported_scanners(cls) -> Dict[str, str]:
        """
        返回所有已注册的扫描器及其支持的格式。

        Returns:
            字典，键为扫描器类型，值为支持的格式描述
        """
        return {
            'nmap': 'Nmap XML (.xml)',
            'nessus': 'Nessus CSV/JSON (.csv, .json)',
            'burp': 'Burp Suite XML (.xml)',
            'awvs': 'AWVS XML/JSON (.xml, .json)',
            'zap': 'OWASP ZAP XML/JSON (.xml, .json)',
            'xray': 'Xray JSON (.json)',
            'nuclei': 'Nuclei JSON (.json)',
            'sqlmap': 'Sqlmap JSON/CSV (.json, .csv)',
            'nsfocus': '绿盟 RSAS HTML/XML/Excel (.html, .htm, .xml, .xlsx, .xls)',
            'anheng': '安恒明鉴 HTML/Excel (.html, .htm, .xlsx, .xls)',
            'venustech': '启明星辰天镜 HTML/XML/Excel (.html, .htm, .xml, .xlsx, .xls)',
        }


def detect_scanner(file_path: str, filename: Optional[str] = None) -> str:
    """
    根据文件内容和扩展名自动检测扫描器类型。

    Args:
        file_path: 文件路径
        filename: 可选的文件名（如不提供则从 file_path 提取）

    Returns:
        扫描器类型字符串，无法检测时返回 'unknown'
    """
    if not filename:
        filename = os.path.basename(file_path)

    ext = os.path.splitext(filename)[1].lower()

    # 先尝试根据文件内容检测
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content_head = f.read(4096).lower()
    except Exception:
        try:
            with open(file_path, 'rb') as f:
                content_head = f.read(4096).decode('utf-8', errors='ignore').lower()
        except Exception:
            content_head = ""

    # 基于内容特征的检测
    if '<nmaprun' in content_head:
        return 'nmap'
    if '<issues>' in content_head and '<issue' in content_head and 'burp' in content_head:
        return 'burp'
    if '<owaspzapreport' in content_head:
        return 'zap'
    if '<scan' in content_head and '<reportitem' in content_head:
        return 'awvs'
    if 'nessus' in content_head and ('plugin' in content_head or 'ReportItem' in content_head):
        return 'nessus'
    if '"vuln_class"' in content_head or '"specific_url"' in content_head:
        return 'xray'
    if '"template-id"' in content_head or '"template_id"' in content_head:
        return 'nuclei'
    if '"data"' in content_head and '"parameter"' in content_head and '"payload"' in content_head:
        return 'sqlmap'
    if 'nsfocus' in content_head or '绿盟' in content_head or 'rsas' in content_head:
        return 'nsfocus'
    if '安恒' in content_head or '明鉴' in content_head:
        return 'anheng'
    if '启明星辰' in content_head or '天镜' in content_head or 'venustech' in content_head:
        return 'venustech'

    # 基于文件名的启发式检测
    name_lower = filename.lower()
    if 'nmap' in name_lower and ext == '.xml':
        return 'nmap'
    if 'nessus' in name_lower and ext in ('.csv', '.json'):
        return 'nessus'
    if 'burp' in name_lower and ext == '.xml':
        return 'burp'
    if 'awvs' in name_lower or 'acunetix' in name_lower:
        return 'awvs'
    if 'zap' in name_lower:
        return 'zap'
    if 'xray' in name_lower and ext == '.json':
        return 'xray'
    if 'nuclei' in name_lower and ext == '.json':
        return 'nuclei'
    if 'sqlmap' in name_lower:
        return 'sqlmap'
    if 'nsfocus' in name_lower or '绿盟' in name_lower:
        return 'nsfocus'
    if 'anheng' in name_lower or '安恒' in name_lower:
        return 'anheng'
    if 'venustech' in name_lower or '启明' in name_lower:
        return 'venustech'

    # 基于扩展名和内容组合检测
    if ext == '.xml':
        if '<nmaprun' in content_head:
            return 'nmap'
        if '<issues>' in content_head:
            return 'burp'
        if '<owaspzapreport' in content_head:
            return 'zap'
        if '<scan' in content_head:
            return 'awvs'

    if ext == '.json':
        try:
            import json
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            if isinstance(data, list):
                if data and 'template-id' in (data[0] if isinstance(data[0], dict) else {}):
                    return 'nuclei'
                if data and 'vuln_class' in (data[0] if isinstance(data[0], dict) else {}):
                    return 'xray'
            elif isinstance(data, dict):
                if 'vulns' in data:
                    return 'xray'
                if 'data' in data and isinstance(data.get('data'), list):
                    return 'sqlmap'
                if 'Report' in data or 'report' in data:
                    return 'nessus'
                if 'vulnerabilities' in data:
                    return 'awvs'
        except Exception:
            pass

    if ext == '.csv':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.readline().lower()
            if 'plugin' in header and 'severity' in header:
                return 'nessus'
            if 'parameter' in header and 'payload' in header:
                return 'sqlmap'
        except Exception:
            pass

    return 'unknown'


def parse_report(file_path: str, scanner_type: Optional[str] = None) -> List[Dict]:
    """
    便捷函数：解析扫描器报告。

    如果未指定 scanner_type，将自动检测。

    Args:
        file_path: 报告文件路径
        scanner_type: 可选的扫描器类型，不提供则自动检测

    Returns:
        漏洞字典列表
    """
    if not scanner_type:
        scanner_type = detect_scanner(file_path)

    parser = ParserFactory.get_parser(scanner_type)
    if parser:
        return parser.parse(file_path)

    logger.error(f"无法解析报告文件: {file_path}，检测到的扫描器类型: {scanner_type}")
    return []


# 导入并注册所有解析器
from .nmap_parser import NmapParser
from .nessus_parser import NessusParser
from .burp_parser import BurpParser
from .awvs_parser import AwvsParser
from .zap_parser import ZapParser
from .xray_parser import XrayParser
from .nuclei_parser import NucleiParser
from .sqlmap_parser import SqlmapParser
from .nsfocus_parser import NsfocusParser
from .anheng_parser import AnhengParser
from .venustech_parser import VenustechParser

ParserFactory.register('nmap', NmapParser)
ParserFactory.register('nessus', NessusParser)
ParserFactory.register('burp', BurpParser)
ParserFactory.register('burpsuite', BurpParser)
ParserFactory.register('awvs', AwvsParser)
ParserFactory.register('zap', ZapParser)
ParserFactory.register('xray', XrayParser)
ParserFactory.register('nuclei', NucleiParser)
ParserFactory.register('sqlmap', SqlmapParser)
ParserFactory.register('nsfocus', NsfocusParser)
ParserFactory.register('anheng', AnhengParser)
ParserFactory.register('venustech', VenustechParser)

__all__ = [
    'BaseParser',
    'ParserFactory',
    'detect_scanner',
    'parse_report',
    'NmapParser',
    'NessusParser',
    'BurpParser',
    'AwvsParser',
    'ZapParser',
    'XrayParser',
    'NucleiParser',
    'SqlmapParser',
    'NsfocusParser',
    'AnhengParser',
    'VenustechParser',
]
