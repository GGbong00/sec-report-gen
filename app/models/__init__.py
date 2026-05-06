"""
数据模型包。

导出统一漏洞数据模型中的所有公共类和枚举，供应用其他模块使用。
"""

from app.models.vulnerability import Vulnerability, ProjectInfo, Severity

__all__ = [
    'Vulnerability',
    'ProjectInfo',
    'Severity',
]
