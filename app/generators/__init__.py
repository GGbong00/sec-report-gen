# -*- coding: utf-8 -*-
"""
安全报告生成器 - 基类与工厂

Security Report Generators - Base Class & Factory
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


# ============================================================
# 中英文语言包 / Language Packs
# ============================================================
LANG_PACKS: Dict[str, Dict[str, str]] = {
    "zh": {
        # 通用 / General
        "report_title": "安全测试报告",
        "cover_title": "安全测试报告",
        "cover_subtitle": "Security Assessment Report",
        "cover_project": "项目名称",
        "cover_client": "客户名称",
        "cover_tester": "测试人员",
        "cover_date": "报告日期",
        "cover_classification": "密级标识",
        "cover_version": "报告版本",
        "toc_title": "目录",
        # 第一章 / Chapter 1
        "ch1_title": "第一章 项目概述",
        "ch1_test_objective": "测试目标",
        "ch1_test_scope": "测试范围",
        "ch1_test_method": "测试方法",
        "ch1_test_tools": "测试工具",
        "ch1_test_objective_desc": "本次安全测试旨在全面评估目标系统的安全状况，发现潜在的安全漏洞和风险点，为系统的安全加固提供依据。",
        "ch1_test_scope_desc": "本次测试范围覆盖目标系统的网络架构、应用服务、操作系统、数据库等关键组件。",
        "ch1_test_method_desc": "采用自动化扫描与手工渗透测试相结合的方式，综合运用黑盒测试与白盒测试方法。",
        "ch1_test_tools_desc": "主要使用专业安全扫描工具和手工测试工具进行检测。",
        # 第二章 / Chapter 2
        "ch2_title": "第二章 风险统计概览",
        "ch2_desc": "本次安全测试共发现以下安全漏洞：",
        "ch2_total": "漏洞总数",
        "ch2_critical": "严重",
        "ch2_high": "高危",
        "ch2_medium": "中危",
        "ch2_low": "低危",
        "ch2_info": "信息",
        "ch2_level": "风险等级",
        "ch2_count": "数量",
        "ch2_percentage": "占比",
        # 第三章 / Chapter 3
        "ch3_title": "第三章 漏洞详情",
        "ch3_vuln_id": "漏洞编号",
        "ch3_cve_id": "CVE编号",
        "ch3_vuln_name": "漏洞名称",
        "ch3_risk_level": "风险等级",
        "ch3_description": "漏洞描述",
        "ch3_impact": "影响分析",
        "ch3_reproduce": "复现步骤",
        "ch3_remediation": "修复建议",
        "ch3_target": "受影响目标",
        "ch3_port": "端口",
        "ch3_protocol": "协议",
        "ch3_source": "来源扫描器",
        # 第四章 / Chapter 4
        "ch4_title": "第四章 综合风险评估",
        "ch4_overall_risk": "整体风险等级",
        "ch4_risk_summary": "风险概述",
        "ch4_risk_summary_desc": "根据本次安全测试的结果，对目标系统的整体安全风险进行综合评估。评估综合考虑了漏洞数量、严重程度、影响范围等因素。",
        "ch4_critical_desc": "系统存在严重级别的安全漏洞，可能导致数据泄露、系统被完全控制等严重后果，需要立即修复。",
        "ch4_high_desc": "系统存在高危级别的安全漏洞，可能导致权限提升、敏感信息泄露等风险，建议尽快修复。",
        "ch4_medium_desc": "系统存在中危级别的安全漏洞，可能被利用造成一定安全影响，建议在合理时间内修复。",
        "ch4_low_desc": "系统存在低危级别的安全漏洞，安全影响有限，建议在常规维护中修复。",
        "ch4_info_desc": "系统存在信息级别的安全发现，主要为安全配置建议，建议关注并优化。",
        "ch4_recommendation": "综合建议",
        "ch4_recommendation_desc": "建议按照修复优先级建议章节中的排序，优先处理严重和高危漏洞，逐步完善系统的安全防护体系。",
        # 第五章 / Chapter 5
        "ch5_title": "第五章 修复优先级建议",
        "ch5_desc": "根据漏洞的风险等级和实际影响，建议按照以下优先级进行修复：",
        "ch5_priority": "优先级",
        "ch5_level": "风险等级",
        "ch5_count": "漏洞数量",
        "ch5_suggestion": "修复建议",
        "ch5_p1": "P1 - 立即修复",
        "ch5_p2": "P2 - 尽快修复",
        "ch5_p3": "P3 - 计划修复",
        "ch5_p4": "P4 - 建议修复",
        "ch5_p1_desc": "严重漏洞需在24小时内完成修复或采取临时缓解措施",
        "ch5_p2_desc": "高危漏洞需在7个工作日内完成修复",
        "ch5_p3_desc": "中危漏洞需在30个工作日内完成修复",
        "ch5_p4_desc": "低危及信息级漏洞建议在下次版本更新时修复",
        # 附录 / Appendix
        "appendix_title": "附录 漏洞统计汇总表",
        "appendix_index": "序号",
        "appendix_cve": "CVE编号",
        "appendix_name": "漏洞名称",
        "appendix_level": "风险等级",
        "appendix_target": "受影响目标",
        "appendix_port": "端口",
        "appendix_protocol": "协议",
        "appendix_desc": "描述",
        "appendix_remediation": "修复建议",
        "appendix_source": "来源",
        # Excel Sheet 名称
        "excel_sheet_vulns": "漏洞清单",
        "excel_sheet_stats": "风险统计",
        "excel_sheet_by_target": "按目标统计",
        "excel_target_col": "目标",
        "excel_vuln_count": "漏洞数量",
        # HTML 专用
        "html_nav_home": "首页",
        "html_nav_overview": "项目概述",
        "html_nav_stats": "风险统计",
        "html_nav_details": "漏洞详情",
        "html_nav_assessment": "风险评估",
        "html_nav_priority": "修复建议",
        "html_no_vulns": "未发现安全漏洞",
        "html_generated_by": "报告由安全测试系统自动生成",
        # 通用字段
        "unknown": "未知",
        "na": "不适用",
        "yes": "是",
        "no": "否",
        "page": "页",
        # 格式名称 / Format Names
        "format_defectdojo": "DefectDojo 格式",
        "format_jira": "Jira 导入格式",
    },
    "en": {
        # General
        "report_title": "Security Assessment Report",
        "cover_title": "Security Assessment Report",
        "cover_subtitle": "安全测试报告",
        "cover_project": "Project Name",
        "cover_client": "Client Name",
        "cover_tester": "Tester",
        "cover_date": "Report Date",
        "cover_classification": "Classification",
        "cover_version": "Version",
        "toc_title": "Table of Contents",
        # Chapter 1
        "ch1_title": "Chapter 1 Project Overview",
        "ch1_test_objective": "Test Objective",
        "ch1_test_scope": "Test Scope",
        "ch1_test_method": "Test Methodology",
        "ch1_test_tools": "Test Tools",
        "ch1_test_objective_desc": "This security assessment aims to comprehensively evaluate the security posture of the target system, identify potential vulnerabilities and risk factors, and provide a basis for security hardening.",
        "ch1_test_scope_desc": "The scope of this assessment covers key components of the target system including network architecture, application services, operating systems, and databases.",
        "ch1_test_method_desc": "A combination of automated scanning and manual penetration testing is employed, utilizing both black-box and white-box testing methodologies.",
        "ch1_test_tools_desc": "Professional security scanning tools and manual testing tools are primarily used for detection.",
        # Chapter 2
        "ch2_title": "Chapter 2 Risk Statistics Overview",
        "ch2_desc": "The following security vulnerabilities were identified during this assessment:",
        "ch2_total": "Total Vulnerabilities",
        "ch2_critical": "Critical",
        "ch2_high": "High",
        "ch2_medium": "Medium",
        "ch2_low": "Low",
        "ch2_info": "Informational",
        "ch2_level": "Risk Level",
        "ch2_count": "Count",
        "ch2_percentage": "Percentage",
        # Chapter 3
        "ch3_title": "Chapter 3 Vulnerability Details",
        "ch3_vuln_id": "Vulnerability ID",
        "ch3_cve_id": "CVE ID",
        "ch3_vuln_name": "Vulnerability Name",
        "ch3_risk_level": "Risk Level",
        "ch3_description": "Description",
        "ch3_impact": "Impact Analysis",
        "ch3_reproduce": "Reproduction Steps",
        "ch3_remediation": "Remediation",
        "ch3_target": "Affected Target",
        "ch3_port": "Port",
        "ch3_protocol": "Protocol",
        "ch3_source": "Source Scanner",
        # Chapter 4
        "ch4_title": "Chapter 4 Comprehensive Risk Assessment",
        "ch4_overall_risk": "Overall Risk Level",
        "ch4_risk_summary": "Risk Summary",
        "ch4_risk_summary_desc": "Based on the results of this security assessment, a comprehensive evaluation of the overall security risk of the target system is provided. The assessment considers factors such as vulnerability count, severity, and scope of impact.",
        "ch4_critical_desc": "The system has critical-level security vulnerabilities that could lead to data breaches, complete system compromise, and other severe consequences requiring immediate remediation.",
        "ch4_high_desc": "The system has high-level security vulnerabilities that could lead to privilege escalation, sensitive information disclosure, and other risks. Prompt remediation is recommended.",
        "ch4_medium_desc": "The system has medium-level security vulnerabilities that could be exploited to cause certain security impacts. Remediation within a reasonable timeframe is recommended.",
        "ch4_low_desc": "The system has low-level security vulnerabilities with limited security impact. Remediation during routine maintenance is recommended.",
        "ch4_info_desc": "The system has informational-level security findings, primarily security configuration recommendations. Attention and optimization are suggested.",
        "ch4_recommendation": "Overall Recommendation",
        "ch4_recommendation_desc": "It is recommended to follow the priority order in the remediation priority chapter, addressing critical and high vulnerabilities first, and gradually improving the system's security posture.",
        # Chapter 5
        "ch5_title": "Chapter 5 Remediation Priority Recommendations",
        "ch5_desc": "Based on the risk level and actual impact of vulnerabilities, remediation is recommended in the following priority order:",
        "ch5_priority": "Priority",
        "ch5_level": "Risk Level",
        "ch5_count": "Vulnerability Count",
        "ch5_suggestion": "Recommendation",
        "ch5_p1": "P1 - Immediate",
        "ch5_p2": "P2 - Urgent",
        "ch5_p3": "P3 - Planned",
        "ch5_p4": "P4 - Suggested",
        "ch5_p1_desc": "Critical vulnerabilities must be remediated within 24 hours or temporary mitigations applied",
        "ch5_p2_desc": "High vulnerabilities should be remediated within 7 business days",
        "ch5_p3_desc": "Medium vulnerabilities should be remediated within 30 business days",
        "ch5_p4_desc": "Low and informational vulnerabilities should be remediated in the next version update",
        # Appendix
        "appendix_title": "Appendix Vulnerability Summary Table",
        "appendix_index": "No.",
        "appendix_cve": "CVE ID",
        "appendix_name": "Vulnerability Name",
        "appendix_level": "Risk Level",
        "appendix_target": "Affected Target",
        "appendix_port": "Port",
        "appendix_protocol": "Protocol",
        "appendix_desc": "Description",
        "appendix_remediation": "Remediation",
        "appendix_source": "Source",
        # Excel Sheet names
        "excel_sheet_vulns": "Vulnerability List",
        "excel_sheet_stats": "Risk Statistics",
        "excel_sheet_by_target": "By Target",
        "excel_target_col": "Target",
        "excel_vuln_count": "Vulnerability Count",
        # HTML specific
        "html_nav_home": "Home",
        "html_nav_overview": "Overview",
        "html_nav_stats": "Statistics",
        "html_nav_details": "Details",
        "html_nav_assessment": "Assessment",
        "html_nav_priority": "Priority",
        "html_no_vulns": "No vulnerabilities found",
        "html_generated_by": "Report generated automatically by Security Assessment System",
        # Common fields
        "unknown": "Unknown",
        "na": "N/A",
        "yes": "Yes",
        "no": "No",
        "page": "Page",
        # Format Names
        "format_defectdojo": "DefectDojo Format",
        "format_jira": "Jira Import Format",
    },
}


def get_text(lang: str, key: str) -> str:
    """获取指定语言包中的文本"""
    pack = LANG_PACKS.get(lang, LANG_PACKS["zh"])
    return pack.get(key, key)


def get_risk_level_text(lang: str, level: str) -> str:
    """将风险等级代码转换为本地化文本"""
    level_map = {
        "zh": {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"},
        "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"},
    }
    return level_map.get(lang, level_map["zh"]).get(level.lower(), level)


def count_by_level(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """按风险等级统计漏洞数量"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in vulnerabilities:
        level = str(vuln.get("risk_level", "info")).lower()
        if level in counts:
            counts[level] += 1
    return counts


def get_overall_risk_level(counts: Dict[str, int]) -> str:
    """根据统计结果确定整体风险等级"""
    if counts["critical"] > 0:
        return "critical"
    if counts["high"] > 0:
        return "high"
    if counts["medium"] > 0:
        return "medium"
    if counts["low"] > 0:
        return "low"
    return "info"


def get_risk_color(level: str) -> str:
    """获取风险等级对应的颜色"""
    colors = {
        "critical": "DC3545",
        "high": "FD7E14",
        "medium": "FFC107",
        "low": "0D6EFD",
        "info": "6C757D",
    }
    return colors.get(level.lower(), "6C757D")


def get_risk_bg_color(level: str) -> str:
    """获取风险等级对应的背景颜色（用于 Excel）"""
    colors = {
        "critical": "FF0000",
        "high": "FF8C00",
        "medium": "FFFF00",
        "low": "00BFFF",
        "info": "A9A9A9",
    }
    return colors.get(level.lower(), "A9A9A9")


# ============================================================
# 支持的格式列表 / Supported Formats
# ============================================================
SUPPORTED_FORMATS = ["word", "pdf", "excel", "html", "xml", "json", "csv", "txt", "markdown", "defectdojo", "jira"]


# ============================================================
# BaseGenerator 抽象基类 / Abstract Base Class
# ============================================================
class BaseGenerator(ABC):
    """报告生成器抽象基类 / Abstract base class for report generators"""

    def __init__(self):
        self.lang = "zh"

    def _t(self, key: str) -> str:
        """获取当前语言的翻译文本"""
        return get_text(self.lang, key)

    def _risk_text(self, level: str) -> str:
        """获取风险等级的本地化文本"""
        return get_risk_level_text(self.lang, level)

    @abstractmethod
    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        """
        生成报告

        Args:
            project_info: 项目信息字典，包含 name, client, tester, date, classification, scope, tools, method 等字段
            vulnerabilities: 漏洞列表，每个漏洞包含 cve_id, name, risk_level, description, impact,
                             reproduce_steps, remediation, target, port, protocol, source 等字段
            output_path: 输出文件路径
            lang: 语言代码，'zh' 或 'en'

        Returns:
            生成的文件路径
        """
        self.lang = lang
        return output_path


# ============================================================
# GeneratorFactory 工厂类 / Factory Class
# ============================================================
class GeneratorFactory:
    """生成器工厂，根据格式返回对应的生成器实例"""

    _registry: Dict[str, type] = {}

    @classmethod
    def register(cls, format_name: str, generator_class: type):
        """注册生成器"""
        cls._registry[format_name.lower()] = generator_class

    @classmethod
    def create(cls, format_name: str) -> BaseGenerator:
        """
        根据格式名称创建对应的生成器实例

        Args:
            format_name: 格式名称，如 'word', 'pdf', 'excel' 等

        Returns:
            对应的生成器实例

        Raises:
            ValueError: 不支持的格式
        """
        format_name = format_name.lower()
        if format_name not in cls._registry:
            supported = ", ".join(sorted(cls._registry.keys()))
            raise ValueError(
                f"Unsupported format: '{format_name}'. Supported formats: {supported}"
            )
        return cls._registry[format_name]()

    @classmethod
    def get_supported_formats(cls) -> List[str]:
        """获取所有已注册的格式列表"""
        return sorted(cls._registry.keys())


# 延迟导入并注册各生成器 / Lazy import and register generators
def _register_all_generators():
    from .word_generator import WordGenerator
    from .pdf_generator import PDFGenerator
    from .excel_generator import ExcelGenerator
    from .html_generator import HTMLGenerator
    from .xml_generator import XMLGenerator
    from .json_generator import JSONGenerator
    from .csv_generator import CSVGenerator
    from .txt_generator import TXTGenerator
    from .markdown_generator import MarkdownGenerator
    from .defectdojo_generator import DefectDojoGenerator
    from .jira_generator import JiraGenerator

    GeneratorFactory.register("word", WordGenerator)
    GeneratorFactory.register("docx", WordGenerator)
    GeneratorFactory.register("pdf", PDFGenerator)
    GeneratorFactory.register("excel", ExcelGenerator)
    GeneratorFactory.register("xlsx", ExcelGenerator)
    GeneratorFactory.register("html", HTMLGenerator)
    GeneratorFactory.register("xml", XMLGenerator)
    GeneratorFactory.register("json", JSONGenerator)
    GeneratorFactory.register("csv", CSVGenerator)
    GeneratorFactory.register("txt", TXTGenerator)
    GeneratorFactory.register("markdown", MarkdownGenerator)
    GeneratorFactory.register("md", MarkdownGenerator)
    GeneratorFactory.register("defectdojo", DefectDojoGenerator)
    GeneratorFactory.register("jira", JiraGenerator)


_register_all_generators()
