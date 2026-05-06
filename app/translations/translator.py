# -*- coding: utf-8 -*-
"""
离线安全报告翻译引擎。

基于术语字典实现英文漏洞报告内容到中文的翻译，支持：
- 完整句子匹配（修复建议模板）
- 漏洞类型名称匹配（最长匹配优先）
- 安全术语逐词替换
- 常用句型模式替换
- 保留专有名词（CVE编号、URL、IP地址等）
"""

import os
import re
from typing import Dict, List, Optional, Tuple

from app.translations.security_glossary import (
    VULN_TYPE_DICT,
    SECURITY_TERM_DICT,
    REMEDIATION_PHRASE_DICT,
)
from app.translations.custom_dictionary import CustomDictionary
from app.translations.vuln_descriptions import VULN_DESCRIPTIONS


class OfflineTranslator:
    """离线安全报告翻译器。

    使用术语字典和模式匹配将英文漏洞报告内容翻译为中文。
    翻译策略按优先级依次为：
    1. 完整句子匹配（修复建议模板）
    2. 漏洞类型名称匹配（最长匹配优先）
    3. 安全术语逐词替换
    4. 常用句型模式替换
    5. 无法匹配的部分保留原文
    """

    # 需要保留不翻译的专有名词模式
    _PRESERVE_PATTERNS = [
        # CVE 编号，如 CVE-2024-1234
        re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
        # CVSS 评分，如 CVSS:3.1/AV:N/AC:L/PR:N
        re.compile(r'\bCVSS:\d+\.\d+[/\w:]+', re.IGNORECASE),
        # URL
        re.compile(r'https?://[^\s<>"\'\)]+', re.IGNORECASE),
        # IP 地址
        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        # 端口号上下文，如 :8080, port 443
        re.compile(r'\bport\s+\d+\b', re.IGNORECASE),
        # 文件路径
        re.compile(r'(?:/[\w\-./]+)+'),
        # 十六进制值
        re.compile(r'\b0x[0-9a-fA-F]+\b'),
        # HTML 标签
        re.compile(r'</?[a-zA-Z][\w-]*(?:\s[^>]*)?>'),
        # SQL/代码片段（简单检测）
        re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s+.*?(?:;|$)",
                    re.IGNORECASE | re.DOTALL),
        # 邮箱地址
        re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.]+\b'),
        # MAC 地址
        re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b'),
    ]

    # 需要保留的占位符正则
    _PLACEHOLDER_RE = re.compile(r'\x00PLACEHOLDER_(\d+)\x00')

    def __init__(self):
        """初始化翻译器，加载术语字典并编译正则表达式。"""
        # 加载自定义翻译字典
        self.custom_dictionary = CustomDictionary()

        # 合并所有字典为统一的翻译字典
        self._full_dict: Dict[str, str] = {}
        self._full_dict.update(VULN_TYPE_DICT)
        self._full_dict.update(SECURITY_TERM_DICT)
        self._full_dict.update(REMEDIATION_PHRASE_DICT)

        # 将自定义字典合并到统一字典（自定义优先）
        merged_custom = self.custom_dictionary.merge_with_builtin(self._full_dict)
        self._full_dict.update(merged_custom)

        # 加载10000条生成的漏洞数据库（延迟加载）
        self._vuln_db = None
        self._vuln_db_loaded = False

        # 漏洞类型字典（按键长度降序排列，实现最长匹配优先）
        self._vuln_type_sorted: List[Tuple[str, str]] = sorted(
            VULN_TYPE_DICT.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )

        # 修复建议句型（按键长度降序排列，实现最长匹配优先）
        self._remediation_sorted: List[Tuple[str, str]] = sorted(
            REMEDIATION_PHRASE_DICT.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )

        # 通用安全术语（按键长度降序排列，实现最长匹配优先）
        self._security_term_sorted: List[Tuple[str, str]] = sorted(
            SECURITY_TERM_DICT.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )

        # 自定义字典中的漏洞类型名称（按键长度降序排列）
        custom_entries = self.custom_dictionary.get_all()
        self._custom_vuln_sorted: List[Tuple[str, str]] = sorted(
            [(k, v.get('name_zh', k)) for k, v in custom_entries.items() if v.get('name_zh')],
            key=lambda x: len(x[0]),
            reverse=True,
        )

        # 编译漏洞类型匹配正则（忽略大小写，全词匹配）
        self._vuln_type_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._vuln_type_sorted
        ]

        # 编译修复建议句型匹配正则（忽略大小写，句子级别匹配）
        self._remediation_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._remediation_sorted
        ]

        # 编译通用安全术语匹配正则（忽略大小写，全词匹配）
        self._security_term_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._security_term_sorted
        ]

        # 编译自定义字典匹配正则（忽略大小写，全词匹配，最高优先级）
        self._custom_vuln_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._custom_vuln_sorted
        ]

        # 常用句型模式（正则表达式模式，用于更灵活的匹配）
        self._phrase_patterns: List[Tuple[re.Pattern, str]] = [
            # "It is recommended to ..." -> "建议..."
            (re.compile(
                r'\bIt\s+is\s+recommended\s+to\s+',
                re.IGNORECASE
            ), '建议'),
            # "An attacker can ..." -> "攻击者可以..."
            (re.compile(
                r'\bAn?\s+(?:remote\s+|local\s+)?attacker\s+(?:can|may|could|might|is\s+able\s+to)\s+',
                re.IGNORECASE
            ), '攻击者可以'),
            # "This vulnerability allows ..." -> "此漏洞允许..."
            (re.compile(
                r'\bThis\s+vulnerability\s+(?:allows?|may\s+allow|could\s+allow)\s+',
                re.IGNORECASE
            ), '此漏洞允许'),
            # "This issue allows ..." -> "此问题允许..."
            (re.compile(
                r'\bThis\s+issue\s+(?:allows?|may\s+allow|could\s+allow)\s+',
                re.IGNORECASE
            ), '此问题允许'),
            # "The vulnerability allows ..." -> "该漏洞允许..."
            (re.compile(
                r'\bThe\s+vulnerability\s+(?:allows?|may\s+allow|could\s+allow)\s+',
                re.IGNORECASE
            ), '该漏洞允许'),
            # "A successful exploit could ..." -> "成功利用可能导致..."
            (re.compile(
                r'\bA\s+successful\s+exploit\s+(?:could|may|might)\s+',
                re.IGNORECASE
            ), '成功利用可能导致'),
            # "Exploiting this vulnerability could ..." -> "利用此漏洞可能导致..."
            (re.compile(
                r'\bExploiting\s+this\s+vulnerability\s+(?:could|may|might)\s+',
                re.IGNORECASE
            ), '利用此漏洞可能导致'),
            # "This may allow an attacker to ..." -> "这可能允许攻击者..."
            (re.compile(
                r'\bThis\s+may\s+allow\s+an?\s+(?:remote\s+|local\s+)?attacker\s+to\s+',
                re.IGNORECASE
            ), '这可能允许攻击者'),
            # "The affected version is ..." -> "受影响版本为..."
            (re.compile(
                r'\bThe\s+affected\s+version\s+(?:is|are)\s+',
                re.IGNORECASE
            ), '受影响版本为'),
            # "The fixed version is ..." -> "修复版本为..."
            (re.compile(
                r'\bThe\s+fixed\s+version\s+(?:is|are)\s+',
                re.IGNORECASE
            ), '修复版本为'),
            # "To fix this issue, ..." -> "要修复此问题，..."
            (re.compile(
                r'\bTo\s+fix\s+this\s+issue,?\s*',
                re.IGNORECASE
            ), '要修复此问题，'),
            # "To resolve this vulnerability, ..." -> "要解决此漏洞，..."
            (re.compile(
                r'\bTo\s+resolve\s+this\s+vulnerability,?\s*',
                re.IGNORECASE
            ), '要解决此漏洞，'),
            # "To mitigate this vulnerability, ..." -> "要缓解此漏洞，..."
            (re.compile(
                r'\bTo\s+mitigate\s+this\s+vulnerability,?\s*',
                re.IGNORECASE
            ), '要缓解此漏洞，'),
            # "See also:" -> "参见："
            (re.compile(r'\bSee\s+also:?\s*', re.IGNORECASE), '参见：'),
            # "References:" -> "参考："
            (re.compile(r'\bReferences:?\s*', re.IGNORECASE), '参考：'),
            # "Overview:" -> "概述："
            (re.compile(r'\bOverview:?\s*', re.IGNORECASE), '概述：'),
            # "Description:" -> "描述："
            (re.compile(r'\bDescription:?\s*', re.IGNORECASE), '描述：'),
            # "Details:" -> "详情："
            (re.compile(r'\bDetails:?\s*', re.IGNORECASE), '详情：'),
            # "Impact:" -> "影响："
            (re.compile(r'\bImpact:?\s*', re.IGNORECASE), '影响：'),
            # "Solution:" -> "解决方案："
            (re.compile(r'\bSolution:?\s*', re.IGNORECASE), '解决方案：'),
            # "Remediation:" -> "修复建议："
            (re.compile(r'\bRemediation:?\s*', re.IGNORECASE), '修复建议：'),
            # "Proof of Concept:" -> "概念验证："
            (re.compile(r'\bProof\s+of\s+Concept:?\s*', re.IGNORECASE), '概念验证：'),
            # "Reproduction Steps:" -> "复现步骤："
            (re.compile(r'\bReproduction\s+Steps:?\s*', re.IGNORECASE), '复现步骤：'),
            # "Risk Factor:" -> "风险因素："
            (re.compile(r'\bRisk\s+Factor:?\s*', re.IGNORECASE), '风险因素：'),
            # "CVSS Base Score:" -> "CVSS基础评分："
            (re.compile(r'\bCVSS\s+Base\s+Score:?\s*', re.IGNORECASE), 'CVSS基础评分：'),
            # "CVSS Vector:" -> "CVSS向量："
            (re.compile(r'\bCVSS\s+Vector:?\s*', re.IGNORECASE), 'CVSS向量：'),
            # "Affected Version:" -> "受影响版本："
            (re.compile(r'\bAffected\s+Version:?\s*', re.IGNORECASE), '受影响版本：'),
            # "Fixed Version:" -> "修复版本："
            (re.compile(r'\bFixed\s+Version:?\s*', re.IGNORECASE), '修复版本：'),
            # "Severity:" -> "严重程度："
            (re.compile(r'\bSeverity:?\s*', re.IGNORECASE), '严重程度：'),
            # "Exploitability:" -> "可利用性："
            (re.compile(r'\bExploitability:?\s*', re.IGNORECASE), '可利用性：'),
            # "Attack Complexity:" -> "攻击复杂度："
            (re.compile(r'\bAttack\s+Complexity:?\s*', re.IGNORECASE), '攻击复杂度：'),
            # "Attack Prerequisites:" -> "攻击前提条件："
            (re.compile(r'\bAttack\s+Prerequisites:?\s*', re.IGNORECASE), '攻击前提条件：'),
            # "User Interaction:" -> "用户交互："
            (re.compile(r'\bUser\s+Interaction:?\s*', re.IGNORECASE), '用户交互：'),
            # "Confidentiality Impact:" -> "机密性影响："
            (re.compile(r'\bConfidentiality\s+Impact:?\s*', re.IGNORECASE), '机密性影响：'),
            # "Integrity Impact:" -> "完整性影响："
            (re.compile(r'\bIntegrity\s+Impact:?\s*', re.IGNORECASE), '完整性影响：'),
            # "Availability Impact:" -> "可用性影响："
            (re.compile(r'\bAvailability\s+Impact:?\s*', re.IGNORECASE), '可用性影响：'),

            # ===== 新增：更多动词短语模式 =====
            # "to exploit" -> "利用"
            (re.compile(r'\bto\s+exploit\b', re.IGNORECASE), '利用'),
            # "to gain" -> "获取"
            (re.compile(r'\bto\s+gain\b', re.IGNORECASE), '获取'),
            # "to access" -> "访问"
            (re.compile(r'\bto\s+access\b', re.IGNORECASE), '访问'),
            # "to execute" -> "执行"
            (re.compile(r'\bto\s+execute\b', re.IGNORECASE), '执行'),
            # "to bypass" -> "绕过"
            (re.compile(r'\bto\s+bypass\b', re.IGNORECASE), '绕过'),
            # "to escalate" -> "提升"
            (re.compile(r'\bto\s+escalate\b', re.IGNORECASE), '提升'),
            # "to compromise" -> "入侵"
            (re.compile(r'\bto\s+compromise\b', re.IGNORECASE), '入侵'),
            # "to obtain" -> "获取"
            (re.compile(r'\bto\s+obtain\b', re.IGNORECASE), '获取'),
            # "to disclose" -> "泄露"
            (re.compile(r'\bto\s+disclose\b', re.IGNORECASE), '泄露'),
            # "to inject" -> "注入"
            (re.compile(r'\bto\s+inject\b', re.IGNORECASE), '注入'),
            # "to read" -> "读取"
            (re.compile(r'\bto\s+read\b', re.IGNORECASE), '读取'),
            # "to write" -> "写入"
            (re.compile(r'\bto\s+write\b', re.IGNORECASE), '写入'),
            # "to modify" -> "修改"
            (re.compile(r'\bto\s+modify\b', re.IGNORECASE), '修改'),
            # "to delete" -> "删除"
            (re.compile(r'\bto\s+delete\b', re.IGNORECASE), '删除'),
            # "to upload" -> "上传"
            (re.compile(r'\bto\s+upload\b', re.IGNORECASE), '上传'),
            # "to download" -> "下载"
            (re.compile(r'\bto\s+download\b', re.IGNORECASE), '下载'),
            # "to prevent" -> "防止"
            (re.compile(r'\bto\s+prevent\b', re.IGNORECASE), '防止'),
            # "to fix" -> "修复"
            (re.compile(r'\bto\s+fix\b', re.IGNORECASE), '修复'),
            # "to resolve" -> "解决"
            (re.compile(r'\bto\s+resolve\b', re.IGNORECASE), '解决'),
            # "to mitigate" -> "缓解"
            (re.compile(r'\bto\s+mitigate\b', re.IGNORECASE), '缓解'),
            # "to update" -> "更新"
            (re.compile(r'\bto\s+update\b', re.IGNORECASE), '更新'),
            # "to upgrade" -> "升级"
            (re.compile(r'\bto\s+upgrade\b', re.IGNORECASE), '升级'),
            # "to install" -> "安装"
            (re.compile(r'\bto\s+install\b', re.IGNORECASE), '安装'),
            # "to configure" -> "配置"
            (re.compile(r'\bto\s+configure\b', re.IGNORECASE), '配置'),
            # "to disable" -> "禁用"
            (re.compile(r'\bto\s+disable\b', re.IGNORECASE), '禁用'),
            # "to enable" -> "启用"
            (re.compile(r'\bto\s+enable\b', re.IGNORECASE), '启用'),
            # "to restrict" -> "限制"
            (re.compile(r'\bto\s+restrict\b', re.IGNORECASE), '限制'),
            # "to protect" -> "保护"
            (re.compile(r'\bto\s+protect\b', re.IGNORECASE), '保护'),
            # "to encrypt" -> "加密"
            (re.compile(r'\bto\s+encrypt\b', re.IGNORECASE), '加密'),
            # "to decrypt" -> "解密"
            (re.compile(r'\bto\s+decrypt\b', re.IGNORECASE), '解密'),
            # "to verify" -> "验证"
            (re.compile(r'\bto\s+verify\b', re.IGNORECASE), '验证'),
            # "to validate" -> "验证"
            (re.compile(r'\bto\s+validate\b', re.IGNORECASE), '验证'),
            # "to sanitize" -> "净化"
            (re.compile(r'\bto\s+sanitize\b', re.IGNORECASE), '净化'),
            # "to encode" -> "编码"
            (re.compile(r'\bto\s+encode\b', re.IGNORECASE), '编码'),
            # "to escape" -> "转义"
            (re.compile(r'\bto\s+escape\b', re.IGNORECASE), '转义'),
            # "to implement" -> "实施"
            (re.compile(r'\bto\s+implement\b', re.IGNORECASE), '实施'),
            # "to use" -> "使用"
            (re.compile(r'\bto\s+use\b', re.IGNORECASE), '使用'),
            # "to remove" -> "删除"
            (re.compile(r'\bto\s+remove\b', re.IGNORECASE), '删除'),
            # "to add" -> "添加"
            (re.compile(r'\bto\s+add\b', re.IGNORECASE), '添加'),
            # "to set" -> "设置"
            (re.compile(r'\bto\s+set\b', re.IGNORECASE), '设置'),
            # "to monitor" -> "监控"
            (re.compile(r'\bto\s+monitor\b', re.IGNORECASE), '监控'),
            # "to detect" -> "检测"
            (re.compile(r'\bto\s+detect\b', re.IGNORECASE), '检测'),
            # "to block" -> "阻止"
            (re.compile(r'\bto\s+block\b', re.IGNORECASE), '阻止'),
            # "to allow" -> "允许"
            (re.compile(r'\bto\s+allow\b', re.IGNORECASE), '允许'),
            # "to deny" -> "拒绝"
            (re.compile(r'\bto\s+deny\b', re.IGNORECASE), '拒绝'),
            # "to filter" -> "过滤"
            (re.compile(r'\bto\s+filter\b', re.IGNORECASE), '过滤'),
            # "to scan" -> "扫描"
            (re.compile(r'\bto\s+scan\b', re.IGNORECASE), '扫描'),
            # "to test" -> "测试"
            (re.compile(r'\bto\s+test\b', re.IGNORECASE), '测试'),
            # "to review" -> "审查"
            (re.compile(r'\bto\s+review\b', re.IGNORECASE), '审查'),
            # "to audit" -> "审计"
            (re.compile(r'\bto\s+audit\b', re.IGNORECASE), '审计'),
            # "to patch" -> "修补"
            (re.compile(r'\bto\s+patch\b', re.IGNORECASE), '修补'),
            # "to harden" -> "加固"
            (re.compile(r'\bto\s+harden\b', re.IGNORECASE), '加固'),
            # "to backup" -> "备份"
            (re.compile(r'\bto\s+backup\b', re.IGNORECASE), '备份'),
            # "to restore" -> "恢复"
            (re.compile(r'\bto\s+restore\b', re.IGNORECASE), '恢复'),
            # "to migrate" -> "迁移"
            (re.compile(r'\bto\s+migrate\b', re.IGNORECASE), '迁移'),
            # "to deploy" -> "部署"
            (re.compile(r'\bto\s+deploy\b', re.IGNORECASE), '部署'),
            # "to isolate" -> "隔离"
            (re.compile(r'\bto\s+isolate\b', re.IGNORECASE), '隔离'),
            # "to quarantine" -> "隔离"
            (re.compile(r'\bto\s+quarantine\b', re.IGNORECASE), '隔离'),

            # ===== 新增：主语+动词句型 =====
            # "The login page is vulnerable to" -> "登录页面存在...漏洞"
            (re.compile(r'\bThe\s+([\w\s]+?)\s+is\s+vulnerable\s+to\b', re.IGNORECASE), r'\1存在'),
            # "The target system" -> "目标系统"
            (re.compile(r'\bThe\s+target\s+system\b', re.IGNORECASE), '目标系统'),
            # "The remote host" -> "远程主机"
            (re.compile(r'\bThe\s+remote\s+host\b', re.IGNORECASE), '远程主机'),
            # "The web server" -> "Web服务器"
            (re.compile(r'\bThe\s+web\s+server\b', re.IGNORECASE), 'Web服务器'),
            # "The application" -> "应用程序"
            (re.compile(r'\bThe\s+application\b', re.IGNORECASE), '应用程序'),
            # "The database" -> "数据库"
            (re.compile(r'\bThe\s+database\b', re.IGNORECASE), '数据库'),
            # "The service" -> "服务"
            (re.compile(r'\bThe\s+service\b', re.IGNORECASE), '服务'),
            # "The plugin" -> "插件"
            (re.compile(r'\bThe\s+plugin\b', re.IGNORECASE), '插件'),
            # "The module" -> "模块"
            (re.compile(r'\bThe\s+module\b', re.IGNORECASE), '模块'),
            # "The component" -> "组件"
            (re.compile(r'\bThe\s+component\b', re.IGNORECASE), '组件'),
            # "The software" -> "软件"
            (re.compile(r'\bThe\s+software\b', re.IGNORECASE), '软件'),
            # "The system" -> "系统"
            (re.compile(r'\bThe\s+system\b', re.IGNORECASE), '系统'),
            # "The server" -> "服务器"
            (re.compile(r'\bThe\s+server\b', re.IGNORECASE), '服务器'),
            # "The client" -> "客户端"
            (re.compile(r'\bThe\s+client\b', re.IGNORECASE), '客户端'),
            # "The admin" -> "管理员"
            (re.compile(r'\bThe\s+admin\b', re.IGNORECASE), '管理员'),
            # "The user" -> "用户"
            (re.compile(r'\bThe\s+user\b', re.IGNORECASE), '用户'),
            # "An unauthenticated user" -> "未认证用户"
            (re.compile(r'\bAn?\s+unauthenticated\s+user\b', re.IGNORECASE), '未认证用户'),
            # "An authenticated user" -> "已认证用户"
            (re.compile(r'\bAn?\s+authenticated\s+user\b', re.IGNORECASE), '已认证用户'),
            # "A remote attacker" -> "远程攻击者"
            (re.compile(r'\bA\s+remote\s+attacker\b', re.IGNORECASE), '远程攻击者'),
            # "A local attacker" -> "本地攻击者"
            (re.compile(r'\bA\s+local\s+attacker\b', re.IGNORECASE), '本地攻击者'),
            # "An attacker" -> "攻击者"
            (re.compile(r'\bAn?\s+attacker\b', re.IGNORECASE), '攻击者'),

            # ===== 新增：连接词和介词短语 =====
            # "on the target system" -> "在目标系统上"
            (re.compile(r'\bon\s+the\s+target\s+system\b', re.IGNORECASE), '在目标系统上'),
            # "on the remote host" -> "在远程主机上"
            (re.compile(r'\bon\s+the\s+remote\s+host\b', re.IGNORECASE), '在远程主机上'),
            # "on the web server" -> "在Web服务器上"
            (re.compile(r'\bon\s+the\s+web\s+server\b', re.IGNORECASE), '在Web服务器上'),
            # "in the database" -> "在数据库中"
            (re.compile(r'\bin\s+the\s+database\b', re.IGNORECASE), '在数据库中'),
            # "through this vulnerability" -> "通过此漏洞"
            (re.compile(r'\bthrough\s+this\s+vulnerability\b', re.IGNORECASE), '通过此漏洞'),
            # "through this issue" -> "通过此问题"
            (re.compile(r'\bthrough\s+this\s+issue\b', re.IGNORECASE), '通过此问题'),
            # "including" -> "包括"
            (re.compile(r'\bincluding\b', re.IGNORECASE), '包括'),
            # "such as" -> "例如"
            (re.compile(r'\bsuch\s+as\b', re.IGNORECASE), '例如'),
            # "for example" -> "例如"
            (re.compile(r'\bfor\s+example\b', re.IGNORECASE), '例如'),
            # "as well as" -> "以及"
            (re.compile(r'\bas\s+well\s+as\b', re.IGNORECASE), '以及'),
            # "in order to" -> "为了"
            (re.compile(r'\bin\s+order\s+to\b', re.IGNORECASE), '为了'),
            # "due to" -> "由于"
            (re.compile(r'\bdue\s+to\b', re.IGNORECASE), '由于'),
            # "because of" -> "因为"
            (re.compile(r'\bbecause\s+of\b', re.IGNORECASE), '因为'),
            # "instead of" -> "而不是"
            (re.compile(r'\binstead\s+of\b', re.IGNORECASE), '而不是'),
            # "in addition" -> "此外"
            (re.compile(r'\bin\s+addition\b', re.IGNORECASE), '此外'),
            # "in particular" -> "特别是"
            (re.compile(r'\bin\s+particular\b', re.IGNORECASE), '特别是'),
            # "is vulnerable to" -> "存在...漏洞"
            (re.compile(r'\bis\s+vulnerable\s+to\b', re.IGNORECASE), '存在'),
            # "is affected by" -> "受...影响"
            (re.compile(r'\bis\s+affected\s+by\b', re.IGNORECASE), '受影响'),
            # "is exposed to" -> "暴露于"
            (re.compile(r'\bis\s+exposed\s+to\b', re.IGNORECASE), '暴露于'),
            # "is susceptible to" -> "容易受到"
            (re.compile(r'\bis\s+susceptible\s+to\b', re.IGNORECASE), '容易受到'),
            # "is not properly" -> "未正确"
            (re.compile(r'\bis\s+not\s+properly\b', re.IGNORECASE), '未正确'),
            # "is not configured" -> "未配置"
            (re.compile(r'\bis\s+not\s+configured\b', re.IGNORECASE), '未配置'),
            # "is not installed" -> "未安装"
            (re.compile(r'\bis\s+not\s+installed\b', re.IGNORECASE), '未安装'),
            # "is not enabled" -> "未启用"
            (re.compile(r'\bis\s+not\s+enabled\b', re.IGNORECASE), '未启用'),
            # "is not disabled" -> "未禁用"
            (re.compile(r'\bis\s+not\s+disabled\b', re.IGNORECASE), '未禁用'),
            # "is not set" -> "未设置"
            (re.compile(r'\bis\s+not\s+set\b', re.IGNORECASE), '未设置'),
            # "is not protected" -> "未受保护"
            (re.compile(r'\bis\s+not\s+protected\b', re.IGNORECASE), '未受保护'),
            # "is not secured" -> "不安全"
            (re.compile(r'\bis\s+not\s+secured\b', re.IGNORECASE), '不安全'),
            # "is not encrypted" -> "未加密"
            (re.compile(r'\bis\s+not\s+encrypted\b', re.IGNORECASE), '未加密'),
            # "is not validated" -> "未验证"
            (re.compile(r'\bis\s+not\s+validated\b', re.IGNORECASE), '未验证'),
            # "is not sanitized" -> "未净化"
            (re.compile(r'\bis\s+not\s+sanitized\b', re.IGNORECASE), '未净化'),
            # "could result in" -> "可能导致"
            (re.compile(r'\bcould\s+result\s+in\b', re.IGNORECASE), '可能导致'),
            # "may result in" -> "可能导致"
            (re.compile(r'\bmay\s+result\s+in\b', re.IGNORECASE), '可能导致'),
            # "can result in" -> "可导致"
            (re.compile(r'\bcan\s+result\s+in\b', re.IGNORECASE), '可导致'),
            # "could lead to" -> "可能导致"
            (re.compile(r'\bcould\s+lead\s+to\b', re.IGNORECASE), '可能导致'),
            # "may lead to" -> "可能导致"
            (re.compile(r'\bmay\s+lead\s+to\b', re.IGNORECASE), '可能导致'),
            # "can lead to" -> "可导致"
            (re.compile(r'\bcan\s+lead\s+to\b', re.IGNORECASE), '可导致'),
            # "by exploiting" -> "通过利用"
            (re.compile(r'\bby\s+exploiting\b', re.IGNORECASE), '通过利用'),
            # "by sending" -> "通过发送"
            (re.compile(r'\bby\s+sending\b', re.IGNORECASE), '通过发送'),
            # "by injecting" -> "通过注入"
            (re.compile(r'\bby\s+injecting\b', re.IGNORECASE), '通过注入'),
            # "by accessing" -> "通过访问"
            (re.compile(r'\bby\s+accessing\b', re.IGNORECASE), '通过访问'),
            # "by manipulating" -> "通过操纵"
            (re.compile(r'\bby\s+manipulating\b', re.IGNORECASE), '通过操纵'),
            # "by modifying" -> "通过修改"
            (re.compile(r'\bby\s+modifying\b', re.IGNORECASE), '通过修改'),
            # "which could" -> "这可能"
            (re.compile(r'\bwhich\s+could\b', re.IGNORECASE), '这可能'),
            # "which may" -> "这可能"
            (re.compile(r'\bwhich\s+may\b', re.IGNORECASE), '这可能'),
            # "which can" -> "这可以"
            (re.compile(r'\bwhich\s+can\b', re.IGNORECASE), '这可以'),
            # "that could" -> "这可能"
            (re.compile(r'\bthat\s+could\b', re.IGNORECASE), '这可能'),
            # "that may" -> "这可能"
            (re.compile(r'\bthat\s+may\b', re.IGNORECASE), '这可能'),
            # "that can" -> "这可以"
            (re.compile(r'\bthat\s+can\b', re.IGNORECASE), '这可以'),
            # "has been detected" -> "已被检测到"
            (re.compile(r'\bhas\s+been\s+detected\b', re.IGNORECASE), '已被检测到'),
            # "has been identified" -> "已被识别"
            (re.compile(r'\bhas\s+been\s+identified\b', re.IGNORECASE), '已被识别'),
            # "has been found" -> "已被发现"
            (re.compile(r'\bhas\s+been\s+found\b', re.IGNORECASE), '已被发现'),
            # "has been reported" -> "已被报告"
            (re.compile(r'\bhas\s+been\s+reported\b', re.IGNORECASE), '已被报告'),
            # "has been fixed" -> "已被修复"
            (re.compile(r'\bhas\s+been\s+fixed\b', re.IGNORECASE), '已被修复'),
            # "has been patched" -> "已被修补"
            (re.compile(r'\bhas\s+been\s+patched\b', re.IGNORECASE), '已被修补'),
            # "has been resolved" -> "已被解决"
            (re.compile(r'\bhas\s+been\s+resolved\b', re.IGNORECASE), '已被解决'),
            # "without authentication" -> "无需身份验证"
            (re.compile(r'\bwithout\s+authentication\b', re.IGNORECASE), '无需身份验证'),
            # "without authorization" -> "无需授权"
            (re.compile(r'\bwithout\s+authorization\b', re.IGNORECASE), '无需授权'),
            # "without proper" -> "缺少适当的"
            (re.compile(r'\bwithout\s+proper\b', re.IGNORECASE), '缺少适当的'),
            # "without valid" -> "缺少有效的"
            (re.compile(r'\bwithout\s+valid\b', re.IGNORECASE), '缺少有效的'),
            # "with a CVSS score of" -> "CVSS评分为"
            (re.compile(r'\bwith\s+a\s+CVSS\s+score\s+of\b', re.IGNORECASE), 'CVSS评分为'),
            # "the following actions" -> "以下操作"
            (re.compile(r'\bthe\s+following\s+actions\b', re.IGNORECASE), '以下操作'),
            # "the following steps" -> "以下步骤"
            (re.compile(r'\bthe\s+following\s+steps\b', re.IGNORECASE), '以下步骤'),
            # "the following vulnerabilities" -> "以下漏洞"
            (re.compile(r'\bthe\s+following\s+vulnerabilities\b', re.IGNORECASE), '以下漏洞'),
            # "the following issues" -> "以下问题"
            (re.compile(r'\bthe\s+following\s+issues\b', re.IGNORECASE), '以下问题'),
        ]

    def translate(self, text: str) -> str:
        """翻译英文文本为中文。

        策略（按优先级）：
        1. 自定义字典匹配（最高优先级）
        2. 完整句子匹配（修复建议模板）
        3. 漏洞类型名称匹配
        4. 安全术语逐词替换
        5. 常用句型模式替换
        6. 无法匹配的部分保留原文

        Args:
            text: 英文文本

        Returns:
            中文翻译文本
        """
        if not text or not text.strip():
            return text

        # 如果文本已经是中文为主，直接返回
        if self._is_mostly_chinese(text):
            return text

        # 第一步：保护专有名词（CVE编号、URL、IP等）
        text, placeholders = self._preserve_special_terms(text)

        # 第二步：按行处理（保持格式）
        lines = text.split('\n')
        translated_lines = []
        for line in lines:
            translated_lines.append(self._translate_line(line))
        result = '\n'.join(translated_lines)

        # 第三步：恢复专有名词
        result = self._restore_special_terms(result, placeholders)

        # 第四步：后处理
        result = self._post_process(result)

        return result

    def _load_vuln_db(self):
        """延迟加载10000条生成的漏洞数据库。

        首次调用时加载，后续调用直接返回缓存结果。
        """
        if self._vuln_db_loaded:
            return self._vuln_db
        self._vuln_db_loaded = True
        try:
            from app.translations.generate_vuln_db import load_vuln_db
            self._vuln_db = load_vuln_db()
        except Exception:
            self._vuln_db = None
        return self._vuln_db

    def _lookup_vuln_db(self, vuln_name):
        """在10000条生成的漏洞数据库中按名称查找匹配的翻译。

        Args:
            vuln_name: 漏洞名称（英文）

        Returns:
            匹配的漏洞条目字典，或 None。
        """
        db = self._load_vuln_db()
        if db is None:
            return None

        by_name = db.get("by_name", {})

        # 1. 精确匹配
        if vuln_name in by_name:
            return by_name[vuln_name]

        # 2. 按漏洞类型关键词匹配（提取漏洞类型部分）
        vuln_name_lower = vuln_name.lower()

        # 尝试匹配包含相同漏洞类型关键词的条目
        best_match = None
        best_overlap = 0

        for name, entry in by_name.items():
            name_lower = name.lower()
            # 计算单词重叠度
            vuln_words = set(vuln_name_lower.split())
            name_words = set(name_lower.split())
            overlap = len(vuln_words & name_words)
            if overlap > best_overlap and overlap >= 2:
                best_overlap = overlap
                best_match = entry

        return best_match

    def translate_vulnerability(self, vuln_dict: dict) -> dict:
        """翻译整个漏洞字典。

        翻译字段：name, description, impact, solution, poc_steps
        保留字段：vuln_id, severity, target, port, protocol, scanner_source

        翻译优先级：
        1. CVE描述库（100条手写的高质量翻译）
        2. 10000条生成的漏洞数据库（按漏洞名称匹配）
        3. 自定义字典精确匹配
        4. 内置术语字典逐词替换

        Args:
            vuln_dict: 漏洞字典

        Returns:
            翻译后的漏洞字典
        """
        translated = dict(vuln_dict)

        # 字段名与自定义字典字段的映射
        field_mapping = {
            'name': 'name_zh',
            'description': 'description_zh',
            'impact': 'impact_zh',
            'solution': 'solution_zh',
        }

        # 需要翻译的字段
        translatable_fields = ['name', 'description', 'impact', 'solution', 'poc_steps']

        for field in translatable_fields:
            value = translated.get(field, '')
            if not value or not isinstance(value, str) or not value.strip():
                continue

            # 优先级1：查CVE描述库（100条手写的高质量翻译）
            vuln_id = translated.get('vuln_id', '')
            if vuln_id and vuln_id in VULN_DESCRIPTIONS:
                desc = VULN_DESCRIPTIONS[vuln_id]
                zh_field = field_mapping.get(field)
                if zh_field and desc.get(zh_field):
                    translated[field] = desc[zh_field]
                    continue

            # 优先级2：查10000条生成的漏洞数据库（按漏洞名称匹配）
            vuln_name = translated.get('name', '')
            if vuln_name:
                db_entry = self._lookup_vuln_db(vuln_name)
                if db_entry:
                    zh_field = field_mapping.get(field)
                    if zh_field and db_entry.get(zh_field):
                        translated[field] = db_entry[zh_field]
                        continue

            # 优先级3：自定义字典匹配
            custom_field = field_mapping.get(field)
            if custom_field:
                custom_value = self.custom_dictionary.get_translation(vuln_name, custom_field)
                if custom_value:
                    translated[field] = custom_value
                    continue

            # 优先级4：使用内置术语字典逐词替换
            translated[field] = self.translate(value)

        return translated

    def translate_vulnerabilities(self, vuln_list: list) -> list:
        """批量翻译漏洞列表。

        Args:
            vuln_list: 漏洞字典列表

        Returns:
            翻译后的漏洞字典列表
        """
        return [self.translate_vulnerability(vuln) for vuln in vuln_list]

    def _translate_line(self, line: str) -> str:
        """翻译单行文本。

        Args:
            line: 单行文本

        Returns:
            翻译后的单行文本
        """
        if not line.strip():
            return line

        # 0. 自定义字典匹配（最高优先级）
        line = self._replace_custom_dict(line)

        # 1. 常用句型模式替换（先匹配长模式）
        line = self._replace_phrase_patterns(line)

        # 2. 完整句子匹配（修复建议模板）
        line = self._match_full_sentence(line)

        # 3. 漏洞类型名称替换（最长匹配优先）
        line = self._replace_vuln_types(line)

        # 4. 安全术语替换
        line = self._replace_security_terms(line)

        return line

    def _match_full_sentence(self, text: str) -> str:
        """完整句子匹配。

        尝试将文本中的完整句子与修复建议模板进行匹配。
        支持句子作为独立行出现，也支持句子嵌入在段落中。

        Args:
            text: 输入文本

        Returns:
            匹配替换后的文本
        """
        for pattern, translation in self._remediation_patterns:
            text = pattern.sub(translation, text)
        return text

    def _replace_vuln_types(self, text: str) -> str:
        """替换漏洞类型名称（最长匹配优先）。

        按键长度从长到短依次匹配，确保优先匹配更长的术语。
        例如 "SQL Injection (Blind)" 优先于 "SQL Injection"。

        Args:
            text: 输入文本

        Returns:
            替换后的文本
        """
        for pattern, translation in self._vuln_type_patterns:
            text = pattern.sub(
                lambda m: self._preserve_case(m, translation),
                text
            )
        return text

    def _replace_security_terms(self, text: str) -> str:
        """替换安全术语（逐词替换）。

        按键长度从长到短依次匹配，确保优先匹配更长的短语。
        例如 "public key" 优先于 "key"。

        Args:
            text: 输入文本

        Returns:
            替换后的文本
        """
        for pattern, translation in self._security_term_patterns:
            text = pattern.sub(
                lambda m: self._preserve_case(m, translation),
                text
            )
        return text

    def _replace_phrase_patterns(self, text: str) -> str:
        """替换常用句型模式。

        使用正则表达式进行更灵活的句型匹配和替换。

        Args:
            text: 输入文本

        Returns:
            替换后的文本
        """
        for pattern, translation in self._phrase_patterns:
            text = pattern.sub(translation, text)
        return text

    def _replace_custom_dict(self, text: str) -> str:
        """替换自定义字典中的条目（最高优先级）。

        使用自定义字典中 name_zh 字段进行匹配替换。

        Args:
            text: 输入文本

        Returns:
            替换后的文本
        """
        for pattern, translation in self._custom_vuln_patterns:
            text = pattern.sub(
                lambda m: self._preserve_case(m, translation),
                text
            )
        return text

    def _preserve_special_terms(self, text: str) -> Tuple[str, Dict[str, str]]:
        """保护专有名词，用占位符替换。

        将 CVE 编号、URL、IP 地址等需要保留原文的内容替换为占位符，
        翻译完成后再恢复。

        Args:
            text: 输入文本

        Returns:
            (替换后的文本, 占位符映射字典)
        """
        placeholders = {}
        counter = 0

        for pattern in self._PRESERVE_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                placeholder = f'\x00PLACEHOLDER_{counter}\x00'
                placeholders[placeholder] = match
                text = text.replace(match, placeholder, 1)
                counter += 1

        return text, placeholders

    def _restore_special_terms(self, text: str, placeholders: Dict[str, str]) -> str:
        """恢复专有名词。

        将占位符替换回原始的专有名词。

        Args:
            text: 包含占位符的文本
            placeholders: 占位符映射字典

        Returns:
            恢复后的文本
        """
        for placeholder, original in placeholders.items():
            text = text.replace(placeholder, original)
        return text

    def _preserve_case(self, match: re.Match, translation: str) -> str:
        """根据原文大小写调整翻译结果。

        如果原文全大写，翻译结果也全大写（对中文无影响）。
        如果原文首字母大写，翻译结果保持原样（中文无大小写）。

        Args:
            match: 正则匹配对象
            translation: 翻译结果

        Returns:
            调整后的翻译结果
        """
        original = match.group(0)
        # 中文翻译不需要大小写转换，直接返回
        return translation

    def _is_mostly_chinese(self, text: str) -> bool:
        """判断文本是否以中文为主。

        如果文本中中文字符占比超过30%，则认为是中文文本。

        Args:
            text: 输入文本

        Returns:
            如果是中文为主返回 True
        """
        if not text:
            return False
        chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        total_chars = sum(1 for c in text if c.isalpha())
        if total_chars == 0:
            return False
        return chinese_chars / total_chars > 0.3

    def _post_process(self, text: str) -> str:
        """后处理：清理多余空格、统一标点等。

        Args:
            text: 翻译后的文本

        Returns:
            清理后的文本
        """
        if not text:
            return text

        # 将英文标点替换为中文标点（在中文上下文中）
        # 句号
        text = re.sub(r'(?<=[\u4e00-\u9fff])\.(?=\s|$)', '。', text)
        # 逗号
        text = re.sub(r'(?<=[\u4e00-\u9fff]),(?=\s)', '，', text)
        # 冒号
        text = re.sub(r'(?<=[\u4e00-\u9fff]):(?=\s)', '：', text)
        # 分号
        text = re.sub(r'(?<=[\u4e00-\u9fff]);(?=\s)', '；', text)
        # 感叹号
        text = re.sub(r'(?<=[\u4e00-\u9fff])!', '！', text)
        # 问号
        text = re.sub(r'(?<=[\u4e00-\u9fff])\?', '？', text)
        # 括号（中文内容使用中文括号）
        text = re.sub(r'\(([\u4e00-\u9fff]+)\)', '（\\1）', text)

        # 清理多余空格
        text = re.sub(r'  +', ' ', text)

        # 清理行首行尾空格
        lines = text.split('\n')
        lines = [line.strip() for line in lines]
        text = '\n'.join(lines)

        # 清理连续空行（最多保留一个空行）
        text = re.sub(r'\n{3,}', '\n\n', text)

        return text

    # ================================================================
    # 自定义字典管理方法
    # ================================================================

    def load_custom_dictionary(self, file_path: str, format: str = 'json') -> dict:
        """加载自定义翻译字典文件。

        根据文件格式调用 CustomDictionary 对应的加载方法，
        并重新编译翻译正则以使新加载的自定义字典生效。

        Args:
            file_path: 字典文件路径。
            format: 文件格式，支持 'json' 或 'csv'。
                    如果为 'auto'，则根据文件扩展名自动判断。

        Returns:
            加载统计信息字典。
        """
        if format == 'auto':
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.csv':
                format = 'csv'
            else:
                format = 'json'

        if format == 'csv':
            stats = self.custom_dictionary.load_from_csv(file_path)
        else:
            stats = self.custom_dictionary.load_from_json(file_path)

        # 重新编译自定义字典匹配正则
        custom_entries = self.custom_dictionary.get_all()
        self._custom_vuln_sorted = sorted(
            [(k, v.get('name_zh', k)) for k, v in custom_entries.items() if v.get('name_zh')],
            key=lambda x: len(x[0]),
            reverse=True,
        )
        self._custom_vuln_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._custom_vuln_sorted
        ]

        # 更新统一字典
        merged_custom = self.custom_dictionary.merge_with_builtin(
            {**VULN_TYPE_DICT, **SECURITY_TERM_DICT, **REMEDIATION_PHRASE_DICT}
        )
        self._full_dict.update(merged_custom)

        return stats

    def rebuild_custom_patterns(self):
        """重新编译自定义字典匹配正则。

        在删除自定义翻译条目后调用，确保翻译正则与字典内容同步。
        """
        import re
        custom_entries = self.custom_dictionary.get_all()
        self._custom_vuln_sorted = sorted(
            [(k, v.get('name_zh', k)) for k, v in custom_entries.items() if v.get('name_zh')],
            key=lambda x: len(x[0]),
            reverse=True,
        )
        self._custom_vuln_patterns = [
            (re.compile(r'\b' + re.escape(key) + r'\b', re.IGNORECASE), value)
            for key, value in self._custom_vuln_sorted
        ]

    def export_custom_dictionary(self, file_path: str, format: str = 'json') -> dict:
        """导出自定义翻译字典。

        Args:
            file_path: 导出文件路径。
            format: 导出格式，支持 'json' 或 'csv'。

        Returns:
            导出统计信息字典。
        """
        return self.custom_dictionary.save(file_path, format)
