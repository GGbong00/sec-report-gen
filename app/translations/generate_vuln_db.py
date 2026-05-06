# -*- coding: utf-8 -*-
"""
漏洞描述数据库生成器

基于 CVE 数据模式自动生成 10000 条漏洞描述翻译数据。
通过组合漏洞类型模板 x 产品 x 版本号 x CVE编号，生成大量漏洞条目。

用法:
    python -m app.translations.generate_vuln_db

生成文件:
    app/translations/vuln_db_10000.json
"""

import json
import os
import random
import hashlib

# ============================================================
# 50 种漏洞类型模板
# ============================================================
VULN_TEMPLATES = [
    {
        "type_en": "SQL Injection",
        "type_zh": "SQL注入",
        "desc_template_en": (
            "A SQL injection vulnerability has been identified in {product} version {version}. "
            "The {component} component fails to properly sanitize user-supplied input before using "
            "it in SQL queries. An attacker can exploit this vulnerability to execute arbitrary SQL "
            "commands on the backend database, potentially gaining unauthorized access to sensitive "
            "data, modifying database records, or executing administrative operations. The vulnerability "
            "arises from insufficient input validation and the use of string concatenation in query "
            "construction rather than parameterized queries or prepared statements."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了SQL注入漏洞。{component}组件在将用户输入用于SQL查询之前"
            "未能正确净化。攻击者可以利用此漏洞在后端数据库上执行任意SQL命令，可能未经授权访问敏感数据、"
            "修改数据库记录或执行管理操作。该漏洞源于输入验证不足以及在查询构造中使用字符串拼接而非参数化查询或预编译语句。"
        ),
        "impact_template_en": (
            "Successful exploitation could allow an attacker to bypass authentication, extract sensitive "
            "data from the database including user credentials and personal information, modify or delete "
            "database records, and in some cases execute operating system commands on the database server."
        ),
        "impact_template_zh": (
            "成功利用可能导致攻击者绕过身份验证、从数据库中提取敏感数据（包括用户凭据和个人信息）、"
            "修改或删除数据库记录，在某些情况下还可以在数据库服务器上执行操作系统命令。"
        ),
        "solution_template_en": (
            "Apply vendor-supplied patches or use parameterized queries (prepared statements) for all "
            "database interactions. Implement strict input validation using allow-lists. Deploy a Web "
            "Application Firewall (WAF) with SQL injection detection rules. Apply the principle of least "
            "privilege to database accounts used by the application."
        ),
        "solution_template_zh": (
            "应用供应商提供的补丁或对所有数据库交互使用参数化查询（预编译语句）。实施使用白名单的严格输入验证。"
            "部署具有SQL注入检测规则的Web应用防火墙（WAF）。对应用程序使用的数据库账户应用最小权限原则。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.0, 10.0),
    },
    {
        "type_en": "Cross-Site Scripting (XSS) - Reflected",
        "type_zh": "反射型跨站脚本攻击（XSS）",
        "desc_template_en": (
            "A reflected cross-site scripting (XSS) vulnerability exists in {product} version {version}. "
            "The {component} component does not properly encode user-supplied input before reflecting it "
            "back in HTTP responses. An attacker can craft a malicious URL containing JavaScript code that, "
            "when clicked by a victim, will execute the injected script in the context of the victim's browser "
            "session. This allows the attacker to steal session cookies, redirect users to malicious websites, "
            "or perform actions on behalf of the authenticated user."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在反射型跨站脚本（XSS）漏洞。{component}组件在将用户输入回显到HTTP响应中之前"
            "未正确编码。攻击者可以构造包含JavaScript代码的恶意URL，当受害者点击该链接时，注入的脚本将在受害者的"
            "浏览器会话上下文中执行。这允许攻击者窃取会话Cookie、将用户重定向到恶意网站或代表已认证用户执行操作。"
        ),
        "impact_template_en": (
            "Attackers can hijack user sessions, steal sensitive information, deface web pages, redirect users "
            "to phishing sites, and perform unauthorized actions on behalf of authenticated users."
        ),
        "impact_template_zh": (
            "攻击者可以劫持用户会话、窃取敏感信息、篡改网页内容、将用户重定向到钓鱼网站，"
            "并代表已认证用户执行未经授权的操作。"
        ),
        "solution_template_en": (
            "Implement context-aware output encoding for all user-supplied data. Apply Content Security Policy "
            "(CSP) headers to restrict script execution. Use modern web frameworks that provide automatic XSS "
            "protection. Sanitize and validate all input parameters."
        ),
        "solution_template_zh": (
            "对所有用户提交的数据实施上下文感知的输出编码。应用内容安全策略（CSP）头以限制脚本执行。"
            "使用提供自动XSS防护的现代Web框架。对所有输入参数进行净化和验证。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Cross-Site Scripting (XSS) - Stored",
        "type_zh": "存储型跨站脚本攻击（XSS）",
        "desc_template_en": (
            "A stored cross-site scripting (XSS) vulnerability has been found in {product} version {version}. "
            "The {component} component stores user-supplied input without proper sanitization and later renders "
            "it to other users without encoding. Unlike reflected XSS, stored XSS does not require the victim to "
            "click a specific link; the malicious script is automatically executed when users view the affected page. "
            "This makes stored XSS particularly dangerous as it can affect a large number of users simultaneously."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了存储型跨站脚本（XSS）漏洞。{component}组件存储用户提交的输入时未进行"
            "适当净化，并在后续向其他用户渲染时未进行编码。与反射型XSS不同，存储型XSS不需要受害者点击特定链接；"
            "当用户查看受影响的页面时，恶意脚本会自动执行。这使得存储型XSS特别危险，因为它可以同时影响大量用户。"
        ),
        "impact_template_en": (
            "Stored XSS can lead to mass session hijacking, data theft from multiple users, website defacement, "
            "and the spread of worms within the application. The persistent nature of the attack amplifies its impact."
        ),
        "impact_template_zh": (
            "存储型XSS可导致大规模会话劫持、多个用户的数据窃取、网站篡改，以及蠕虫在应用程序内的传播。"
            "攻击的持久性放大了其影响。"
        ),
        "solution_template_en": (
            "Apply input validation and output encoding for all stored user content. Implement Content Security "
            "Policy (CSP) headers. Use HTML sanitization libraries to clean user-submitted HTML content. "
            "Enforce server-side validation for all user inputs."
        ),
        "solution_template_zh": (
            "对所有存储的用户内容应用输入验证和输出编码。实施内容安全策略（CSP）头。使用HTML净化库清理用户提交的HTML内容。"
            "对所有用户输入强制执行服务端验证。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.5, 9.0),
    },
    {
        "type_en": "Remote Code Execution (RCE)",
        "type_zh": "远程代码执行",
        "desc_template_en": (
            "A critical remote code execution vulnerability exists in {product} version {version}. "
            "The {component} component allows an attacker to execute arbitrary code on the target system "
            "by sending specially crafted requests. The vulnerability is caused by insufficient input validation "
            "and improper handling of user-controlled data in a way that allows code injection. An unauthenticated "
            "remote attacker can exploit this vulnerability to gain complete control over the affected system."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在严重的远程代码执行漏洞。{component}组件允许攻击者通过发送特制请求在目标系统上"
            "执行任意代码。该漏洞由输入验证不足和对用户可控数据的不当处理导致，使得代码注入成为可能。未经身份验证的"
            "远程攻击者可以利用此漏洞完全控制受影响的系统。"
        ),
        "impact_template_en": (
            "Complete system compromise is possible. Attackers can install malware, create backdoors, steal "
            "sensitive data, use the system as a pivot point for further network intrusion, and disrupt "
            "critical services."
        ),
        "impact_template_zh": (
            "系统可能被完全攻陷。攻击者可以安装恶意软件、创建后门、窃取敏感数据、利用系统作为进一步网络入侵的跳板，"
            "并中断关键服务。"
        ),
        "solution_template_en": (
            "Immediately apply the vendor-supplied security patches. Restrict network access to the affected "
            "component using firewall rules. Implement network segmentation to limit the blast radius. "
            "Monitor system logs for signs of exploitation."
        ),
        "solution_template_zh": (
            "立即应用供应商提供的安全补丁。使用防火墙规则限制对受影响组件的网络访问。实施网络分段以限制爆炸半径。"
            "监控系统日志以发现利用迹象。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (8.0, 10.0),
    },
    {
        "type_en": "Buffer Overflow",
        "type_zh": "缓冲区溢出",
        "desc_template_en": (
            "A buffer overflow vulnerability has been discovered in {product} version {version}. "
            "The {component} component does not properly validate the length of input data before copying "
            "it into a fixed-size buffer. An attacker can exploit this vulnerability by sending oversized input "
            "that overflows the buffer, potentially overwriting adjacent memory, corrupting program execution "
            "flow, and executing arbitrary code with the privileges of the vulnerable process."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了缓冲区溢出漏洞。{component}组件在将输入数据复制到固定大小的缓冲区之前"
            "未正确验证输入数据的长度。攻击者可以通过发送超大的输入来利用此漏洞，溢出缓冲区，可能覆盖相邻内存、"
            "破坏程序执行流程，并以存在漏洞的进程的权限执行任意代码。"
        ),
        "impact_template_en": (
            "Buffer overflow can lead to denial of service, arbitrary code execution, privilege escalation, "
            "and complete system compromise depending on the context of the vulnerability."
        ),
        "impact_template_zh": (
            "缓冲区溢出可导致拒绝服务、任意代码执行、权限提升，根据漏洞的具体上下文，还可能导致系统被完全攻陷。"
        ),
        "solution_template_en": (
            "Apply vendor patches to fix the buffer overflow. Implement bounds checking for all buffer operations. "
            "Use secure coding practices such as safe string handling functions. Enable compiler-level protections "
            "like stack canaries and ASLR."
        ),
        "solution_template_zh": (
            "应用供应商补丁修复缓冲区溢出。对所有缓冲区操作实施边界检查。使用安全编码实践，如安全的字符串处理函数。"
            "启用编译器级别的保护机制，如堆栈金丝雀和ASLR。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.5, 10.0),
    },
    {
        "type_en": "Privilege Escalation",
        "type_zh": "权限提升",
        "desc_template_en": (
            "A privilege escalation vulnerability exists in {product} version {version}. "
            "The {component} component improperly checks access controls, allowing a low-privileged user "
            "to gain elevated privileges. The vulnerability may be exploited by manipulating certain function "
            "calls or by exploiting race conditions in the permission verification process. A successful attack "
            "could allow an attacker to perform actions that are normally restricted to administrators."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在权限提升漏洞。{component}组件未正确检查访问控制，允许低权限用户获得提升的权限。"
            "该漏洞可能通过操纵某些函数调用或利用权限验证过程中的竞态条件来利用。成功的攻击可能允许攻击者执行通常"
            "仅限于管理员才能执行的操作。"
        ),
        "impact_template_en": (
            "An attacker with limited privileges can gain administrative access, allowing them to modify system "
            "configurations, access restricted data, install malicious software, and compromise other user accounts."
        ),
        "impact_template_zh": (
            "具有有限权限的攻击者可以获得管理员访问权限，从而修改系统配置、访问受限数据、安装恶意软件，"
            "并危及其他用户账户的安全。"
        ),
        "solution_template_en": (
            "Apply the latest security patches from the vendor. Implement proper access control checks throughout "
            "the application. Follow the principle of least privilege for all user accounts and service accounts. "
            "Audit permission assignments regularly."
        ),
        "solution_template_zh": (
            "应用供应商的最新安全补丁。在整个应用程序中实施适当的访问控制检查。对所有用户账户和服务账户遵循最小权限原则。"
            "定期审计权限分配。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.5, 8.5),
    },
    {
        "type_en": "Path Traversal",
        "type_zh": "路径穿越",
        "desc_template_en": (
            "A path traversal (directory traversal) vulnerability has been identified in {product} version {version}. "
            "The {component} component does not properly sanitize file path input, allowing an attacker to use "
            "directory traversal sequences (such as ../) to access files outside the intended directory. An attacker "
            "can exploit this vulnerability to read sensitive configuration files, source code, credentials, and "
            "other files on the server filesystem."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了路径穿越（目录穿越）漏洞。{component}组件未正确净化文件路径输入，"
            "允许攻击者使用目录穿越序列（如../）访问预期目录之外的文件。攻击者可以利用此漏洞读取敏感的配置文件、"
            "源代码、凭据以及服务器文件系统上的其他文件。"
        ),
        "impact_template_en": (
            "Attackers can read arbitrary files on the server, potentially exposing credentials, configuration "
            "data, and application source code. In some cases, the vulnerability may also allow file writing "
            "or deletion."
        ),
        "impact_template_zh": (
            "攻击者可以读取服务器上的任意文件，可能暴露凭据、配置数据和应用程序源代码。在某些情况下，"
            "该漏洞还可能允许文件写入或删除。"
        ),
        "solution_template_en": (
            "Apply vendor patches. Validate and canonicalize all file paths before use. Use chroot jails or "
            "restrict file access to specific directories. Implement allow-lists for permitted file paths. "
            "Avoid passing user input directly to file system operations."
        ),
        "solution_template_zh": (
            "应用供应商补丁。在使用前验证和规范化所有文件路径。使用chroot监狱或将文件访问限制在特定目录。"
            "对允许的文件路径实施白名单。避免将用户输入直接传递给文件系统操作。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.0),
    },
    {
        "type_en": "Server-Side Request Forgery (SSRF)",
        "type_zh": "服务端请求伪造",
        "desc_template_en": (
            "A server-side request forgery (SSRF) vulnerability exists in {product} version {version}. "
            "The {component} component allows an attacker to induce the server to make HTTP requests to "
            "arbitrary URLs, including internal network addresses. By manipulating request parameters, an "
            "attacker can force the server to access internal services, cloud metadata endpoints, and other "
            "resources that are not intended to be publicly accessible."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在服务端请求伪造（SSRF）漏洞。{component}组件允许攻击者诱导服务器向任意URL"
            "发起HTTP请求，包括内部网络地址。通过操纵请求参数，攻击者可以强制服务器访问内部服务、云元数据端点"
            "以及其他不应对外公开的资源。"
        ),
        "impact_template_en": (
            "SSRF can be used to scan internal networks, access cloud metadata services (e.g., AWS IMDS), "
            "bypass firewalls, and potentially execute code on internal services. In cloud environments, "
            "SSRF can lead to credential theft and full cloud account compromise."
        ),
        "impact_template_zh": (
            "SSRF可用于扫描内部网络、访问云元数据服务（如AWS IMDS）、绕过防火墙，并可能在内部服务上执行代码。"
            "在云环境中，SSRF可导致凭据窃取和完整的云账户被攻陷。"
        ),
        "solution_template_en": (
            "Validate and restrict all URLs that the server is allowed to request. Implement allow-lists for "
            "permitted domains and IP ranges. Block requests to internal IP addresses and cloud metadata endpoints. "
            "Use network-level controls to restrict outbound connections."
        ),
        "solution_template_zh": (
            "验证并限制服务器允许请求的所有URL。对允许的域名和IP范围实施白名单。阻止对内部IP地址和云元数据端点的请求。"
            "使用网络级别的控制来限制出站连接。"
        ),
        "severity_range": ("medium", "critical"),
        "cvss_range": (5.0, 10.0),
    },
    {
        "type_en": "Insecure Deserialization",
        "type_zh": "不安全的反序列化",
        "desc_template_en": (
            "An insecure deserialization vulnerability has been found in {product} version {version}. "
            "The {component} component deserializes untrusted data without proper validation, allowing an "
            "attacker to manipulate serialized objects to execute arbitrary code. The vulnerability can be "
            "exploited by sending crafted serialized objects that trigger gadget chains, leading to remote "
            "code execution with the privileges of the application."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了不安全的反序列化漏洞。{component}组件在未进行适当验证的情况下反序列化"
            "不受信任的数据，允许攻击者操纵序列化对象以执行任意代码。该漏洞可以通过发送精心构造的序列化对象来利用，"
            "触发Gadget Chain，以应用程序的权限实现远程代码执行。"
        ),
        "impact_template_en": (
            "Insecure deserialization can lead to remote code execution, authentication bypass, privilege "
            "escalation, and complete application compromise. The attack is particularly dangerous as it "
            "may bypass existing security controls."
        ),
        "impact_template_zh": (
            "不安全的反序列化可导致远程代码执行、身份验证绕过、权限提升和应用程序被完全攻陷。该攻击特别危险，"
            "因为它可能绕过现有的安全控制。"
        ),
        "solution_template_en": (
            "Avoid deserializing untrusted data. Use data formats like JSON instead of native serialization. "
            "Implement type checking and integrity validation for serialized data. Use serialization allow-lists "
            "to restrict which classes can be deserialized."
        ),
        "solution_template_zh": (
            "避免反序列化不受信任的数据。使用JSON等数据格式替代原生序列化。对序列化数据实施类型检查和完整性验证。"
            "使用序列化白名单限制可以反序列化的类。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.5, 10.0),
    },
    {
        "type_en": "XML External Entity (XXE) Injection",
        "type_zh": "XML外部实体注入",
        "desc_template_en": (
            "An XML External Entity (XXE) injection vulnerability exists in {product} version {version}. "
            "The {component} component parses XML input without disabling external entity processing. "
            "An attacker can exploit this vulnerability by including malicious XML entities that reference "
            "external resources, allowing them to read arbitrary files from the server filesystem, perform "
            "server-side request forgery, or cause denial of service through entity expansion attacks."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在XML外部实体（XXE）注入漏洞。{component}组件在解析XML输入时未禁用外部实体处理。"
            "攻击者可以通过包含引用外部资源的恶意XML实体来利用此漏洞，允许他们从服务器文件系统读取任意文件、"
            "执行服务端请求伪造，或通过实体扩展攻击导致拒绝服务。"
        ),
        "impact_template_en": (
            "XXE injection can lead to sensitive file disclosure, internal network scanning via SSRF, denial "
            "of service through billion laughs attack, and in some cases remote code execution."
        ),
        "impact_template_zh": (
            "XXE注入可导致敏感文件泄露、通过SSRF进行内部网络扫描、通过Billion Laughs攻击导致拒绝服务，"
            "在某些情况下还可导致远程代码执行。"
        ),
        "solution_template_en": (
            "Disable external entity processing in all XML parsers. Use JSON or other data formats instead of "
            "XML when possible. Configure XML parsers to limit entity expansion and disable DTD processing. "
            "Implement input validation for XML content."
        ),
        "solution_template_zh": (
            "在所有XML解析器中禁用外部实体处理。尽可能使用JSON或其他数据格式替代XML。配置XML解析器以限制实体扩展"
            "并禁用DTD处理。对XML内容实施输入验证。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 9.0),
    },
    {
        "type_en": "Cross-Site Request Forgery (CSRF)",
        "type_zh": "跨站请求伪造",
        "desc_template_en": (
            "A cross-site request forgery (CSRF) vulnerability has been identified in {product} version {version}. "
            "The {component} component does not properly verify the origin of HTTP requests, allowing an attacker "
            "to trick an authenticated user into executing unwanted actions. By crafting a malicious web page that "
            "submits requests to the vulnerable application, an attacker can perform actions on behalf of the victim "
            "without their knowledge or consent."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了跨站请求伪造（CSRF）漏洞。{component}组件未正确验证HTTP请求的来源，"
            "允许攻击者欺骗已认证的用户执行非预期的操作。通过构造一个向存在漏洞的应用程序提交请求的恶意网页，"
            "攻击者可以在受害者不知情或不同意的情况下代表受害者执行操作。"
        ),
        "impact_template_en": (
            "CSRF can be exploited to perform unauthorized actions such as changing account settings, transferring "
            "funds, modifying data, or administering the application on behalf of the victim."
        ),
        "impact_template_zh": (
            "CSRF可被利用来执行未经授权的操作，如更改账户设置、转移资金、修改数据或代表受害者管理应用程序。"
        ),
        "solution_template_en": (
            "Implement anti-CSRF tokens for all state-changing requests. Verify the Origin and Referer headers. "
            "Use SameSite cookie attribute. Require re-authentication for sensitive operations."
        ),
        "solution_template_zh": (
            "对所有状态更改请求实施反CSRF令牌。验证Origin和Referer头。使用SameSite Cookie属性。"
            "对敏感操作要求重新身份验证。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "Authentication Bypass",
        "type_zh": "身份验证绕过",
        "desc_template_en": (
            "An authentication bypass vulnerability exists in {product} version {version}. "
            "The {component} component does not properly verify user credentials or session tokens, "
            "allowing an attacker to access protected resources without valid authentication. The vulnerability "
            "may be caused by improper session management, weak token validation, or logic errors in the "
            "authentication flow."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在身份验证绕过漏洞。{component}组件未正确验证用户凭据或会话令牌，"
            "允许攻击者在没有有效身份验证的情况下访问受保护的资源。该漏洞可能由不当的会话管理、"
            "弱令牌验证或身份验证流程中的逻辑错误引起。"
        ),
        "impact_template_en": (
            "Attackers can gain unauthorized access to protected resources and functionality, potentially "
            "accessing sensitive data, modifying system configurations, and performing administrative actions."
        ),
        "impact_template_zh": (
            "攻击者可以未经授权访问受保护的资源和功能，可能访问敏感数据、修改系统配置并执行管理操作。"
        ),
        "solution_template_en": (
            "Apply vendor patches to fix the authentication logic. Implement multi-factor authentication. "
            "Use secure session management practices. Regularly audit authentication mechanisms for logic flaws."
        ),
        "solution_template_zh": (
            "应用供应商补丁修复身份验证逻辑。实施多因素身份验证。使用安全的会话管理实践。"
            "定期审计身份验证机制是否存在逻辑缺陷。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.0, 10.0),
    },
    {
        "type_en": "Denial of Service (DoS)",
        "type_zh": "拒绝服务",
        "desc_template_en": (
            "A denial of service (DoS) vulnerability has been found in {product} version {version}. "
            "The {component} component does not properly handle certain input conditions, allowing an "
            "attacker to consume excessive system resources or cause the application to crash. By sending "
            "specially crafted requests, an attacker can render the service unavailable to legitimate users."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了拒绝服务（DoS）漏洞。{component}组件未正确处理某些输入条件，"
            "允许攻击者消耗过多的系统资源或导致应用程序崩溃。通过发送特制请求，攻击者可以使服务对合法用户不可用。"
        ),
        "impact_template_en": (
            "Service disruption leading to loss of availability for legitimate users. In critical systems, "
            "this can result in significant business impact, financial losses, and safety concerns."
        ),
        "impact_template_zh": (
            "服务中断导致合法用户无法使用。在关键系统中，这可能导致重大的业务影响、经济损失和安全问题。"
        ),
        "solution_template_en": (
            "Apply vendor patches. Implement rate limiting and request throttling. Use resource quotas and "
            "timeouts for processing requests. Deploy load balancers and DDoS protection services."
        ),
        "solution_template_zh": (
            "应用供应商补丁。实施速率限制和请求节流。对请求处理使用资源配额和超时设置。"
            "部署负载均衡器和DDoS防护服务。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.0),
    },
    {
        "type_en": "Information Disclosure",
        "type_zh": "信息泄露",
        "desc_template_en": (
            "An information disclosure vulnerability exists in {product} version {version}. "
            "The {component} component exposes sensitive information through error messages, debug interfaces, "
            "or improper access controls. An attacker can exploit this vulnerability to obtain sensitive data "
            "such as internal IP addresses, software versions, configuration details, user information, or "
            "cryptographic keys that can be used to facilitate further attacks."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在信息泄露漏洞。{component}组件通过错误消息、调试接口或不当的访问控制"
            "暴露敏感信息。攻击者可以利用此漏洞获取敏感数据，如内部IP地址、软件版本、配置详情、用户信息或"
            "加密密钥，这些信息可用于协助进一步的攻击。"
        ),
        "impact_template_en": (
            "Exposed information can be used for reconnaissance, planning targeted attacks, and exploiting "
            "other vulnerabilities. Credential and key exposure can lead to direct system compromise."
        ),
        "impact_template_zh": (
            "暴露的信息可用于侦察、规划定向攻击和利用其他漏洞。凭据和密钥的暴露可直接导致系统被攻陷。"
        ),
        "solution_template_en": (
            "Disable debug modes in production environments. Implement proper error handling that does not "
            "expose internal details. Restrict access to sensitive endpoints and configuration interfaces. "
            "Review and remove unnecessary information from HTTP response headers."
        ),
        "solution_template_zh": (
            "在生产环境中禁用调试模式。实施不暴露内部细节的正确错误处理。限制对敏感端点和配置接口的访问。"
            "审查并移除HTTP响应头中不必要的信息。"
        ),
        "severity_range": ("low", "high"),
        "cvss_range": (3.0, 8.0),
    },
    {
        "type_en": "Command Injection",
        "type_zh": "命令注入",
        "desc_template_en": (
            "A command injection vulnerability has been identified in {product} version {version}. "
            "The {component} component passes user-supplied input to system commands without proper "
            "sanitization. An attacker can inject arbitrary operating system commands that will be executed "
            "with the privileges of the application process. This vulnerability allows complete system "
            "compromise when the application runs with elevated privileges."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了命令注入漏洞。{component}组件将用户提交的输入传递给系统命令时"
            "未进行适当净化。攻击者可以注入任意的操作系统命令，这些命令将以应用程序进程的权限执行。"
            "当应用程序以提升的权限运行时，此漏洞可导致系统被完全攻陷。"
        ),
        "impact_template_en": (
            "Arbitrary command execution with application privileges, potentially leading to full system "
            "compromise, data theft, and lateral movement within the network."
        ),
        "impact_template_zh": (
            "以应用程序权限执行任意命令，可能导致系统被完全攻陷、数据窃取和网络内的横向移动。"
        ),
        "solution_template_en": (
            "Avoid passing user input to system commands. Use language-native APIs instead of shell commands. "
            "If shell commands are necessary, use strict input validation and parameterized execution. "
            "Apply the principle of least privilege to the application process."
        ),
        "solution_template_zh": (
            "避免将用户输入传递给系统命令。使用语言原生API替代Shell命令。如果必须使用Shell命令，"
            "使用严格的输入验证和参数化执行。对应用程序进程应用最小权限原则。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (8.0, 10.0),
    },
    {
        "type_en": "LDAP Injection",
        "type_zh": "LDAP注入",
        "desc_template_en": (
            "An LDAP injection vulnerability exists in {product} version {version}. "
            "The {component} component constructs LDAP queries using user-supplied input without proper "
            "sanitization. An attacker can modify the structure of LDAP queries to bypass authentication, "
            "extract unauthorized information from the directory, or modify directory entries."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在LDAP注入漏洞。{component}组件使用用户提交的输入构造LDAP查询时"
            "未进行适当净化。攻击者可以修改LDAP查询的结构以绕过身份验证、从目录中提取未经授权的信息或修改目录条目。"
        ),
        "impact_template_en": (
            "Authentication bypass, unauthorized access to directory information, modification of directory "
            "entries, and potential privilege escalation within the organization's identity management system."
        ),
        "impact_template_zh": (
            "身份验证绕过、对目录信息的未经授权访问、目录条目修改，以及在组织身份管理系统内的潜在权限提升。"
        ),
        "solution_template_en": (
            "Use parameterized LDAP queries. Validate and sanitize all user input before using it in LDAP "
            "queries. Implement input allow-lists. Use LDAP escape functions for special characters."
        ),
        "solution_template_zh": (
            "使用参数化LDAP查询。在使用用户输入构造LDAP查询之前进行验证和净化。实施输入白名单。"
            "对特殊字符使用LDAP转义函数。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Broken Access Control",
        "type_zh": "访问控制失效",
        "desc_template_en": (
            "A broken access control vulnerability has been found in {product} version {version}. "
            "The {component} component does not properly enforce authorization checks, allowing users "
            "to access resources or perform actions that are beyond their assigned privileges. This includes "
            "both vertical privilege escalation (accessing admin functions as a regular user) and horizontal "
            "privilege escalation (accessing other users' data)."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了访问控制失效漏洞。{component}组件未正确执行授权检查，"
            "允许用户访问超出其分配权限的资源或执行超出其权限的操作。这包括垂直权限提升（普通用户访问管理员功能）"
            "和水平权限提升（访问其他用户的数据）。"
        ),
        "impact_template_en": (
            "Unauthorized access to sensitive data, administrative functions, and system configurations. "
            "Attackers can view, modify, or delete other users' data and gain elevated privileges."
        ),
        "impact_template_zh": (
            "对敏感数据、管理功能和系统配置的未经授权访问。攻击者可以查看、修改或删除其他用户的数据并获得提升的权限。"
        ),
        "solution_template_en": (
            "Implement proper access control checks on every request. Deny access by default and use "
            "allow-lists for authorized actions. Use role-based access control (RBAC). Regularly test "
            "access control mechanisms for bypass vulnerabilities."
        ),
        "solution_template_zh": (
            "在每个请求上实施适当的访问控制检查。默认拒绝访问，对授权操作使用白名单。使用基于角色的访问控制（RBAC）。"
            "定期测试访问控制机制是否存在绕过漏洞。"
        ),
        "severity_range": ("medium", "critical"),
        "cvss_range": (5.0, 10.0),
    },
    {
        "type_en": "Insecure Direct Object Reference (IDOR)",
        "type_zh": "不安全的直接对象引用",
        "desc_template_en": (
            "An insecure direct object reference (IDOR) vulnerability exists in {product} version {version}. "
            "The {component} component exposes internal implementation objects (such as database IDs or file "
            "names) directly to users without proper authorization checks. An attacker can manipulate these "
            "references to access other users' data or perform unauthorized actions by simply changing the "
            "object identifier in the request."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在不安全的直接对象引用（IDOR）漏洞。{component}组件将内部实现对象"
            "（如数据库ID或文件名）直接暴露给用户，而未进行适当的授权检查。攻击者可以通过简单地更改请求中的"
            "对象标识符来操纵这些引用，从而访问其他用户的数据或执行未经授权的操作。"
        ),
        "impact_template_en": (
            "Unauthorized access to other users' data, ability to modify or delete resources belonging to "
            "other users, and potential privilege escalation."
        ),
        "impact_template_zh": (
            "未经授权访问其他用户的数据、修改或删除属于其他用户的资源的能力，以及潜在的权限提升。"
        ),
        "solution_template_en": (
            "Implement proper authorization checks for every object access. Use indirect references instead "
            "of exposing internal identifiers. Verify that the current user has permission to access the "
            "requested resource before serving the request."
        ),
        "solution_template_zh": (
            "对每个对象访问实施适当的授权检查。使用间接引用替代暴露内部标识符。在处理请求之前验证当前用户"
            "是否有权限访问请求的资源。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "Security Misconfiguration",
        "type_zh": "安全配置错误",
        "desc_template_en": (
            "A security misconfiguration has been identified in {product} version {version}. "
            "The {component} component is deployed with insecure default settings, unnecessary features "
            "enabled, or overly permissive access controls. Common misconfigurations include default "
            "credentials, open cloud storage, unnecessary services, verbose error messages, and missing "
            "security headers."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了安全配置错误。{component}组件部署时使用了不安全的默认设置、"
            "启用了不必要的功能或过于宽松的访问控制。常见的配置错误包括默认凭据、开放的云存储、不必要的服务、"
            "详细的错误消息和缺少安全头。"
        ),
        "impact_template_en": (
            "Security misconfigurations can expose sensitive data, provide attack surfaces for exploitation, "
            "and allow unauthorized access to system resources and administrative functions."
        ),
        "impact_template_zh": (
            "安全配置错误可能暴露敏感数据、提供可被利用的攻击面，并允许未经授权访问系统资源和管理功能。"
        ),
        "solution_template_en": (
            "Review and harden all configuration settings. Disable unnecessary features and services. "
            "Change all default credentials. Implement security headers and proper error handling. "
            "Automate configuration management to prevent drift from secure baselines."
        ),
        "solution_template_zh": (
            "审查并加固所有配置设置。禁用不必要的功能和服务。更改所有默认凭据。实施安全头和正确的错误处理。"
            "自动化配置管理以防止偏离安全基线。"
        ),
        "severity_range": ("low", "high"),
        "cvss_range": (3.0, 8.5),
    },
    {
        "type_en": "Cryptographic Failure",
        "type_zh": "加密失败",
        "desc_template_en": (
            "A cryptographic failure vulnerability has been found in {product} version {version}. "
            "The {component} component uses weak or deprecated cryptographic algorithms, improper key "
            "management, or insufficient encryption strength. This can allow attackers to decrypt sensitive "
            "data, forge digital signatures, or tamper with encrypted communications."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了加密失败漏洞。{component}组件使用了弱或已弃用的加密算法、"
            "不当的密钥管理或不足的加密强度。这可能允许攻击者解密敏感数据、伪造数字签名或篡改加密通信。"
        ),
        "impact_template_en": (
            "Exposure of sensitive data through weak encryption, ability to forge signatures or certificates, "
            "and potential compromise of encrypted communications."
        ),
        "impact_template_zh": (
            "通过弱加密暴露敏感数据、伪造签名或证书的能力，以及加密通信可能被攻陷。"
        ),
        "solution_template_en": (
            "Upgrade to strong, modern cryptographic algorithms (AES-256, RSA-2048+, TLS 1.2+). Implement "
            "proper key management practices. Use established cryptographic libraries. Regularly review "
            "and update cryptographic implementations."
        ),
        "solution_template_zh": (
            "升级到强健的现代加密算法（AES-256、RSA-2048+、TLS 1.2+）。实施适当的密钥管理实践。"
            "使用成熟的加密库。定期审查和更新加密实现。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.0, 9.0),
    },
    {
        "type_en": "Open Redirect",
        "type_zh": "开放重定向",
        "desc_template_en": (
            "An open redirect vulnerability exists in {product} version {version}. "
            "The {component} component accepts user-supplied URLs for redirection without proper validation. "
            "An attacker can craft a legitimate-looking URL that redirects victims to malicious websites, "
            "facilitating phishing attacks, credential theft, and social engineering campaigns."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在开放重定向漏洞。{component}组件接受用户提交的URL进行重定向，"
            "而未进行适当验证。攻击者可以构造一个看起来合法的URL，将受害者重定向到恶意网站，"
            "从而协助钓鱼攻击、凭据窃取和社会工程活动。"
        ),
        "impact_template_en": (
            "Open redirects facilitate phishing attacks, credential theft, malware distribution, and can "
            "undermine user trust in the application."
        ),
        "impact_template_zh": (
            "开放重定向可协助钓鱼攻击、凭据窃取、恶意软件分发，并可能损害用户对应用程序的信任。"
        ),
        "solution_template_en": (
            "Validate all redirect URLs against an allow-list of trusted domains. Use relative paths for "
            "internal redirects. Avoid passing user input directly to redirect functions."
        ),
        "solution_template_zh": (
            "根据受信任域名的白名单验证所有重定向URL。对内部重定向使用相对路径。避免将用户输入直接传递给重定向函数。"
        ),
        "severity_range": ("low", "medium"),
        "cvss_range": (3.0, 6.0),
    },
    {
        "type_en": "File Upload Vulnerability",
        "type_zh": "文件上传漏洞",
        "desc_template_en": (
            "A file upload vulnerability has been identified in {product} version {version}. "
            "The {component} component allows users to upload files without proper type validation "
            "or content inspection. An attacker can upload malicious files such as web shells, executables, "
            "or scripts that can be executed on the server, leading to remote code execution or other "
            "security compromises."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了文件上传漏洞。{component}组件允许用户上传文件，而未进行适当的"
            "类型验证或内容检查。攻击者可以上传恶意文件，如Web Shell、可执行文件或脚本，这些文件可以在服务器上"
            "执行，导致远程代码执行或其他安全违规。"
        ),
        "impact_template_en": (
            "Remote code execution through uploaded web shells, malware distribution, storage exhaustion, "
            "and potential full system compromise."
        ),
        "impact_template_zh": (
            "通过上传的Web Shell实现远程代码执行、恶意软件分发、存储耗尽，以及潜在的完全系统攻陷。"
        ),
        "solution_template_en": (
            "Implement strict file type validation based on content (not just extension). Restrict upload "
            "directory permissions. Use random file names for uploaded files. Store uploads outside the "
            "web root. Scan uploaded files with antivirus software."
        ),
        "solution_template_zh": (
            "基于内容（而非仅扩展名）实施严格的文件类型验证。限制上传目录权限。对上传的文件使用随机文件名。"
            "将上传文件存储在Web根目录之外。使用杀毒软件扫描上传的文件。"
        ),
        "severity_range": ("medium", "critical"),
        "cvss_range": (5.0, 10.0),
    },
    {
        "type_en": "Race Condition",
        "type_zh": "竞态条件",
        "desc_template_en": (
            "A race condition vulnerability exists in {product} version {version}. "
            "The {component} component performs security-critical operations in a non-atomic manner, "
            "allowing an attacker to exploit timing windows between operations to bypass security checks "
            "or corrupt data. By carefully timing concurrent requests, an attacker can manipulate the "
            "application state in unintended ways."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在竞态条件漏洞。{component}组件以非原子方式执行安全关键操作，"
            "允许攻击者利用操作之间的时间窗口绕过安全检查或破坏数据。通过精心安排并发请求的时序，"
            "攻击者可以以非预期的方式操纵应用程序状态。"
        ),
        "impact_template_en": (
            "Race conditions can lead to privilege escalation, authentication bypass, data corruption, "
            "and financial exploitation in transactional systems."
        ),
        "impact_template_zh": (
            "竞态条件可导致权限提升、身份验证绕过、数据损坏，以及在事务系统中被金融利用。"
        ),
        "solution_template_en": (
            "Use atomic operations and proper locking mechanisms for security-critical code paths. "
            "Implement synchronization primitives. Avoid time-of-check to time-of-use (TOCTOU) vulnerabilities. "
            "Use database transactions where appropriate."
        ),
        "solution_template_zh": (
            "对安全关键代码路径使用原子操作和适当的锁定机制。实施同步原语。避免检查时间到使用时间（TOCTOU）漏洞。"
            "在适当的地方使用数据库事务。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.5),
    },
    {
        "type_en": "Template Injection",
        "type_zh": "模板注入",
        "desc_template_en": (
            "A server-side template injection (SSTI) vulnerability has been found in {product} version {version}. "
            "The {component} component embeds user-supplied input directly into template expressions without "
            "proper sanitization. An attacker can inject template code that is executed on the server, "
            "potentially gaining access to the underlying system and executing arbitrary commands."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了服务端模板注入（SSTI）漏洞。{component}组件将用户提交的输入"
            "直接嵌入到模板表达式中，而未进行适当净化。攻击者可以注入在服务器上执行的模板代码，"
            "可能获得对底层系统的访问并执行任意命令。"
        ),
        "impact_template_en": (
            "Server-side template injection can lead to remote code execution, data extraction from the "
            "server, and full system compromise depending on the template engine capabilities."
        ),
        "impact_template_zh": (
            "服务端模板注入可导致远程代码执行、从服务器提取数据，以及根据模板引擎的能力实现完全系统攻陷。"
        ),
        "solution_template_en": (
            "Never pass user input directly to template engines. Use parameterized templates with explicit "
            "variable binding. Implement sandbox mode for template engines when available. Validate and "
            "sanitize all user input before template processing."
        ),
        "solution_template_zh": (
            "切勿将用户输入直接传递给模板引擎。使用带有显式变量绑定的参数化模板。在可用时为模板引擎启用沙箱模式。"
            "在模板处理之前验证和净化所有用户输入。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.5, 10.0),
    },
    {
        "type_en": "HTTP Response Splitting",
        "type_zh": "HTTP响应拆分",
        "desc_template_en": (
            "An HTTP response splitting vulnerability exists in {product} version {version}. "
            "The {component} component embeds user-supplied data into HTTP response headers without "
            "proper sanitization. An attacker can inject CR and LF characters to split the HTTP response, "
            "enabling various attacks including response injection, cross-site scripting, and cache poisoning."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在HTTP响应拆分漏洞。{component}组件将用户提交的数据嵌入到HTTP响应头中，"
            "而未进行适当净化。攻击者可以注入CR和LF字符来拆分HTTP响应，从而实现各种攻击，包括响应注入、"
            "跨站脚本攻击和缓存中毒。"
        ),
        "impact_template_en": (
            "HTTP response splitting can lead to XSS, cache poisoning, session hijacking, and response "
            "injection attacks."
        ),
        "impact_template_zh": (
            "HTTP响应拆分可导致XSS、缓存中毒、会话劫持和响应注入攻击。"
        ),
        "solution_template_en": (
            "Validate and sanitize all user input before including it in HTTP headers. Reject any input "
            "containing CR or LF characters. Use modern web frameworks that automatically encode header values."
        ),
        "solution_template_zh": (
            "在将用户输入包含在HTTP头中之前进行验证和净化。拒绝任何包含CR或LF字符的输入。"
            "使用自动编码头值的现代Web框架。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "CORS Misconfiguration",
        "type_zh": "CORS配置错误",
        "desc_template_en": (
            "A CORS (Cross-Origin Resource Sharing) misconfiguration has been identified in {product} version {version}. "
            "The {component} component returns overly permissive Access-Control-Allow-Origin headers, potentially "
            "allowing any origin to access sensitive resources. This misconfiguration can be exploited by malicious "
            "websites to make cross-origin requests and read sensitive data from the application."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了CORS（跨源资源共享）配置错误。{component}组件返回过于宽松的"
            "Access-Control-Allow-Origin头，可能允许任何来源访问敏感资源。此配置错误可被恶意网站利用，"
            "发起跨源请求并读取应用程序中的敏感数据。"
        ),
        "impact_template_en": (
            "Malicious websites can access sensitive data through cross-origin requests, potentially leading "
            "to data theft and unauthorized actions performed on behalf of authenticated users."
        ),
        "impact_template_zh": (
            "恶意网站可以通过跨源请求访问敏感数据，可能导致数据窃取和代表已认证用户执行未经授权的操作。"
        ),
        "solution_template_en": (
            "Configure CORS to allow only specific trusted origins. Avoid using wildcard (*) in production. "
            "Do not reflect the Origin header in the Access-Control-Allow-Origin response header. "
            "Implement proper credential handling for cross-origin requests."
        ),
        "solution_template_zh": (
            "配置CORS仅允许特定的受信任来源。避免在生产环境中使用通配符(*)。不要在Access-Control-Allow-Origin"
            "响应头中反射Origin头。为跨源请求实施适当的凭据处理。"
        ),
        "severity_range": ("low", "medium"),
        "cvss_range": (3.0, 6.5),
    },
    {
        "type_en": "Expression Language Injection",
        "type_zh": "表达式语言注入",
        "desc_template_en": (
            "An expression language injection vulnerability exists in {product} version {version}. "
            "The {component} component evaluates user-supplied expressions without proper restrictions, "
            "allowing an attacker to execute arbitrary code or access sensitive system information through "
            "expression language constructs. The injected expressions can manipulate application objects, "
            "access system properties, and execute operating system commands."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在表达式语言注入漏洞。{component}组件在未进行适当限制的情况下评估"
            "用户提交的表达式，允许攻击者通过表达式语言构造执行任意代码或访问敏感的系统信息。注入的表达式"
            "可以操纵应用程序对象、访问系统属性并执行操作系统命令。"
        ),
        "impact_template_en": (
            "Arbitrary code execution, access to application internals, system information disclosure, "
            "and potential full system compromise."
        ),
        "impact_template_zh": (
            "任意代码执行、访问应用程序内部、系统信息泄露，以及潜在的完全系统攻陷。"
        ),
        "solution_template_en": (
            "Disable or restrict expression language evaluation for user input. Use sandbox environments "
            "for expression evaluation. Implement input validation to reject expression language syntax. "
            "Apply the latest security patches from the vendor."
        ),
        "solution_template_zh": (
            "对用户输入禁用或限制表达式语言评估。使用沙箱环境进行表达式评估。实施输入验证以拒绝表达式语言语法。"
            "应用供应商的最新安全补丁。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.5, 10.0),
    },
    {
        "type_en": "Integer Overflow",
        "type_zh": "整数溢出",
        "desc_template_en": (
            "An integer overflow vulnerability has been discovered in {product} version {version}. "
            "The {component} component performs arithmetic operations on integer values without proper "
            "bounds checking. An attacker can exploit this vulnerability by providing values that cause "
            "integer overflow or underflow, leading to unexpected behavior, memory corruption, or "
            "potentially arbitrary code execution."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了整数溢出漏洞。{component}组件对整数值执行算术运算时未进行"
            "适当的边界检查。攻击者可以通过提供导致整数溢出或下溢的值来利用此漏洞，导致意外行为、"
            "内存损坏或潜在的任意代码执行。"
        ),
        "impact_template_en": (
            "Integer overflow can lead to buffer overflow, memory corruption, denial of service, and "
            "in some cases arbitrary code execution."
        ),
        "impact_template_zh": (
            "整数溢出可导致缓冲区溢出、内存损坏、拒绝服务，在某些情况下还可导致任意代码执行。"
        ),
        "solution_template_en": (
            "Apply vendor patches. Use safe integer arithmetic libraries. Implement bounds checking for "
            "all arithmetic operations. Use larger integer types where overflow is possible."
        ),
        "solution_template_zh": (
            "应用供应商补丁。使用安全的整数算术库。对所有算术运算实施边界检查。在可能发生溢出的地方使用更大的整数类型。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Null Pointer Dereference",
        "type_zh": "空指针解引用",
        "desc_template_en": (
            "A null pointer dereference vulnerability exists in {product} version {version}. "
            "The {component} component does not properly check for null values before dereferencing "
            "pointers. An attacker can trigger this vulnerability by providing input that causes a null "
            "pointer to be dereferenced, leading to application crash or, in some cases, arbitrary code "
            "execution."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在空指针解引用漏洞。{component}组件在解引用指针之前未正确检查空值。"
            "攻击者可以通过提供导致空指针被解引用的输入来触发此漏洞，导致应用程序崩溃，在某些情况下"
            "还可导致任意代码执行。"
        ),
        "impact_template_en": (
            "Application crash leading to denial of service. In rare cases, null pointer dereference "
            "can be exploited for arbitrary code execution."
        ),
        "impact_template_zh": (
            "应用程序崩溃导致拒绝服务。在极少数情况下，空指针解引用可被利用来实现任意代码执行。"
        ),
        "solution_template_en": (
            "Apply vendor patches. Implement null checks before dereferencing pointers. Use optional "
            "types or nullable wrappers where appropriate. Enable compiler warnings for potential null "
            "pointer dereferences."
        ),
        "solution_template_zh": (
            "应用供应商补丁。在解引用指针之前实施空值检查。在适当的地方使用可选类型或可空包装器。"
            "启用编译器对潜在空指针解引用的警告。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "Memory Corruption",
        "type_zh": "内存损坏",
        "desc_template_en": (
            "A memory corruption vulnerability has been found in {product} version {version}. "
            "The {component} component improperly handles memory operations, allowing an attacker to "
            "corrupt memory through techniques such as use-after-free, double-free, or heap spraying. "
            "Successful exploitation can lead to arbitrary code execution or denial of service."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了内存损坏漏洞。{component}组件不当处理内存操作，"
            "允许攻击者通过释放后使用、重复释放或堆喷射等技术来损坏内存。成功利用可导致任意代码执行或拒绝服务。"
        ),
        "impact_template_en": (
            "Arbitrary code execution, denial of service, and potential system compromise. Memory corruption "
            "vulnerabilities are particularly dangerous as they can bypass modern security mitigations."
        ),
        "impact_template_zh": (
            "任意代码执行、拒绝服务和潜在的系统被攻陷。内存损坏漏洞特别危险，因为它们可以绕过现代安全缓解措施。"
        ),
        "solution_template_en": (
            "Apply vendor security patches. Use memory-safe programming languages where possible. Enable "
            "memory protection features like ASLR, DEP, and stack canaries. Use address sanitizer tools "
            "during development and testing."
        ),
        "solution_template_zh": (
            "应用供应商安全补丁。尽可能使用内存安全的编程语言。启用ASLR、DEP和堆栈金丝雀等内存保护功能。"
            "在开发和测试期间使用地址清理器工具。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.5, 10.0),
    },
    {
        "type_en": "WebSocket Security Vulnerability",
        "type_zh": "WebSocket安全漏洞",
        "desc_template_en": (
            "A WebSocket security vulnerability exists in {product} version {version}. "
            "The {component} component implements WebSocket connections without proper security controls, "
            "allowing attackers to intercept WebSocket communications, inject malicious messages, or "
            "exploit the WebSocket connection for cross-site WebSocket hijacking (CSWSH)."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在WebSocket安全漏洞。{component}组件在实现WebSocket连接时缺乏适当的"
            "安全控制，允许攻击者拦截WebSocket通信、注入恶意消息或利用WebSocket连接进行跨站WebSocket劫持（CSWSH）。"
        ),
        "impact_template_en": (
            "Interception of real-time communications, injection of malicious data into WebSocket streams, "
            "and cross-site WebSocket hijacking leading to unauthorized actions."
        ),
        "impact_template_zh": (
            "实时通信被拦截、恶意数据被注入到WebSocket流中，以及跨站WebSocket劫持导致未经授权的操作。"
        ),
        "solution_template_en": (
            "Implement origin validation for WebSocket connections. Use WebSocket Secure (wss://) protocol. "
            "Authenticate WebSocket handshake requests. Implement message validation and rate limiting."
        ),
        "solution_template_zh": (
            "对WebSocket连接实施来源验证。使用WebSocket安全（wss://）协议。对WebSocket握手请求进行身份验证。"
            "实施消息验证和速率限制。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "JWT Token Vulnerability",
        "type_zh": "JWT令牌漏洞",
        "desc_template_en": (
            "A JWT (JSON Web Token) security vulnerability has been identified in {product} version {version}. "
            "The {component} component does not properly validate JWT signatures or uses weak signing algorithms, "
            "allowing an attacker to forge tokens, bypass authentication, or escalate privileges by manipulating "
            "token claims."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了JWT（JSON Web Token）安全漏洞。{component}组件未正确验证JWT签名"
            "或使用了弱签名算法，允许攻击者伪造令牌、绕过身份验证或通过操纵令牌声明来提升权限。"
        ),
        "impact_template_en": (
            "Authentication bypass, privilege escalation through token manipulation, and unauthorized access "
            "to protected resources and functionality."
        ),
        "impact_template_zh": (
            "身份验证绕过、通过令牌操纵实现权限提升，以及对受保护资源和功能的未经授权访问。"
        ),
        "solution_template_en": (
            "Use strong signing algorithms (RS256, ES256) and validate signatures properly. Restrict allowed "
            "algorithms to prevent algorithm confusion attacks. Implement proper token expiration and revocation "
            "mechanisms. Validate all token claims."
        ),
        "solution_template_zh": (
            "使用强签名算法（RS256、ES256）并正确验证签名。限制允许的算法以防止算法混淆攻击。"
            "实施适当的令牌过期和撤销机制。验证所有令牌声明。"
        ),
        "severity_range": ("medium", "critical"),
        "cvss_range": (5.0, 10.0),
    },
    {
        "type_en": "GraphQL Injection",
        "type_zh": "GraphQL注入",
        "desc_template_en": (
            "A GraphQL injection vulnerability exists in {product} version {version}. "
            "The {component} component exposes a GraphQL endpoint without proper query depth limiting, "
            "authorization checks, or input validation. An attacker can craft malicious GraphQL queries "
            "to extract sensitive data, cause denial of service through complex nested queries, or "
            "bypass authorization controls."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在GraphQL注入漏洞。{component}组件暴露了GraphQL端点，但缺乏适当的"
            "查询深度限制、授权检查或输入验证。攻击者可以构造恶意的GraphQL查询来提取敏感数据、"
            "通过复杂的嵌套查询导致拒绝服务，或绕过授权控制。"
        ),
        "impact_template_en": (
            "Unauthorized data extraction, denial of service through resource exhaustion, and bypass "
            "of application-level authorization controls."
        ),
        "impact_template_zh": (
            "未经授权的数据提取、通过资源耗尽导致拒绝服务，以及绕过应用程序级别的授权控制。"
        ),
        "solution_template_en": (
            "Implement query depth limiting and complexity analysis. Apply authorization checks at the "
            "resolver level. Disable introspection in production. Use persisted queries to prevent "
            "malicious query injection."
        ),
        "solution_template_zh": (
            "实施查询深度限制和复杂度分析。在解析器级别应用授权检查。在生产环境中禁用内省。"
            "使用持久化查询以防止恶意查询注入。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 9.0),
    },
    {
        "type_en": "Mass Assignment",
        "type_zh": "批量赋值",
        "desc_template_en": (
            "A mass assignment vulnerability has been found in {product} version {version}. "
            "The {component} component automatically binds user-supplied input to internal object "
            "properties without proper filtering. An attacker can modify sensitive fields such as "
            "user roles, permissions, or internal state by including them in request parameters."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了批量赋值漏洞。{component}组件自动将用户提交的输入绑定到"
            "内部对象属性，而未进行适当的过滤。攻击者可以通过在请求参数中包含敏感字段来修改用户角色、"
            "权限或内部状态等敏感字段。"
        ),
        "impact_template_en": (
            "Privilege escalation, unauthorized modification of user roles and permissions, and "
            "potential admin account creation by regular users."
        ),
        "impact_template_zh": (
            "权限提升、未经授权修改用户角色和权限，以及普通用户创建管理员账户的潜在可能。"
        ),
        "solution_template_en": (
            "Implement explicit allow-lists for fields that can be set through user input. Use DTOs "
            "(Data Transfer Objects) to control which fields are bound. Apply input validation at the "
            "model level."
        ),
        "solution_template_zh": (
            "对可以通过用户输入设置的字段实施显式白名单。使用DTO（数据传输对象）控制绑定的字段。"
            "在模型级别应用输入验证。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Host Header Injection",
        "type_zh": "主机头注入",
        "desc_template_en": (
            "A host header injection vulnerability exists in {product} version {version}. "
            "The {component} component trusts the HTTP Host header without validation, allowing an "
            "attacker to manipulate the header to perform various attacks including password reset "
            "poisoning, cache poisoning, and web cache deception."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在主机头注入漏洞。{component}组件在未验证的情况下信任HTTP Host头，"
            "允许攻击者操纵该头以执行各种攻击，包括密码重置中毒、缓存中毒和Web缓存欺骗。"
        ),
        "impact_template_en": (
            "Password reset poisoning, cache poisoning, SSRF through host manipulation, and potential "
            "phishing attacks."
        ),
        "impact_template_zh": (
            "密码重置中毒、缓存中毒、通过主机操纵实现SSRF，以及潜在的钓鱼攻击。"
        ),
        "solution_template_en": (
            "Validate the Host header against a configured allow-list of valid hostnames. Use a "
            "default virtual host for unmatched requests. Avoid using the Host header for critical "
            "operations without validation."
        ),
        "solution_template_zh": (
            "根据配置的有效主机名白名单验证Host头。对不匹配的请求使用默认虚拟主机。"
            "避免在未验证的情况下将Host头用于关键操作。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "Prototype Pollution",
        "type_zh": "原型污染",
        "desc_template_en": (
            "A prototype pollution vulnerability has been identified in {product} version {version}. "
            "The {component} component recursively merges user-supplied objects without proper validation, "
            "allowing an attacker to modify the prototype of base JavaScript objects. This can lead to "
            "property injection, denial of service, or remote code execution depending on the application "
            "context."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了原型污染漏洞。{component}组件在未进行适当验证的情况下递归合并"
            "用户提交的对象，允许攻击者修改基础JavaScript对象的原型。根据应用程序的上下文，这可能导致属性注入、"
            "拒绝服务或远程代码执行。"
        ),
        "impact_template_en": (
            "Property injection into all objects, bypass of security checks, denial of service, and "
            "in some cases remote code execution."
        ),
        "impact_template_zh": (
            "向所有对象注入属性、绕过安全检查、拒绝服务，在某些情况下还可导致远程代码执行。"
        ),
        "solution_template_en": (
            "Use safe object merging utilities that do not recursively merge prototypes. Implement input "
            "validation for JSON objects. Use Object.create(null) for creating objects without prototypes. "
            "Apply the latest security patches."
        ),
        "solution_template_zh": (
            "使用不会递归合并原型的安全对象合并工具。对JSON对象实施输入验证。使用Object.create(null)创建"
            "没有原型的对象。应用最新的安全补丁。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 9.0),
    },
    {
        "type_en": "HTTP Request Smuggling",
        "type_zh": "HTTP请求走私",
        "desc_template_en": (
            "An HTTP request smuggling vulnerability exists in {product} version {version}. "
            "The {component} component processes HTTP requests differently from front-end and back-end "
            "servers, allowing an attacker to smuggle malicious requests. By exploiting discrepancies "
            "in how Content-Length and Transfer-Encoding headers are processed, an attacker can prepend "
            "or append malicious requests to legitimate ones."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在HTTP请求走私漏洞。{component}组件处理HTTP请求的方式与前端和后端服务器"
            "不同，允许攻击者走私恶意请求。通过利用Content-Length和Transfer-Encoding头处理方式的差异，"
            "攻击者可以在合法请求之前或之后附加恶意请求。"
        ),
        "impact_template_en": (
            "Request smuggling can lead to cache poisoning, session hijacking, credential theft, and "
            "bypass of security controls by prepending malicious requests to victim requests."
        ),
        "impact_template_zh": (
            "请求走私可导致缓存中毒、会话劫持、凭据窃取，以及通过在受害者请求之前附加恶意请求来绕过安全控制。"
        ),
        "solution_template_en": (
            "Normalize HTTP request processing between front-end and back-end servers. Disable support "
            "for Transfer-Encoding: chunked if not needed. Use consistent HTTP parsing libraries. "
            "Implement request validation and sanitization."
        ),
        "solution_template_zh": (
            "统一前端和后端服务器之间的HTTP请求处理。如果不需要，禁用Transfer-Encoding: chunked支持。"
            "使用一致的HTTP解析库。实施请求验证和净化。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 9.0),
    },
    {
        "type_en": "Zip Slip Vulnerability",
        "type_zh": "Zip Slip目录穿越漏洞",
        "desc_template_en": (
            "A Zip Slip (path traversal via archive extraction) vulnerability has been found in {product} "
            "version {version}. The {component} component extracts archive files without properly validating "
            "file paths within the archive. An attacker can create a malicious archive containing files with "
            "path traversal sequences (such as ../../) that, when extracted, will be written to arbitrary "
            "locations on the filesystem."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了Zip Slip（通过归档提取进行路径穿越）漏洞。{component}组件"
            "在提取归档文件时未正确验证归档中的文件路径。攻击者可以创建包含带有路径穿越序列（如../../）的"
            "文件的恶意归档，提取时这些文件将被写入文件系统上的任意位置。"
        ),
        "impact_template_en": (
            "Arbitrary file write to any location on the filesystem, potentially overwriting critical system "
            "files, deploying backdoors, or achieving remote code execution."
        ),
        "impact_template_zh": (
            "对文件系统上任意位置的任意文件写入，可能覆盖关键系统文件、部署后门或实现远程代码执行。"
        ),
        "solution_template_en": (
            "Validate and canonicalize all file paths during archive extraction. Restrict extracted files "
            "to a designated directory. Use secure archive extraction libraries that check for path traversal."
        ),
        "solution_template_zh": (
            "在归档提取期间验证和规范化所有文件路径。将提取的文件限制在指定目录中。使用检查路径穿越的安全归档提取库。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "ReDoS (Regular Expression Denial of Service)",
        "type_zh": "正则表达式拒绝服务",
        "desc_template_en": (
            "A Regular Expression Denial of Service (ReDoS) vulnerability exists in {product} version {version}. "
            "The {component} component uses regular expressions that contain catastrophic backtracking patterns. "
            "An attacker can craft input strings that cause the regular expression engine to consume excessive "
            "CPU resources, leading to denial of service."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在正则表达式拒绝服务（ReDoS）漏洞。{component}组件使用的正则表达式"
            "包含灾难性回溯模式。攻击者可以构造输入字符串，使正则表达式引擎消耗过多的CPU资源，导致拒绝服务。"
        ),
        "impact_template_en": (
            "CPU exhaustion leading to denial of service. In multi-tenant environments, ReDoS can affect "
            "all users sharing the same resources."
        ),
        "impact_template_zh": (
            "CPU耗尽导致拒绝服务。在多租户环境中，ReDoS可能影响共享相同资源的所有用户。"
        ),
        "solution_template_en": (
            "Replace vulnerable regular expressions with non-backtracking alternatives. Implement input "
            "length limits. Use timeout mechanisms for regex evaluation. Test regular expressions for "
            "catastrophic backtracking."
        ),
        "solution_template_zh": (
            "用非回溯替代方案替换存在漏洞的正则表达式。实施输入长度限制。为正则表达式评估使用超时机制。"
            "测试正则表达式是否存在灾难性回溯。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 7.5),
    },
    {
        "type_en": "Kerberoasting",
        "type_zh": "Kerberoasting攻击",
        "desc_template_en": (
            "A Kerberoasting vulnerability has been identified in {product} version {version}. "
            "The {component} component uses Kerberos service accounts with weak or default passwords. "
            "An attacker can request service tickets for these accounts and perform offline brute-force "
            "attacks to crack the passwords, gaining access to the associated services."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了Kerberoasting漏洞。{component}组件使用的Kerberos服务账户"
            "具有弱或默认密码。攻击者可以请求这些账户的服务票证并执行离线暴力破解攻击来破解密码，"
            "从而获得对相关服务的访问权限。"
        ),
        "impact_template_en": (
            "Offline cracking of service account passwords, unauthorized access to network services, "
            "and potential lateral movement within the Active Directory environment."
        ),
        "impact_template_zh": (
            "离线破解服务账户密码、对网络服务的未经授权访问，以及在Active Directory环境中的潜在横向移动。"
        ),
        "solution_template_en": (
            "Use strong, complex passwords for all service accounts (25+ characters). Implement Group "
            "Managed Service Accounts (gMSA) where possible. Regularly audit service account passwords. "
            "Monitor for unusual Kerberos ticket requests."
        ),
        "solution_template_zh": (
            "对所有服务账户使用强复杂密码（25个以上字符）。尽可能实施组管理的服务账户（gMSA）。"
            "定期审计服务账户密码。监控异常的Kerberos票证请求。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "DLL Hijacking / Library Injection",
        "type_zh": "DLL劫持/库注入",
        "desc_template_en": (
            "A DLL hijacking (or shared library injection) vulnerability exists in {product} version {version}. "
            "The {component} component loads dynamic libraries without specifying absolute paths or verifying "
            "library integrity. An attacker can place a malicious DLL or shared library in a location where "
            "the application will load it instead of the legitimate library, achieving arbitrary code execution."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在DLL劫持（或共享库注入）漏洞。{component}组件加载动态库时未指定"
            "绝对路径或验证库的完整性。攻击者可以在应用程序加载恶意DLL或共享库的位置放置恶意库，"
            "替代合法库，从而实现任意代码执行。"
        ),
        "impact_template_en": (
            "Arbitrary code execution with application privileges, persistence on the compromised system, "
            "and potential privilege escalation."
        ),
        "impact_template_zh": (
            "以应用程序权限执行任意代码、在被攻陷的系统上建立持久化，以及潜在的权限提升。"
        ),
        "solution_template_en": (
            "Use absolute paths when loading dynamic libraries. Implement library signature verification. "
            "Restrict write permissions to application directories. Use secure search order for library loading."
        ),
        "solution_template_zh": (
            "加载动态库时使用绝对路径。实施库签名验证。限制对应用程序目录的写入权限。"
            "对库加载使用安全的搜索顺序。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "OAuth Token Misuse",
        "type_zh": "OAuth令牌误用",
        "desc_template_en": (
            "An OAuth token misuse vulnerability has been found in {product} version {version}. "
            "The {component} component does not properly validate OAuth tokens or implements the OAuth "
            "flow incorrectly, allowing attackers to steal, forge, or replay tokens to gain unauthorized "
            "access to user accounts and resources."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了OAuth令牌误用漏洞。{component}组件未正确验证OAuth令牌或"
            "不正确地实现了OAuth流程，允许攻击者窃取、伪造或重放令牌以获得对用户账户和资源的未经授权访问。"
        ),
        "impact_template_en": (
            "Unauthorized access to user accounts and resources through token theft or forgery. "
            "Account takeover and data exposure."
        ),
        "impact_template_zh": (
            "通过令牌窃取或伪造对用户账户和资源的未经授权访问。账户被接管和数据暴露。"
        ),
        "solution_template_en": (
            "Implement proper OAuth token validation. Use short-lived tokens with secure refresh mechanisms. "
            "Validate token audience and issuer claims. Implement token binding and revocation capabilities."
        ),
        "solution_template_zh": (
            "实施适当的OAuth令牌验证。使用带有安全刷新机制的短期令牌。验证令牌的受众和颁发者声明。"
            "实施令牌绑定和撤销功能。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "DNS Rebinding Attack",
        "type_zh": "DNS重绑定攻击",
        "desc_template_en": (
            "A DNS rebinding vulnerability exists in {product} version {version}. "
            "The {component} component performs access control based on DNS resolution without proper "
            "re-validation. An attacker can configure a domain with a very short TTL to initially resolve "
            "to a trusted IP address and then resolve to an internal IP address, bypassing same-origin "
            "policy and accessing internal services."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在DNS重绑定漏洞。{component}组件基于DNS解析执行访问控制，而未进行"
            "适当的重新验证。攻击者可以配置一个具有极短TTL的域名，初始解析为受信任的IP地址，然后解析为"
            "内部IP地址，绕过同源策略并访问内部服务。"
        ),
        "impact_template_en": (
            "Bypass of same-origin policy, unauthorized access to internal services and APIs, "
            "and potential data exfiltration from internal network resources."
        ),
        "impact_template_zh": (
            "绕过同源策略、对内部服务和API的未经授权访问，以及从内部网络资源中潜在的数据泄露。"
        ),
        "solution_template_en": (
            "Implement DNS pinning or cache DNS resolutions. Validate the IP address of incoming requests "
            "against private IP ranges. Use network-level controls to prevent access to internal resources."
        ),
        "solution_template_zh": (
            "实施DNS固定或缓存DNS解析。根据私有IP范围验证传入请求的IP地址。使用网络级别的控制来防止访问内部资源。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (4.5, 8.0),
    },
    {
        "type_en": "Cache Poisoning",
        "type_zh": "缓存中毒",
        "desc_template_en": (
            "A cache poisoning vulnerability has been identified in {product} version {version}. "
            "The {component} component caches content based on untrusted input without proper key "
            "validation. An attacker can manipulate cache keys or headers to inject malicious content "
            "into the cache, causing all subsequent users to receive the poisoned content."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了缓存中毒漏洞。{component}组件基于不受信任的输入缓存内容，"
            "而未进行适当的键验证。攻击者可以操纵缓存键或头信息，将恶意内容注入缓存，导致所有后续用户"
            "接收到被中毒的内容。"
        ),
        "impact_template_en": (
            "Delivery of malicious content to all users accessing the cached resource, potential XSS "
            "or defacement attacks, and undermining the integrity of cached responses."
        ),
        "impact_template_zh": (
            "向所有访问缓存资源的用户传递恶意内容、潜在的XSS或篡改攻击，以及破坏缓存响应的完整性。"
        ),
        "solution_template_en": (
            "Use cache keys that include all relevant headers. Implement cache key normalization. "
            "Set appropriate cache directives. Validate all inputs used for cache key generation."
        ),
        "solution_template_zh": (
            "使用包含所有相关头的缓存键。实施缓存键规范化。设置适当的缓存指令。验证用于缓存键生成的所有输入。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Insecure API Endpoint",
        "type_zh": "不安全的API端点",
        "desc_template_en": (
            "An insecure API endpoint vulnerability exists in {product} version {version}. "
            "The {component} component exposes API endpoints without proper authentication, authorization, "
            "rate limiting, or input validation. These endpoints may expose sensitive functionality or "
            "data that can be accessed or manipulated by unauthorized users."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在不安全的API端点漏洞。{component}组件暴露了API端点，但缺乏适当的"
            "身份验证、授权、速率限制或输入验证。这些端点可能暴露敏感功能或数据，可被未经授权的用户"
            "访问或操纵。"
        ),
        "impact_template_en": (
            "Unauthorized access to sensitive data and functionality, data manipulation, and potential "
            "system compromise through exposed administrative APIs."
        ),
        "impact_template_zh": (
            "对敏感数据和功能的未经授权访问、数据操纵，以及通过暴露的管理API导致的潜在系统被攻陷。"
        ),
        "solution_template_en": (
            "Implement authentication and authorization for all API endpoints. Apply rate limiting and "
            "input validation. Use API gateways for centralized security control. Document and review "
            "all exposed API endpoints."
        ),
        "solution_template_zh": (
            "对所有API端点实施身份验证和授权。应用速率限制和输入验证。使用API网关进行集中安全控制。"
            "记录并审查所有暴露的API端点。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 9.0),
    },
    {
        "type_en": "Session Fixation",
        "type_zh": "会话固定",
        "desc_template_en": (
            "A session fixation vulnerability has been found in {product} version {version}. "
            "The {component} component does not properly invalidate existing session identifiers "
            "when a user authenticates, allowing an attacker to set a known session ID for a victim "
            "and then hijack the authenticated session."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了会话固定漏洞。{component}组件在用户身份验证时未正确使现有"
            "会话标识符失效，允许攻击者为受害者设置已知的会话ID，然后劫持已认证的会话。"
        ),
        "impact_template_en": (
            "Session hijacking leading to unauthorized access to victim's account and data. "
            "The attacker gains the same privileges as the victim user."
        ),
        "impact_template_zh": (
            "会话劫持导致对受害者账户和数据的未经授权访问。攻击者获得与受害者用户相同的权限。"
        ),
        "solution_template_en": (
            "Regenerate session identifiers upon successful authentication. Implement proper session "
            "management with secure cookie attributes (HttpOnly, Secure, SameSite). Set reasonable "
            "session timeouts."
        ),
        "solution_template_zh": (
            "在成功身份验证后重新生成会话标识符。实施带有安全Cookie属性（HttpOnly、Secure、SameSite）的"
            "适当会话管理。设置合理的会话超时时间。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.0),
    },
    {
        "type_en": "Clickjacking",
        "type_zh": "点击劫持",
        "desc_template_en": (
            "A clickjacking (UI redress attack) vulnerability exists in {product} version {version}. "
            "The {component} component does not set the X-Frame-Options header or Content-Security-Policy "
            "frame-ancestors directive, allowing the application to be embedded in iframes on malicious "
            "websites. An attacker can trick users into clicking on hidden elements to perform unintended actions."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在点击劫持（UI重定向攻击）漏洞。{component}组件未设置X-Frame-Options头"
            "或Content-Security-Policy的frame-ancestors指令，允许应用程序被嵌入到恶意网站的iframe中。"
            "攻击者可以欺骗用户点击隐藏的元素以执行非预期的操作。"
        ),
        "impact_template_en": (
            "Unauthorized actions performed by victims through invisible UI overlays, including financial "
            "transactions, account settings changes, and data deletion."
        ),
        "impact_template_zh": (
            "受害者通过不可见的UI覆盖层执行未经授权的操作，包括金融交易、账户设置更改和数据删除。"
        ),
        "solution_template_en": (
            "Set X-Frame-Options to DENY or SAMEORIGIN. Implement Content-Security-Policy frame-ancestors "
            "directive. Use frame-busting JavaScript as a defense-in-depth measure."
        ),
        "solution_template_zh": (
            "将X-Frame-Options设置为DENY或SAMEORIGIN。实施Content-Security-Policy的frame-ancestors指令。"
            "使用frame-busting JavaScript作为纵深防御措施。"
        ),
        "severity_range": ("low", "medium"),
        "cvss_range": (3.0, 6.5),
    },
    {
        "type_en": "Subdomain Takeover",
        "type_zh": "子域名接管",
        "desc_template_en": (
            "A subdomain takeover vulnerability has been identified in {product} version {version}. "
            "The {component} component manages DNS records for subdomains that point to external services "
            "which have been deprovisioned or removed. An attacker can claim the dangling DNS record on "
            "the external service and gain control over the subdomain."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了子域名接管漏洞。{component}组件管理的子域名DNS记录指向已停用"
            "或移除的外部服务。攻击者可以在外部服务上认领悬空的DNS记录并获得对子域名的控制权。"
        ),
        "impact_template_en": (
            "Control over the subdomain allows attackers to set cookies, serve malicious content, "
            "bypass same-origin policy, and potentially harvest credentials through convincing phishing pages."
        ),
        "impact_template_zh": (
            "对子域名的控制允许攻击者设置Cookie、提供恶意内容、绕过同源策略，并可能通过逼真的钓鱼页面收集凭据。"
        ),
        "solution_template_en": (
            "Audit DNS records regularly to identify dangling entries. Remove DNS records for deprovisioned "
            "services. Use DNS validation to verify service availability. Implement automated monitoring "
            "for DNS record changes."
        ),
        "solution_template_zh": (
            "定期审计DNS记录以识别悬空条目。移除已停用服务的DNS记录。使用DNS验证来验证服务可用性。"
            "实施自动化DNS记录变更监控。"
        ),
        "severity_range": ("medium", "high"),
        "cvss_range": (5.0, 8.5),
    },
    {
        "type_en": "Unvalidated Redirects and Forwards",
        "type_zh": "未验证的重定向和转发",
        "desc_template_en": (
            "An unvalidated redirect vulnerability exists in {product} version {version}. "
            "The {component} component forwards user requests to internal endpoints without proper "
            "validation of the target URL. An attacker can manipulate the forwarding mechanism to access "
            "internal resources or bypass authentication by redirecting to authenticated endpoints."
        ),
        "desc_template_zh": (
            "{product}版本{version}中存在未验证的重定向漏洞。{component}组件将用户请求转发到内部端点时"
            "未正确验证目标URL。攻击者可以操纵转发机制来访问内部资源或通过重定向到已认证端点来绕过身份验证。"
        ),
        "impact_template_en": (
            "Bypass of access controls, unauthorized access to internal endpoints, and potential SSRF "
            "through the forwarding mechanism."
        ),
        "impact_template_zh": (
            "绕过访问控制、对内部端点的未经授权访问，以及通过转发机制实现的潜在SSRF。"
        ),
        "solution_template_en": (
            "Validate all redirect and forward targets against an allow-list. Avoid passing user input "
            "directly to redirect or forward functions. Log all redirect and forward operations."
        ),
        "solution_template_zh": (
            "根据白名单验证所有重定向和转发目标。避免将用户输入直接传递给重定向或转发函数。"
            "记录所有重定向和转发操作。"
        ),
        "severity_range": ("low", "medium"),
        "cvss_range": (3.0, 6.0),
    },
    {
        "type_en": "Server-Side Prototype Pollution",
        "type_zh": "服务端原型污染",
        "desc_template_en": (
            "A server-side prototype pollution vulnerability has been identified in {product} version {version}. "
            "The {component} component processes JSON or object input in a way that allows an attacker to modify "
            "the prototype of built-in objects on the server side. Unlike client-side prototype pollution, this "
            "vulnerability can lead to server-side code execution, authentication bypass, or privilege escalation "
            "by polluting object properties that are used in security-critical operations."
        ),
        "desc_template_zh": (
            "在{product}版本{version}中发现了服务端原型污染漏洞。{component}组件处理JSON或对象输入的方式"
            "允许攻击者修改服务器端内置对象的原型。与客户端原型污染不同，此漏洞可通过污染用于安全关键操作中的"
            "对象属性来导致服务端代码执行、身份验证绕过或权限提升。"
        ),
        "impact_template_en": (
            "Server-side prototype pollution can lead to remote code execution, authentication bypass, "
            "privilege escalation, and complete application compromise on the server side."
        ),
        "impact_template_zh": (
            "服务端原型污染可导致远程代码执行、身份验证绕过、权限提升，以及在服务器端完全攻陷应用程序。"
        ),
        "solution_template_en": (
            "Use safe object parsing libraries that prevent prototype pollution. Implement input validation "
            "to reject JSON with __proto__ or constructor properties. Use Object.create(null) for data objects. "
            "Apply the latest security patches from the vendor."
        ),
        "solution_template_zh": (
            "使用防止原型污染的安全对象解析库。实施输入验证以拒绝包含__proto__或constructor属性的JSON。"
            "对数据对象使用Object.create(null)。应用供应商的最新安全补丁。"
        ),
        "severity_range": ("high", "critical"),
        "cvss_range": (7.0, 10.0),
    },
]

# ============================================================
# 200 种常见软件产品名称
# ============================================================
PRODUCTS = [
    {"name": "Apache Tomcat", "component": "Servlet Container"},
    {"name": "Nginx", "component": "Web Server"},
    {"name": "MySQL", "component": "Database Server"},
    {"name": "Redis", "component": "Cache Server"},
    {"name": "OpenSSL", "component": "TLS Library"},
    {"name": "OpenSSH", "component": "SSH Server"},
    {"name": "WordPress", "component": "CMS"},
    {"name": "Joomla", "component": "CMS"},
    {"name": "Drupal", "component": "CMS"},
    {"name": "Django", "component": "Web Framework"},
    {"name": "Flask", "component": "Web Framework"},
    {"name": "Spring Boot", "component": "Application Framework"},
    {"name": "Node.js", "component": "Runtime"},
    {"name": "Express.js", "component": "Web Framework"},
    {"name": "React", "component": "Frontend Library"},
    {"name": "Angular", "component": "Frontend Framework"},
    {"name": "Vue.js", "component": "Frontend Framework"},
    {"name": "phpMyAdmin", "component": "Database Admin"},
    {"name": "PostgreSQL", "component": "Database Server"},
    {"name": "MongoDB", "component": "Database Server"},
    {"name": "Apache Kafka", "component": "Message Broker"},
    {"name": "RabbitMQ", "component": "Message Broker"},
    {"name": "Elasticsearch", "component": "Search Engine"},
    {"name": "Logstash", "component": "Log Processor"},
    {"name": "Kibana", "component": "Visualization"},
    {"name": "Jenkins", "component": "CI/CD Server"},
    {"name": "GitLab", "component": "DevOps Platform"},
    {"name": "Docker", "component": "Container Runtime"},
    {"name": "Kubernetes", "component": "Container Orchestration"},
    {"name": "Consul", "component": "Service Discovery"},
    {"name": "Vault", "component": "Secret Management"},
    {"name": "Prometheus", "component": "Monitoring"},
    {"name": "Grafana", "component": "Dashboard"},
    {"name": "Apache Struts", "component": "Web Framework"},
    {"name": "Ruby on Rails", "component": "Web Framework"},
    {"name": "Laravel", "component": "PHP Framework"},
    {"name": "Symfony", "component": "PHP Framework"},
    {"name": "ASP.NET Core", "component": "Web Framework"},
    {"name": "Microsoft IIS", "component": "Web Server"},
    {"name": "Apache HTTP Server", "component": "Web Server"},
    {"name": "LiteSpeed Web Server", "component": "Web Server"},
    {"name": "Caddy", "component": "Web Server"},
    {"name": "HAProxy", "component": "Load Balancer"},
    {"name": "Traefik", "component": "Reverse Proxy"},
    {"name": "Envoy Proxy", "component": "Service Proxy"},
    {"name": "Squid Proxy", "component": "Web Proxy"},
    {"name": "MariaDB", "component": "Database Server"},
    {"name": "Oracle Database", "component": "Database Server"},
    {"name": "Microsoft SQL Server", "component": "Database Server"},
    {"name": "SQLite", "component": "Database Engine"},
    {"name": "Cassandra", "component": "Database Server"},
    {"name": "CouchDB", "component": "Document Database"},
    {"name": "Couchbase", "component": "NoSQL Database"},
    {"name": "Memcached", "component": "Cache Server"},
    {"name": "Apache Solr", "component": "Search Platform"},
    {"name": "Apache Lucene", "component": "Search Library"},
    {"name": "Sphinx Search", "component": "Search Engine"},
    {"name": "MinIO", "component": "Object Storage"},
    {"name": "Ceph", "component": "Storage Platform"},
    {"name": "OpenStack Swift", "component": "Object Storage"},
    {"name": "FreeIPA", "component": "Identity Management"},
    {"name": "Keycloak", "component": "Identity Provider"},
    {"name": "Auth0", "component": "Authentication Service"},
    {"name": "Okta", "component": "Identity Management"},
    {"name": "LDAP Server", "component": "Directory Service"},
    {"name": "Active Directory", "component": "Directory Service"},
    {"name": "OpenLDAP", "component": "Directory Server"},
    {"name": "Samba", "component": "File Sharing"},
    {"name": "ProFTPD", "component": "FTP Server"},
    {"name": "vsftpd", "component": "FTP Server"},
    {"name": "FileZilla Server", "component": "FTP Server"},
    {"name": "Postfix", "component": "Mail Server"},
    {"name": "Sendmail", "component": "Mail Server"},
    {"name": "Exim", "component": "Mail Server"},
    {"name": "Dovecot", "component": "IMAP Server"},
    {"name": "OpenVPN", "component": "VPN Server"},
    {"name": "WireGuard", "component": "VPN Tunnel"},
    {"name": "IPSec", "component": "VPN Protocol"},
    {"name": "StrongSwan", "component": "VPN Server"},
    {"name": "Pi-hole", "component": "DNS Sinkhole"},
    {"name": "BIND", "component": "DNS Server"},
    {"name": "Unbound", "component": "DNS Resolver"},
    {"name": "PowerDNS", "component": "DNS Server"},
    {"name": "CoreDNS", "component": "DNS Server"},
    {"name": "Cloudflare DNS", "component": "DNS Resolver"},
    {"name": "HAProxy", "component": "Proxy Server"},
    {"name": "Squid", "component": "Cache Proxy"},
    {"name": "Varnish", "component": "HTTP Cache"},
    {"name": "Redis Sentinel", "component": "High Availability"},
    {"name": "Apache ZooKeeper", "component": "Coordination Service"},
    {"name": "etcd", "component": "Key-Value Store"},
    {"name": "Apache Flink", "component": "Stream Processing"},
    {"name": "Apache Spark", "component": "Data Processing"},
    {"name": "Apache Hadoop", "component": "Big Data Platform"},
    {"name": "Presto", "component": "SQL Engine"},
    {"name": "Apache Hive", "component": "Data Warehouse"},
    {"name": "Apache Airflow", "component": "Workflow Manager"},
    {"name": "Apache NiFi", "component": "Data Integration"},
    {"name": "Ansible", "component": "Configuration Management"},
    {"name": "Puppet", "component": "Configuration Management"},
    {"name": "Chef", "component": "Configuration Management"},
    {"name": "SaltStack", "component": "Configuration Management"},
    {"name": "Terraform", "component": "Infrastructure as Code"},
    {"name": "Packer", "component": "Image Builder"},
    {"name": "Vagrant", "component": "Development Environment"},
    {"name": "Jira", "component": "Project Management"},
    {"name": "Confluence", "component": "Wiki Platform"},
    {"name": "Bitbucket", "component": "Git Repository"},
    {"name": "GitHub Enterprise", "component": "Git Platform"},
    {"name": "Gitea", "component": "Git Service"},
    {"name": "Gogs", "component": "Git Service"},
    {"name": "SonarQube", "component": "Code Quality"},
    {"name": "Nexus Repository", "component": "Artifact Manager"},
    {"name": "Artifactory", "component": "Artifact Manager"},
    {"name": "JFrog", "component": "DevOps Platform"},
    {"name": "Nagios", "component": "Monitoring"},
    {"name": "Zabbix", "component": "Monitoring"},
    {"name": "Datadog", "component": "Monitoring"},
    {"name": "New Relic", "component": "APM"},
    {"name": "Splunk", "component": "SIEM"},
    {"name": "Elastic SIEM", "component": "SIEM"},
    {"name": "Wazuh", "component": "Security Platform"},
    {"name": "Snort", "component": "IDS"},
    {"name": "Suricata", "component": "IDS/IPS"},
    {"name": "ModSecurity", "component": "WAF"},
    {"name": "Fail2Ban", "component": "Intrusion Prevention"},
    {"name": "CrowdSec", "component": "Collaborative IPS"},
    {"name": "phpBB", "component": "Forum Software"},
    {"name": "Discourse", "component": "Forum Platform"},
    {"name": "Mattermost", "component": "Messaging Platform"},
    {"name": "Rocket.Chat", "component": "Messaging Platform"},
    {"name": "Nextcloud", "component": "File Sync Platform"},
    {"name": "ownCloud", "component": "File Sync Platform"},
    {"name": "Seafile", "component": "File Sync Platform"},
    {"name": "Pydio", "component": "File Sharing"},
    {"name": "Ghost", "component": "Blogging Platform"},
    {"name": "Moodle", "component": "LMS"},
    {"name": "Canvas LMS", "component": "Learning Platform"},
    {"name": "Odoo", "component": "ERP Platform"},
    {"name": "ERPNext", "component": "ERP System"},
    {"name": "Magento", "component": "E-Commerce"},
    {"name": "PrestaShop", "component": "E-Commerce"},
    {"name": "Shopware", "component": "E-Commerce"},
    {"name": "WooCommerce", "component": "E-Commerce Plugin"},
    {"name": "OpenCart", "component": "E-Commerce"},
    {"name": "Typo3", "component": "CMS"},
    {"name": "Contao", "component": "CMS"},
    {"name": "SilverStripe", "component": "CMS"},
    {"name": "Grav CMS", "component": "Flat-File CMS"},
    {"name": "Hugo", "component": "Static Site Generator"},
    {"name": "Jekyll", "component": "Static Site Generator"},
    {"name": "Hexo", "component": "Static Site Generator"},
    {"name": "Gatsby", "component": "Static Site Generator"},
    {"name": "FastAPI", "component": "Web Framework"},
    {"name": "Starlette", "component": "ASGI Framework"},
    {"name": "Sanic", "component": "Web Framework"},
    {"name": "Tornado", "component": "Web Framework"},
    {"name": "Bottle", "component": "Web Framework"},
    {"name": "Pyramid", "component": "Web Framework"},
    {"name": "AIOHTTP", "component": "HTTP Client/Server"},
    {"name": "Ktor", "component": "Web Framework"},
    {"name": "Micronaut", "component": "Application Framework"},
    {"name": "Quarkus", "component": "Application Framework"},
    {"name": "Vert.x", "component": "Application Framework"},
    {"name": "Dropwizard", "component": "Application Framework"},
    {"name": "Play Framework", "component": "Web Framework"},
    {"name": "Gin", "component": "Web Framework"},
    {"name": "Echo", "component": "Web Framework"},
    {"name": "Fiber", "component": "Web Framework"},
    {"name": "Chi", "component": "HTTP Router"},
    {"name": "Actix Web", "component": "Web Framework"},
    {"name": "NestJS", "component": "Web Framework"},
    {"name": "Koa", "component": "Web Framework"},
    {"name": "Hapi", "component": "Web Framework"},
    {"name": "Fastify", "component": "Web Framework"},
    {"name": "Sails.js", "component": "Web Framework"},
    {"name": "AdonisJS", "component": "Web Framework"},
    {"name": "Strapi", "component": "Headless CMS"},
    {"name": "Directus", "component": "Headless CMS"},
    {"name": "Contentful", "component": "Content Platform"},
    {"name": "Supabase", "component": "Backend as Service"},
    {"name": "Firebase", "component": "Backend Platform"},
    {"name": "Appwrite", "component": "Backend Server"},
    {"name": "PocketBase", "component": "Backend Server"},
    {"name": "Hasura", "component": "GraphQL Engine"},
    {"name": "Prisma", "component": "ORM"},
    {"name": "TypeORM", "component": "ORM"},
    {"name": "Hibernate", "component": "ORM"},
    {"name": "Sequelize", "component": "ORM"},
    {"name": "SQLAlchemy", "component": "ORM"},
    {"name": "Peewee", "component": "ORM"},
    {"name": "GORM", "component": "ORM"},
    {"name": "Apache Shiro", "component": "Security Framework"},
    {"name": "Spring Security", "component": "Security Framework"},
    {"name": "Keycloak", "component": "Identity Provider"},
    {"name": "Casbin", "component": "Authorization Library"},
    {"name": "OPA", "component": "Policy Engine"},
    {"name": "Pomerium", "component": "Identity-Aware Proxy"},
    {"name": "OAuth2 Proxy", "component": "Reverse Proxy"},
    {"name": "Traefik", "component": "Edge Router"},
    {"name": "Istio", "component": "Service Mesh"},
    {"name": "Linkerd", "component": "Service Mesh"},
    {"name": "Envoy", "component": "Proxy"},
    {"name": "gRPC", "component": "RPC Framework"},
    {"name": "Apache Thrift", "component": "RPC Framework"},
    {"name": "WebSocket", "component": "Communication Protocol"},
    {"name": "Socket.IO", "component": "Real-time Library"},
    {"name": "SignalR", "component": "Real-time Framework"},
    {"name": "Apache Camel", "component": "Integration Framework"},
    {"name": "MuleSoft", "component": "Integration Platform"},
    {"name": "Apache ActiveMQ", "component": "Message Broker"},
    {"name": "IBM MQ", "component": "Message Queue"},
    {"name": "NSQ", "component": "Message Queue"},
    {"name": "NATS", "component": "Messaging System"},
    {"name": "Pulsar", "component": "Messaging Platform"},
    {"name": "Apache Pulsar", "component": "Messaging Platform"},
    {"name": "Amazon MQ", "component": "Message Broker"},
    {"name": "Azure Service Bus", "component": "Messaging Service"},
    {"name": "Google Pub/Sub", "component": "Messaging Service"},
    {"name": "RabbitMQ Management", "component": "Management Plugin"},
    {"name": "MinIO Console", "component": "Management UI"},
    {"name": "Portainer", "component": "Container Management"},
    {"name": "Rancher", "component": "Container Management"},
    {"name": "OpenShift", "component": "Container Platform"},
    {"name": "Harbor", "component": "Container Registry"},
    {"name": "Container Registry", "component": "Image Registry"},
    {"name": "Trivy", "component": "Security Scanner"},
    {"name": "Clair", "component": "Vulnerability Scanner"},
    {"name": "Anchore", "component": "Container Security"},
    {"name": "Falco", "component": "Runtime Security"},
    {"name": "Open Policy Agent", "component": "Policy Engine"},
    {"name": "Kyverno", "component": "Policy Engine"},
    {"name": "OPA Gatekeeper", "component": "Admission Controller"},
    {"name": "Cert-Manager", "component": "Certificate Manager"},
    {"name": "External DNS", "component": "DNS Controller"},
    {"name": "Ingress NGINX", "component": "Ingress Controller"},
    {"name": "ArgoCD", "component": "GitOps Tool"},
    {"name": "Flux", "component": "GitOps Tool"},
    {"name": "Tekton", "component": "CI/CD Framework"},
    {"name": "Spinnaker", "component": "Continuous Delivery"},
    {"name": "Argo Workflows", "component": "Workflow Engine"},
    {"name": "Prefect", "component": "Workflow Orchestrator"},
    {"name": "Apache Airflow", "component": "Workflow Orchestrator"},
]

# ============================================================
# 版本号生成器
# ============================================================
VERSION_PATTERNS = [
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}.{random.randint(0,99)}",
    lambda: f"{random.randint(10,99)}.{random.randint(0,9)}.{random.randint(0,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(10,99)}.{random.randint(0,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(10,99)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}-rc{random.randint(1,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}-beta{random.randint(1,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}-alpha{random.randint(1,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}-SP{random.randint(1,9)}",
    lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}-p{random.randint(1,9)}",
]

SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [0.05, 0.15, 0.45, 0.35]


def generate_cve_id(year=None, used_cves=None):
    """Generate a random unique CVE ID.

    Args:
        year: Optional year for the CVE. If None, random year 2019-2026.
        used_cves: Set of already used CVE IDs to ensure uniqueness.

    Returns:
        A unique CVE ID string.
    """
    if year is None:
        year = random.randint(2019, 2026)
    if used_cves is None:
        used_cves = set()

    while True:
        num = random.randint(10000, 99999)
        cve_id = f"CVE-{year}-{num}"
        if cve_id not in used_cves:
            used_cves.add(cve_id)
            return cve_id


def generate_version():
    """Generate a random version string.

    Returns:
        A random version string.
    """
    return random.choice(VERSION_PATTERNS)()


def generate_cvss_score(severity, cvss_range):
    """Generate a CVSS score within the given range.

    Args:
        severity: The severity level.
        cvss_range: Tuple of (min_cvss, max_cvss).

    Returns:
        A CVSS score rounded to one decimal place.
    """
    min_cvss, max_cvss = cvss_range
    score = round(random.uniform(min_cvss, max_cvss), 1)
    # Ensure score matches severity
    severity_cvss = {
        "low": (0.1, 3.9),
        "medium": (4.0, 6.9),
        "high": (7.0, 8.9),
        "critical": (9.0, 10.0),
    }
    s_min, s_max = severity_cvss.get(severity, (min_cvss, max_cvss))
    final_min = max(min_cvss, s_min)
    final_max = min(max_cvss, s_max)
    if final_min > final_max:
        final_min, final_max = s_min, s_max
    return round(random.uniform(final_min, final_max), 1)


def pick_severity(severity_range):
    """Pick a severity level from the given range.

    Args:
        severity_range: Tuple of (min_severity, max_severity).

    Returns:
        A severity level string.
    """
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_s, max_s = severity_range
    min_idx = severity_order.get(min_s, 0)
    max_idx = severity_order.get(max_s, 3)
    candidates = [s for s, idx in severity_order.items() if min_idx <= idx <= max_idx]
    weights = []
    for s in candidates:
        weights.append(SEVERITY_WEIGHTS[severity_order[s]])
    total = sum(weights)
    weights = [w / total for w in weights]
    return random.choices(candidates, weights=weights, k=1)[0]


def generate_vuln_entry(template, product, version, cve_id):
    """Generate a single vulnerability entry from a template.

    Args:
        template: Vulnerability type template dict.
        product: Product dict with 'name' and 'component'.
        version: Version string.
        cve_id: CVE identifier string.

    Returns:
        A complete vulnerability entry dict.
    """
    product_name = product["name"]
    component = product["component"]

    severity = pick_severity(template["severity_range"])
    cvss = generate_cvss_score(severity, template["cvss_range"])

    # Fill templates
    name_en = f"{template['type_en']} in {product_name} {version}"
    name_zh = f"{product_name} {version} {template['type_zh']}"

    description_en = template["desc_template_en"].format(
        product=product_name, version=version, component=component
    )
    description_zh = template["desc_template_zh"].format(
        product=product_name, version=version, component=component
    )

    impact_en = template["impact_template_en"]
    impact_zh = template["impact_template_zh"]

    solution_en = template["solution_template_en"]
    solution_zh = template["solution_template_zh"]

    affected_products = [f"{product_name} {version}"]

    return {
        "cve_id": cve_id,
        "name_en": name_en,
        "name_zh": name_zh,
        "description_en": description_en,
        "description_zh": description_zh,
        "impact_en": impact_en,
        "impact_zh": impact_zh,
        "solution_en": solution_en,
        "solution_zh": solution_zh,
        "severity": severity,
        "cvss": cvss,
        "affected_products": affected_products,
    }


def generate_vuln_db(target_count=10000, seed=42):
    """Generate the complete vulnerability database.

    Args:
        target_count: Target number of vulnerability entries.
        seed: Random seed for reproducibility.

    Returns:
        List of vulnerability entry dicts.
    """
    random.seed(seed)

    used_cves = set()
    entries = []
    entry_set = set()  # For deduplication by (template_type, product_name)

    # Generate all possible combinations
    all_combinations = []
    for t_idx, template in enumerate(VULN_TEMPLATES):
        for p_idx, product in enumerate(PRODUCTS):
            all_combinations.append((t_idx, p_idx))

    # Shuffle for variety
    random.shuffle(all_combinations)

    # First pass: generate one entry per combination
    for t_idx, p_idx in all_combinations:
        if len(entries) >= target_count:
            break

        template = VULN_TEMPLATES[t_idx]
        product = PRODUCTS[p_idx]
        version = generate_version()
        cve_id = generate_cve_id(used_cves=used_cves)

        entry = generate_vuln_entry(template, product, version, cve_id)
        entries.append(entry)

    # If we need more entries, generate additional ones with different versions
    round_num = 1
    while len(entries) < target_count:
        random.shuffle(all_combinations)
        for t_idx, p_idx in all_combinations:
            if len(entries) >= target_count:
                break

            template = VULN_TEMPLATES[t_idx]
            product = PRODUCTS[p_idx]
            version = generate_version()
            cve_id = generate_cve_id(used_cves=used_cves)

            entry = generate_vuln_entry(template, product, version, cve_id)
            entries.append(entry)
        round_num += 1

    # Trim to exact target count
    entries = entries[:target_count]

    return entries


def save_vuln_db(entries, output_path):
    """Save vulnerability database to JSON file.

    Args:
        entries: List of vulnerability entry dicts.
        output_path: Path to the output JSON file.
    """
    # Create index by CVE ID
    by_cve = {}
    # Create index by name_en (for fuzzy matching)
    by_name = {}
    for entry in entries:
        by_cve[entry["cve_id"]] = entry
        by_name[entry["name_en"]] = entry

    data = {
        "_metadata": {
            "total_count": len(entries),
            "description": "Auto-generated vulnerability description database with 10000 entries",
            "generator": "generate_vuln_db.py",
        },
        "by_cve": by_cve,
        "by_name": by_name,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(entries)} vulnerability entries")
    print(f"Saved to: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024 / 1024:.1f} MB")


def load_vuln_db(db_path=None):
    """Load vulnerability database from JSON file.

    This function can be imported and used by other modules to quickly
    load the generated vulnerability database.

    Args:
        db_path: Path to the JSON file. If None, uses the default path.

    Returns:
        dict with keys: '_metadata', 'by_cve', 'by_name'
        Or None if the file does not exist.
    """
    if db_path is None:
        db_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "vuln_db_10000.json",
        )

    if not os.path.exists(db_path):
        return None

    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)


def search_vuln_by_name(name, db=None):
    """Search for a vulnerability by name (exact or partial match).

    Args:
        name: The vulnerability name to search for.
        db: The loaded database dict. If None, loads from default path.

    Returns:
        The matching vulnerability entry dict, or None.
    """
    if db is None:
        db = load_vuln_db()
    if db is None:
        return None

    # Try exact match first
    by_name = db.get("by_name", {})
    if name in by_name:
        return by_name[name]

    # Try partial match (case-insensitive)
    name_lower = name.lower()
    for key, entry in by_name.items():
        if name_lower in key.lower() or key.lower() in name_lower:
            return entry

    return None


def search_vuln_by_cve(cve_id, db=None):
    """Search for a vulnerability by CVE ID.

    Args:
        cve_id: The CVE identifier.
        db: The loaded database dict. If None, loads from default path.

    Returns:
        The matching vulnerability entry dict, or None.
    """
    if db is None:
        db = load_vuln_db()
    if db is None:
        return None

    by_cve = db.get("by_cve", {})
    return by_cve.get(cve_id)


if __name__ == "__main__":
    # Default output path
    default_output = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "vuln_db_10000.json",
    )

    print("Generating vulnerability database with 10000 entries...")
    print(f"Templates: {len(VULN_TEMPLATES)}")
    print(f"Products: {len(PRODUCTS)}")
    print(f"Max combinations: {len(VULN_TEMPLATES) * len(PRODUCTS)}")
    print()

    entries = generate_vuln_db(target_count=10000, seed=42)
    save_vuln_db(entries, default_output)

    # Verify
    db = load_vuln_db(default_output)
    if db:
        print(f"\nVerification:")
        print(f"  Total entries: {db['_metadata']['total_count']}")
        print(f"  CVE index size: {len(db['by_cve'])}")
        print(f"  Name index size: {len(db['by_name'])}")

        # Test search
        test_entry = search_vuln_by_name("SQL Injection in Apache Tomcat", db)
        if test_entry:
            print(f"  Search test: Found '{test_entry['name_zh']}'")
        else:
            print("  Search test: No match found (expected for partial name)")
    else:
        print("ERROR: Failed to load generated database for verification")
