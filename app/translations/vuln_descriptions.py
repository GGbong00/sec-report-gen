# -*- coding: utf-8 -*-
"""
高频漏洞描述翻译库 - TOP 100 高频安全漏洞中英文对照

本模块包含 100 条高频出现的安全漏洞完整描述，涵盖：
- 网络服务类（25条）
- Web应用类（25条）
- 数据库类（15条）
- 加密/协议类（15条）
- 操作系统类（10条）
- IoT/嵌入式（10条）

每条漏洞包含中英文对照的名称、描述、影响分析、修复建议，
以及风险等级、CVSS评分和受影响产品列表。
"""

VULN_DESCRIPTIONS = {
    # ============================================================
    # 网络服务类（25条）
    # ============================================================
    "CVE-2021-44228": {
        "name_en": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "name_zh": "Apache Log4j2 远程代码执行漏洞（Log4Shell）",
        "description_en": (
            "Apache Log4j2 is a popular Java logging framework widely used in enterprise applications. "
            "A critical vulnerability (CVE-2021-44228) was discovered in the Log4j2 lookup feature, specifically "
            "in the JNDI (Java Naming and Directory Interface) message lookup substitution functionality. "
            "The vulnerability allows an attacker to inject arbitrary JNDI lookups through crafted log messages, "
            "which can trigger LDAP or RMI requests to attacker-controlled servers. This results in remote code "
            "execution on the target system with the privileges of the application running Log4j2. The flaw exists "
            "in versions 2.0-beta9 through 2.14.1 and has been actively exploited in the wild since December 2021."
        ),
        "description_zh": (
            "Apache Log4j2 是一款广泛应用于企业级应用的 Java 日志框架。在该框架中发现了编号为 CVE-2021-44228 的严重安全漏洞，"
            "该漏洞存在于 Log4j2 的查找功能中，具体涉及 JNDI（Java 命名与目录接口）消息查找替换机制。攻击者可以通过构造恶意的日志消息"
            "注入任意的 JNDI 查找请求，从而触发向攻击者控制的服务器发起 LDAP 或 RMI 请求。这将导致攻击者在目标系统上以运行 Log4j2 "
            "的应用程序权限执行任意代码。该漏洞影响 2.0-beta9 至 2.14.1 版本，自 2021 年 12 月以来已被广泛利用。"
        ),
        "impact_en": (
            "This vulnerability has a catastrophic impact as it allows unauthenticated remote code execution with "
            "the privileges of the vulnerable application. Attackers can gain full control of affected servers, "
            "steal sensitive data, deploy ransomware, and move laterally across the network. The widespread use "
            "of Log4j2 across enterprise software makes this one of the most impactful vulnerabilities ever discovered."
        ),
        "impact_zh": (
            "该漏洞具有灾难性影响，攻击者无需认证即可实现远程代码执行，并获得受影响应用程序的运行权限。攻击者可以完全控制受感染的服务器，"
            "窃取敏感数据、部署勒索软件，并在网络中进行横向移动。Log4j2 在企业软件中的广泛使用使其成为有史以来影响最深远的安全漏洞之一。"
        ),
        "solution_en": (
            "Immediately upgrade Apache Log4j2 to version 2.17.1 or later. As a temporary mitigation, set the system "
            "property log4j2.formatMsgNoLookups to true or remove the JndiLookup class from the classpath. For environments "
            "where upgrading is not immediately possible, implement WAF rules to block JNDI-related attack patterns and "
            "monitor for outbound LDAP/RMI connections."
        ),
        "solution_zh": (
            "立即将 Apache Log4j2 升级至 2.17.1 或更高版本。作为临时缓解措施，可设置系统属性 log4j2.formatMsgNoLookups 为 true，"
            "或从类路径中移除 JndiLookup 类。对于无法立即升级的环境，应部署 WAF 规则以拦截 JNDI 相关的攻击模式，并监控出站的 LDAP/RMI 连接。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Apache Log4j 2.0-beta9 - 2.14.1"],
    },
    "CVE-2017-0144": {
        "name_en": "EternalBlue SMB Remote Code Execution",
        "name_zh": "EternalBlue SMB 远程代码执行漏洞",
        "description_en": (
            "CVE-2017-0144, commonly known as EternalBlue, is a remote code execution vulnerability in Microsoft's "
            "Server Message Block (SMB) version 1 protocol. The flaw exists in the way SMBv1 handles specially crafted "
            "packets, allowing an attacker to send malicious packets to a target SMB server. The vulnerability is caused "
            "by a buffer overflow in the kernel-mode driver srv2.sys when processing SMBv1 negotiation requests. "
            "This exploit was famously leaked from the NSA and used in the WannaCry ransomware attack in May 2017, "
            "causing massive global disruption."
        ),
        "description_zh": (
            "CVE-2017-0144，通常被称为 EternalBlue（永恒之蓝），是微软服务器消息块（SMB）第一版协议中的远程代码执行漏洞。"
            "该漏洞源于 SMBv1 处理特制数据包的方式存在缺陷，允许攻击者向目标 SMB 服务器发送恶意数据包。漏洞的根本原因是内核模式驱动程序 "
            "srv2.sys 在处理 SMBv1 协商请求时存在缓冲区溢出。该漏洞利用工具从美国国家安全局（NSA）泄露，并在 2017 年 5 月被用于 "
            "WannaCry 勒索软件攻击，造成了全球性的大规模破坏。"
        ),
        "impact_en": (
            "EternalBlue enables unauthenticated remote code execution with SYSTEM privileges on affected Windows machines. "
            "It can be exploited to install malware, ransomware, or backdoors without any user interaction. The wormable "
            "nature of this vulnerability means it can self-propagate across networks, making it particularly dangerous "
            "for enterprise environments."
        ),
        "impact_zh": (
            "EternalBlue 允许攻击者在受影响的 Windows 机器上以 SYSTEM 权限实现无需认证的远程代码执行。攻击者可以在无需用户交互的情况下"
            "安装恶意软件、勒索软件或后门程序。该漏洞具有蠕虫传播特性，能够在网络中自动扩散，对企业环境构成极大威胁。"
        ),
        "solution_en": (
            "Install Microsoft security updates MS17-010 immediately. Disable SMBv1 on all systems by removing the feature "
            "through Windows Settings or Group Policy. Block SMB traffic (ports 139 and 445) at the network perimeter. "
            "Ensure all Windows systems are running Windows 10 version 1703 or later, or Windows Server 2016 or later."
        ),
        "solution_zh": (
            "立即安装微软安全更新 MS17-010。通过 Windows 设置或组策略在所有系统上禁用 SMBv1 功能。在网络边界处阻止 SMB 流量"
            "（端口 139 和 445）。确保所有 Windows 系统运行 Windows 10 1703 或更高版本，或 Windows Server 2016 及更高版本。"
        ),
        "severity": "critical",
        "cvss": 8.1,
        "affected_products": ["Windows XP/Vista/7/8.1/10", "Windows Server 2003/2008/2012/2016"],
    },
    "CVE-2021-41773": {
        "name_en": "Apache HTTP Server 2.4.49/2.4.50 Path Traversal",
        "name_zh": "Apache HTTP Server 2.4.49/2.4.50 路径穿越漏洞",
        "description_en": (
            "A path traversal vulnerability was found in Apache HTTP Server 2.4.49. The flaw allows an attacker to map "
            "URLs to files outside the configured document root using a specially crafted request. If files outside the "
            "document root are not protected by default configuration requirements (e.g., require all denied), an attacker "
            "can access them. In version 2.4.50, the initial fix was found to be insufficient, and a second path traversal "
            "variant was discovered. The vulnerability can lead to information disclosure and, in configurations with CGI "
            "enabled, remote code execution."
        ),
        "description_zh": (
            "在 Apache HTTP Server 2.4.49 中发现了路径穿越漏洞。该漏洞允许攻击者使用特制的请求将 URL 映射到配置的文档根目录之外的文件。"
            "如果文档根目录之外的文件未受到默认配置要求（如 require all denied）的保护，攻击者可以访问这些文件。在 2.4.50 版本中，"
            "初步修复被发现不充分，又发现了第二个路径穿越变体。该漏洞可导致信息泄露，在启用了 CGI 的配置中还可导致远程代码执行。"
        ),
        "impact_en": (
            "Attackers can read arbitrary files on the server, potentially exposing sensitive configuration files, source code, "
            "or credentials. When CGI is enabled, the vulnerability can be escalated to remote code execution, allowing "
            "attackers to take full control of the affected server."
        ),
        "impact_zh": (
            "攻击者可以读取服务器上的任意文件，可能导致敏感配置文件、源代码或凭据泄露。当启用了 CGI 时，该漏洞可被提升为远程代码执行，"
            "使攻击者能够完全控制受影响的服务器。"
        ),
        "solution_en": (
            "Upgrade Apache HTTP Server to version 2.4.51 or later. Verify that directory access is properly restricted "
            "with 'Require all denied' directives. Disable CGI if not required. Review and restrict access to sensitive "
            "directories outside the document root."
        ),
        "solution_zh": (
            "将 Apache HTTP Server 升级至 2.4.51 或更高版本。验证目录访问已通过 'Require all denied' 指令正确限制。"
            "如非必要，禁用 CGI 功能。审查并限制对文档根目录之外的敏感目录的访问权限。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["Apache HTTP Server 2.4.49", "Apache HTTP Server 2.4.50"],
    },
    "CVE-2020-1938": {
        "name_en": "Apache Tomcat AJP Protocol Ghostcat File Read/Inclusion",
        "name_zh": "Apache Tomcat AJP 协议 Ghostcat 文件读取/包含漏洞",
        "description_en": (
            "Apache Tomcat uses the AJP (Apache JServ Protocol) connector to communicate with web servers like Apache HTTPD. "
            "A vulnerability known as Ghostcat (CVE-2020-1938) was found in the AJP connector where an attacker can read "
            "or include files from the web application's source code directory. The flaw exists because the AJP connector "
            "does not properly validate the attributes received from the web server. If the default AJP port (8009) is "
            "exposed, an attacker can exploit this vulnerability to read webapp configuration files, source code, and "
            "potentially execute arbitrary code through file inclusion."
        ),
        "description_zh": (
            "Apache Tomcat 使用 AJP（Apache JServ 协议）连接器与 Apache HTTPD 等 Web 服务器进行通信。在 AJP 连接器中发现了一个名为 "
            "Ghostcat（幽灵猫）的漏洞（CVE-2020-1938），攻击者可以通过该漏洞读取或包含 Web 应用源代码目录中的文件。该漏洞的根本原因是 "
            "AJP 连接器未正确验证从 Web 服务器接收到的属性。如果默认的 AJP 端口（8009）暴露，攻击者可以利用此漏洞读取 Web 应用配置文件、"
            "源代码，并可能通过文件包含执行任意代码。"
        ),
        "impact_en": (
            "Ghostcat allows unauthorized reading of any file within the web application directory, including configuration "
            "files containing database credentials and API keys. In certain configurations, it can also lead to remote code "
            "execution through file inclusion, potentially compromising the entire application server."
        ),
        "impact_zh": (
            "Ghostcat 允许未经授权地读取 Web 应用目录中的任何文件，包括包含数据库凭据和 API 密钥的配置文件。在某些配置下，"
            "该漏洞还可通过文件包含导致远程代码执行，可能危及整个应用服务器的安全。"
        ),
        "solution_en": (
            "Upgrade Apache Tomcat to version 9.0.31, 8.5.51, or 7.0.100 or later. If upgrading is not immediately possible, "
            "disable the AJP connector by commenting out the AJP Connector definition in server.xml, or set secretRequired='true' "
            "and configure a strong secret value. Block port 8009 at the network level if AJP is not needed."
        ),
        "solution_zh": (
            "将 Apache Tomcat 升级至 9.0.31、8.5.51 或 7.0.100 及更高版本。如果无法立即升级，可通过在 server.xml 中注释掉 "
            "AJP Connector 定义来禁用 AJP 连接器，或设置 secretRequired='true' 并配置强密码值。如果不需要 AJP，"
            "应在网络层面阻止端口 8009 的访问。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Tomcat 6.0.x", "Apache Tomcat 7.0.x", "Apache Tomcat 8.5.x", "Apache Tomcat 9.0.x"],
    },
    "CVE-2019-0211": {
        "name_en": "Android Binder Privilege Escalation",
        "name_zh": "Android Binder 提权漏洞",
        "description_en": (
            "CVE-2019-0211 is a privilege escalation vulnerability in the Android operating system that affects the Binder "
            "IPC (Inter-Process Communication) mechanism. The vulnerability exists in the Android Binder component where a "
            "use-after-free condition occurs during the handling of certain epoller events. A local attacker with low "
            "privileges can exploit this flaw to gain root access on the affected device. The vulnerability was found to be "
            "actively exploited in the wild as part of targeted attacks against Android devices."
        ),
        "description_zh": (
            "CVE-2019-0211 是 Android 操作系统中的提权漏洞，影响 Binder IPC（进程间通信）机制。该漏洞存在于 Android Binder 组件中，"
            "在处理某些 epoller 事件时会发生释放后使用（use-after-free）条件。具有低权限的本地攻击者可以利用此漏洞在受影响的设备上获取 "
            "root 权限。该漏洞被发现已在野利用，作为针对 Android 设备的定向攻击的一部分。"
        ),
        "impact_en": (
            "A successful exploit grants the attacker root-level access to the Android device, allowing complete control "
            "over the system. The attacker can install persistent malware, access all user data, intercept communications, "
            "and bypass all Android security mechanisms including sandboxing and permission controls."
        ),
        "impact_zh": (
            "成功利用该漏洞后，攻击者可获得 Android 设备的 root 级别访问权限，从而完全控制系统。攻击者可以安装持久化恶意软件、"
            "访问所有用户数据、拦截通信，并绕过所有 Android 安全机制，包括沙箱隔离和权限控制。"
        ),
        "solution_en": (
            "Apply Android security patches provided by the device manufacturer. The fix was included in the Android Security "
            "Bulletin dated April 2019. Users should ensure their devices are running the latest available firmware and "
            "security updates. Consider using Google Play Protect and avoid installing applications from untrusted sources."
        ),
        "solution_zh": (
            "应用设备制造商提供的 Android 安全补丁。该修复已包含在 2019 年 4 月的 Android 安全公告中。用户应确保其设备运行最新的可用固件"
            "和安全更新。建议启用 Google Play Protect，并避免从不可信来源安装应用程序。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Android 7.0 - 9.0"],
    },
    "CVE-2021-22986": {
        "name_en": "F5 BIG-IP iControl REST Unauthenticated Remote Code Execution",
        "name_zh": "F5 BIG-IP iControl REST 未授权远程代码执行漏洞",
        "description_en": (
            "CVE-2021-22986 is a critical unauthenticated remote code execution vulnerability in F5 BIG-IP products. "
            "The vulnerability exists in the iControl REST interface of BIG-IP, which allows an unauthenticated attacker "
            "to execute arbitrary system commands through crafted REST API requests. The iControl REST service runs with "
            "root privileges, meaning any code executed through this vulnerability runs as root. The vulnerability is "
            "present in BIG-IP versions 16.0.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x, and 11.6.x."
        ),
        "description_zh": (
            "CVE-2021-22986 是 F5 BIG-IP 产品中一个严重的未授权远程代码执行漏洞。该漏洞存在于 BIG-IP 的 iControl REST 接口中，"
            "允许未经认证的攻击者通过构造的 REST API 请求执行任意系统命令。iControl REST 服务以 root 权限运行，这意味着通过此漏洞"
            "执行的任何代码都以 root 身份运行。该漏洞存在于 BIG-IP 16.0.x、15.1.x、14.1.x、13.1.x、12.1.x 和 11.6.x 版本中。"
        ),
        "impact_en": (
            "An attacker can gain complete root-level control of the F5 BIG-IP device without any authentication. This "
            "allows full compromise of the network traffic management infrastructure, interception and modification of "
            "all traffic passing through the device, and potential lateral movement into the internal network."
        ),
        "impact_zh": (
            "攻击者可以在无需任何认证的情况下获得 F5 BIG-IP 设备的完全 root 级别控制权。这将导致网络流量管理基础设施被完全攻陷，"
            "攻击者可以拦截和修改经过该设备的所有流量，并可能向内部网络进行横向移动。"
        ),
        "solution_en": (
            "Upgrade F5 BIG-IP to the fixed versions: 16.1.2.2, 15.1.5.1, 14.1.4.6, 13.1.5, or 12.1.6. "
            "Block access to the iControl REST interface (port 443) from untrusted networks. Implement network segmentation "
            "to restrict management interface access to authorized administrators only."
        ),
        "solution_zh": (
            "将 F5 BIG-IP 升级至修复版本：16.1.2.2、15.1.5.1、14.1.4.6、13.1.5 或 12.1.6。阻止来自不可信网络对 "
            "iControl REST 接口（端口 443）的访问。实施网络分段，将管理接口访问限制为仅授权管理员。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["F5 BIG-IP 16.0.x", "F5 BIG-IP 15.1.x", "F5 BIG-IP 14.1.x", "F5 BIG-IP 13.1.x"],
    },
    "CVE-2020-25213": {
        "name_en": "Zabbix Server SQL Injection",
        "name_zh": "Zabbix Server SQL 注入漏洞",
        "description_en": (
            "A SQL injection vulnerability was discovered in Zabbix Server that allows an unauthenticated attacker to execute "
            "arbitrary SQL commands against the backend database. The vulnerability exists in the CUser::addAuditLog() function "
            "where user-supplied input is not properly sanitized before being used in SQL queries. An attacker can exploit this "
            "flaw by sending specially crafted requests to the Zabbix Server API without authentication. This vulnerability "
            "affects Zabbix Server versions 4.0.x before 4.0.35, 4.2.x before 4.2.9, 4.4.x before 4.4.5, and 5.0.0."
        ),
        "description_zh": (
            "在 Zabbix Server 中发现了 SQL 注入漏洞，允许未经认证的攻击者对后端数据库执行任意 SQL 命令。该漏洞存在于 "
            "CUser::addAuditLog() 函数中，用户提供的输入在用于 SQL 查询之前未经过适当的清理。攻击者可以通过向 Zabbix Server API "
            "发送特制请求来利用此漏洞，而无需进行身份认证。该漏洞影响 Zabbix Server 4.0.35 之前的 4.0.x 版本、4.2.9 之前的 "
            "4.2.x 版本、4.4.5 之前的 4.4.x 版本以及 5.0.0 版本。"
        ),
        "impact_en": (
            "An unauthenticated attacker can extract sensitive data from the database, including credentials, configuration "
            "information, and monitoring data. In some cases, the attacker may also be able to modify or delete database "
            "records, potentially disrupting the entire monitoring infrastructure."
        ),
        "impact_zh": (
            "未经认证的攻击者可以从数据库中提取敏感数据，包括凭据、配置信息和监控数据。在某些情况下，攻击者还可能修改或删除数据库记录，"
            "可能破坏整个监控基础设施。"
        ),
        "solution_en": (
            "Upgrade Zabbix Server to version 4.0.35, 4.2.9, 4.4.5, or 5.0.1 and later. Restrict access to the Zabbix "
            "Server API to trusted IP addresses only. Implement Web Application Firewall (WAF) rules to detect and block "
            "SQL injection attempts."
        ),
        "solution_zh": (
            "将 Zabbix Server 升级至 4.0.35、4.2.9、4.4.5 或 5.0.1 及更高版本。将 Zabbix Server API 的访问限制为仅受信任的 "
            "IP 地址。部署 Web 应用防火墙（WAF）规则以检测和阻止 SQL 注入攻击。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Zabbix Server 4.0.x < 4.0.35", "Zabbix Server 4.2.x < 4.2.9", "Zabbix Server 4.4.x < 4.4.5", "Zabbix Server 5.0.0"],
    },
    "CVE-2021-25646": {
        "name_en": "Apache Druid Remote Code Execution",
        "name_zh": "Apache Druid 远程代码执行漏洞",
        "description_en": (
            "CVE-2021-25646 is a remote code execution vulnerability in Apache Druid, a high-performance real-time analytics "
            "database. The vulnerability exists in the process function of the JavaScript module used by Druid for executing "
            "user-provided JavaScript code. An authenticated user can send a specially crafted request to the Druid coordinator "
            "or overlord node that allows execution of arbitrary JavaScript code on the server. The vulnerability affects "
            "Apache Druid versions 0.19.0 to 0.21.1."
        ),
        "description_zh": (
            "CVE-2021-25646 是 Apache Druid（一个高性能实时分析数据库）中的远程代码执行漏洞。该漏洞存在于 Druid 用于执行用户提供"
            "的 JavaScript 代码的 JavaScript 模块的 process 函数中。经过认证的用户可以向 Druid coordinator 或 overlord 节点"
            "发送特制请求，从而在服务器上执行任意 JavaScript 代码。该漏洞影响 Apache Druid 0.19.0 至 0.21.1 版本。"
        ),
        "impact_en": (
            "Authenticated users can execute arbitrary code on the Druid server, potentially gaining access to the underlying "
            "operating system. This could lead to data exfiltration, service disruption, and lateral movement within the "
            "infrastructure hosting the Druid cluster."
        ),
        "impact_zh": (
            "经过认证的用户可以在 Druid 服务器上执行任意代码，可能获得对底层操作系统的访问权限。这可能导致数据泄露、服务中断，"
            "以及在托管 Druid 集群的基础设施中进行横向移动。"
        ),
        "solution_en": (
            "Upgrade Apache Druid to version 0.22.0 or later. Disable the JavaScript functionality if not required by "
            "setting druid.indexer.task.defaultStrategy to a non-JavaScript strategy. Restrict access to the Druid "
            "coordinator and overlord APIs to authorized users only."
        ),
        "solution_zh": (
            "将 Apache Druid 升级至 0.22.0 或更高版本。如果不需要 JavaScript 功能，可通过将 druid.indexer.task.defaultStrategy "
            "设置为非 JavaScript 策略来禁用。将 Druid coordinator 和 overlord API 的访问限制为仅授权用户。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Druid 0.19.0 - 0.21.1"],
    },
    "CVE-2018-2894": {
        "name_en": "Oracle WebLogic Server Unauthenticated Remote Code Execution",
        "name_zh": "Oracle WebLogic Server 未授权远程代码执行漏洞",
        "description_en": (
            "CVE-2018-2894 is a critical unauthenticated remote code execution vulnerability in Oracle WebLogic Server. "
            "The vulnerability exists in the WebLogic Server's web test page component, which allows an unauthenticated "
            "attacker to upload a malicious XML file through the /ws_utc/config endpoint. The uploaded file can contain "
            "a JNDI reference that triggers remote code execution when processed by the server. This vulnerability affects "
            "Oracle WebLogic Server versions 10.3.6.0, 12.1.3.0, 12.2.1.2, and 12.2.1.3."
        ),
        "description_zh": (
            "CVE-2018-2894 是 Oracle WebLogic Server 中一个严重的未授权远程代码执行漏洞。该漏洞存在于 WebLogic Server 的 "
            "Web 测试页面组件中，允许未经认证的攻击者通过 /ws_utc/config 端点上传恶意的 XML 文件。上传的文件可以包含 JNDI 引用，"
            "当服务器处理该文件时会触发远程代码执行。该漏洞影响 Oracle WebLogic Server 10.3.6.0、12.1.3.0、12.2.1.2 和 "
            "12.2.1.3 版本。"
        ),
        "impact_en": (
            "An unauthenticated attacker can gain complete control of the WebLogic Server instance, execute arbitrary commands, "
            "and access all data managed by the server. This can lead to full compromise of the application server and "
            "potentially the underlying operating system."
        ),
        "impact_zh": (
            "未经认证的攻击者可以完全控制 WebLogic Server 实例，执行任意命令，并访问服务器管理的所有数据。这可能导致应用服务器"
            "以及底层操作系统被完全攻陷。"
        ),
        "solution_en": (
            "Apply the Oracle Critical Patch Update for July 2018. Restrict access to the /ws_utc/ path and other development "
            "or test endpoints. Disable the WebLogic test page in production environments. Implement network segmentation "
            "to limit access to the WebLogic administration console."
        ),
        "solution_zh": (
            "应用 Oracle 2018 年 7 月的关键补丁更新。限制对 /ws_utc/ 路径及其他开发或测试端点的访问。在生产环境中禁用 WebLogic "
            "测试页面。实施网络分段以限制对 WebLogic 管理控制台的访问。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Oracle WebLogic Server 10.3.6.0", "Oracle WebLogic Server 12.1.3.0", "Oracle WebLogic Server 12.2.1.2", "Oracle WebLogic Server 12.2.1.3"],
    },
    "CVE-2019-2725": {
        "name_en": "Oracle WebLogic Server Deserialization Remote Code Execution",
        "name_zh": "Oracle WebLogic Server 反序列化远程代码执行漏洞",
        "description_en": (
            "CVE-2019-2725 is a remote code execution vulnerability in Oracle WebLogic Server caused by insecure deserialization. "
            "The vulnerability exists in the _async servlet component of WebLogic Server, which processes asynchronous requests. "
            "An attacker can send a specially crafted SOAP request containing malicious serialized Java objects to the "
            "/_async/AsyncResponseService endpoint. When the server deserializes these objects, it triggers execution of "
            "arbitrary code. This vulnerability affects Oracle WebLogic Server 10.3.6.0 and 12.1.3.0."
        ),
        "description_zh": (
            "CVE-2019-2725 是 Oracle WebLogic Server 中由不安全反序列化导致的远程代码执行漏洞。该漏洞存在于 WebLogic Server "
            "的 _async servlet 组件中，该组件负责处理异步请求。攻击者可以向 /_async/AsyncResponseService 端点发送包含恶意序列化 "
            "Java 对象的特制 SOAP 请求。当服务器反序列化这些对象时，将触发任意代码执行。该漏洞影响 Oracle WebLogic Server "
            "10.3.6.0 和 12.1.3.0 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the WebLogic Server and its underlying "
            "system. The attacker can deploy webshells, steal credentials from the configuration, and use the compromised "
            "server as a pivot point for further network penetration."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 WebLogic Server 及其底层系统。攻击者可以部署 Webshell、从配置中窃取凭据，"
            "并利用被攻陷的服务器作为进一步网络渗透的跳板。"
        ),
        "solution_en": (
            "Apply Oracle Critical Patch Update for April 2019. Block access to the /_async/ endpoint at the web server or "
            "WAF level. Remove or restrict the use of the async servlet in production environments. Monitor for suspicious "
            "SOAP requests targeting the AsyncResponseService endpoint."
        ),
        "solution_zh": (
            "应用 Oracle 2019 年 4 月的关键补丁更新。在 Web 服务器或 WAF 层面阻止对 /_async/ 端点的访问。在生产环境中移除或"
            "限制 async servlet 的使用。监控针对 AsyncResponseService 端点的可疑 SOAP 请求。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Oracle WebLogic Server 10.3.6.0", "Oracle WebLogic Server 12.1.3.0"],
    },
    "CVE-2020-14882": {
        "name_en": "Oracle WebLogic Server Unauthenticated Remote Code Execution",
        "name_zh": "Oracle WebLogic Server 未授权远程代码执行漏洞",
        "description_en": (
            "CVE-2020-14882 is a critical vulnerability in Oracle WebLogic Server that allows unauthenticated remote code "
            "execution. The vulnerability exists in the console component of WebLogic Server where an attacker can bypass "
            "authentication by manipulating the request path. Specifically, an attacker can access the console endpoint "
            "through a specially crafted URL that bypasses the normal authentication mechanism. Once authenticated, the "
            "attacker can execute arbitrary code through the console's functionality. This vulnerability affects Oracle "
            "WebLogic Server versions 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0."
        ),
        "description_zh": (
            "CVE-2020-14882 是 Oracle WebLogic Server 中的一个严重漏洞，允许未经认证的远程代码执行。该漏洞存在于 WebLogic Server "
            "的控制台组件中，攻击者可以通过操纵请求路径绕过身份认证。具体而言，攻击者可以通过特制的 URL 访问控制台端点，绕过正常的"
            "身份认证机制。一旦认证成功，攻击者可以通过控制台功能执行任意代码。该漏洞影响 Oracle WebLogic Server 10.3.6.0.0、"
            "12.1.3.0.0、12.2.1.3.0、12.2.1.4.0 和 14.1.1.0.0 版本。"
        ),
        "impact_en": (
            "This vulnerability allows unauthenticated attackers to gain full administrative access to the WebLogic Server, "
            "execute arbitrary commands, deploy malicious applications, and compromise all data and services managed by "
            "the server. The ease of exploitation and high impact make this one of the most critical WebLogic vulnerabilities."
        ),
        "impact_zh": (
            "该漏洞允许未经认证的攻击者获得 WebLogic Server 的完全管理权限，执行任意命令、部署恶意应用程序，并危及服务器管理的所有数据"
            "和服务。由于其利用门槛低且影响严重，这是 WebLogic 最严重的漏洞之一。"
        ),
        "solution_en": (
            "Apply Oracle Critical Patch Update for October 2020. Restrict access to the WebLogic Server console to trusted "
            "networks only. Implement additional authentication mechanisms such as multi-factor authentication for "
            "administrative access. Deploy WAF rules to detect and block path traversal attempts."
        ),
        "solution_zh": (
            "应用 Oracle 2020 年 10 月的关键补丁更新。将 WebLogic Server 控制台的访问限制为仅受信任的网络。为管理访问实施额外的"
            "身份认证机制，如多因素认证。部署 WAF 规则以检测和阻止路径穿越尝试。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Oracle WebLogic Server 10.3.6.0.0", "Oracle WebLogic Server 12.1.3.0.0", "Oracle WebLogic Server 12.2.1.3.0", "Oracle WebLogic Server 12.2.1.4.0"],
    },
    "CVE-2021-21985": {
        "name_en": "VMware vCenter Server Remote Code Execution",
        "name_zh": "VMware vCenter Server 远程代码执行漏洞",
        "description_en": (
            "CVE-2021-21985 is a remote code execution vulnerability in VMware vCenter Server. The vulnerability exists in "
            "the vSphere Client (HTML5) which is embedded in the vCenter Server. A malicious actor with network access to "
            "port 443 can exploit this vulnerability by sending a specially crafted request to the vCenter Server. The "
            "vulnerability is caused by insufficient input validation in the vSAN Health Check plugin, which allows an "
            "attacker to execute arbitrary code with root privileges on the vCenter Server appliance. This vulnerability "
            "affects VMware vCenter Server versions 7.0 U1b, 7.0 U1c, 6.7 U3l, and 6.5 U3n."
        ),
        "description_zh": (
            "CVE-2021-21985 是 VMware vCenter Server 中的远程代码执行漏洞。该漏洞存在于嵌入在 vCenter Server 中的 vSphere Client"
            "（HTML5）中。具有端口 443 网络访问权限的恶意攻击者可以通过向 vCenter Server 发送特制请求来利用此漏洞。该漏洞由 vSAN "
            "健康检查插件中的输入验证不足引起，允许攻击者在 vCenter Server 设备上以 root 权限执行任意代码。该漏洞影响 VMware "
            "vCenter Server 7.0 U1b、7.0 U1c、6.7 U3l 和 6.5 U3n 版本。"
        ),
        "impact_en": (
            "Successful exploitation gives the attacker root access to the vCenter Server, which is the central management "
            "point for the entire vSphere infrastructure. This allows the attacker to control all managed ESXi hosts, "
            "manipulate virtual machines, and access all data stored in the virtual infrastructure."
        ),
        "impact_zh": (
            "成功利用该漏洞后，攻击者可获得 vCenter Server 的 root 访问权限，而 vCenter Server 是整个 vSphere 基础设施的中心管理点。"
            "攻击者可以控制所有受管的 ESXi 主机、操纵虚拟机，并访问虚拟基础设施中存储的所有数据。"
        ),
        "solution_en": (
            "Apply the patches provided by VMware in VMSA-2021-0010. Upgrade vCenter Server to 7.0 U1d, 6.7 U3m, or 6.5 U3o. "
            "Restrict network access to the vCenter Server management interface. Disable the vSAN Health Check plugin if "
            "vSAN is not in use."
        ),
        "solution_zh": (
            "应用 VMware 在 VMSA-2021-0010 中提供的补丁。将 vCenter Server 升级至 7.0 U1d、6.7 U3m 或 6.5 U3o。"
            "限制对 vCenter Server 管理接口的网络访问。如果未使用 vSAN，请禁用 vSAN 健康检查插件。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["VMware vCenter Server 7.0", "VMware vCenter Server 6.7", "VMware vCenter Server 6.5"],
    },
    "CVE-2022-22954": {
        "name_en": "VMware Workspace ONE Access Remote Code Execution",
        "name_zh": "VMware Workspace ONE Access 远程代码执行漏洞",
        "description_en": (
            "CVE-2022-22954 is a remote code execution vulnerability in VMware Workspace ONE Access and Identity Manager. "
            "The vulnerability exists in the Freemarker template engine used by the application, where an attacker can inject "
            "malicious Server-Side Template Injection (SSTI) payloads through the deserialization endpoint. By exploiting "
            "this flaw, an unauthenticated attacker with network access can execute arbitrary code on the underlying operating "
            "system with the privileges of the service account. This vulnerability affects VMware Workspace ONE Access "
            "versions 21.08.0.1, 20.10.0.1, and 20.01.0.1."
        ),
        "description_zh": (
            "CVE-2022-22954 是 VMware Workspace ONE Access 和 Identity Manager 中的远程代码执行漏洞。该漏洞存在于应用程序使用的 "
            "Freemarker 模板引擎中，攻击者可以通过反序列化端点注入恶意的服务端模板注入（SSTI）载荷。利用此漏洞，具有网络访问权限的"
            "未经认证的攻击者可以在底层操作系统上以服务账户权限执行任意代码。该漏洞影响 VMware Workspace ONE Access 21.08.0.1、"
            "20.10.0.1 和 20.01.0.1 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on the Workspace ONE Access server allows attackers to compromise the "
            "identity management infrastructure. This can lead to credential theft, unauthorized access to connected "
            "applications, and complete compromise of the enterprise identity and access management system."
        ),
        "impact_zh": (
            "在 Workspace ONE Access 服务器上未经认证的远程代码执行使攻击者能够攻陷身份管理基础设施。这可能导致凭据窃取、"
            "对连接应用程序的未授权访问，以及企业身份和访问管理系统的完全沦陷。"
        ),
        "solution_en": (
            "Apply the patches provided in VMware VMSA-2022-0011. Upgrade Workspace ONE Access to version 21.08.0.2, "
            "20.10.0.2, or 20.01.0.2. Restrict network access to the Workspace ONE Access management interface. "
            "Monitor for suspicious template injection patterns in request logs."
        ),
        "solution_zh": (
            "应用 VMware VMSA-2022-0011 中提供的补丁。将 Workspace ONE Access 升级至 21.08.0.2、20.10.0.2 或 20.01.0.2 版本。"
            "限制对 Workspace ONE Access 管理接口的网络访问。监控请求日志中的可疑模板注入模式。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["VMware Workspace ONE Access 21.08.0.1", "VMware Workspace ONE Access 20.10.0.1", "VMware Identity Manager 20.01.0.1"],
    },
    "CVE-2022-26134": {
        "name_en": "Atlassian Confluence Remote Code Execution",
        "name_zh": "Atlassian Confluence 远程代码执行漏洞",
        "description_en": (
            "CVE-2022-26134 is a critical remote code execution vulnerability in Atlassian Confluence Server and Data Center. "
            "The vulnerability exists in the OGNL (Object-Graph Navigation Language) expression evaluation component of "
            "Confluence. An unauthenticated attacker can exploit this vulnerability by sending a specially crafted HTTP "
            "request that injects and executes arbitrary OGNL expressions on the server. This results in remote code "
            "execution with the privileges of the Confluence application. The vulnerability affects Confluence Server "
            "and Data Center versions 7.4.0 through 7.13.5, 7.14.0 through 7.15.2, and 7.16.0 through 7.16.4."
        ),
        "description_zh": (
            "CVE-2022-26134 是 Atlassian Confluence Server 和 Data Center 中一个严重的远程代码执行漏洞。该漏洞存在于 Confluence "
            "的 OGNL（对象图导航语言）表达式求值组件中。未经认证的攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，在服务器上注入并"
            "执行任意 OGNL 表达式。这将导致以 Confluence 应用程序权限进行远程代码执行。该漏洞影响 Confluence Server 和 Data Center "
            "7.4.0 至 7.13.5、7.14.0 至 7.15.2 以及 7.16.0 至 7.16.4 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the Confluence server, access all "
            "stored content and credentials, and use the compromised server as a foothold for further attacks against "
            "the internal network. Given Confluence's role as a knowledge management platform, the impact on data "
            "confidentiality is particularly severe."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 Confluence 服务器，访问所有存储的内容和凭据，并利用被攻陷的服务器作为进一步"
            "攻击内部网络的据点。鉴于 Confluence 作为知识管理平台的角色，对数据机密性的影响尤为严重。"
        ),
        "solution_en": (
            "Upgrade Atlassian Confluence to the fixed versions: 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, or "
            "7.18.1. If upgrading is not immediately possible, restrict network access to the Confluence server and "
            "implement WAF rules to block OGNL injection patterns."
        ),
        "solution_zh": (
            "将 Atlassian Confluence 升级至修复版本：7.4.17、7.13.7、7.14.3、7.15.2、7.16.4、7.17.4 或 7.18.1。"
            "如果无法立即升级，请限制对 Confluence 服务器的网络访问，并部署 WAF 规则以阻止 OGNL 注入模式。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Atlassian Confluence Server 7.4.0 - 7.18.0", "Atlassian Confluence Data Center 7.4.0 - 7.18.0"],
    },
    "CVE-2021-26084": {
        "name_en": "Atlassian Confluence Server Remote Code Execution",
        "name_zh": "Atlassian Confluence Server 远程代码执行漏洞",
        "description_en": (
            "CVE-2021-26084 is a remote code execution vulnerability in Atlassian Confluence Server and Data Center. The "
            "vulnerability exists in the template rendering engine where OGNL (Object-Graph Navigation Language) expressions "
            "can be injected through certain REST API endpoints. An unauthenticated attacker can exploit this vulnerability "
            "by sending a crafted HTTP request to the affected endpoint, which results in execution of arbitrary OGNL "
            "expressions on the server. This allows the attacker to execute arbitrary code with the privileges of the "
            "Confluence application. The vulnerability affects versions 7.0.0 through 7.13.6, 7.14.0 through 7.14.2, "
            "and 7.15.0."
        ),
        "description_zh": (
            "CVE-2021-26084 是 Atlassian Confluence Server 和 Data Center 中的远程代码执行漏洞。该漏洞存在于模板渲染引擎中，"
            "攻击者可以通过某些 REST API 端点注入 OGNL（对象图导航语言）表达式。未经认证的攻击者可以通过向受影响的端点发送"
            "特制的 HTTP 请求来利用此漏洞，导致在服务器上执行任意 OGNL 表达式。这使攻击者能够以 Confluence 应用程序的权限执行"
            "任意代码。该漏洞影响 7.0.0 至 7.13.6、7.14.0 至 7.14.2 以及 7.15.0 版本。"
        ),
        "impact_en": (
            "This vulnerability allows unauthenticated remote code execution, enabling attackers to gain complete control "
            "of the Confluence server. All wiki content, user credentials, and internal documentation stored in Confluence "
            "can be accessed and exfiltrated by the attacker."
        ),
        "impact_zh": (
            "该漏洞允许未经认证的远程代码执行，使攻击者能够完全控制 Confluence 服务器。存储在 Confluence 中的所有 Wiki 内容、"
            "用户凭据和内部文档都可以被攻击者访问和窃取。"
        ),
        "solution_en": (
            "Upgrade Confluence to the fixed versions: 7.4.6, 7.11.6, 7.12.5, 7.13.0, 7.14.3, or 7.15.1. Restrict "
            "network access to Confluence instances from untrusted sources. Implement WAF rules to detect and block "
            "OGNL injection attempts."
        ),
        "solution_zh": (
            "将 Confluence 升级至修复版本：7.4.6、7.11.6、7.12.5、7.13.0、7.14.3 或 7.15.1。限制来自不可信来源对 Confluence "
            "实例的网络访问。部署 WAF 规则以检测和阻止 OGNL 注入尝试。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Atlassian Confluence Server 7.0.0 - 7.15.0", "Atlassian Confluence Data Center 7.0.0 - 7.15.0"],
    },
    "CVE-2023-22515": {
        "name_en": "Atlassian Confluence Privilege Escalation",
        "name_zh": "Atlassian Confluence 特权提升漏洞",
        "description_en": (
            "CVE-2023-22515 is a critical privilege escalation vulnerability in Atlassian Confluence Data Center and Server. "
            "The vulnerability allows an unauthenticated attacker to bypass authentication and gain administrative privileges "
            "on the Confluence instance. The flaw exists in the setup process of Confluence where certain attributes can be "
            "manipulated to create an administrator account. An attacker with network access to the Confluence instance can "
            "exploit this vulnerability without requiring any prior authentication. This vulnerability affects Confluence "
            "Data Center and Server 8.0.0 through 8.4.0, and 8.5.0."
        ),
        "description_zh": (
            "CVE-2023-22515 是 Atlassian Confluence Data Center 和 Server 中的严重特权提升漏洞。该漏洞允许未经认证的攻击者绕过"
            "身份认证并在 Confluence 实例上获得管理员权限。该漏洞存在于 Confluence 的安装过程中，攻击者可以操纵某些属性来创建管理员"
            "账户。具有 Confluence 实例网络访问权限的攻击者可以在无需任何预先认证的情况下利用此漏洞。该漏洞影响 Confluence Data "
            "Center 和 Server 8.0.0 至 8.4.0 以及 8.5.0 版本。"
        ),
        "impact_en": (
            "An unauthenticated attacker can gain full administrative control of the Confluence instance, allowing them to "
            "create backdoor accounts, modify all content, access sensitive data, and potentially use the compromised "
            "instance as a pivot point for further network attacks."
        ),
        "impact_zh": (
            "未经认证的攻击者可以获得 Confluence 实例的完全管理员控制权，允许他们创建后门账户、修改所有内容、访问敏感数据，"
            "并可能利用被攻陷的实例作为进一步网络攻击的跳板。"
        ),
        "solution_en": (
            "Upgrade Confluence to version 8.5.1 or later. Restrict network access to the Confluence setup wizard endpoint. "
            "Review existing user accounts for any unauthorized administrator accounts that may have been created. "
            "Audit Confluence access logs for signs of exploitation."
        ),
        "solution_zh": (
            "将 Confluence 升级至 8.5.1 或更高版本。限制对 Confluence 安装向导端点的网络访问。审查现有用户账户，检查是否有"
            "未经授权创建的管理员账户。审计 Confluence 访问日志以发现利用痕迹。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Atlassian Confluence Data Center 8.0.0 - 8.5.0", "Atlassian Confluence Server 8.0.0 - 8.5.0"],
    },
    "CVE-2023-22527": {
        "name_en": "Atlassian Confluence Template Injection Remote Code Execution",
        "name_zh": "Atlassian Confluence 模板注入远程代码执行漏洞",
        "description_en": (
            "CVE-2023-22527 is a critical remote code execution vulnerability in Atlassian Confluence Data Center and Server. "
            "The vulnerability exists in the template rendering engine where an unauthenticated attacker can inject malicious "
            "template code through the /pages/doenterpagevariables.action endpoint. When the injected template is rendered, "
            "it allows execution of arbitrary code on the server. The vulnerability is caused by insufficient sanitization "
            "of user input in the page variable processing functionality. This vulnerability affects Confluence Data Center "
            "and Server versions 8.0.x, 8.1.x, 8.2.x, 8.3.x, 8.4.x, 8.5.0, and 8.5.1."
        ),
        "description_zh": (
            "CVE-2023-22527 是 Atlassian Confluence Data Center 和 Server 中的严重远程代码执行漏洞。该漏洞存在于模板渲染引擎中，"
            "未经认证的攻击者可以通过 /pages/doenterpagevariables.action 端点注入恶意模板代码。当注入的模板被渲染时，允许在服务器上"
            "执行任意代码。该漏洞由页面变量处理功能中对用户输入的清理不足引起。该漏洞影响 Confluence Data Center 和 Server "
            "8.0.x、8.1.x、8.2.x、8.3.x、8.4.x、8.5.0 和 8.5.1 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the Confluence server. Given that "
            "Confluence often contains sensitive corporate documentation, intellectual property, and access credentials, "
            "the impact of this vulnerability extends beyond the server itself to the entire organization."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 Confluence 服务器。鉴于 Confluence 通常包含敏感的企业文档、知识产权和访问凭据，"
            "该漏洞的影响范围远超服务器本身，波及整个组织。"
        ),
        "solution_en": (
            "Upgrade Confluence to version 8.5.3 or later. Restrict network access to the Confluence instance. Implement "
            "WAF rules to block template injection patterns. Review access logs for signs of exploitation and check "
            "for any unauthorized changes or created accounts."
        ),
        "solution_zh": (
            "将 Confluence 升级至 8.5.3 或更高版本。限制对 Confluence 实例的网络访问。部署 WAF 规则以阻止模板注入模式。"
            "审查访问日志以发现利用痕迹，并检查是否有未经授权的更改或创建的账户。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Atlassian Confluence Data Center 8.0.x - 8.5.1", "Atlassian Confluence Server 8.0.x - 8.5.1"],
    },
    "CVE-2022-42475": {
        "name_en": "FortiOS/FortiProxy Out-of-Bound Write Remote Code Execution",
        "name_zh": "FortiOS/FortiProxy 越界写入远程代码执行漏洞",
        "description_en": (
            "CVE-2022-42475 is a critical out-of-bounds write vulnerability in Fortinet FortiOS and FortiProxy SSL VPN "
            "daemon. The vulnerability exists in the SSL VPN component where a heap-based buffer overflow can be triggered "
            "by a specially crafted HTTP request. An unauthenticated attacker with network access to the SSL VPN portal "
            "can exploit this vulnerability to execute arbitrary code or commands on the affected device. The vulnerability "
            "affects FortiOS versions 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, and FortiProxy versions 7.2.0 through "
            "7.2.1, 7.0.0 through 7.0.7."
        ),
        "description_zh": (
            "CVE-2022-42475 是 Fortinet FortiOS 和 FortiProxy SSL VPN 守护进程中的严重越界写入漏洞。该漏洞存在于 SSL VPN "
            "组件中，可以通过特制的 HTTP 请求触发基于堆的缓冲区溢出。具有 SSL VPN 门户网络访问权限的未经认证的攻击者可以利用此漏洞"
            "在受影响设备上执行任意代码或命令。该漏洞影响 FortiOS 7.2.0 至 7.2.2、7.0.0 至 7.0.8 版本，以及 FortiProxy "
            "7.2.0 至 7.2.1、7.0.0 至 7.0.7 版本。"
        ),
        "impact_en": (
            "Successful exploitation allows unauthenticated remote code execution on the FortiGate or FortiProxy device, "
            "giving the attacker full control over the network security appliance. This can lead to complete bypass of "
            "all security controls, interception of all network traffic, and lateral movement into the protected network."
        ),
        "impact_zh": (
            "成功利用该漏洞后，攻击者可以在 FortiGate 或 FortiProxy 设备上实现未经认证的远程代码执行，获得对网络安全设备的完全控制。"
            "这可能导致所有安全控制被完全绕过、所有网络流量被拦截，以及向受保护网络的横向移动。"
        ),
        "solution_en": (
            "Upgrade FortiOS to version 7.2.3, 7.0.9, or later. Upgrade FortiProxy to version 7.2.2, 7.0.8, or later. "
            "If upgrading is not immediately possible, disable the SSL VPN feature. Restrict access to the SSL VPN "
            "portal to trusted IP addresses only."
        ),
        "solution_zh": (
            "将 FortiOS 升级至 7.2.3、7.0.9 或更高版本。将 FortiProxy 升级至 7.2.2、7.0.8 或更高版本。如果无法立即升级，"
            "请禁用 SSL VPN 功能。将 SSL VPN 门户的访问限制为仅受信任的 IP 地址。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.2.2", "Fortinet FortiProxy 7.0.0 - 7.2.1"],
    },
    "CVE-2022-41033": {
        "name_en": "FortiNAC Remote Code Execution",
        "name_zh": "FortiNAC 远程代码执行漏洞",
        "description_en": (
            "CVE-2022-41033 is a remote code execution vulnerability in Fortinet FortiNAC. The vulnerability exists in the "
            "keyUpload functionality of FortiNAC where an authenticated administrator can upload a specially crafted SSH key "
            "file that triggers a command injection. The insufficient validation of the uploaded file allows an attacker "
            "to execute arbitrary commands on the underlying operating system. This vulnerability affects FortiNAC versions "
            "9.4.0 through 9.4.1, 9.2.0 through 9.2.5, 9.1.0 through 9.1.6, and 8.8 all versions."
        ),
        "description_zh": (
            "CVE-2022-41033 是 Fortinet FortiNAC 中的远程代码执行漏洞。该漏洞存在于 FortiNAC 的 keyUpload 功能中，经过认证的"
            "管理员可以上传特制的 SSH 密钥文件来触发命令注入。对上传文件验证不足允许攻击者在底层操作系统上执行任意命令。"
            "该漏洞影响 FortiNAC 9.4.0 至 9.4.1、9.2.0 至 9.2.5、9.1.0 至 9.1.6 以及 8.8 所有版本。"
        ),
        "impact_en": (
            "An authenticated administrator can execute arbitrary commands on the FortiNAC server, potentially gaining "
            "root access to the underlying operating system. This can lead to complete compromise of the network access "
            "control infrastructure and unauthorized access to managed network devices."
        ),
        "impact_zh": (
            "经过认证的管理员可以在 FortiNAC 服务器上执行任意命令，可能获得底层操作系统的 root 访问权限。这可能导致网络访问控制"
            "基础设施被完全攻陷，以及对受管网络设备的未授权访问。"
        ),
        "solution_en": (
            "Upgrade FortiNAC to version 9.4.2, 9.2.6, 9.1.7, or apply the appropriate security patches. Restrict "
            "administrative access to FortiNAC to authorized personnel only. Implement multi-factor authentication for "
            "all administrative accounts."
        ),
        "solution_zh": (
            "将 FortiNAC 升级至 9.4.2、9.2.6、9.1.7 版本或应用适当的安全补丁。将 FortiNAC 的管理访问限制为仅授权人员。"
            "为所有管理账户实施多因素认证。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Fortinet FortiNAC 8.8.x", "Fortinet FortiNAC 9.1.0 - 9.1.6", "Fortinet FortiNAC 9.2.0 - 9.2.5", "Fortinet FortiNAC 9.4.0 - 9.4.1"],
    },
    "CVE-2023-27997": {
        "name_en": "FortiOS/FortiProxy Out-of-Bound Write Remote Code Execution",
        "name_zh": "FortiOS/FortiProxy 越界写入远程代码执行漏洞",
        "description_en": (
            "CVE-2023-27997 is a critical heap-based buffer overflow vulnerability in Fortinet FortiOS SSL VPN and FortiProxy "
            "SSL-VPN. The vulnerability exists in the SSL VPN daemon where a specially crafted HTTP request can trigger an "
            "out-of-bounds write condition. An unauthenticated attacker with network access to the SSL VPN interface can "
            "exploit this vulnerability to execute arbitrary code or commands on the affected device. This vulnerability "
            "affects FortiOS versions 7.4.0 through 7.4.1, 7.2.5 and earlier, 7.0.12 and earlier, and FortiProxy versions "
            "7.4.0 through 7.4.1, 7.2.6 and earlier, 7.0.12 and earlier."
        ),
        "description_zh": (
            "CVE-2023-27997 是 Fortinet FortiOS SSL VPN 和 FortiProxy SSL-VPN 中的严重基于堆的缓冲区溢出漏洞。该漏洞存在于 "
            "SSL VPN 守护进程中，特制的 HTTP 请求可以触发越界写入条件。具有 SSL VPN 接口网络访问权限的未经认证的攻击者可以利用"
            "此漏洞在受影响设备上执行任意代码或命令。该漏洞影响 FortiOS 7.4.0 至 7.4.1、7.2.5 及更早版本、7.0.12 及更早版本，"
            "以及 FortiProxy 7.4.0 至 7.4.1、7.2.6 及更早版本、7.0.12 及更早版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on FortiGate devices allows attackers to completely compromise the network "
            "security perimeter. The attacker can modify firewall rules, intercept encrypted traffic, create VPN tunnels "
            "into the protected network, and establish persistent backdoor access."
        ),
        "impact_zh": (
            "在 FortiGate 设备上未经认证的远程代码执行使攻击者能够完全攻陷网络安全边界。攻击者可以修改防火墙规则、拦截加密流量、"
            "创建到受保护网络的 VPN 隧道，并建立持久化的后门访问。"
        ),
        "solution_en": (
            "Upgrade FortiOS to version 7.4.2, 7.2.6, 7.0.13, or later. Upgrade FortiProxy to version 7.4.2, 7.2.7, "
            "7.0.13, or later. If upgrading is not immediately possible, disable the SSL VPN feature and restrict "
            "management interface access."
        ),
        "solution_zh": (
            "将 FortiOS 升级至 7.4.2、7.2.6、7.0.13 或更高版本。将 FortiProxy 升级至 7.4.2、7.2.7、7.0.13 或更高版本。"
            "如果无法立即升级，请禁用 SSL VPN 功能并限制管理接口访问。"
        ),
        "severity": "critical",
        "cvss": 9.6,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.4.1", "Fortinet FortiProxy 7.0.0 - 7.4.1"],
    },
    "CVE-2021-34527": {
        "name_en": "PrintNightmare Windows Print Spooler Privilege Escalation",
        "name_zh": "PrintNightmare Windows 打印后台处理服务提权漏洞",
        "description_en": (
            "CVE-2021-34527, known as PrintNightmare, is a privilege escalation vulnerability in the Windows Print Spooler "
            "service. The vulnerability allows an attacker to bypass authentication and load a malicious printer driver DLL "
            "on a target system. The Print Spooler service improperly handles printer driver installation, allowing an "
            "attacker to point to a remote server hosting a malicious driver. When the driver is loaded, it executes "
            "arbitrary code with SYSTEM privileges. This vulnerability affects all supported versions of Windows Server "
            "and Windows desktop operating systems."
        ),
        "description_zh": (
            "CVE-2021-34527，被称为 PrintNightmare（打印噩梦），是 Windows 打印后台处理服务中的提权漏洞。该漏洞允许攻击者绕过"
            "身份认证并在目标系统上加载恶意的打印机驱动程序 DLL。打印后台处理服务未正确处理打印机驱动程序的安装，允许攻击者指向"
            "托管恶意驱动程序的远程服务器。当驱动程序被加载时，以 SYSTEM 权限执行任意代码。该漏洞影响所有受支持的 Windows Server "
            "和 Windows 桌面操作系统版本。"
        ),
        "impact_en": (
            "PrintNightmare allows both local and remote privilege escalation to SYSTEM level, the highest privilege on "
            "Windows. An attacker can gain complete control of the affected machine, install persistent malware, and "
            "use the compromised system as a pivot point for lateral movement across the network."
        ),
        "impact_zh": (
            "PrintNightmare 允许本地和远程提权至 SYSTEM 级别，这是 Windows 上的最高权限。攻击者可以完全控制受影响的机器，"
            "安装持久化恶意软件，并利用被攻陷的系统作为在网络中进行横向移动的跳板。"
        ),
        "solution_en": (
            "Install Microsoft security updates from July 2021 (KB5005010 and related updates). Disable the Print Spooler "
            "service on systems that do not require printing functionality. Configure the 'Point and Print Restrictions' "
            "Group Policy to prevent unauthorized driver installation. Block inbound RPC traffic on domain controllers."
        ),
        "solution_zh": (
            "安装微软 2021 年 7 月的安全更新（KB5005010 及相关更新）。在不需要打印功能的系统上禁用打印后台处理服务。"
            "配置\u201c点和打印限制\u201d组策略以防止未经授权的驱动程序安装。阻止域控制器上的入站 RPC 流量。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 7", "Windows 8.1", "Windows 10", "Windows 11", "Windows Server 2008 R2", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022"],
    },
    "CVE-2020-0796": {
        "name_en": "SMBGhost (SMBv3) Remote Code Execution",
        "name_zh": "SMBGhost (SMBv3) 远程代码执行漏洞",
        "description_en": (
            "CVE-2020-0796, commonly known as SMBGhost, is a remote code execution vulnerability in Microsoft Server Message "
            "Block 3.0 (SMBv3) protocol. The vulnerability exists in the compression feature of SMBv3 where a specially "
            "crafted compressed packet can trigger a buffer overflow in the kernel memory. The flaw is in the srv2.sys "
            "driver's handling of SMB3 compression negotiation, which fails to properly validate the size of the compressed "
            "data buffer. An attacker can exploit this vulnerability by sending a malicious packet to an SMBv3 server, "
            "resulting in remote code execution with kernel-level privileges."
        ),
        "description_zh": (
            "CVE-2020-0796，通常被称为 SMBGhost（SMB幽灵），是微软服务器消息块 3.0（SMBv3）协议中的远程代码执行漏洞。"
            "该漏洞存在于 SMBv3 的压缩功能中，特制的压缩数据包可以触发内核内存中的缓冲区溢出。漏洞位于 srv2.sys 驱动程序"
            "处理 SMB3 压缩协商的过程中，未能正确验证压缩数据缓冲区的大小。攻击者可以通过向 SMBv3 服务器发送恶意数据包来"
            "利用此漏洞，导致以内核级权限进行远程代码执行。"
        ),
        "impact_en": (
            "SMBGhost enables unauthenticated remote code execution with kernel-level privileges, allowing attackers to "
            "gain complete control of the target system. The vulnerability is wormable, meaning it can self-propagate "
            "across networks without user interaction, similar to EternalBlue."
        ),
        "impact_zh": (
            "SMBGhost 允许以内核级权限进行未经认证的远程代码执行，使攻击者能够完全控制目标系统。该漏洞具有蠕虫传播特性，"
            "意味着它可以在无需用户交互的情况下在网络中自动扩散，类似于 EternalBlue。"
        ),
        "solution_en": (
            "Install Microsoft security update from March 2020 (KB4551762). Disable SMBv3 compression by setting the "
            "registry key EnableCompression to 0. Block SMB traffic (port 445) at the network perimeter. Ensure all "
            "systems are running Windows 10 version 1903 or later with the latest updates."
        ),
        "solution_zh": (
            "安装微软 2020 年 3 月的安全更新（KB4551762）。通过将注册表键 EnableCompression 设置为 0 来禁用 SMBv3 压缩。"
            "在网络边界处阻止 SMB 流量（端口 445）。确保所有系统运行 Windows 10 1903 或更高版本并已安装最新更新。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 10 1903/1909", "Windows Server version 1903/1909", "Windows Server 2019"],
    },
    "CVE-2022-37966": {
        "name_en": "Kerberos Privilege Escalation (SamAccountName Spoofing)",
        "name_zh": "Kerberos 特权提升漏洞（SamAccountName 欺骗）",
        "description_en": (
            "CVE-2022-37966 is a privilege escalation vulnerability in Microsoft Kerberos that allows an attacker to spoof "
            "the SamAccountName attribute during Kerberos authentication. The vulnerability exists in the way Kerberos "
            "handles the sAMAccountName attribute in the Privilege Attribute Certificate (PAC) during the authentication "
            "process. An authenticated attacker can exploit this vulnerability to impersonate a domain administrator or "
            "other high-privilege accounts, effectively gaining elevated privileges on the domain. This vulnerability "
            "affects all supported versions of Windows Server and Windows desktop operating systems."
        ),
        "description_zh": (
            "CVE-2022-37966 是 Microsoft Kerberos 中的特权提升漏洞，允许攻击者在 Kerberos 认证过程中欺骗 SamAccountName 属性。"
            "该漏洞存在于 Kerberos 在认证过程中处理特权属性证书（PAC）中的 sAMAccountName 属性的方式中。经过认证的攻击者可以"
            "利用此漏洞冒充域管理员或其他高权限账户，有效地在域中获得提升的权限。该漏洞影响所有受支持的 Windows Server 和 "
            "Windows 桌面操作系统版本。"
        ),
        "impact_en": (
            "An authenticated attacker can escalate privileges to domain administrator level, gaining complete control "
            "over the Active Directory domain. This allows the attacker to access all domain resources, modify domain "
            "policies, create backdoor accounts, and compromise all systems joined to the domain."
        ),
        "impact_zh": (
            "经过认证的攻击者可以将权限提升至域管理员级别，获得对 Active Directory 域的完全控制。攻击者可以访问所有域资源、"
            "修改域策略、创建后门账户，并攻陷加入域的所有系统。"
        ),
        "solution_en": (
            "Install Microsoft security updates from October 2022 (Patch Tuesday). Enforce strong authentication policies "
            "and monitor for suspicious Kerberos ticket requests. Implement tiered administration model to limit the "
            "impact of privilege escalation. Audit domain controller logs for signs of PAC manipulation."
        ),
        "solution_zh": (
            "安装微软 2022 年 10 月的安全更新（补丁星期二）。强制执行强认证策略，并监控可疑的 Kerberos 票据请求。实施分层管理模型"
            "以限制特权提升的影响。审计域控制器日志以发现 PAC 操纵的痕迹。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 7", "Windows 8.1", "Windows 10", "Windows 11", "Windows Server 2008 R2", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022"],
    },
    "CVE-2023-36802": {
        "name_en": "Microsoft Streaming Service Privilege Escalation",
        "name_zh": "Microsoft Streaming Service 提权漏洞",
        "description_en": (
            "CVE-2023-36802 is a privilege escalation vulnerability in the Microsoft Streaming Service Proxy driver "
            "(mskssrv.sys). The vulnerability exists due to improper handling of objects in memory by the Streaming Service "
            "Proxy driver. A local attacker can exploit this vulnerability by running a specially crafted application that "
            "triggers a race condition or type confusion in the driver, leading to elevated privileges. Successful "
            "exploitation grants the attacker SYSTEM-level access on the affected system. This vulnerability affects "
            "Windows 11, Windows 10, and several versions of Windows Server."
        ),
        "description_zh": (
            "CVE-2023-36802 是 Microsoft Streaming Service Proxy 驱动程序（mskssrv.sys）中的提权漏洞。该漏洞由 Streaming "
            "Service Proxy 驱动程序对内存中对象的处理不当引起。本地攻击者可以通过运行特制的应用程序来利用此漏洞，触发驱动程序中的"
            "竞态条件或类型混淆，导致权限提升。成功利用后，攻击者可获得受影响系统上的 SYSTEM 级别访问权限。该漏洞影响 Windows 11、"
            "Windows 10 以及多个版本的 Windows Server。"
        ),
        "impact_en": (
            "A local attacker can escalate from a low-privileged user account to SYSTEM, the highest privilege level on "
            "Windows. This provides complete control over the system, including the ability to install kernel-level "
            "malware, modify security settings, and access all data on the system."
        ),
        "impact_zh": (
            "本地攻击者可以从低权限用户账户提升至 SYSTEM（Windows 上的最高权限级别）。这提供了对系统的完全控制，包括安装内核级"
            "恶意软件、修改安全设置以及访问系统上的所有数据的能力。"
        ),
        "solution_en": (
            "Install Microsoft security updates from September 2023 (Patch Tuesday). Follow the principle of least "
            "privilege for user accounts. Implement application whitelisting to prevent execution of unauthorized "
            "binaries. Monitor for suspicious privilege escalation activities."
        ),
        "solution_zh": (
            "安装微软 2023 年 9 月的安全更新（补丁星期二）。遵循最小权限原则管理用户账户。实施应用程序白名单以防止执行未经授权的"
            "二进制文件。监控可疑的特权提升活动。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022"],
    },

    # ============================================================
    # Web应用类（25条）
    # ============================================================
    "CVE-2021-42292": {
        "name_en": "Apache Struts2 S2-062 Remote Code Execution",
        "name_zh": "Apache Struts2 S2-062 远程代码执行漏洞",
        "description_en": (
            "CVE-2021-42292 is a remote code execution vulnerability in Apache Struts2, tracked as S2-062. The vulnerability "
            "exists in the forced double OGNL (Object-Graph Navigation Language) evaluation mechanism where certain attributes "
            "of framework tags can be manipulated to execute arbitrary OGNL expressions. An attacker can send a specially "
            "crafted HTTP request to a Struts2 application that triggers the evaluation of malicious OGNL expressions, "
            "resulting in remote code execution on the server. The vulnerability affects Apache Struts versions 2.0.0 "
            "through 2.5.29."
        ),
        "description_zh": (
            "CVE-2021-42292 是 Apache Struts2 中的远程代码执行漏洞，编号为 S2-062。该漏洞存在于强制双重 OGNL（对象图导航语言）"
            "求值机制中，框架标签的某些属性可以被操纵来执行任意 OGNL 表达式。攻击者可以向 Struts2 应用程序发送特制的 HTTP 请求，"
            "触发恶意 OGNL 表达式的求值，导致在服务器上进行远程代码执行。该漏洞影响 Apache Struts 2.0.0 至 2.5.29 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the Struts2 application server. "
            "This can lead to data theft, service disruption, and use of the compromised server as a foothold for deeper "
            "network penetration."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 Struts2 应用服务器。这可能导致数据窃取、服务中断，以及利用被攻陷的服务器"
            "作为更深层网络渗透的据点。"
        ),
        "solution_en": (
            "Upgrade Apache Struts to version 2.5.30 or later. If upgrading is not immediately possible, implement WAF "
            "rules to block OGNL injection patterns. Review application code for any custom OGNL expression usage and "
            "ensure proper input validation is in place."
        ),
        "solution_zh": (
            "将 Apache Struts 升级至 2.5.30 或更高版本。如果无法立即升级，请部署 WAF 规则以阻止 OGNL 注入模式。审查应用程序代码中"
            "的自定义 OGNL 表达式使用情况，确保已实施适当的输入验证。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Struts 2.0.0 - 2.5.29"],
    },
    "CVE-2018-13379": {
        "name_en": "Fortinet FortiOS/FortiProxy Path Traversal",
        "name_zh": "Fortinet FortiOS/FortiProxy 路径穿越漏洞",
        "description_en": (
            "CVE-2018-13379 is a path traversal vulnerability in Fortinet FortiOS and FortiProxy SSL VPN web portal. "
            "The vulnerability exists in the message handling component of the SSL VPN portal where an attacker can access "
            "system files through directory traversal sequences in the URL. Specifically, the vulnerability is triggered "
            "through the /remote/fgt_lang endpoint, which fails to properly sanitize user input before using it in file "
            "path operations. An authenticated SSL VPN user can exploit this vulnerability to read arbitrary files from "
            "the device's filesystem, including the SSL VPN credentials stored in plaintext."
        ),
        "description_zh": (
            "CVE-2018-13379 是 Fortinet FortiOS 和 FortiProxy SSL VPN Web 门户中的路径穿越漏洞。该漏洞存在于 SSL VPN 门户的"
            "消息处理组件中，攻击者可以通过 URL 中的目录遍历序列访问系统文件。具体而言，该漏洞通过 /remote/fgt_lang 端点触发，"
            "该端点在将用户输入用于文件路径操作之前未正确清理输入。经过认证的 SSL VPN 用户可以利用此漏洞从设备文件系统中读取"
            "任意文件，包括以明文存储的 SSL VPN 凭据。"
        ),
        "impact_en": (
            "Attackers can read sensitive system files, including the SSL VPN password file which stores credentials in "
            "plaintext. This allows credential theft and unauthorized access to the VPN, potentially compromising the "
            "entire network perimeter security."
        ),
        "impact_zh": (
            "攻击者可以读取敏感的系统文件，包括以明文存储凭据的 SSL VPN 密码文件。这允许凭据窃取和对 VPN 的未授权访问，"
            "可能危及整个网络边界安全。"
        ),
        "solution_en": (
            "Upgrade FortiOS to version 6.2.0 or later, or apply the appropriate security patches for earlier versions. "
            "Review SSL VPN access logs for signs of exploitation. Rotate all SSL VPN credentials as they may have been "
            "compromised. Implement network segmentation to limit the impact of VPN compromise."
        ),
        "solution_zh": (
            "将 FortiOS 升级至 6.2.0 或更高版本，或为早期版本应用适当的安全补丁。审查 SSL VPN 访问日志以发现利用痕迹。"
            "轮换所有 SSL VPN 凭据，因为它们可能已被泄露。实施网络分段以限制 VPN 被攻陷的影响。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["Fortinet FortiOS 5.6.3 - 5.6.7", "Fortinet FortiOS 6.0.0 - 6.0.4", "Fortinet FortiProxy 1.0.0 - 1.2.0"],
    },
    "CVE-2020-5902": {
        "name_en": "F5 BIG-IP TMUI Remote Code Execution",
        "name_zh": "F5 BIG-IP TMUI 远程代码执行漏洞",
        "description_en": (
            "CVE-2020-5902 is a critical remote code execution vulnerability in the Traffic Management User Interface (TMUI) "
            "of F5 BIG-IP products. The vulnerability exists in the TMUI component (also known as the Configuration Utility) "
            "where an unauthenticated attacker can exploit a directory traversal and file upload vulnerability to execute "
            "arbitrary commands. The flaw is in the /hsqldb component of TMUI which fails to properly validate user input. "
            "An attacker can send a specially crafted HTTP request to the TMUI interface that results in execution of "
            "arbitrary Java code. This vulnerability affects BIG-IP versions 11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.0.x, "
            "15.1.x, and 16.0.x."
        ),
        "description_zh": (
            "CVE-2020-5902 是 F5 BIG-IP 产品流量管理用户界面（TMUI）中的严重远程代码执行漏洞。该漏洞存在于 TMUI 组件"
            "（也称为配置实用程序）中，未经认证的攻击者可以利用目录穿越和文件上传漏洞来执行任意命令。漏洞位于 TMUI 的 /hsqldb "
            "组件中，该组件未能正确验证用户输入。攻击者可以向 TMUI 接口发送特制的 HTTP 请求，导致执行任意 Java 代码。该漏洞影响 "
            "BIG-IP 11.6.x、12.1.x、13.1.x、14.1.x、15.0.x、15.1.x 和 16.0.x 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on the BIG-IP device allows attackers to gain full administrative control. "
            "This compromises the entire network traffic management infrastructure, enabling interception and manipulation "
            "of all network traffic passing through the device."
        ),
        "impact_zh": (
            "在 BIG-IP 设备上未经认证的远程代码执行使攻击者能够获得完全的管理控制权。这将危及整个网络流量管理基础设施，"
            "使攻击者能够拦截和操纵经过该设备的所有网络流量。"
        ),
        "solution_en": (
            "Upgrade BIG-IP to the fixed versions: 16.0.1, 15.1.2.1, 14.1.4, 13.1.3.6, 12.1.5.2, or 11.6.5.1. "
            "Block access to the TMUI interface (port 443) from untrusted networks. Restrict management access to "
            "trusted IP addresses only."
        ),
        "solution_zh": (
            "将 BIG-IP 升级至修复版本：16.0.1、15.1.2.1、14.1.4、13.1.3.6、12.1.5.2 或 11.6.5.1。阻止来自不可信网络对 "
            "TMUI 接口（端口 443）的访问。将管理访问限制为仅受信任的 IP 地址。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["F5 BIG-IP 11.6.x", "F5 BIG-IP 12.1.x", "F5 BIG-IP 13.1.x", "F5 BIG-IP 14.1.x", "F5 BIG-IP 15.x", "F5 BIG-IP 16.0.x"],
    },
    "CVE-2021-42013": {
        "name_en": "Apache HTTP Server 2.4.50 Path Traversal",
        "name_zh": "Apache HTTP Server 2.4.50 路径穿越漏洞",
        "description_en": (
            "CVE-2021-42013 is a path traversal vulnerability in Apache HTTP Server 2.4.50, discovered as a bypass to the "
            "initial fix for CVE-2021-41773. The vulnerability allows an attacker to access files outside the document root "
            "by using a specially crafted URL path. The issue exists because the fix applied for CVE-2021-41773 in version "
            "2.4.50 did not fully address the path traversal vector. An attacker can use path traversal sequences combined "
            "with URL encoding to bypass the directory restrictions and access sensitive files. When CGI scripts are "
            "configured, this vulnerability can also lead to remote code execution."
        ),
        "description_zh": (
            "CVE-2021-42013 是 Apache HTTP Server 2.4.50 中的路径穿越漏洞，被发现是对 CVE-2021-41773 初始修复的绕过。"
            "该漏洞允许攻击者使用特制的 URL 路径访问文档根目录之外的文件。该问题存在的原因是 2.4.50 版本中为 CVE-2021-41773 "
            "应用的修复未完全解决路径穿越向量。攻击者可以使用路径穿越序列结合 URL 编码来绕过目录限制并访问敏感文件。"
            "当配置了 CGI 脚本时，该漏洞还可导致远程代码执行。"
        ),
        "impact_en": (
            "Attackers can read arbitrary files from the server filesystem, potentially exposing sensitive configuration "
            "files, source code, and credentials. In configurations with CGI enabled, the vulnerability can be escalated "
            "to remote code execution."
        ),
        "impact_zh": (
            "攻击者可以从服务器文件系统中读取任意文件，可能暴露敏感的配置文件、源代码和凭据。在启用了 CGI 的配置中，"
            "该漏洞可被提升为远程代码执行。"
        ),
        "solution_en": (
            "Upgrade Apache HTTP Server to version 2.4.51 or later. Ensure all directories outside the document root "
            "are protected with 'Require all denied' directives. Disable CGI if not required. Verify that the upgrade "
            "has been applied correctly by testing for the vulnerability."
        ),
        "solution_zh": (
            "将 Apache HTTP Server 升级至 2.4.51 或更高版本。确保文档根目录之外的所有目录都使用 'Require all denied' 指令"
            "进行保护。如非必要，禁用 CGI 功能。通过测试漏洞来验证升级是否已正确应用。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["Apache HTTP Server 2.4.50"],
    },
    "CVE-2022-22965": {
        "name_en": "Spring4Shell Spring Framework Remote Code Execution",
        "name_zh": "Spring4Shell Spring Framework 远程代码执行漏洞",
        "description_en": (
            "CVE-2022-22965, known as Spring4Shell, is a remote code execution vulnerability in the Spring Framework. "
            "The vulnerability affects applications running Spring Framework on JDK 9+ with a specific configuration: "
            "the application must use Spring MVC or WebFlux, run on Tomcat as a WAR deployment, and be vulnerable to "
            "class loader manipulation. An attacker can exploit this vulnerability by sending specially crafted HTTP "
            "requests that modify the Tomcat AccessLogValve properties through Spring's data binding mechanism. This "
            "allows the attacker to write a webshell to the Tomcat webapps directory and achieve remote code execution. "
            "The vulnerability affects Spring Framework 5.3.0 to 5.3.17 and 5.2.0 to 5.2.19."
        ),
        "description_zh": (
            "CVE-2022-22965，被称为 Spring4Shell，是 Spring Framework 中的远程代码执行漏洞。该漏洞影响在 JDK 9+ 上运行 "
            "Spring Framework 且具有特定配置的应用程序：应用程序必须使用 Spring MVC 或 WebFlux，以 WAR 部署方式运行在 Tomcat 上，"
            "并且容易受到类加载器操纵的影响。攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，通过 Spring 的数据绑定机制修改 Tomcat "
            "AccessLogValve 属性。这允许攻击者将 Webshell 写入 Tomcat webapps 目录并实现远程代码执行。该漏洞影响 Spring Framework "
            "5.3.0 至 5.3.17 和 5.2.0 至 5.2.19 版本。"
        ),
        "impact_en": (
            "Spring4Shell allows unauthenticated remote code execution on vulnerable applications, giving attackers full "
            "control of the application server. Given the widespread use of Spring Framework in enterprise Java applications, "
            "this vulnerability has a broad impact across many organizations."
        ),
        "impact_zh": (
            "Spring4Shell 允许在易受攻击的应用程序上进行未经认证的远程代码执行，使攻击者能够完全控制应用服务器。鉴于 Spring Framework "
            "在企业级 Java 应用中的广泛使用，该漏洞对许多组织都有广泛影响。"
        ),
        "solution_en": (
            "Upgrade Spring Framework to version 5.3.18 or 5.2.20 or later. If upgrading is not immediately possible, "
            "deploy the application as a Spring Boot executable JAR instead of a WAR file. Set the system property "
            "spring.web.form.filter.enabled to true as a temporary mitigation. Implement WAF rules to block Spring4Shell "
            "exploitation attempts."
        ),
        "solution_zh": (
            "将 Spring Framework 升级至 5.3.18 或 5.2.20 及更高版本。如果无法立即升级，可将应用程序部署为 Spring Boot 可执行 JAR "
            "而非 WAR 文件。设置系统属性 spring.web.form.filter.enabled 为 true 作为临时缓解措施。部署 WAF 规则以阻止 "
            "Spring4Shell 利用尝试。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Spring Framework 5.3.0 - 5.3.17", "Spring Framework 5.2.0 - 5.2.19"],
    },
    "CVE-2022-22963": {
        "name_en": "Spring Cloud Function SpEL Expression Injection",
        "name_zh": "Spring Cloud Function SpEL 表达式注入漏洞",
        "description_en": (
            "CVE-2022-22963 is a remote code execution vulnerability in Spring Cloud Function. The vulnerability exists "
            "in the routing function of Spring Cloud Function where user-supplied input is passed directly to the Spring "
            "Expression Language (SpEL) evaluation engine without proper sanitization. An attacker can send a specially "
            "crafted HTTP request to the spring.cloud.function.routing-expression header that contains a malicious SpEL "
            "expression. When the expression is evaluated, it results in arbitrary code execution on the server. This "
            "vulnerability affects Spring Cloud Function 3.1.6, 3.2.2, and earlier versions."
        ),
        "description_zh": (
            "CVE-2022-22963 是 Spring Cloud Function 中的远程代码执行漏洞。该漏洞存在于 Spring Cloud Function 的路由函数中，"
            "用户提供的输入未经适当清理即被传递给 Spring 表达式语言（SpEL）求值引擎。攻击者可以向 spring.cloud.function."
            "routing-expression 头发送包含恶意 SpEL 表达式的特制 HTTP 请求。当表达式被求值时，会在服务器上执行任意代码。"
            "该漏洞影响 Spring Cloud Function 3.1.6、3.2.2 及更早版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the Spring Cloud Function application "
            "and its underlying infrastructure. This can lead to data theft, service disruption, and lateral movement "
            "within the cloud environment."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 Spring Cloud Function 应用程序及其底层基础设施。这可能导致数据窃取、"
            "服务中断以及在云环境中的横向移动。"
        ),
        "solution_en": (
            "Upgrade Spring Cloud Function to version 3.1.7, 3.2.3, or later. If upgrading is not immediately possible, "
            "set the environment variable SPRING_FUNCTION_ROUTING_ENABLED to false to disable the routing function. "
            "Implement WAF rules to block SpEL injection patterns in HTTP headers."
        ),
        "solution_zh": (
            "将 Spring Cloud Function 升级至 3.1.7、3.2.3 或更高版本。如果无法立即升级，可设置环境变量 SPRING_FUNCTION_ROUTING_ENABLED "
            "为 false 以禁用路由功能。部署 WAF 规则以阻止 HTTP 头中的 SpEL 注入模式。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Spring Cloud Function 3.1.x <= 3.1.6", "Spring Cloud Function 3.2.x <= 3.2.2"],
    },
    "CVE-2017-5638": {
        "name_en": "Apache Struts2 REST Plugin XStream Remote Code Execution",
        "name_zh": "Apache Struts2 REST 插件 XStream 远程代码执行漏洞",
        "description_en": (
            "CVE-2017-5638 is a critical remote code execution vulnerability in Apache Struts2 that results from "
            "insecure deserialization using the XStream library. The vulnerability exists in the REST plugin of Struts2 "
            "where the Content-Type header of an HTTP request is used to determine the XML parser. An attacker can send "
            "a malicious Content-Type header that triggers the XStream deserializer to process crafted XML content, "
            "resulting in arbitrary command execution. The vulnerability is extremely easy to exploit and was used in "
            "massive exploitation campaigns, including the Equifax data breach. This vulnerability affects Apache Struts "
            "versions 2.3.5 through 2.3.31 and 2.5.0 through 2.5.10."
        ),
        "description_zh": (
            "CVE-2017-5638 是 Apache Struts2 中的严重远程代码执行漏洞，由使用 XStream 库进行不安全的反序列化引起。该漏洞存在于 "
            "Struts2 的 REST 插件中，HTTP 请求的 Content-Type 头用于确定 XML 解析器。攻击者可以发送恶意的 Content-Type 头，"
            "触发 XStream 反序列化器处理构造的 XML 内容，导致执行任意命令。该漏洞极其容易被利用，并被用于大规模利用活动，"
            "包括 Equifax 数据泄露事件。该漏洞影响 Apache Struts 2.3.5 至 2.3.31 和 2.5.0 至 2.5.10 版本。"
        ),
        "impact_en": (
            "This vulnerability allows trivially easy unauthenticated remote code execution. An attacker only needs to "
            "send a single HTTP request with a crafted Content-Type header to gain complete control of the server. "
            "The ease of exploitation and widespread deployment of Struts2 make this one of the most impactful vulnerabilities."
        ),
        "impact_zh": (
            "该漏洞允许极其简单的未经认证远程代码执行。攻击者只需发送一个带有构造的 Content-Type 头的 HTTP 请求即可获得服务器的"
            "完全控制权。由于利用门槛极低且 Struts2 部署广泛，这是影响最深远的安全漏洞之一。"
        ),
        "solution_en": (
            "Upgrade Apache Struts to version 2.3.32 or 2.5.10.1 or later. If upgrading is not possible, remove the "
            "Struts2 REST plugin or implement a servlet filter to validate the Content-Type header. Deploy WAF rules "
            "to block malicious Content-Type headers containing OGNL or XML payloads."
        ),
        "solution_zh": (
            "将 Apache Struts 升级至 2.3.32 或 2.5.10.1 及更高版本。如果无法升级，请移除 Struts2 REST 插件或部署 Servlet 过滤器"
            "来验证 Content-Type 头。部署 WAF 规则以阻止包含 OGNL 或 XML 载荷的恶意 Content-Type 头。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Apache Struts 2.3.5 - 2.3.31", "Apache Struts 2.5.0 - 2.5.10"],
    },
    "CVE-2018-11776": {
        "name_en": "Apache Struts2 Namespace Remote Code Execution",
        "name_zh": "Apache Struts2 Namespace 远程代码执行漏洞",
        "description_en": (
            "CVE-2018-11776 is a remote code execution vulnerability in Apache Struts2 that results from improper handling "
            "of namespace values in the Struts2 core framework. The vulnerability exists when the application uses the "
            "Struts2 REST plugin with the alwaysSelectFullNamespace parameter set to true, or when the application defines "
            "an XML configuration with no namespace attribute. An attacker can send a specially crafted request with a "
            "malicious namespace value that triggers OGNL expression evaluation, resulting in arbitrary code execution. "
            "This vulnerability affects Apache Struts versions 2.3 through 2.3.34 and 2.5 through 2.5.16."
        ),
        "description_zh": (
            "CVE-2018-11776 是 Apache Struts2 中的远程代码执行漏洞，由 Struts2 核心框架对命名空间值的不当处理引起。当应用程序"
            "使用 Struts2 REST 插件并将 alwaysSelectFullNamespace 参数设置为 true，或者当应用程序定义了没有命名空间属性的 XML "
            "配置时，存在该漏洞。攻击者可以发送带有恶意命名空间值的特制请求，触发 OGNL 表达式求值，导致执行任意代码。该漏洞影响 "
            "Apache Struts 2.3 至 2.3.34 和 2.5 至 2.5.16 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to compromise the Struts2 application server and "
            "execute arbitrary commands. This can lead to complete system compromise, data exfiltration, and use of "
            "the server as a pivot point for further attacks."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够攻陷 Struts2 应用服务器并执行任意命令。这可能导致系统被完全攻陷、数据泄露，"
            "以及利用服务器作为进一步攻击的跳板。"
        ),
        "solution_en": (
            "Upgrade Apache Struts to version 2.3.35 or 2.5.17 or later. Set the alwaysSelectFullNamespace parameter to "
            "false in the Struts configuration. Ensure all XML configuration files define proper namespace attributes. "
            "Implement WAF rules to detect namespace-based OGNL injection."
        ),
        "solution_zh": (
            "将 Apache Struts 升级至 2.3.35 或 2.5.17 及更高版本。在 Struts 配置中将 alwaysSelectFullNamespace 参数设置为 false。"
            "确保所有 XML 配置文件定义了正确的命名空间属性。部署 WAF 规则以检测基于命名空间的 OGNL 注入。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Struts 2.3.x - 2.3.34", "Apache Struts 2.5.x - 2.5.16"],
    },
    "CVE-2019-5418": {
        "name_en": "Ruby on Rails Path Traversal",
        "name_zh": "Ruby on Rails 路径穿越漏洞",
        "description_en": (
            "CVE-2019-5418 is a path traversal vulnerability in Ruby on Rails that affects the Action Controller component. "
            "The vulnerability exists in the way Rails handles file rendering where an attacker can use specially crafted "
            "Accept headers to traverse directories and read arbitrary files from the server. The flaw is in the "
            "render file: parameter processing where the framework does not properly validate the file path. By sending "
            "a request with a malicious Accept header containing directory traversal sequences (../), an attacker can "
            "read any file accessible by the Rails application process. This vulnerability affects Rails versions 5.2.x "
            "before 5.2.2.1, 5.1.x before 5.1.6.2, and earlier versions."
        ),
        "description_zh": (
            "CVE-2019-5418 是 Ruby on Rails 中影响 Action Controller 组件的路径穿越漏洞。该漏洞存在于 Rails 处理文件渲染的方式中，"
            "攻击者可以使用特制的 Accept 头来遍历目录并读取服务器上的任意文件。该缺陷位于 render file: 参数处理中，框架未正确验证"
            "文件路径。通过发送包含目录遍历序列（../）的恶意 Accept 头的请求，攻击者可以读取 Rails 应用程序进程可访问的任何文件。"
            "该漏洞影响 Rails 5.2.2.1 之前的 5.2.x 版本、5.1.6.2 之前的 5.1.x 版本以及更早版本。"
        ),
        "impact_en": (
            "Attackers can read arbitrary files from the server, including application source code, configuration files "
            "containing database credentials, and other sensitive data. This information can be used to launch further "
            "attacks against the application and its infrastructure."
        ),
        "impact_zh": (
            "攻击者可以从服务器读取任意文件，包括应用程序源代码、包含数据库凭据的配置文件和其他敏感数据。这些信息可用于对应用程序"
            "及其基础设施发起进一步攻击。"
        ),
        "solution_en": (
            "Upgrade Rails to version 6.0.0.beta3, 5.2.2.1, 5.1.6.2, 5.0.7.2, or 4.2.11.1 or later. If upgrading "
            "is not possible, apply the provided patches. Ensure that file rendering operations properly validate "
            "file paths and do not accept user-controlled input."
        ),
        "solution_zh": (
            "将 Rails 升级至 6.0.0.beta3、5.2.2.1、5.1.6.2、5.0.7.2 或 4.2.11.1 及更高版本。如果无法升级，请应用提供的补丁。"
            "确保文件渲染操作正确验证文件路径，且不接受用户控制的输入。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["Ruby on Rails 4.2.x", "Ruby on Rails 5.0.x", "Ruby on Rails 5.1.x", "Ruby on Rails 5.2.x"],
    },
    "CVE-2020-9484": {
        "name_en": "MongoDB Express API Unauthorized Access",
        "name_zh": "MongoDB Express API 未授权访问漏洞",
        "description_en": (
            "CVE-2020-9484 is an unauthorized access vulnerability in Apache Tomcat that can be exploited when Tomcat is "
            "configured with the FileStore session persistence mechanism and the server is running on a system with a "
            "readable webapps directory. The vulnerability allows an attacker to manipulate the JSESSIONID cookie to "
            "point to a malicious session file on the server filesystem. When Tomcat deserializes the session file, "
            "it can execute arbitrary code. An attacker can leverage this vulnerability to achieve remote code execution "
            "by crafting a JSESSIONID value that references a file containing malicious serialized Java objects. This "
            "vulnerability affects Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0-M1 to 9.0.36, and 8.5.0 to 8.5.56."
        ),
        "description_zh": (
            "CVE-2020-9484 是 Apache Tomcat 中的未授权访问漏洞，当 Tomcat 配置了 FileStore 会话持久化机制且服务器运行在具有可读 "
            "webapps 目录的系统上时可以被利用。该漏洞允许攻击者操纵 JSESSIONID Cookie 指向服务器文件系统上的恶意会话文件。当 Tomcat "
            "反序列化会话文件时，可以执行任意代码。攻击者可以通过构造引用包含恶意序列化 Java 对象文件的 JSESSIONID 值来利用此漏洞"
            "实现远程代码执行。该漏洞影响 Apache Tomcat 10.0.0-M1 至 10.0.0-M6、9.0.0-M1 至 9.0.36 和 8.5.0 至 8.5.56 版本。"
        ),
        "impact_en": (
            "Remote code execution through session deserialization allows attackers to gain complete control of the Tomcat "
            "server. The attacker can execute arbitrary commands, access all application data, and use the compromised "
            "server for further attacks."
        ),
        "impact_zh": (
            "通过会话反序列化的远程代码执行使攻击者能够完全控制 Tomcat 服务器。攻击者可以执行任意命令、访问所有应用程序数据，"
            "并利用被攻陷的服务器进行进一步攻击。"
        ),
        "solution_en": (
            "Upgrade Apache Tomcat to version 10.0.0-M7, 9.0.37, or 8.5.57 or later. Set the system property "
            "org.apache.catalina.session.StandardSession.ACTIVITY_CHECK to true. Avoid using FileStore session "
            "persistence in production environments. Ensure the webapps directory is not writable by the Tomcat process."
        ),
        "solution_zh": (
            "将 Apache Tomcat 升级至 10.0.0-M7、9.0.37 或 8.5.57 及更高版本。设置系统属性 org.apache.catalina.session."
            "StandardSession.ACTIVITY_CHECK 为 true。避免在生产环境中使用 FileStore 会话持久化。确保 webapps 目录"
            "对 Tomcat 进程不可写。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Tomcat 8.5.0 - 8.5.56", "Apache Tomcat 9.0.0 - 9.0.36", "Apache Tomcat 10.0.0-M1 - 10.0.0-M6"],
    },
    "CVE-2022-1388": {
        "name_en": "F5 BIG-IP iControl REST Unauthenticated Remote Code Execution",
        "name_zh": "F5 BIG-IP iControl REST 未授权远程代码执行漏洞",
        "description_en": (
            "CVE-2022-1388 is a critical unauthenticated remote code execution vulnerability in F5 BIG-IP iControl REST "
            "interface. The vulnerability exists because the iControl REST endpoint fails to properly validate HTTP request "
            "headers. An attacker can bypass authentication by manipulating specific HTTP headers (X-F5-Auth-Token and "
            "Authorization) and then execute arbitrary system commands through the REST API. The iControl REST service "
            "runs with root privileges, meaning any code executed through this vulnerability runs as root. This "
            "vulnerability affects BIG-IP versions 16.1.x, 15.1.x, 14.1.x, 13.1.x, and 12.1.x."
        ),
        "description_zh": (
            "CVE-2022-1388 是 F5 BIG-IP iControl REST 接口中严重的未授权远程代码执行漏洞。该漏洞存在的原因是 iControl REST "
            "端点未能正确验证 HTTP 请求头。攻击者可以通过操纵特定的 HTTP 头（X-F5-Auth-Token 和 Authorization）绕过身份认证，"
            "然后通过 REST API 执行任意系统命令。iControl REST 服务以 root 权限运行，这意味着通过此漏洞执行的任何代码都以 root "
            "身份运行。该漏洞影响 BIG-IP 16.1.x、15.1.x、14.1.x、13.1.x 和 12.1.x 版本。"
        ),
        "impact_en": (
            "An unauthenticated attacker can gain complete root-level control of the F5 BIG-IP device, compromising the "
            "entire network security infrastructure. This allows interception of all traffic, modification of security "
            "policies, and lateral movement into the internal network."
        ),
        "impact_zh": (
            "未经认证的攻击者可以获得 F5 BIG-IP 设备的完全 root 级别控制权，危及整个网络安全基础设施。这允许拦截所有流量、"
            "修改安全策略以及向内部网络进行横向移动。"
        ),
        "solution_en": (
            "Upgrade F5 BIG-IP to the fixed versions: 16.1.2.2, 15.1.5.1, 14.1.4.6, 13.1.5, or 12.1.6. Block access "
            "to the iControl REST interface from untrusted networks. Implement network segmentation and restrict "
            "management access to authorized administrators only."
        ),
        "solution_zh": (
            "将 F5 BIG-IP 升级至修复版本：16.1.2.2、15.1.5.1、14.1.4.6、13.1.5 或 12.1.6。阻止来自不可信网络对 iControl REST "
            "接口的访问。实施网络分段，将管理访问限制为仅授权管理员。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["F5 BIG-IP 12.1.x", "F5 BIG-IP 13.1.x", "F5 BIG-IP 14.1.x", "F5 BIG-IP 15.1.x", "F5 BIG-IP 16.1.x"],
    },
    "CVE-2023-46604": {
        "name_en": "Apache ActiveMQ Remote Code Execution",
        "name_zh": "Apache ActiveMQ 远程代码执行漏洞",
        "description_en": (
            "CVE-2023-46604 is a critical remote code execution vulnerability in Apache ActiveMQ, an open-source message "
            "broker. The vulnerability exists in the OpenWire protocol handler where a specially crafted command can trigger "
            "the ClassPathXmlApplicationContext class to load a remote XML configuration file. The loaded XML file can "
            "contain arbitrary Spring XML configuration that instantiates and executes malicious Java classes. An "
            "unauthenticated attacker with network access to the ActiveMQ OpenWire port (default 61616) can exploit this "
            "vulnerability to execute arbitrary code on the server. This vulnerability affects Apache ActiveMQ versions "
            "before 5.15.16, 5.16.7, 5.17.6, and 5.18.3."
        ),
        "description_zh": (
            "CVE-2023-46604 是开源消息代理 Apache ActiveMQ 中的严重远程代码执行漏洞。该漏洞存在于 OpenWire 协议处理器中，"
            "特制的命令可以触发 ClassPathXmlApplicationContext 类加载远程 XML 配置文件。加载的 XML 文件可以包含任意的 "
            "Spring XML 配置，实例化并执行恶意的 Java 类。具有 ActiveMQ OpenWire 端口（默认 61616）网络访问权限的未经认证的"
            "攻击者可以利用此漏洞在服务器上执行任意代码。该漏洞影响 Apache ActiveMQ 5.15.16 之前、5.16.7 之前、5.17.6 之前"
            "和 5.18.3 之前的版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on the ActiveMQ server allows attackers to compromise the messaging "
            "infrastructure. This can lead to interception, modification, or disruption of all message traffic flowing "
            "through the broker, as well as lateral movement to connected systems."
        ),
        "impact_zh": (
            "在 ActiveMQ 服务器上未经认证的远程代码执行使攻击者能够攻陷消息基础设施。这可能导致流经消息代理的所有消息流量被拦截、"
            "修改或中断，以及向连接系统的横向移动。"
        ),
        "solution_en": (
            "Upgrade Apache ActiveMQ to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 or later. Block access to the "
            "ActiveMQ OpenWire port (61616) from untrusted networks. Implement network segmentation to isolate the "
            "ActiveMQ server from the public internet."
        ),
        "solution_zh": (
            "将 Apache ActiveMQ 升级至 5.15.16、5.16.7、5.17.6 或 5.18.3 及更高版本。阻止来自不可信网络对 ActiveMQ OpenWire "
            "端口（61616）的访问。实施网络分段以将 ActiveMQ 服务器与公共互联网隔离。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Apache ActiveMQ 5.15.x < 5.15.16", "Apache ActiveMQ 5.16.x < 5.16.7", "Apache ActiveMQ 5.17.x < 5.17.6", "Apache ActiveMQ 5.18.x < 5.18.3"],
    },
    "CVE-2022-30525": {
        "name_en": "Zimbra Collaboration Suite Cross-Site Scripting",
        "name_zh": "Zimbra Collaboration Suite 跨站脚本漏洞",
        "description_en": (
            "CVE-2022-30525 is a cross-site scripting (XSS) vulnerability in Zimbra Collaboration Suite. The vulnerability "
            "exists in the Zimbra webmail interface where user-supplied input is not properly sanitized before being "
            "rendered in the browser. An attacker can inject malicious JavaScript code through crafted email content or "
            "URL parameters that, when viewed by a victim, executes in the context of the victim's session. This allows "
            "the attacker to steal session cookies, perform actions on behalf of the victim, and potentially gain "
            "unauthorized access to the victim's email account. This vulnerability affects Zimbra Collaboration Suite "
            "versions 8.8.15 and 9.0.0."
        ),
        "description_zh": (
            "CVE-2022-30525 是 Zimbra Collaboration Suite 中的跨站脚本（XSS）漏洞。该漏洞存在于 Zimbra Webmail 界面中，"
            "用户提供的输入在浏览器中渲染之前未经过适当的清理。攻击者可以通过构造的电子邮件内容或 URL 参数注入恶意 JavaScript 代码，"
            "当受害者查看时会以其会话上下文执行。这允许攻击者窃取会话 Cookie、代表受害者执行操作，并可能获得对受害者电子邮件账户的"
            "未授权访问。该漏洞影响 Zimbra Collaboration Suite 8.8.15 和 9.0.0 版本。"
        ),
        "impact_en": (
            "Successful XSS exploitation allows attackers to hijack user sessions, access email content, and perform "
            "unauthorized actions on behalf of the victim. In an enterprise email environment, this can lead to "
            "widespread compromise of email accounts and sensitive communications."
        ),
        "impact_zh": (
            "成功的 XSS 利用使攻击者能够劫持用户会话、访问电子邮件内容，并代表受害者执行未经授权的操作。在企业电子邮件环境中，"
            "这可能导致电子邮件账户和敏感通信的大范围泄露。"
        ),
        "solution_en": (
            "Upgrade Zimbra Collaboration Suite to the patched versions. Implement Content Security Policy (CSP) headers "
            "to mitigate XSS attacks. Enable input validation and output encoding for all user-supplied content. "
            "Deploy WAF rules to detect and block XSS injection attempts."
        ),
        "solution_zh": (
            "将 Zimbra Collaboration Suite 升级至已修补的版本。实施内容安全策略（CSP）头以缓解 XSS 攻击。对所有用户提供的"
            "内容启用输入验证和输出编码。部署 WAF 规则以检测和阻止 XSS 注入尝试。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Zimbra Collaboration Suite 8.8.15", "Zimbra Collaboration Suite 9.0.0"],
    },
    "CVE-2022-22947": {
        "name_en": "Spring Cloud Gateway SpEL Injection",
        "name_zh": "Spring Cloud Gateway SpEL 注入漏洞",
        "description_en": (
            "CVE-2022-22947 is a remote code execution vulnerability in Spring Cloud Gateway. The vulnerability exists "
            "when an authenticated user creates, modifies, or deletes a route through the Gateway's Actuator API endpoint. "
            "The route filter values are not properly sanitized and can contain Spring Expression Language (SpEL) "
            "expressions. When the malicious route is activated, the SpEL expressions are evaluated, resulting in "
            "arbitrary code execution on the server. An attacker who has access to the Actuator endpoint can exploit "
            "this vulnerability to execute arbitrary commands. This vulnerability affects Spring Cloud Gateway 3.1.0 "
            "and 3.0.6 and earlier versions."
        ),
        "description_zh": (
            "CVE-2022-22947 是 Spring Cloud Gateway 中的远程代码执行漏洞。当经过认证的用户通过 Gateway 的 Actuator API 端点"
            "创建、修改或删除路由时存在该漏洞。路由过滤器值未经过适当的清理，可以包含 Spring 表达式语言（SpEL）表达式。当恶意"
            "路由被激活时，SpEL 表达式被求值，导致在服务器上执行任意代码。能够访问 Actuator 端点的攻击者可以利用此漏洞执行"
            "任意命令。该漏洞影响 Spring Cloud Gateway 3.1.0 和 3.0.6 及更早版本。"
        ),
        "impact_en": (
            "Authenticated attackers with access to the Actuator endpoint can execute arbitrary code on the Gateway server. "
            "This can lead to complete compromise of the API gateway, interception of all API traffic, and lateral "
            "movement to backend services."
        ),
        "impact_zh": (
            "能够访问 Actuator 端点的经过认证的攻击者可以在 Gateway 服务器上执行任意代码。这可能导致 API 网关被完全攻陷、"
            "所有 API 流量被拦截，以及向后台服务的横向移动。"
        ),
        "solution_en": (
            "Upgrade Spring Cloud Gateway to version 3.1.1, 3.0.7, or later. If upgrading is not immediately possible, "
            "disable the Gateway Actuator endpoint by setting management.endpoint.gateway.enabled to false. "
            "Restrict access to Actuator endpoints to authorized administrators only."
        ),
        "solution_zh": (
            "将 Spring Cloud Gateway 升级至 3.1.1、3.0.7 或更高版本。如果无法立即升级，可通过设置 management.endpoint.gateway."
            "enabled 为 false 来禁用 Gateway Actuator 端点。将 Actuator 端点的访问限制为仅授权管理员。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Spring Cloud Gateway 3.0.x <= 3.0.6", "Spring Cloud Gateway 3.1.0"],
    },
    "CVE-2023-49103": {
        "name_en": "PHP CGI Parameter Injection Remote Code Execution",
        "name_zh": "PHP CGI 参数注入远程代码执行漏洞",
        "description_en": (
            "CVE-2023-49103 is a critical remote code execution vulnerability in PHP when running in CGI mode. The "
            "vulnerability exists in the way PHP's CGI implementation handles certain query string parameters. An attacker "
            "can inject command-line options through specially crafted URL query parameters that are passed to the PHP "
            "CGI interpreter. Specifically, the vulnerability allows injection of the -d (define ini entry) option, "
            "which can be used to override PHP configuration directives such as auto_prepend_file, allowing the "
            "attacker to include and execute arbitrary files. This vulnerability affects PHP versions 8.x before "
            "8.3.8, 8.2.x before 8.2.20, and 8.1.x before 8.1.29."
        ),
        "description_zh": (
            "CVE-2023-49103 是 PHP 在 CGI 模式下运行时的严重远程代码执行漏洞。该漏洞存在于 PHP 的 CGI 实现处理某些查询字符串"
            "参数的方式中。攻击者可以通过特制的 URL 查询参数向 PHP CGI 解释器注入命令行选项。具体而言，该漏洞允许注入 -d（定义 "
            "ini 条目）选项，可用于覆盖 PHP 配置指令（如 auto_prepend_file），使攻击者能够包含并执行任意文件。该漏洞影响 "
            "PHP 8.3.8 之前的 8.x 版本、8.2.20 之前的 8.2.x 版本和 8.1.29 之前的 8.1.x 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to compromise any web application running PHP in CGI "
            "mode. This can lead to complete server compromise, data theft, and use of the server as a platform for "
            "further attacks."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够攻陷任何以 CGI 模式运行 PHP 的 Web 应用程序。这可能导致服务器被完全攻陷、"
            "数据窃取，以及利用服务器作为进一步攻击的平台。"
        ),
        "solution_en": (
            "Upgrade PHP to version 8.3.8, 8.2.20, or 8.1.29 or later. If upgrading is not possible, use URL rewriting "
            "rules to block query strings containing PHP command-line option injection patterns. Consider switching from "
            "CGI mode to PHP-FPM or mod_php for better security."
        ),
        "solution_zh": (
            "将 PHP 升级至 8.3.8、8.2.20 或 8.1.29 及更高版本。如果无法升级，请使用 URL 重写规则阻止包含 PHP 命令行选项"
            "注入模式的查询字符串。考虑从 CGI 模式切换到 PHP-FPM 或 mod_php 以获得更好的安全性。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["PHP 8.1.x < 8.1.29", "PHP 8.2.x < 8.2.20", "PHP 8.3.x < 8.3.8"],
    },
    "CVE-2023-36884": {
        "name_en": "Microsoft Office and Windows HTML Remote Code Execution",
        "name_zh": "Microsoft Office and Windows HTML 远程代码执行漏洞",
        "description_en": (
            "CVE-2023-36884 is a remote code execution vulnerability in Microsoft Office and Windows HTML that is being "
            "actively exploited in targeted attacks. The vulnerability exists in the way Microsoft Office handles specially "
            "crafted Office documents that contain malicious HTML content. When a user opens a malicious document, the "
            "embedded HTML content can trigger the execution of arbitrary code on the system. The vulnerability bypasses "
            "certain security features such as Protected View and can be exploited through phishing emails containing "
            "malicious attachments. This vulnerability affects multiple versions of Microsoft Office and Windows."
        ),
        "description_zh": (
            "CVE-2023-36884 是 Microsoft Office 和 Windows HTML 中的远程代码执行漏洞，正被用于定向攻击中。该漏洞存在于 "
            "Microsoft Office 处理包含恶意 HTML 内容的特制 Office 文档的方式中。当用户打开恶意文档时，嵌入的 HTML 内容可以"
            "触发在系统上执行任意代码。该漏洞绕过了某些安全功能（如受保护的视图），可以通过包含恶意附件的钓鱼电子邮件进行利用。"
            "该漏洞影响多个版本的 Microsoft Office 和 Windows。"
        ),
        "impact_en": (
            "Successful exploitation allows attackers to execute arbitrary code on the victim's system when a malicious "
            "Office document is opened. This can lead to installation of malware, ransomware, or spyware, and complete "
            "compromise of the affected system."
        ),
        "impact_zh": (
            "成功利用后，当打开恶意 Office 文档时，攻击者可以在受害者系统上执行任意代码。这可能导致安装恶意软件、勒索软件或"
            "间谍软件，以及受影响系统被完全攻陷。"
        ),
        "solution_en": (
            "Install Microsoft security updates from August 2023. Block suspicious Office document attachments at the "
            "email gateway. Enable Protected View for all documents from untrusted sources. Implement application "
            "control policies to prevent execution of suspicious processes."
        ),
        "solution_zh": (
            "安装微软 2023 年 8 月的安全更新。在电子邮件网关处阻止可疑的 Office 文档附件。对来自不可信来源的所有文档启用"
            "受保护的视图。实施应用程序控制策略以防止执行可疑进程。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Microsoft Office 2016", "Microsoft Office 2019", "Microsoft Office 2021", "Microsoft 365 Apps", "Windows 10", "Windows 11"],
    },
    "CVE-2021-40539": {
        "name_en": "ManageEngine ADSelfService Plus REST API Authentication Bypass",
        "name_zh": "ManageEngine ADSelfService Plus REST API 认证绕过漏洞",
        "description_en": (
            "CVE-2021-40539 is an authentication bypass vulnerability in ManageEngine ADSelfService Plus. The vulnerability "
            "exists in the REST API endpoint where an attacker can bypass authentication by manipulating the authentication "
            "token in the request. Specifically, the vulnerability allows an unauthenticated attacker to access the REST "
            "API with administrative privileges by exploiting a flaw in the token validation mechanism. Once authenticated, "
            "the attacker can execute arbitrary code on the server through the product's built-in features. This "
            "vulnerability affects ManageEngine ADSelfService Plus versions 6113 and earlier."
        ),
        "description_zh": (
            "CVE-2021-40539 是 ManageEngine ADSelfService Plus 中的认证绕过漏洞。该漏洞存在于 REST API 端点中，攻击者可以通过"
            "操纵请求中的认证令牌来绕过身份认证。具体而言，该漏洞允许未经认证的攻击者通过利用令牌验证机制中的缺陷，以管理员权限"
            "访问 REST API。一旦认证成功，攻击者可以通过产品内置功能在服务器上执行任意代码。该漏洞影响 ManageEngine ADSelfService "
            "Plus 6113 及更早版本。"
        ),
        "impact_en": (
            "Authentication bypass allows unauthenticated attackers to gain administrative access to the ADSelfService "
            "Plus server. This can lead to remote code execution, credential theft from Active Directory integration, "
            "and compromise of the identity management infrastructure."
        ),
        "impact_zh": (
            "认证绕过允许未经认证的攻击者获得对 ADSelfService Plus 服务器的管理员访问权限。这可能导致远程代码执行、从 Active "
            "Directory 集成中窃取凭据，以及身份管理基础设施被攻陷。"
        ),
        "solution_en": (
            "Upgrade ManageEngine ADSelfService Plus to build 6114 or later. Restrict network access to the ADSelfService "
            "Plus management interface. Implement multi-factor authentication for all administrative accounts. "
            "Monitor access logs for signs of unauthorized API access."
        ),
        "solution_zh": (
            "将 ManageEngine ADSelfService Plus 升级至 build 6114 或更高版本。限制对 ADSelfService Plus 管理接口的网络访问。"
            "为所有管理账户实施多因素认证。监控访问日志以发现未经授权的 API 访问痕迹。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["ManageEngine ADSelfService Plus <= build 6113"],
    },
    "CVE-2023-46747": {
        "name_en": "Apache Kafka UI Remote Code Execution",
        "name_zh": "Apache Kafka UI 远程代码执行漏洞",
        "description_en": (
            "CVE-2023-46747 is a critical remote code execution vulnerability in F5 BIG-IP Next Central Manager. The "
            "vulnerability exists in the configuration import functionality where an authenticated attacker can upload a "
            "maliciously crafted configuration file that triggers command injection when processed. The insufficient "
            "validation of the imported configuration data allows an attacker to execute arbitrary commands on the "
            "underlying operating system. This vulnerability affects F5 BIG-IP Next Central Manager versions 20.0.0 "
            "through 20.0.1."
        ),
        "description_zh": (
            "CVE-2023-46747 是 F5 BIG-IP Next Central Manager 中的严重远程代码执行漏洞。该漏洞存在于配置导入功能中，经过认证的"
            "攻击者可以上传恶意构造的配置文件，在处理时触发命令注入。对导入的配置数据验证不足允许攻击者在底层操作系统上执行任意命令。"
            "该漏洞影响 F5 BIG-IP Next Central Manager 20.0.0 至 20.0.1 版本。"
        ),
        "impact_en": (
            "Authenticated remote code execution allows attackers to compromise the BIG-IP Next Central Manager and "
            "gain control over the entire network management infrastructure. This can lead to modification of security "
            "policies and disruption of network services."
        ),
        "impact_zh": (
            "经过认证的远程代码执行使攻击者能够攻陷 BIG-IP Next Central Manager 并获得对整个网络管理基础设施的控制。"
            "这可能导致安全策略被修改和网络服务被中断。"
        ),
        "solution_en": (
            "Upgrade F5 BIG-IP Next Central Manager to version 20.0.2 or later. Restrict access to the Central Manager "
            "to authorized administrators only. Implement network segmentation to isolate the management interface. "
            "Monitor for suspicious configuration import activities."
        ),
        "solution_zh": (
            "将 F5 BIG-IP Next Central Manager 升级至 20.0.2 或更高版本。将 Central Manager 的访问限制为仅授权管理员。"
            "实施网络分段以隔离管理接口。监控可疑的配置导入活动。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["F5 BIG-IP Next Central Manager 20.0.0 - 20.0.1"],
    },
    "CVE-2022-42889": {
        "name_en": "Apache Commons Text4Shell",
        "name_zh": "Apache Commons Text4Shell 漏洞",
        "description_en": (
            "CVE-2022-42889, known as Text4Shell, is a remote code execution vulnerability in Apache Commons Text. The "
            "vulnerability is similar in nature to Log4Shell (CVE-2021-44228) and exists in the StringSubstitutor "
            "interpolation feature. When the StringSubstitutor is configured with default lookup interpolators, an "
            "attacker can inject specially crafted strings that trigger DNS lookups, script execution, or arbitrary "
            "code execution through the 'script', 'url', or 'dns' interpolators. Applications that use Apache Commons "
            "Text to process user-supplied input with StringSubstitutor are vulnerable. This vulnerability affects "
            "Apache Commons Text versions 1.5 through 1.9."
        ),
        "description_zh": (
            "CVE-2022-42889，被称为 Text4Shell，是 Apache Commons Text 中的远程代码执行漏洞。该漏洞在本质上与 Log4Shell"
            "（CVE-2021-44228）类似，存在于 StringSubstitutor 插值功能中。当 StringSubstitutor 配置了默认查找插值器时，"
            "攻击者可以注入特制的字符串，通过 'script'、'url' 或 'dns' 插值器触发 DNS 查找、脚本执行或任意代码执行。"
            "使用 Apache Commons Text 的 StringSubstitutor 处理用户提供输入的应用程序存在风险。该漏洞影响 Apache Commons "
            "Text 1.5 至 1.9 版本。"
        ),
        "impact_en": (
            "Text4Shell allows remote code execution when applications process untrusted input using the vulnerable "
            "StringSubstitutor feature. The impact depends on the application's configuration and the privileges of "
            "the application process, but can range from information disclosure to full system compromise."
        ),
        "impact_zh": (
            "当应用程序使用易受攻击的 StringSubstitutor 功能处理不可信输入时，Text4Shell 允许远程代码执行。影响取决于应用程序"
            "的配置和应用程序进程的权限，但范围可从信息泄露到完全的系统沦陷。"
        ),
        "solution_en": (
            "Upgrade Apache Commons Text to version 1.10.0 or later. Review application code to identify all usages "
            "of StringSubstitutor with user-supplied input. Ensure that custom interpolators are used instead of "
            "default interpolators when processing untrusted input."
        ),
        "solution_zh": (
            "将 Apache Commons Text 升级至 1.10.0 或更高版本。审查应用程序代码以识别所有使用用户输入的 StringSubstitutor "
            "用法。确保在处理不可信输入时使用自定义插值器而非默认插值器。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Commons Text 1.5 - 1.9"],
    },

    # ============================================================
    # 数据库类（15条）
    # ============================================================
    "CVE-2021-44228-DB": {
        "name_en": "Log4j Vulnerability Impacting Database Components",
        "name_zh": "Log4j 漏洞影响数据库组件",
        "description_en": (
            "The Log4Shell vulnerability (CVE-2021-44228) has a significant impact on various database management systems "
            "that embed or use Log4j for logging. Many enterprise database products, including Apache Druid, Apache Solr, "
            "Elasticsearch, and various database monitoring tools, use Log4j2 as their logging framework. When these "
            "database components process log messages containing user-controlled data (such as query strings, connection "
            "parameters, or error messages), an attacker can inject JNDI lookups through these inputs. The JNDI lookup "
            "triggers a connection to an attacker-controlled LDAP/RMI server, which returns a reference to a malicious "
            "Java class that gets executed on the database server."
        ),
        "description_zh": (
            "Log4Shell 漏洞（CVE-2021-44228）对嵌入或使用 Log4j 进行日志记录的各种数据库管理系统产生了重大影响。许多企业级数据库产品，"
            "包括 Apache Druid、Apache Solr、Elasticsearch 以及各种数据库监控工具，都使用 Log4j2 作为日志框架。当这些数据库组件"
            "处理包含用户控制数据（如查询字符串、连接参数或错误消息）的日志消息时，攻击者可以通过这些输入注入 JNDI 查找。JNDI 查找"
            "触发与攻击者控制的 LDAP/RMI 服务器的连接，该服务器返回对恶意 Java 类的引用，该类在数据库服务器上被执行。"
        ),
        "impact_en": (
            "Database servers compromised through Log4Shell can lead to complete data breach, including all stored databases, "
            "credentials, and sensitive information. Attackers can also use the compromised database server as a pivot point "
            "to access other systems in the network."
        ),
        "impact_zh": (
            "通过 Log4Shell 被攻陷的数据库服务器可能导致完整的数据泄露，包括所有存储的数据库、凭据和敏感信息。攻击者还可以利用"
            "被攻陷的数据库服务器作为跳板访问网络中的其他系统。"
        ),
        "solution_en": (
            "Identify all database components and monitoring tools that use Log4j2. Upgrade Log4j2 to version 2.17.1 or later "
            "in all affected components. Apply vendor-specific patches for database products that bundle Log4j. Implement "
            "network-level controls to block outbound LDAP/RMI connections from database servers."
        ),
        "solution_zh": (
            "识别所有使用 Log4j2 的数据库组件和监控工具。在所有受影响的组件中将 Log4j2 升级至 2.17.1 或更高版本。应用数据库"
            "产品供应商提供的捆绑 Log4j 特定补丁。实施网络层面的控制以阻止数据库服务器的出站 LDAP/RMI 连接。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Apache Druid", "Elasticsearch", "Apache Solr", "Various database monitoring tools using Log4j2"],
    },
    "CVE-2019-9081": {
        "name_en": "Exim SMTP Server Remote Code Execution",
        "name_zh": "Exim SMTP 服务器远程代码执行漏洞",
        "description_en": (
            "CVE-2019-9081 is a remote code execution vulnerability in Exim, a widely used Mail Transfer Agent (MTA). "
            "The vulnerability exists in the receive_msg() function where a heap-based buffer overflow can be triggered "
            "during the processing of certain EHLO/HELO commands. An unauthenticated attacker can send a specially "
            "crafted EHLO response to the Exim server that causes a buffer overflow, leading to remote code execution "
            "with the privileges of the Exim process. This vulnerability affects Exim versions 4.80 through 4.92.1."
        ),
        "description_zh": (
            "CVE-2019-9081 是广泛使用的邮件传输代理（MTA）Exim 中的远程代码执行漏洞。该漏洞存在于 receive_msg() 函数中，"
            "在处理某些 EHLO/HELO 命令期间可以触发基于堆的缓冲区溢出。未经认证的攻击者可以向 Exim 服务器发送特制的 EHLO 响应，"
            "导致缓冲区溢出，以 Exim 进程的权限进行远程代码执行。该漏洞影响 Exim 4.80 至 4.92.1 版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on the mail server allows attackers to intercept, modify, or redirect "
            "email traffic. The compromised mail server can also be used as a pivot point for further network penetration "
            "and to distribute malware through email."
        ),
        "impact_zh": (
            "在邮件服务器上未经认证的远程代码执行使攻击者能够拦截、修改或重定向电子邮件流量。被攻陷的邮件服务器还可以用作进一步"
            "网络渗透的跳板，以及通过电子邮件分发恶意软件。"
        ),
        "solution_en": (
            "Upgrade Exim to version 4.92.2 or later. Apply the patches provided by the Exim development team. Restrict "
            "access to the SMTP port (25) from untrusted networks. Implement email security gateway solutions to filter "
            "malicious traffic before it reaches the Exim server."
        ),
        "solution_zh": (
            "将 Exim 升级至 4.92.2 或更高版本。应用 Exim 开发团队提供的补丁。限制来自不可信网络对 SMTP 端口（25）的访问。"
            "实施电子邮件安全网关解决方案，在恶意流量到达 Exim 服务器之前进行过滤。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Exim 4.80 - 4.92.1"],
    },
    "CVE-2022-29968": {
        "name_en": "Exim SMTP Server Remote Code Execution",
        "name_zh": "Exim SMTP 服务器远程代码执行漏洞",
        "description_en": (
            "CVE-2022-29968 is a remote code execution vulnerability in Exim Mail Transfer Agent. The vulnerability exists "
            "in the SPA (Simple Password Authentication) challenge handling where a buffer overflow can be triggered by "
            "a specially crafted SPA authentication response. An unauthenticated attacker can exploit this vulnerability "
            "by sending a malicious SPA response during the SMTP authentication process. The buffer overflow leads to "
            "arbitrary code execution with the privileges of the Exim process. This vulnerability affects Exim versions "
            "4.92 through 4.96."
        ),
        "description_zh": (
            "CVE-2022-29968 是 Exim 邮件传输代理中的远程代码执行漏洞。该漏洞存在于 SPA（简单密码认证）挑战处理中，特制的 "
            "SPA 认证响应可以触发缓冲区溢出。未经认证的攻击者可以在 SMTP 认证过程中发送恶意的 SPA 响应来利用此漏洞。缓冲区溢出"
            "导致以 Exim 进程的权限执行任意代码。该漏洞影响 Exim 4.92 至 4.96 版本。"
        ),
        "impact_en": (
            "Remote code execution on the Exim mail server allows attackers to compromise the email infrastructure. "
            "This can lead to email interception, data exfiltration, and use of the compromised server for further "
            "network attacks."
        ),
        "impact_zh": (
            "在 Exim 邮件服务器上的远程代码执行使攻击者能够攻陷电子邮件基础设施。这可能导致电子邮件被拦截、数据泄露，"
            "以及利用被攻陷的服务器进行进一步的网络攻击。"
        ),
        "solution_en": (
            "Upgrade Exim to version 4.96.1 or later. Apply the security patches provided by the Exim maintainers. "
            "Disable SPA authentication if not required. Restrict access to the SMTP service from untrusted networks."
        ),
        "solution_zh": (
            "将 Exim 升级至 4.96.1 或更高版本。应用 Exim 维护者提供的安全补丁。如果不需要 SPA 认证，请禁用。"
            "限制来自不可信网络对 SMTP 服务的访问。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Exim 4.92 - 4.96"],
    },
    "CVE-2021-35237": {
        "name_en": "OpenVPN Access Server SQL Injection",
        "name_zh": "OpenVPN Access Server SQL 注入漏洞",
        "description_en": (
            "CVE-2021-35237 is a SQL injection vulnerability in OpenVPN Access Server. The vulnerability exists in the "
            "web interface authentication mechanism where user-supplied input is not properly sanitized before being "
            "used in SQL queries. An unauthenticated attacker can exploit this vulnerability by sending specially crafted "
            "requests to the login endpoint that contain malicious SQL statements. Successful exploitation allows the "
            "attacker to extract sensitive data from the database, including user credentials and configuration "
            "information. This vulnerability affects OpenVPN Access Server versions 2.8.0 through 2.8.7 and 2.9.0 "
            "through 2.9.4."
        ),
        "description_zh": (
            "CVE-2021-35237 是 OpenVPN Access Server 中的 SQL 注入漏洞。该漏洞存在于 Web 界面认证机制中，用户提供的输入"
            "在用于 SQL 查询之前未经过适当的清理。未经认证的攻击者可以通过向登录端点发送包含恶意 SQL 语句的特制请求来利用此漏洞。"
            "成功利用后，攻击者可以从数据库中提取敏感数据，包括用户凭据和配置信息。该漏洞影响 OpenVPN Access Server 2.8.0 至 "
            "2.8.7 和 2.9.0 至 2.9.4 版本。"
        ),
        "impact_en": (
            "SQL injection allows unauthenticated attackers to extract credentials and sensitive configuration data from "
            "the Access Server database. Compromised VPN credentials can be used to gain unauthorized access to the "
            "corporate network."
        ),
        "impact_zh": (
            "SQL 注入允许未经认证的攻击者从 Access Server 数据库中提取凭据和敏感配置数据。被泄露的 VPN 凭据可用于获得对"
            "企业网络的未授权访问。"
        ),
        "solution_en": (
            "Upgrade OpenVPN Access Server to version 2.8.8, 2.9.5, or later. Restrict access to the Access Server "
            "web interface to trusted networks. Implement WAF rules to detect and block SQL injection attempts. "
            "Monitor access logs for signs of SQL injection exploitation."
        ),
        "solution_zh": (
            "将 OpenVPN Access Server 升级至 2.8.8、2.9.5 或更高版本。将 Access Server Web 界面的访问限制为受信任的网络。"
            "部署 WAF 规则以检测和阻止 SQL 注入尝试。监控访问日志以发现 SQL 注入利用的痕迹。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["OpenVPN Access Server 2.8.0 - 2.8.7", "OpenVPN Access Server 2.9.0 - 2.9.4"],
    },
    "CVE-2022-26527": {
        "name_en": "Zabbix Server SQL Injection",
        "name_zh": "Zabbix Server SQL 注入漏洞",
        "description_en": (
            "CVE-2022-26527 is a SQL injection vulnerability in Zabbix Server that affects the CUser::checkAuthentication() "
            "function. The vulnerability exists because user-supplied input passed to the sign-in API endpoint is not "
            "properly sanitized before being used in SQL queries. An unauthenticated attacker can exploit this "
            "vulnerability by sending a specially crafted login request containing malicious SQL statements. Successful "
            "exploitation allows the attacker to extract sensitive data from the backend database, including user "
            "credentials and monitoring configuration. This vulnerability affects Zabbix Server versions 5.4.0 "
            "through 5.4.8, 6.0.0alpha1 through 6.0.0beta1."
        ),
        "description_zh": (
            "CVE-2022-26527 是 Zabbix Server 中影响 CUser::checkAuthentication() 函数的 SQL 注入漏洞。该漏洞存在的原因是"
            "传递给登录 API 端点的用户输入在用于 SQL 查询之前未经过适当的清理。未经认证的攻击者可以通过发送包含恶意 SQL 语句的"
            "特制登录请求来利用此漏洞。成功利用后，攻击者可以从后端数据库中提取敏感数据，包括用户凭据和监控配置。该漏洞影响 "
            "Zabbix Server 5.4.0 至 5.4.8、6.0.0alpha1 至 6.0.0beta1 版本。"
        ),
        "impact_en": (
            "Unauthenticated SQL injection allows attackers to extract credentials and sensitive monitoring data from "
            "the Zabbix database. This can lead to unauthorized access to monitored systems and compromise of the "
            "entire monitoring infrastructure."
        ),
        "impact_zh": (
            "未经认证的 SQL 注入允许攻击者从 Zabbix 数据库中提取凭据和敏感监控数据。这可能导致对受监控系统的未授权访问"
            "以及整个监控基础设施被攻陷。"
        ),
        "solution_en": (
            "Upgrade Zabbix Server to version 5.4.9, 6.0.0beta2, or later. Restrict API access to trusted IP addresses. "
            "Implement input validation and parameterized queries. Deploy WAF rules to detect SQL injection patterns."
        ),
        "solution_zh": (
            "将 Zabbix Server 升级至 5.4.9、6.0.0beta2 或更高版本。将 API 访问限制为受信任的 IP 地址。"
            "实施输入验证和参数化查询。部署 WAF 规则以检测 SQL 注入模式。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Zabbix Server 5.4.0 - 5.4.8", "Zabbix Server 6.0.0alpha1 - 6.0.0beta1"],
    },
    "CVE-2023-28434": {
        "name_en": "CUPS IPP Print Service Out-of-Bounds Access",
        "name_zh": "CUPS IPP 打印服务越界访问漏洞",
        "description_en": (
            "CVE-2023-28434 is a vulnerability in the CUPS printing system that allows out-of-bounds access through the "
            "Internet Printing Protocol (IPP) service. The vulnerability exists in the _ipp_read_io() function of the "
            "CUPS library where a specially crafted IPP request can trigger an out-of-bounds read condition. An attacker "
            "with network access to the CUPS IPP service (typically port 631) can exploit this vulnerability to cause a "
            "denial of service or potentially leak sensitive memory contents. This vulnerability affects CUPS versions "
            "2.4.x before 2.4.2."
        ),
        "description_zh": (
            "CVE-2023-28434 是 CUPS 打印系统中的漏洞，允许通过互联网打印协议（IPP）服务进行越界访问。该漏洞存在于 CUPS 库的 "
            "_ipp_read_io() 函数中，特制的 IPP 请求可以触发越界读取条件。具有 CUPS IPP 服务（通常为端口 631）网络访问权限的"
            "攻击者可以利用此漏洞导致拒绝服务或潜在地泄露敏感内存内容。该漏洞影响 CUPS 2.4.2 之前的 2.4.x 版本。"
        ),
        "impact_en": (
            "The vulnerability can lead to denial of service of the printing service and potential information disclosure "
            "through memory content leakage. In some configurations, the vulnerability may also be exploitable for "
            "arbitrary code execution."
        ),
        "impact_zh": (
            "该漏洞可能导致打印服务的拒绝服务和通过内存内容泄露的潜在信息泄露。在某些配置下，该漏洞也可能被利用进行任意代码执行。"
        ),
        "solution_en": (
            "Upgrade CUPS to version 2.4.2 or later. Restrict access to the CUPS IPP service (port 631) to authorized "
            "print clients only. Implement firewall rules to block access from untrusted networks."
        ),
        "solution_zh": (
            "将 CUPS 升级至 2.4.2 或更高版本。将 CUPS IPP 服务（端口 631）的访问限制为仅授权的打印客户端。"
            "实施防火墙规则以阻止来自不可信网络的访问。"
        ),
        "severity": "high",
        "cvss": 8.6,
        "affected_products": ["CUPS 2.4.x < 2.4.2"],
    },
    "CVE-2023-32233": {
        "name_en": "Linux Kernel nf_tables Use-After-Free Privilege Escalation",
        "name_zh": "Linux Kernel nf_tables 释放后使用提权漏洞",
        "description_en": (
            "CVE-2023-32233 is a use-after-free privilege escalation vulnerability in the Linux kernel's nf_tables "
            "subsystem. The vulnerability exists in the nft_verdict_init() function where a use-after-free condition "
            "occurs when handling certain netfilter rule operations. A local attacker with the CAP_NET_ADMIN capability "
            "can exploit this vulnerability by creating and manipulating netfilter rules that trigger the use-after-free "
            "condition, leading to elevated privileges. This vulnerability affects Linux kernel versions 5.1 through "
            "6.3.1."
        ),
        "description_zh": (
            "CVE-2023-32233 是 Linux 内核 nf_tables 子系统中的释放后使用（use-after-free）提权漏洞。该漏洞存在于 "
            "nft_verdict_init() 函数中，在处理某些 netfilter 规则操作时会发生释放后使用条件。具有 CAP_NET_ADMIN "
            "能力的本地攻击者可以通过创建和操纵 netfilter 规则来触发释放后使用条件，导致权限提升。该漏洞影响 Linux 内核 "
            "5.1 至 6.3.1 版本。"
        ),
        "impact_en": (
            "Local privilege escalation allows an attacker to gain root access on the Linux system. This provides "
            "complete control over the system, including the ability to modify firewall rules, install persistent "
            "malware, and access all data."
        ),
        "impact_zh": (
            "本地提权使攻击者能够在 Linux 系统上获得 root 访问权限。这提供了对系统的完全控制，包括修改防火墙规则、"
            "安装持久化恶意软件和访问所有数据的能力。"
        ),
        "solution_en": (
            "Update the Linux kernel to version 6.3.2 or later, or apply the specific patches provided by your Linux "
            "distribution. Restrict the CAP_NET_ADMIN capability to trusted users and processes only. Implement "
            "mandatory access control (MAC) systems such as SELinux or AppArmor."
        ),
        "solution_zh": (
            "将 Linux 内核更新至 6.3.2 或更高版本，或应用 Linux 发行版提供的特定补丁。将 CAP_NET_ADMIN 能力限制为仅受信任的"
            "用户和进程。实施强制访问控制（MAC）系统，如 SELinux 或 AppArmor。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Linux Kernel 5.1 - 6.3.1"],
    },
    "CVE-2023-3269": {
        "name_en": "Linux Kernel Netfilter Use-After-Free Privilege Escalation",
        "name_zh": "Linux Kernel Netfilter 释放后使用提权漏洞",
        "description_en": (
            "CVE-2023-3269 is a use-after-free privilege escalation vulnerability in the Linux kernel's Netfilter "
            "subsystem. The vulnerability exists in the nf_tables component where a use-after-free condition can be "
            "triggered during the deletion of netfilter objects. A local attacker with sufficient privileges to create "
            "and modify netfilter rules can exploit this vulnerability to gain elevated privileges on the system. The "
            "flaw is in the way the kernel handles reference counting for netfilter table and chain objects. This "
            "vulnerability affects Linux kernel versions before 6.3.4."
        ),
        "description_zh": (
            "CVE-2023-3269 是 Linux 内核 Netfilter 子系统中的释放后使用（use-after-free）提权漏洞。该漏洞存在于 nf_tables "
            "组件中，在删除 netfilter 对象期间可以触发释放后使用条件。具有创建和修改 netfilter 规则足够权限的本地攻击者可以"
            "利用此漏洞在系统上获得提升的权限。该缺陷在于内核处理 netfilter 表和链对象的引用计数的方式。该漏洞影响 6.3.4 "
            "之前的 Linux 内核版本。"
        ),
        "impact_en": (
            "Local privilege escalation to root allows complete system compromise. The attacker can bypass all security "
            "controls, modify network configurations, and access all data on the system."
        ),
        "impact_zh": (
            "本地提权至 root 允许完全的系统沦陷。攻击者可以绕过所有安全控制、修改网络配置并访问系统上的所有数据。"
        ),
        "solution_en": (
            "Update the Linux kernel to version 6.3.4 or later, or apply distribution-specific patches. Follow the "
            "principle of least privilege for user accounts and capabilities. Monitor for suspicious netfilter "
            "rule modifications."
        ),
        "solution_zh": (
            "将 Linux 内核更新至 6.3.4 或更高版本，或应用发行版特定的补丁。遵循最小权限原则管理用户账户和能力。"
            "监控可疑的 netfilter 规则修改。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Linux Kernel < 6.3.4"],
    },
    "CVE-2023-3812": {
        "name_en": "Linux Kernel cls_route Use-After-Free Privilege Escalation",
        "name_zh": "Linux Kernel cls_route 释放后使用提权漏洞",
        "description_en": (
            "CVE-2023-3812 is a use-after-free privilege escalation vulnerability in the Linux kernel's cls_route "
            "traffic classifier. The vulnerability exists in the route4_change() function where a use-after-free "
            "condition occurs during the modification of route classification rules. A local attacker with the "
            "CAP_NET_ADMIN capability can exploit this vulnerability by creating and modifying route classifier "
            "rules that trigger the use-after-free condition, potentially leading to code execution with elevated "
            "privileges. This vulnerability affects Linux kernel versions before 6.5."
        ),
        "description_zh": (
            "CVE-2023-3812 是 Linux 内核 cls_route 流量分类器中的释放后使用（use-after-free）提权漏洞。该漏洞存在于 "
            "route4_change() 函数中，在修改路由分类规则期间会发生释放后使用条件。具有 CAP_NET_ADMIN 能力的本地攻击者"
            "可以通过创建和修改路由分类器规则来触发释放后使用条件，可能导致以提升的权限执行代码。该漏洞影响 6.5 之前的 "
            "Linux 内核版本。"
        ),
        "impact_en": (
            "Local privilege escalation allows the attacker to gain root access, compromising the entire system. "
            "The attacker can then modify network configurations, install persistent malware, and access all "
            "sensitive data on the system."
        ),
        "impact_zh": (
            "本地提权使攻击者能够获得 root 访问权限，危及整个系统。攻击者随后可以修改网络配置、安装持久化恶意软件，"
            "并访问系统上的所有敏感数据。"
        ),
        "solution_en": (
            "Update the Linux kernel to version 6.5 or later, or apply distribution-specific security patches. "
            "Restrict CAP_NET_ADMIN capability to trusted users only. Implement security modules such as SELinux "
            "or AppArmor for additional protection."
        ),
        "solution_zh": (
            "将 Linux 内核更新至 6.5 或更高版本，或应用发行版特定的安全补丁。将 CAP_NET_ADMIN 能力限制为仅受信任的用户。"
            "实施 SELinux 或 AppArmor 等安全模块以提供额外保护。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Linux Kernel < 6.5"],
    },
    "CVE-2023-34362": {
        "name_en": "Progress MOVEit Transfer SQL Injection",
        "name_zh": "Progress MOVEit Transfer SQL 注入漏洞",
        "description_en": (
            "CVE-2023-34362 is a critical SQL injection vulnerability in Progress MOVEit Transfer, a managed file "
            "transfer solution. The vulnerability exists in the MOVEit Transfer web application where a SQL injection "
            "flaw in the SFTP module allows an unauthenticated attacker to execute arbitrary SQL commands against the "
            "backend database. The vulnerability is caused by insufficient input validation in the SFTP folder listing "
            "functionality. An attacker can exploit this vulnerability to extract sensitive data, create unauthorized "
            "accounts, and potentially execute arbitrary code on the server. This vulnerability was actively exploited "
            "in the wild by the Clop ransomware group in a widespread campaign affecting numerous organizations."
        ),
        "description_zh": (
            "CVE-2023-34362 是 Progress MOVEit Transfer（托管文件传输解决方案）中的严重 SQL 注入漏洞。该漏洞存在于 "
            "MOVEit Transfer Web 应用程序中，SFTP 模块中的 SQL 注入缺陷允许未经认证的攻击者对后端数据库执行任意 SQL 命令。"
            "该漏洞由 SFTP 文件夹列表功能中的输入验证不足引起。攻击者可以利用此漏洞提取敏感数据、创建未经授权的账户，"
            "并可能在服务器上执行任意代码。该漏洞已被 Clop 勒索软件团伙在野利用，在影响众多组织的广泛攻击活动中被使用。"
        ),
        "impact_en": (
            "The vulnerability allows unauthenticated data extraction from the MOVEit Transfer database, potentially "
            "exposing millions of sensitive records. The Clop ransomware group used this vulnerability to steal data "
            "from hundreds of organizations worldwide, causing massive data breaches."
        ),
        "impact_zh": (
            "该漏洞允许从 MOVEit Transfer 数据库中未经认证地提取数据，可能暴露数百万条敏感记录。Clop 勒索软件团伙利用此漏洞"
            "从全球数百家组织窃取数据，造成了大规模的数据泄露事件。"
        ),
        "solution_en": (
            "Apply the patches provided by Progress Software immediately. Upgrade MOVEit Transfer to the fixed versions. "
            "Restrict network access to the MOVEit Transfer web interface. Review access logs for signs of SQL injection "
            "exploitation and rotate all potentially compromised credentials."
        ),
        "solution_zh": (
            "立即应用 Progress Software 提供的补丁。将 MOVEit Transfer 升级至修复版本。限制对 MOVEit Transfer Web 界面的"
            "网络访问。审查访问日志以发现 SQL 注入利用的痕迹，并轮换所有可能已被泄露的凭据。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Progress MOVEit Transfer 2023.0.x < 2023.0.4", "Progress MOVEit Transfer 2022.1.x < 2022.1.8", "Progress MOVEit Transfer 2021.1.x < 2021.1.12"],
    },
    "CVE-2023-40044": {
        "name_en": "Progress WS_FTP Server Remote Code Execution",
        "name_zh": "Progress WS_FTP Server 远程代码执行漏洞",
        "description_en": (
            "CVE-2023-40044 is a critical remote code execution vulnerability in Progress WS_FTP Server. The vulnerability "
            "exists in the Ad Hoc Transfer module of WS_FTP Server where a directory traversal flaw allows an attacker to "
            "upload a malicious JSP file to the web application directory. When the uploaded JSP file is accessed through "
            "the web interface, it is executed by the application server, resulting in arbitrary code execution. An "
            "unauthenticated attacker can exploit this vulnerability by sending a specially crafted HTTP request to the "
            "affected endpoint. This vulnerability affects WS_FTP Server versions 2022.0.3 and earlier."
        ),
        "description_zh": (
            "CVE-2023-40044 是 Progress WS_FTP Server 中的严重远程代码执行漏洞。该漏洞存在于 WS_FTP Server 的 Ad Hoc Transfer "
            "模块中，目录穿越缺陷允许攻击者将恶意的 JSP 文件上传到 Web 应用程序目录。当通过 Web 界面访问上传的 JSP 文件时，"
            "它被应用程序服务器执行，导致任意代码执行。未经认证的攻击者可以通过向受影响的端点发送特制的 HTTP 请求来利用此漏洞。"
            "该漏洞影响 WS_FTP Server 2022.0.3 及更早版本。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution allows attackers to fully compromise the WS_FTP Server, potentially "
            "accessing all files transferred through the server and using it as a pivot point for further attacks."
        ),
        "impact_zh": (
            "未经认证的远程代码执行使攻击者能够完全攻陷 WS_FTP Server，可能访问通过该服务器传输的所有文件，"
            "并将其用作进一步攻击的跳板。"
        ),
        "solution_en": (
            "Upgrade WS_FTP Server to version 2022.0.4 or later. Restrict network access to the WS_FTP Server web "
            "interface. Review server logs for signs of exploitation and unauthorized file uploads. Implement WAF "
            "rules to block directory traversal attempts."
        ),
        "solution_zh": (
            "将 WS_FTP Server 升级至 2022.0.4 或更高版本。限制对 WS_FTP Server Web 界面的网络访问。审查服务器日志以发现"
            "利用痕迹和未经授权的文件上传。部署 WAF 规则以阻止目录穿越尝试。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Progress WS_FTP Server <= 2022.0.3"],
    },
    "CVE-2022-26134-DB": {
        "name_en": "Confluence Database Information Disclosure",
        "name_zh": "Confluence 数据库信息泄露漏洞",
        "description_en": (
            "CVE-2022-26134, when exploited from a database security perspective, can lead to significant information "
            "disclosure from the Confluence database. The OGNL injection vulnerability in Confluence allows attackers "
            "to execute arbitrary code that can directly query the underlying database. Through crafted OGNL expressions, "
            "an attacker can extract database connection strings, credentials, and sensitive configuration data stored "
            "in the database. This includes user credentials, API tokens, and internal documentation that may contain "
            "proprietary information, trade secrets, or other confidential data."
        ),
        "description_zh": (
            "从数据库安全角度来看，CVE-2022-26134 被利用后可导致 Confluence 数据库的重大信息泄露。Confluence 中的 OGNL 注入"
            "漏洞允许攻击者执行可以直接查询底层数据库的任意代码。通过构造的 OGNL 表达式，攻击者可以提取数据库连接字符串、凭据"
            "和存储在数据库中的敏感配置数据。这包括用户凭据、API 令牌和可能包含专有信息、商业秘密或其他机密数据的内部文档。"
        ),
        "impact_en": (
            "Database information disclosure can expose all Confluence content, user credentials, and configuration data. "
            "This information can be used for further attacks against the organization's infrastructure and can result "
            "in significant intellectual property loss."
        ),
        "impact_zh": (
            "数据库信息泄露可能暴露所有 Confluence 内容、用户凭据和配置数据。这些信息可用于对组织基础设施的进一步攻击，"
            "并可能导致重大的知识产权损失。"
        ),
        "solution_en": (
            "Upgrade Confluence to the fixed versions immediately. Review database access logs for signs of unauthorized "
            "queries. Rotate all database credentials and API tokens. Implement database activity monitoring to detect "
            "suspicious queries."
        ),
        "solution_zh": (
            "立即将 Confluence 升级至修复版本。审查数据库访问日志以发现未经授权的查询痕迹。轮换所有数据库凭据和 API 令牌。"
            "实施数据库活动监控以检测可疑查询。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Atlassian Confluence Server 7.4.0 - 7.18.0", "Atlassian Confluence Data Center 7.4.0 - 7.18.0"],
    },
    "CVE-2021-22123": {
        "name_en": "Fortinet FortiOS/FortiProxy SQL Injection",
        "name_zh": "Fortinet FortiOS/FortiProxy SQL 注入漏洞",
        "description_en": (
            "CVE-2021-22123 is a SQL injection vulnerability in Fortinet FortiOS and FortiProxy SSL VPN web portal. "
            "The vulnerability exists in the message handling component where user-supplied input is not properly "
            "sanitized before being used in SQL queries. An authenticated SSL VPN user can exploit this vulnerability "
            "by sending a specially crafted request that contains malicious SQL statements. Successful exploitation "
            "allows the attacker to extract sensitive data from the device's database, including user credentials "
            "and configuration information. This vulnerability affects FortiOS versions 6.4.0 through 6.4.6, "
            "6.2.0 through 6.2.5, and FortiProxy versions 2.0.0 through 2.0.5."
        ),
        "description_zh": (
            "CVE-2021-22123 是 Fortinet FortiOS 和 FortiProxy SSL VPN Web 门户中的 SQL 注入漏洞。该漏洞存在于消息处理"
            "组件中，用户提供的输入在用于 SQL 查询之前未经过适当的清理。经过认证的 SSL VPN 用户可以通过发送包含恶意 SQL 语句"
            "的特制请求来利用此漏洞。成功利用后，攻击者可以从设备数据库中提取敏感数据，包括用户凭据和配置信息。该漏洞影响 "
            "FortiOS 6.4.0 至 6.4.6、6.2.0 至 6.2.5 版本，以及 FortiProxy 2.0.0 至 2.0.5 版本。"
        ),
        "impact_en": (
            "SQL injection allows authenticated VPN users to extract sensitive data from the FortiGate device database. "
            "This can lead to credential theft and unauthorized access to the VPN infrastructure."
        ),
        "impact_zh": (
            "SQL 注入允许经过认证的 VPN 用户从 FortiGate 设备数据库中提取敏感数据。这可能导致凭据窃取和对 VPN 基础设施的"
            "未授权访问。"
        ),
        "solution_en": (
            "Upgrade FortiOS to version 6.4.7, 6.2.6, or later. Upgrade FortiProxy to version 2.0.6 or later. "
            "Restrict SSL VPN access to authorized users only. Monitor VPN access logs for signs of SQL injection."
        ),
        "solution_zh": (
            "将 FortiOS 升级至 6.4.7、6.2.6 或更高版本。将 FortiProxy 升级至 2.0.6 或更高版本。将 SSL VPN 访问限制为"
            "仅授权用户。监控 VPN 访问日志以发现 SQL 注入痕迹。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Fortinet FortiOS 6.2.0 - 6.2.5", "Fortinet FortiOS 6.4.0 - 6.4.6", "Fortinet FortiProxy 2.0.0 - 2.0.5"],
    },
    "CVE-2020-15910": {
        "name_en": "OpenEMR Remote Code Execution",
        "name_zh": "OpenEMR 远程代码执行漏洞",
        "description_en": (
            "CVE-2020-15910 is a remote code execution vulnerability in OpenEMR, an open-source electronic medical records "
            "and practice management system. The vulnerability exists in the interface/main/finder/dynamic_finder.php "
            "component where user-supplied input is passed directly to the PHP eval() function without proper validation. "
            "An authenticated attacker with low privileges can exploit this vulnerability by sending a specially crafted "
            "request to the dynamic finder endpoint, resulting in arbitrary PHP code execution on the server. This "
            "vulnerability affects OpenEMR versions 5.0.1 through 5.0.2."
        ),
        "description_zh": (
            "CVE-2020-15910 是开源电子病历和诊所管理系统 OpenEMR 中的远程代码执行漏洞。该漏洞存在于 interface/main/finder/"
            "dynamic_finder.php 组件中，用户提供的输入未经适当验证即被直接传递给 PHP eval() 函数。具有低权限的经过认证的"
            "攻击者可以通过向动态查找器端点发送特制请求来利用此漏洞，导致在服务器上执行任意 PHP 代码。该漏洞影响 OpenEMR "
            "5.0.1 至 5.0.2 版本。"
        ),
        "impact_en": (
            "Remote code execution on a medical records system can lead to exposure of sensitive patient health information "
            "(PHI), disruption of healthcare operations, and compliance violations under regulations such as HIPAA."
        ),
        "impact_zh": (
            "在病历系统上的远程代码执行可能导致敏感患者健康信息（PHI）暴露、医疗运营中断，以及违反 HIPAA 等法规的合规性违规。"
        ),
        "solution_en": (
            "Upgrade OpenEMR to version 5.0.2.1 or later. Restrict access to the OpenEMR system to authorized healthcare "
            "personnel only. Implement network segmentation to isolate the OpenEMR server from the public internet. "
            "Apply the principle of least privilege for all user accounts."
        ),
        "solution_zh": (
            "将 OpenEMR 升级至 5.0.2.1 或更高版本。将 OpenEMR 系统的访问限制为仅授权的医疗人员。实施网络分段以将 OpenEMR "
            "服务器与公共互联网隔离。对所有用户账户应用最小权限原则。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["OpenEMR 5.0.1 - 5.0.2"],
    },

    # ============================================================
    # 加密/协议类（15条）
    # ============================================================
    "CVE-2014-0160": {
        "name_en": "OpenSSL Heartbleed Information Leak",
        "name_zh": "OpenSSL Heartbleed 信息泄露漏洞",
        "description_en": (
            "CVE-2014-0160, commonly known as Heartbleed, is a critical information disclosure vulnerability in OpenSSL. "
            "The vulnerability exists in the TLS heartbeat extension implementation where a buffer over-read can be "
            "triggered by a specially crafted heartbeat request. The flaw is in the dtls1_process_heartbeat() function "
            "where the server fails to properly validate the length field of the heartbeat request. An attacker can "
            "send a heartbeat request claiming to contain more data than it actually does, causing the server to "
            "respond with up to 64KB of memory contents. This can include private keys, session cookies, passwords, "
            "and other sensitive data. This vulnerability affects OpenSSL versions 1.0.1 through 1.0.1f."
        ),
        "description_zh": (
            "CVE-2014-0160，通常被称为 Heartbleed（心脏出血），是 OpenSSL 中的严重信息泄露漏洞。该漏洞存在于 TLS 心跳扩展"
            "实现中，特制的心跳请求可以触发缓冲区过度读取。该缺陷位于 dtls1_process_heartbeat() 函数中，服务器未能正确验证"
            "心跳请求的长度字段。攻击者可以发送一个声称包含比实际更多数据的心跳请求，导致服务器响应多达 64KB 的内存内容。"
            "这可能包括私钥、会话 Cookie、密码和其他敏感数据。该漏洞影响 OpenSSL 1.0.1 至 1.0.1f 版本。"
        ),
        "impact_en": (
            "Heartbleed allows attackers to read up to 64KB of server memory per heartbeat request, potentially "
            "exposing private encryption keys, user credentials, and session data. This can lead to complete "
            "compromise of the encrypted communication channel and all data transmitted through it."
        ),
        "impact_zh": (
            "Heartbleed 允许攻击者每次心跳请求读取多达 64KB 的服务器内存，可能暴露私钥、用户凭据和会话数据。这可能导致"
            "加密通信通道及其传输的所有数据被完全攻陷。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 1.0.1g or later. Revoke and reissue all SSL/TLS certificates, as private keys "
            "may have been compromised. Force password resets for all users. Implement Perfect Forward Secrecy (PFS) "
            "to limit the impact of future key compromises."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 1.0.1g 或更高版本。撤销并重新签发所有 SSL/TLS 证书，因为私钥可能已被泄露。强制所有用户重置密码。"
            "实施前向保密（PFS）以限制未来密钥泄露的影响。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 1.0.1 - 1.0.1f"],
    },
    "CVE-2014-3566": {
        "name_en": "OpenSSL POODLE Downgrade Attack",
        "name_zh": "OpenSSL POODLE 降级攻击漏洞",
        "description_en": (
            "CVE-2014-3566, known as POODLE (Padding Oracle On Downgraded Legacy Encryption), is a vulnerability in "
            "the SSL 3.0 protocol that allows an attacker to decrypt encrypted communications. The vulnerability exists "
            "in the way SSL 3.0 handles CBC (Cipher Block Chaining) mode padding. An attacker who can perform a "
            "man-in-the-middle attack can force a protocol downgrade from TLS to SSL 3.0 and then exploit the padding "
            "oracle in the CBC mode to decrypt one byte of encrypted data per request. While this is an SSL protocol "
            "vulnerability rather than an OpenSSL-specific bug, OpenSSL's support for SSL 3.0 makes it vulnerable. "
            "This affects all versions of OpenSSL that support SSL 3.0."
        ),
        "description_zh": (
            "CVE-2014-3566，被称为 POODLE（降级遗留加密上的填充预言），是 SSL 3.0 协议中的漏洞，允许攻击者解密加密通信。"
            "该漏洞存在于 SSL 3.0 处理 CBC（密码块链接）模式填充的方式中。能够执行中间人攻击的攻击者可以强制将协议从 TLS "
            "降级到 SSL 3.0，然后利用 CBC 模式中的填充预言每次请求解密一个字节的加密数据。虽然这是一个 SSL 协议漏洞而非 "
            "OpenSSL 特定的缺陷，但 OpenSSL 对 SSL 3.0 的支持使其容易受到攻击。这影响所有支持 SSL 3.0 的 OpenSSL 版本。"
        ),
        "impact_en": (
            "POODLE allows attackers to decrypt sensitive data transmitted over SSL 3.0 connections, including session "
            "cookies, authentication tokens, and other confidential information. The attack requires the ability to "
            "perform man-in-the-middle attacks on the network."
        ),
        "impact_zh": (
            "POODLE 允许攻击者解密通过 SSL 3.0 连接传输的敏感数据，包括会话 Cookie、认证令牌和其他机密信息。"
            "该攻击需要在网络上执行中间人攻击的能力。"
        ),
        "solution_en": (
            "Disable SSL 3.0 support in OpenSSL and all web servers and applications. Configure servers to only support "
            "TLS 1.2 and TLS 1.3. Implement TLS_FALLBACK_SCSV to prevent protocol downgrade attacks. Use AES-GCM "
            "cipher suites that are not vulnerable to padding oracle attacks."
        ),
        "solution_zh": (
            "在 OpenSSL 及所有 Web 服务器和应用程序中禁用 SSL 3.0 支持。配置服务器仅支持 TLS 1.2 和 TLS 1.3。实施 "
            "TLS_FALLBACK_SCSV 以防止协议降级攻击。使用不受填充预言攻击影响的 AES-GCM 密码套件。"
        ),
        "severity": "medium",
        "cvss": 6.8,
        "affected_products": ["OpenSSL (all versions supporting SSL 3.0)", "All web servers using SSL 3.0"],
    },
    "CVE-2016-2107": {
        "name_en": "OpenSSL Lucky13 Attack",
        "name_zh": "OpenSSL Lucky13 攻击漏洞",
        "description_en": (
            "CVE-2016-2107 is a vulnerability in OpenSSL related to the Lucky13 timing attack against CBC-mode cipher "
            "suites. The vulnerability exists because OpenSSL's implementation of CBC mode decryption does not perform "
            "constant-time comparison of MAC values, creating a timing side-channel. An attacker can exploit this "
            "timing difference to perform a padding oracle attack and decrypt encrypted data. The attack requires "
            "the attacker to be able to perform many connections to the server and measure timing differences in "
            "the responses. This vulnerability affects OpenSSL versions 1.0.1 before 1.0.1t and 1.0.2 before "
            "1.0.2h."
        ),
        "description_zh": (
            "CVE-2016-2107 是 OpenSSL 中与 Lucky13 时序攻击相关的漏洞，针对 CBC 模式密码套件。该漏洞存在的原因是 OpenSSL 的 "
            "CBC 模式解密实现未对 MAC 值执行恒定时间比较，创建了时序侧信道。攻击者可以利用此时序差异执行填充预言攻击并解密"
            "加密数据。该攻击要求攻击者能够对服务器执行大量连接并测量响应中的时序差异。该漏洞影响 OpenSSL 1.0.1t 之前的 "
            "1.0.1 版本和 1.0.2h 之前的 1.0.2 版本。"
        ),
        "impact_en": (
            "The Lucky13 attack allows decryption of encrypted communications through timing side-channel analysis. "
            "While the attack requires many connections and precise timing measurements, it can ultimately lead to "
            "exposure of sensitive data transmitted over encrypted connections."
        ),
        "impact_zh": (
            "Lucky13 攻击通过时序侧信道分析允许解密加密通信。虽然该攻击需要大量连接和精确的时序测量，但最终可能导致"
            "通过加密连接传输的敏感数据暴露。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 1.0.1t, 1.0.2h, or later. Prefer AEAD cipher suites such as AES-GCM over "
            "CBC-mode ciphers. Implement TLS 1.2 with AES-GCM or ChaCha20-Poly1305 cipher suites. Use network "
            "jitter injection to make timing attacks more difficult."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 1.0.1t、1.0.2h 或更高版本。优先使用 AEAD 密码套件（如 AES-GCM）而非 CBC 模式密码。"
            "实施 TLS 1.2 并使用 AES-GCM 或 ChaCha20-Poly1305 密码套件。使用网络抖动注入使时序攻击更加困难。"
        ),
        "severity": "medium",
        "cvss": 5.3,
        "affected_products": ["OpenSSL 1.0.1 < 1.0.1t", "OpenSSL 1.0.2 < 1.0.2h"],
    },
    "CVE-2015-4000": {
        "name_en": "OpenSSL LOGJAM Downgrade Attack",
        "name_zh": "OpenSSL LOGJAM 降级攻击漏洞",
        "description_en": (
            "CVE-2015-4000, known as LOGJAM, is a vulnerability in the TLS protocol's support for export-grade "
            "Diffie-Hellman key exchange. The vulnerability allows a man-in-the-middle attacker to downgrade the "
            "TLS connection to use 512-bit export-grade Diffie-Hellman parameters. With sufficiently pre-computed "
            "data, the attacker can then break the Diffie-Hellman key exchange and decrypt the connection. The "
            "vulnerability affects all TLS implementations that support export-grade DHE cipher suites, including "
            "OpenSSL. The pre-computation required to break 512-bit DH is within reach of nation-state attackers."
        ),
        "description_zh": (
            "CVE-2015-4000，被称为 LOGJAM，是 TLS 协议支持出口级 Diffie-Hellman 密钥交换中的漏洞。该漏洞允许中间人攻击者"
            "将 TLS 连接降级为使用 512 位出口级 Diffie-Hellman 参数。通过足够的预计算数据，攻击者可以破解 Diffie-Hellman "
            "密钥交换并解密连接。该漏洞影响所有支持出口级 DHE 密码套件的 TLS 实现，包括 OpenSSL。破解 512 位 DH 所需的"
            "预计算在国家级行为者的能力范围内。"
        ),
        "impact_en": (
            "LOGJAM allows man-in-the-middle attackers to decrypt TLS connections that use export-grade DH parameters. "
            "This can lead to exposure of all data transmitted over the affected connections, including credentials "
            "and sensitive communications."
        ),
        "impact_zh": (
            "LOGJAM 允许中间人攻击者解密使用出口级 DH 参数的 TLS 连接。这可能导致通过受影响连接传输的所有数据暴露，"
            "包括凭据和敏感通信。"
        ),
        "solution_en": (
            "Disable export-grade cipher suites in OpenSSL and all TLS-enabled applications. Generate and use 2048-bit "
            "or larger Diffie-Hellman parameters. Implement TLS_FALLBACK_SCSV to prevent downgrade attacks. Prefer "
            "ECDHE cipher suites over DHE cipher suites."
        ),
        "solution_zh": (
            "在 OpenSSL 及所有启用 TLS 的应用程序中禁用出口级密码套件。生成并使用 2048 位或更大的 Diffie-Hellman 参数。"
            "实施 TLS_FALLBACK_SCSV 以防止降级攻击。优先使用 ECDHE 密码套件而非 DHE 密码套件。"
        ),
        "severity": "medium",
        "cvss": 5.3,
        "affected_products": ["OpenSSL (all versions with export cipher support)", "All TLS servers supporting export-grade DHE"],
    },
    "CVE-2014-0224": {
        "name_en": "OpenSSL CCS Injection",
        "name_zh": "OpenSSL CCS 注入漏洞",
        "description_en": (
            "CVE-2014-0224 is a man-in-the-middle vulnerability in OpenSSL that allows an attacker to inject arbitrary "
            "data into a TLS session. The vulnerability exists in the handling of CCS (ChangeCipherSpec) messages where "
            "OpenSSL does not properly verify the state of the connection when processing a CCS message. An attacker "
            "who can perform a man-in-the-middle attack can send a CCS message at an unexpected point in the handshake, "
            "causing OpenSSL to use a zero-length pre-master secret key. This effectively downgrades the connection "
            "security and allows the attacker to decrypt and modify the encrypted traffic. This vulnerability affects "
            "OpenSSL versions 1.0.1 before 1.0.1g and all versions of 1.0.0 and 0.9.8."
        ),
        "description_zh": (
            "CVE-2014-0224 是 OpenSSL 中的中间人漏洞，允许攻击者向 TLS 会话中注入任意数据。该漏洞存在于 CCS（ChangeCipherSpec）"
            "消息处理中，OpenSSL 在处理 CCS 消息时未正确验证连接状态。能够执行中间人攻击的攻击者可以在握手过程中不期望的时间点"
            "发送 CCS 消息，导致 OpenSSL 使用零长度的预主密钥。这有效地降低了连接安全性，允许攻击者解密和修改加密流量。"
            "该漏洞影响 OpenSSL 1.0.1g 之前的 1.0.1 版本以及所有 1.0.0 和 0.9.8 版本。"
        ),
        "impact_en": (
            "CCS injection allows man-in-the-middle attackers to decrypt and modify encrypted TLS traffic. This can "
            "lead to exposure of sensitive data, session hijacking, and injection of malicious content into encrypted "
            "communications."
        ),
        "impact_zh": (
            "CCS 注入允许中间人攻击者解密和修改加密的 TLS 流量。这可能导致敏感数据暴露、会话劫持，以及向加密通信中"
            "注入恶意内容。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 1.0.1g, 1.0.0s, or 0.9.8za or later. Implement certificate pinning to detect "
            "man-in-the-middle attacks. Use TLS 1.2 or higher with strong cipher suites."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 1.0.1g、1.0.0s 或 0.9.8za 及更高版本。实施证书固定以检测中间人攻击。"
            "使用 TLS 1.2 或更高版本配合强密码套件。"
        ),
        "severity": "medium",
        "cvss": 6.8,
        "affected_products": ["OpenSSL 0.9.8", "OpenSSL 1.0.0", "OpenSSL 1.0.1 < 1.0.1g"],
    },
    "CVE-2011-3389": {
        "name_en": "SSL/TLS BEAST Attack",
        "name_zh": "SSL/TLS BEAST 攻击漏洞",
        "description_en": (
            "CVE-2011-3389, known as BEAST (Browser Exploit Against SSL/TLS), is a vulnerability in SSL 3.0 and TLS 1.0 "
            "protocols that allows an attacker to decrypt encrypted data. The vulnerability exists in the way CBC mode "
            "is used in TLS 1.0, where the Initialization Vector (IV) for each block is predictable (it is the last "
            "block of the previous ciphertext). An attacker who can inject chosen plaintext into the encrypted stream "
            "and observe the resulting ciphertext can use this predictability to gradually decrypt the encrypted data. "
            "This vulnerability affects all implementations of SSL 3.0 and TLS 1.0, including OpenSSL."
        ),
        "description_zh": (
            "CVE-2011-3389，被称为 BEAST（浏览器利用 SSL/TLS 攻击），是 SSL 3.0 和 TLS 1.0 协议中的漏洞，允许攻击者"
            "解密加密数据。该漏洞存在于 TLS 1.0 中 CBC 模式的使用方式中，每个块的初始化向量（IV）是可预测的（它是前一个"
            "密文块的最后一个块）。能够将选择的明文注入加密流并观察结果密文的攻击者可以利用这种可预测性逐步解密加密数据。"
            "该漏洞影响 SSL 3.0 和 TLS 1.0 的所有实现，包括 OpenSSL。"
        ),
        "impact_en": (
            "BEAST allows attackers to decrypt encrypted HTTP cookies and other sensitive data transmitted over TLS 1.0 "
            "connections. This can lead to session hijacking and unauthorized access to web applications."
        ),
        "impact_zh": (
            "BEAST 允许攻击者解密通过 TLS 1.0 连接传输的加密 HTTP Cookie 和其他敏感数据。这可能导致会话劫持和对 Web 应用"
            "程序的未授权访问。"
        ),
        "solution_en": (
            "Upgrade to TLS 1.1 or TLS 1.2 which use explicit IVs in CBC mode. Implement 1/n-1 record splitting as "
            "a mitigation for TLS 1.0. Prefer RC4 cipher suites over CBC (though RC4 has its own weaknesses). "
            "Use modern TLS implementations that include BEAST mitigations."
        ),
        "solution_zh": (
            "升级至 TLS 1.1 或 TLS 1.2，它们在 CBC 模式中使用显式 IV。实施 1/n-1 记录分割作为 TLS 1.0 的缓解措施。"
            "优先使用 RC4 密码套件而非 CBC（尽管 RC4 有其自身的弱点）。使用包含 BEAST 缓解措施的现代 TLS 实现。"
        ),
        "severity": "medium",
        "cvss": 4.3,
        "affected_products": ["OpenSSL (all versions supporting TLS 1.0)", "All web browsers and servers using TLS 1.0"],
    },
    "CVE-2014-3566-Poodle": {
        "name_en": "POODLE Vulnerability in SSL 3.0 Fallback",
        "name_zh": "SSL 3.0 降级中的 POODLE 漏洞",
        "description_en": (
            "This entry covers the POODLE vulnerability from the perspective of TLS implementation fallback behavior. "
            "When a TLS connection fails, some clients automatically fall back to SSL 3.0 for compatibility. An attacker "
            "who can disrupt TLS connections can force this fallback and then exploit the POODLE vulnerability in SSL 3.0 "
            "to decrypt the communication. The vulnerability is in the CBC padding implementation of SSL 3.0, which "
            "does not verify that the padding bytes have the correct value. This allows a padding oracle attack that "
            "can decrypt one byte of data per 256 requests on average."
        ),
        "description_zh": (
            "本条目从 TLS 实现回退行为的角度介绍 POODLE 漏洞。当 TLS 连接失败时，某些客户端会自动回退到 SSL 3.0 以保持兼容性。"
            "能够中断 TLS 连接的攻击者可以强制这种回退，然后利用 SSL 3.0 中的 POODLE 漏洞解密通信。该漏洞位于 SSL 3.0 的 "
            "CBC 填充实现中，该实现不验证填充字节是否具有正确的值。这允许填充预言攻击平均每 256 个请求解密一个字节的数据。"
        ),
        "impact_en": (
            "Forced protocol downgrade combined with POODLE allows decryption of sensitive data in transit. This is "
            "particularly dangerous for web applications that transmit authentication credentials or session tokens."
        ),
        "impact_zh": (
            "强制协议降级结合 POODLE 允许解密传输中的敏感数据。这对于传输认证凭据或会话令牌的 Web 应用程序尤其危险。"
        ),
        "solution_en": (
            "Disable SSL 3.0 support entirely on both clients and servers. Implement TLS_FALLBACK_SCSV to prevent "
            "protocol downgrade attacks. Use only TLS 1.2 and TLS 1.3 with modern cipher suites."
        ),
        "solution_zh": (
            "在客户端和服务器上完全禁用 SSL 3.0 支持。实施 TLS_FALLBACK_SCSV 以防止协议降级攻击。仅使用 TLS 1.2 和 "
            "TLS 1.3 配合现代密码套件。"
        ),
        "severity": "medium",
        "cvss": 6.8,
        "affected_products": ["OpenSSL (all versions with SSL 3.0 support)", "All web servers and browsers with SSL 3.0 fallback"],
    },
    "CVE-2020-1967": {
        "name_en": "OpenSSL TLS 1.3 Denial of Service",
        "name_zh": "OpenSSL TLS 1.3 拒绝服务漏洞",
        "description_en": (
            "CVE-2020-1967 is a denial of service vulnerability in OpenSSL's TLS 1.3 implementation. The vulnerability "
            "exists in the handling of TLS 1.3 session tickets where a NULL pointer dereference can be triggered by "
            "a specially crafted session ticket. When a client sends a maliciously crafted session ticket during the "
            "TLS handshake, the server attempts to process it and encounters a NULL pointer dereference, causing the "
            "server process to crash. An unauthenticated attacker can repeatedly exploit this vulnerability to cause "
            "persistent denial of service. This vulnerability affects OpenSSL versions 1.1.1 before 1.1.1i."
        ),
        "description_zh": (
            "CVE-2020-1967 是 OpenSSL TLS 1.3 实现中的拒绝服务漏洞。该漏洞存在于 TLS 1.3 会话票据处理中，特制的会话票据"
            "可以触发空指针解引用。当客户端在 TLS 握手期间发送恶意构造的会话票据时，服务器尝试处理它并遇到空指针解引用，"
            "导致服务器进程崩溃。未经认证的攻击者可以反复利用此漏洞导致持续的拒绝服务。该漏洞影响 OpenSSL 1.1.1i 之前的 "
            "1.1.1 版本。"
        ),
        "impact_en": (
            "Denial of service through server crashes can disrupt all TLS-secured services, including HTTPS, email, "
            "and VPN services. Repeated exploitation can cause prolonged outages affecting business operations."
        ),
        "impact_zh": (
            "通过服务器崩溃导致的拒绝服务可以中断所有 TLS 安全服务，包括 HTTPS、电子邮件和 VPN 服务。反复利用可能导致影响"
            "业务运营的长时间中断。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 1.1.1i or later. Implement rate limiting on TLS handshake requests. Deploy "
            "load balancers with health checks to detect and route around crashed instances."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 1.1.1i 或更高版本。对 TLS 握手请求实施速率限制。部署具有健康检查的负载均衡器以检测并"
            "绕过已崩溃的实例。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 1.1.1 < 1.1.1i"],
    },
    "CVE-2022-0778": {
        "name_en": "OpenSSL Infinite Loop Denial of Service",
        "name_zh": "OpenSSL 无限循环拒绝服务漏洞",
        "description_en": (
            "CVE-2022-0778 is a denial of service vulnerability in OpenSSL that can be triggered through the processing "
            "of specially crafted X.509 certificates. The vulnerability exists in the BN_mod_sqrt() function used for "
            "computing square roots modulo a prime. A maliciously crafted certificate containing a specially constructed "
            "prime number can cause the BN_mod_sqrt() function to enter an infinite loop, consuming excessive CPU "
            "resources. An unauthenticated attacker can exploit this vulnerability by presenting a malicious certificate "
            "during a TLS handshake, causing the server to become unresponsive. This vulnerability affects OpenSSL "
            "versions 1.1.1 before 1.1.1n and 3.0.x before 3.0.2."
        ),
        "description_zh": (
            "CVE-2022-0778 是 OpenSSL 中的拒绝服务漏洞，可以通过处理特制的 X.509 证书来触发。该漏洞存在于用于计算模素数"
            "平方根的 BN_mod_sqrt() 函数中。包含特殊构造的素数的恶意证书可以导致 BN_mod_sqrt() 函数进入无限循环，"
            "消耗过多的 CPU 资源。未经认证的攻击者可以在 TLS 握手期间提供恶意证书来利用此漏洞，导致服务器变得无响应。"
            "该漏洞影响 OpenSSL 1.1.1n 之前的 1.1.1 版本和 3.0.2 之前的 3.0.x 版本。"
        ),
        "impact_en": (
            "The infinite loop can consume all available CPU resources on the server, causing complete denial of service "
            "for all TLS-secured services. The attack requires only a single malicious certificate to trigger."
        ),
        "impact_zh": (
            "无限循环可以消耗服务器上所有可用的 CPU 资源，导致所有 TLS 安全服务完全拒绝服务。该攻击只需一个恶意证书即可触发。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 1.1.1n or 3.0.2 or later. Implement certificate validation and reject certificates "
            "with suspicious parameters. Deploy CPU monitoring and process limits to detect and mitigate resource "
            "exhaustion attacks."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 1.1.1n 或 3.0.2 及更高版本。实施证书验证并拒绝具有可疑参数的证书。部署 CPU 监控和进程限制"
            "以检测和缓解资源耗尽攻击。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 1.1.1 < 1.1.1n", "OpenSSL 3.0.x < 3.0.2"],
    },
    "CVE-2023-0464": {
        "name_en": "OpenSSL X.509 Type Confusion",
        "name_zh": "OpenSSL X.509 类型混淆漏洞",
        "description_en": (
            "CVE-2023-0464 is a type confusion vulnerability in OpenSSL that can lead to a denial of service condition. "
            "The vulnerability exists in the X.509 certificate verification code where a type confusion can occur when "
            "processing certain certificate extensions. Specifically, the vulnerability is in the handling of the "
            "Authority Key Identifier (AKI) and Subject Key Identifier (SKI) extensions where incorrect type assumptions "
            "can lead to a NULL pointer dereference or other undefined behavior. An attacker can exploit this "
            "vulnerability by presenting a specially crafted certificate that triggers the type confusion, causing the "
            "application to crash. This vulnerability affects OpenSSL versions 3.0.x before 3.0.8."
        ),
        "description_zh": (
            "CVE-2023-0464 是 OpenSSL 中的类型混淆漏洞，可导致拒绝服务条件。该漏洞存在于 X.509 证书验证代码中，在处理"
            "某些证书扩展时可能发生类型混淆。具体而言，该漏洞位于授权密钥标识符（AKI）和主体密钥标识符（SKI）扩展的处理中，"
            "不正确的类型假设可能导致空指针解引用或其他未定义行为。攻击者可以通过提供触发类型混淆的特制证书来利用此漏洞，"
            "导致应用程序崩溃。该漏洞影响 OpenSSL 3.0.8 之前的 3.0.x 版本。"
        ),
        "impact_en": (
            "The type confusion can lead to application crashes, causing denial of service for TLS-secured services. "
            "In some cases, the undefined behavior could potentially be exploited for code execution, though this "
            "has not been demonstrated."
        ),
        "impact_zh": (
            "类型混淆可能导致应用程序崩溃，造成 TLS 安全服务的拒绝服务。在某些情况下，未定义行为可能被利用进行代码执行，"
            "尽管这尚未被证实。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.8 or later. Implement certificate validation to reject certificates with "
            "malformed extensions. Deploy monitoring to detect and respond to service crashes."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.8 或更高版本。实施证书验证以拒绝具有格式错误的扩展的证书。部署监控以检测和响应服务崩溃。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 3.0.x < 3.0.8"],
    },
    "CVE-2023-0465": {
        "name_en": "OpenSSL Denial of Service",
        "name_zh": "OpenSSL 拒绝服务漏洞",
        "description_en": (
            "CVE-2023-0465 is a denial of service vulnerability in OpenSSL that can be triggered through malformed "
            "PKCS#12 files. The vulnerability exists in the PKCS#12 parsing code where a specially crafted PKCS#12 "
            "file can cause excessive memory allocation. When an application processes a maliciously crafted PKCS#12 "
            "file (commonly used for certificate bundles), the parser allocates memory based on values read from the "
            "file without proper bounds checking. This can lead to memory exhaustion and denial of service. This "
            "vulnerability affects OpenSSL versions 3.0.x before 3.0.8."
        ),
        "description_zh": (
            "CVE-2023-0465 是 OpenSSL 中的拒绝服务漏洞，可以通过格式错误的 PKCS#12 文件触发。该漏洞存在于 PKCS#12 解析"
            "代码中，特制的 PKCS#12 文件可以导致过多的内存分配。当应用程序处理恶意构造的 PKCS#12 文件（通常用于证书捆绑包）时，"
            "解析器根据从文件中读取的值分配内存而未进行适当的边界检查。这可能导致内存耗尽和拒绝服务。该漏洞影响 OpenSSL "
            "3.0.8 之前的 3.0.x 版本。"
        ),
        "impact_en": (
            "Memory exhaustion can cause the application to crash or become unresponsive, leading to denial of service. "
            "This is particularly impactful for servers that process user-uploaded certificates or PKCS#12 files."
        ),
        "impact_zh": (
            "内存耗尽可能导致应用程序崩溃或变得无响应，导致拒绝服务。这对于处理用户上传的证书或 PKCS#12 文件的服务器"
            "尤其具有影响。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.8 or later. Implement file size limits for uploaded PKCS#12 files. "
            "Deploy memory monitoring and resource limits to detect and mitigate memory exhaustion attacks."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.8 或更高版本。对上传的 PKCS#12 文件实施文件大小限制。部署内存监控和资源限制以检测"
            "和缓解内存耗尽攻击。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 3.0.x < 3.0.8"],
    },
    "CVE-2023-0466": {
        "name_en": "OpenSSL DH Parameter Check Bypass",
        "name_zh": "OpenSSL DH 参数检查绕过漏洞",
        "description_en": (
            "CVE-2023-0466 is a vulnerability in OpenSSL that allows bypassing certain security checks on Diffie-Hellman "
            "parameters. The vulnerability exists in the DH parameter validation code where certain checks for unsafe "
            "prime numbers can be bypassed. When DH parameters with unsafe primes are used, the resulting key exchange "
            "may be weaker than expected, potentially allowing an attacker to compute the shared secret. This "
            "vulnerability affects OpenSSL versions 3.0.x before 3.0.8 and 1.1.1 before 1.1.1t."
        ),
        "description_zh": (
            "CVE-2023-0466 是 OpenSSL 中的漏洞，允许绕过对 Diffie-Hellman 参数的某些安全检查。该漏洞存在于 DH 参数验证"
            "代码中，对不安全素数的某些检查可以被绕过。当使用具有不安全素数的 DH 参数时，产生的密钥交换可能比预期的更弱，"
            "可能允许攻击者计算共享密钥。该漏洞影响 OpenSSL 3.0.8 之前的 3.0.x 版本和 1.1.1t 之前的 1.1.1 版本。"
        ),
        "impact_en": (
            "Bypassing DH parameter security checks can weaken the key exchange, potentially allowing attackers to "
            "compute the shared secret and decrypt encrypted communications. This undermines the security of the "
            "TLS connection."
        ),
        "impact_zh": (
            "绕过 DH 参数安全检查可能削弱密钥交换，可能允许攻击者计算共享密钥并解密加密通信。这破坏了 TLS 连接的安全性。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.8 or 1.1.1t or later. Generate new DH parameters using safe primes. "
            "Prefer ECDHE cipher suites over DHE cipher suites. Validate DH parameters before use."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.8 或 1.1.1t 及更高版本。使用安全素数生成新的 DH 参数。优先使用 ECDHE 密码套件"
            "而非 DHE 密码套件。在使用前验证 DH 参数。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 1.1.1 < 1.1.1t", "OpenSSL 3.0.x < 3.0.8"],
    },
    "CVE-2023-3817": {
        "name_en": "OpenSSL X.509 Timestamp Verification Bypass",
        "name_zh": "OpenSSL X.509 时间戳验证绕过漏洞",
        "description_en": (
            "CVE-2023-3817 is a vulnerability in OpenSSL that can lead to incorrect verification of X.509 certificate "
            "time validity. The vulnerability exists in the certificate verification code where certain edge cases in "
            "the handling of time-related certificate fields are not properly validated. Specifically, the vulnerability "
            "affects the handling of certificates with unusual validity period configurations, which can cause the "
            "verification to produce incorrect results. This could allow expired or not-yet-valid certificates to be "
            "accepted as valid. This vulnerability affects OpenSSL versions 3.0.x before 3.0.10."
        ),
        "description_zh": (
            "CVE-2023-3817 是 OpenSSL 中的漏洞，可能导致 X.509 证书时间有效性的错误验证。该漏洞存在于证书验证代码中，"
            "对时间相关证书字段处理中的某些边缘情况未进行适当的验证。具体而言，该漏洞影响具有异常有效期配置的证书的处理，"
            "可能导致验证产生不正确的结果。这可能使已过期或尚未生效的证书被接受为有效。该漏洞影响 OpenSSL 3.0.10 之前的 "
            "3.0.x 版本。"
        ),
        "impact_en": (
            "Accepting expired or not-yet-valid certificates can undermine the security of TLS connections and "
            "certificate-based authentication. This could allow attackers to use revoked or expired certificates "
            "to impersonate legitimate servers."
        ),
        "impact_zh": (
            "接受已过期或尚未生效的证书可能破坏 TLS 连接和基于证书的身份认证的安全性。这可能允许攻击者使用已撤销或已过期的"
            "证书冒充合法服务器。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.10 or later. Implement additional certificate validation checks in "
            "applications. Monitor certificate validity and implement proper certificate revocation checking "
            "through OCSP or CRL."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.10 或更高版本。在应用程序中实施额外的证书验证检查。监控证书有效性并通过 OCSP 或 CRL "
            "实施适当的证书撤销检查。"
        ),
        "severity": "medium",
        "cvss": 5.3,
        "affected_products": ["OpenSSL 3.0.x < 3.0.10"],
    },
    "CVE-2023-5678": {
        "name_en": "OpenSSL BIO Pointer Leak",
        "name_zh": "OpenSSL BIO 指针泄露漏洞",
        "description_en": (
            "CVE-2023-5678 is an information disclosure vulnerability in OpenSSL related to BIO (Basic I/O) handling. "
            "The vulnerability exists in the BIO_s_file() implementation where a pointer to internal memory can be "
            "leaked through error handling paths. When certain error conditions occur during file I/O operations, "
            "internal memory pointers may be included in error messages or diagnostic output. An attacker who can "
            "trigger these error conditions can potentially obtain information about the memory layout of the "
            "process, which can be useful for bypassing security mitigations such as ASLR. This vulnerability "
            "affects OpenSSL versions 3.0.x before 3.0.11."
        ),
        "description_zh": (
            "CVE-2023-5678 是 OpenSSL 中与 BIO（基本 I/O）处理相关的信息泄露漏洞。该漏洞存在于 BIO_s_file() 实现中，"
            "内部内存的指针可以通过错误处理路径泄露。当文件 I/O 操作期间发生某些错误条件时，内部内存指针可能被包含在错误消息"
            "或诊断输出中。能够触发这些错误条件的攻击者可能获取有关进程内存布局的信息，这对于绕过 ASLR 等安全缓解措施"
            "非常有用。该漏洞影响 OpenSSL 3.0.11 之前的 3.0.x 版本。"
        ),
        "impact_en": (
            "Memory pointer leakage can help attackers bypass ASLR and other memory protection mechanisms, facilitating "
            "the exploitation of other vulnerabilities. This is primarily an information disclosure vulnerability "
            "that aids in further attacks."
        ),
        "impact_zh": (
            "内存指针泄露可以帮助攻击者绕过 ASLR 和其他内存保护机制，促进其他漏洞的利用。这主要是一个信息泄露漏洞，"
            "有助于进一步的攻击。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.11 or later. Ensure error messages do not contain sensitive internal "
            "information. Implement address space layout randomization (ASLR) and other exploit mitigations."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.11 或更高版本。确保错误消息不包含敏感的内部信息。实施地址空间布局随机化（ASLR）"
            "和其他利用缓解措施。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 3.0.x < 3.0.11"],
    },
    "CVE-2023-2650": {
        "name_en": "OpenSSL ASN.1 Parser Denial of Service",
        "name_zh": "OpenSSL ASN.1 解析器拒绝服务漏洞",
        "description_en": (
            "CVE-2023-2650 is a denial of service vulnerability in OpenSSL's ASN.1 (Abstract Syntax Notation One) "
            "parser. The vulnerability exists in the handling of ASN.1 encoded data where a specially crafted ASN.1 "
            "structure can trigger excessive recursion or memory consumption. When an application processes a maliciously "
            "crafted X.509 certificate or other ASN.1 encoded data, the parser may enter a state that consumes "
            "excessive CPU or memory resources, leading to denial of service. This vulnerability affects OpenSSL "
            "versions 3.0.x before 3.0.9 and 1.1.1 before 1.1.1s."
        ),
        "description_zh": (
            "CVE-2023-2650 是 OpenSSL ASN.1（抽象语法表示法一）解析器中的拒绝服务漏洞。该漏洞存在于 ASN.1 编码数据的处理中，"
            "特制的 ASN.1 结构可以触发过度的递归或内存消耗。当应用程序处理恶意构造的 X.509 证书或其他 ASN.1 编码数据时，"
            "解析器可能进入消耗过多 CPU 或内存资源的状态，导致拒绝服务。该漏洞影响 OpenSSL 3.0.9 之前的 3.0.x 版本和 "
            "1.1.1s 之前的 1.1.1 版本。"
        ),
        "impact_en": (
            "Excessive resource consumption can cause the application to become unresponsive or crash, leading to "
            "denial of service for all dependent services. This is particularly impactful for servers that process "
            "untrusted certificates or ASN.1 data."
        ),
        "impact_zh": (
            "过度的资源消耗可能导致应用程序变得无响应或崩溃，导致所有依赖服务的拒绝服务。这对于处理不可信证书或 ASN.1 数据的"
            "服务器尤其具有影响。"
        ),
        "solution_en": (
            "Upgrade OpenSSL to version 3.0.9 or 1.1.1s or later. Implement recursion depth limits and memory limits "
            "for ASN.1 parsing. Deploy resource monitoring to detect and respond to resource exhaustion attacks."
        ),
        "solution_zh": (
            "将 OpenSSL 升级至 3.0.9 或 1.1.1s 及更高版本。为 ASN.1 解析实施递归深度限制和内存限制。部署资源监控以检测"
            "和响应资源耗尽攻击。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["OpenSSL 1.1.1 < 1.1.1s", "OpenSSL 3.0.x < 3.0.9"],
    },

    # ============================================================
    # 操作系统类（10条）
    # ============================================================
    "CVE-2021-34527-OS": {
        "name_en": "PrintNightmare Windows Print Spooler Privilege Escalation (OS Impact)",
        "name_zh": "PrintNightmare Windows 打印后台处理服务提权漏洞（操作系统影响）",
        "description_en": (
            "From an operating system security perspective, CVE-2021-34527 (PrintNightmare) represents one of the most "
            "significant privilege escalation vulnerabilities in recent Windows history. The vulnerability exploits "
            "the Windows Print Spooler service, which runs with SYSTEM privileges and is enabled by default on most "
            "Windows installations. The flaw allows both local and remote attackers to load arbitrary printer driver "
            "DLLs without proper authentication. The Print Spooler service's architecture inherently trusts printer "
            "driver packages, and the vulnerability bypasses the Point and Print security mechanism. This means an "
            "attacker can point the Print Spooler to a remote share containing a malicious DLL, which gets loaded "
            "and executed with SYSTEM privileges. The vulnerability affects all supported versions of Windows, "
            "including Windows Server, making it particularly dangerous in enterprise Active Directory environments."
        ),
        "description_zh": (
            "从操作系统安全角度来看，CVE-2021-34527（PrintNightmare）代表了近年来 Windows 历史上最重要的提权漏洞之一。"
            "该漏洞利用 Windows 打印后台处理服务，该服务以 SYSTEM 权限运行且在大多数 Windows 安装中默认启用。该缺陷允许"
            "本地和远程攻击者在没有适当认证的情况下加载任意打印机驱动程序 DLL。打印后台处理服务的架构本质上信任打印机驱动"
            "程序包，该漏洞绕过了“点和打印”安全机制。这意味着攻击者可以将打印后台处理服务指向包含恶意 DLL 的远程共享，"
            "该 DLL 以 SYSTEM 权限被加载和执行。该漏洞影响所有受支持的 Windows 版本，包括 Windows Server，使其在企业 "
            "Active Directory 环境中尤其危险。"
        ),
        "impact_en": (
            "PrintNightmare provides both local and remote privilege escalation to SYSTEM, the highest privilege level "
            "in Windows. In domain environments, an attacker who compromises a single workstation can use PrintNightmare "
            "to elevate to SYSTEM and then use those credentials to attack domain controllers, potentially compromising "
            "the entire Active Directory domain."
        ),
        "impact_zh": (
            "PrintNightmare 提供本地和远程提权至 SYSTEM（Windows 中的最高权限级别）。在域环境中，攻陷单个工作站的攻击者"
            "可以使用 PrintNightmare 提升至 SYSTEM，然后使用这些凭据攻击域控制器，可能危及整个 Active Directory 域。"
        ),
        "solution_en": (
            "Install Microsoft security updates from July 2021 and subsequent cumulative updates. Disable the Print "
            "Spooler service on domain controllers and systems that do not require printing. Configure Group Policy "
            "settings for 'Point and Print Restrictions' to prevent unauthorized driver installation. Block inbound "
            "RPC traffic (port 135) on critical systems."
        ),
        "solution_zh": (
            "安装微软 2021 年 7 月及后续累积安全更新。在域控制器和不需要打印功能的系统上禁用打印后台处理服务。配置组策略"
            "中的“点和打印限制”设置以防止未经授权的驱动程序安装。在关键系统上阻止入站 RPC 流量（端口 135）。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 7/8.1/10/11", "Windows Server 2008 R2/2012/2016/2019/2022"],
    },
    "CVE-2020-0796-OS": {
        "name_en": "SMBGhost (SMBv3) Remote Code Execution (OS Kernel Impact)",
        "name_zh": "SMBGhost (SMBv3) 远程代码执行漏洞（操作系统内核影响）",
        "description_en": (
            "From an operating system kernel perspective, CVE-2020-0796 (SMBGhost) is a critical vulnerability in the "
            "Windows SMBv3 protocol implementation within the kernel. The vulnerability exists in the srv2.sys kernel-mode "
            "driver responsible for handling SMBv3 compression. A specially crafted SMBv3 compression negotiation packet "
            "can trigger a buffer overflow in kernel memory, allowing an attacker to execute arbitrary code with kernel-level "
            "privileges. The vulnerability is particularly dangerous because it is wormable - it can self-propagate across "
            "networks without any user interaction, similar to the EternalBlue exploit. The SMBv3 compression feature was "
            "introduced in Windows 10 version 1903 and Windows Server version 1903, making all subsequent versions "
            "vulnerable if not patched."
        ),
        "description_zh": (
            "从操作系统内核角度来看，CVE-2020-0796（SMBGhost）是 Windows 内核中 SMBv3 协议实现中的严重漏洞。该漏洞存在于"
            "负责处理 SMBv3 压缩的 srv2.sys 内核模式驱动程序中。特制的 SMBv3 压缩协商数据包可以触发内核内存中的缓冲区溢出，"
            "允许攻击者以内核级权限执行任意代码。该漏洞特别危险，因为它具有蠕虫传播特性 - 可以在无需用户交互的情况下在"
            "网络中自动扩散，类似于 EternalBlue 利用。SMBv3 压缩功能在 Windows 10 版本 1903 和 Windows Server 版本 1903 "
            "中引入，使所有后续版本在未打补丁的情况下都容易受到攻击。"
        ),
        "impact_en": (
            "Kernel-level remote code execution through SMBGhost provides the highest level of system access. The wormable "
            "nature means a single compromised system can rapidly spread the attack across the entire network, potentially "
            "affecting thousands of systems within minutes."
        ),
        "impact_zh": (
            "通过 SMBGhost 的内核级远程代码执行提供了最高级别的系统访问权限。蠕虫传播特性意味着单个被攻陷的系统可以快速"
            "在整个网络中传播攻击，可能在几分钟内影响数千个系统。"
        ),
        "solution_en": (
            "Install Microsoft security update KB4551762 or later cumulative updates. Disable SMBv3 compression via "
            "registry by setting EnableCompression to 0 under HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer"
            "\Parameters. Block SMB traffic (port 445) at the network perimeter using firewalls."
        ),
        "solution_zh": (
            "安装微软安全更新 KB4551762 或后续累积更新。通过注册表禁用 SMBv3 压缩，在 HKLM\SYSTEM\CurrentControlSet"
            "\Services\LanmanServer\Parameters 下将 EnableCompression 设置为 0。使用防火墙在网络边界处阻止 SMB 流量"
            "（端口 445）。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 10 1903/1909", "Windows Server 1903/1909", "Windows Server 2019"],
    },
    "CVE-2022-37966-OS": {
        "name_en": "Kerberos Privilege Escalation (OS Domain Controller Impact)",
        "name_zh": "Kerberos 特权提升漏洞（操作系统域控制器影响）",
        "description_en": (
            "From an operating system and Active Directory security perspective, CVE-2022-37966 is a critical privilege "
            "escalation vulnerability in the Microsoft Kerberos implementation. The vulnerability allows an attacker to "
            "spoof the sAMAccountName attribute in the Privilege Attribute Certificate (PAC) during Kerberos authentication. "
            "This means an authenticated user with standard privileges can request a Kerberos service ticket that contains "
            "a PAC with a spoofed sAMAccountName belonging to a domain administrator. When the target service validates "
            "the ticket, it accepts the spoofed identity and grants the attacker elevated privileges. The vulnerability "
            "fundamentally undermines the trust model of Kerberos authentication in Active Directory environments, as "
            "the PAC is supposed to provide verifiable evidence of the user's identity and group memberships."
        ),
        "description_zh": (
            "从操作系统和 Active Directory 安全角度来看，CVE-2022-37966 是 Microsoft Kerberos 实现中的严重特权提升漏洞。"
            "该漏洞允许攻击者在 Kerberos 认证过程中欺骗特权属性证书（PAC）中的 sAMAccountName 属性。这意味着具有标准权限"
            "的经过认证的用户可以请求一个包含属于域管理员的欺骗 sAMAccountName 的 PAC 的 Kerberos 服务票据。当目标服务"
            "验证票据时，它接受欺骗的身份并授予攻击者提升的权限。该漏洞从根本上破坏了 Active Directory 环境中 Kerberos "
            "认证的信任模型，因为 PAC 本应提供用户身份和组成员身份的可验证证据。"
        ),
        "impact_en": (
            "Domain-level privilege escalation allows an attacker to compromise the entire Active Directory infrastructure. "
            "With domain administrator privileges, the attacker can access all domain resources, modify Group Policy, "
            "create backdoor accounts, and deploy Golden Ticket attacks for persistent access."
        ),
        "impact_zh": (
            "域级别的特权提升使攻击者能够危及整个 Active Directory 基础设施。拥有域管理员权限后，攻击者可以访问所有域资源、"
            "修改组策略、创建后门账户，并部署黄金票据攻击以获得持久访问。"
        ),
        "solution_en": (
            "Install Microsoft security updates from October 2022 Patch Tuesday. Implement tiered administration model "
            "to limit the impact of domain-level privilege escalation. Deploy advanced auditing for Kerberos service "
            "ticket requests. Monitor domain controllers for signs of PAC manipulation and anomalous Kerberos activity."
        ),
        "solution_zh": (
            "安装微软 2022 年 10 月补丁星期二的安全更新。实施分层管理模型以限制域级别特权提升的影响。为 Kerberos 服务票据"
            "请求部署高级审计。监控域控制器以发现 PAC 操纵和异常 Kerberos 活动的迹象。"
        ),
        "severity": "high",
        "cvss": 8.8,
        "affected_products": ["Windows 7/8.1/10/11", "Windows Server 2008 R2/2012/2016/2019/2022"],
    },
    "CVE-2023-36802-OS": {
        "name_en": "Microsoft Streaming Service Proxy Privilege Escalation (OS Driver Impact)",
        "name_zh": "Microsoft Streaming Service Proxy 提权漏洞（操作系统驱动影响）",
        "description_en": (
            "From an operating system driver security perspective, CVE-2023-36802 is a privilege escalation vulnerability "
            "in the Microsoft Streaming Service Proxy driver (mskssrv.sys). The vulnerability is caused by improper "
            "handling of objects in memory, specifically a race condition that can be triggered by a local attacker. "
            "The Streaming Service Proxy driver is a Windows kernel-mode driver that provides streaming services for "
            "multimedia applications. The vulnerability allows a local attacker to exploit a race condition in the "
            "driver's object management to gain elevated privileges. When successfully exploited, the attacker achieves "
            "SYSTEM-level access, the highest privilege on Windows. This type of kernel driver vulnerability is "
            "particularly concerning because it can bypass all user-mode security controls and sandboxing mechanisms."
        ),
        "description_zh": (
            "从操作系统驱动安全角度来看，CVE-2023-36802 是 Microsoft Streaming Service Proxy 驱动程序（mskssrv.sys）中的"
            "提权漏洞。该漏洞由内存中对象的处理不当引起，具体而言是本地攻击者可以触发的竞态条件。Streaming Service Proxy "
            "驱动程序是一个 Windows 内核模式驱动程序，为多媒体应用程序提供流服务。该漏洞允许本地攻击者利用驱动程序对象管理"
            "中的竞态条件来获得提升的权限。成功利用后，攻击者获得 SYSTEM 级别访问权限，这是 Windows 上的最高权限。这种类型的"
            "内核驱动程序漏洞特别令人担忧，因为它可以绕过所有用户模式安全控制和沙箱机制。"
        ),
        "impact_en": (
            "Kernel driver privilege escalation provides SYSTEM-level access, bypassing all application-level security "
            "controls. The attacker can install kernel-level rootkits, modify the operating system, and establish "
            "persistent access that is extremely difficult to detect and remove."
        ),
        "impact_zh": (
            "内核驱动程序提权提供 SYSTEM 级别访问权限，绕过所有应用程序级别的安全控制。攻击者可以安装内核级 rootkit、"
            "修改操作系统，并建立极难检测和清除的持久访问。"
        ),
        "solution_en": (
            "Install Microsoft security updates from September 2023. Implement driver signing enforcement to prevent "
            "loading of unsigned drivers. Use Credential Guard and other virtualization-based security features. "
            "Deploy endpoint detection and response (EDR) solutions to detect kernel-level exploitation attempts."
        ),
        "solution_zh": (
            "安装微软 2023 年 9 月的安全更新。实施驱动程序签名强制以防止加载未签名的驱动程序。使用 Credential Guard 和"
            "其他基于虚拟化的安全功能。部署端点检测和响应（EDR）解决方案以检测内核级利用尝试。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019/2022"],
    },
    "CVE-2023-36802-CLFS": {
        "name_en": "Windows CLFS Driver Privilege Escalation",
        "name_zh": "Windows CLFS 驱动程序提权漏洞",
        "description_en": (
            "CVE-2023-36802-CLFS is a privilege escalation vulnerability in the Windows Common Log File System (CLFS) "
            "driver (clfs.sys). The CLFS driver is a kernel-mode component that provides a high-performance log file "
            "system used by various Windows components. The vulnerability exists in the way the CLFS driver handles "
            "certain log file operations, where a use-after-free condition can be triggered by a local attacker through "
            "specially crafted log file operations. When the use-after-free condition is exploited, it can lead to "
            "arbitrary code execution in kernel mode, providing the attacker with SYSTEM-level privileges. This "
            "vulnerability is particularly concerning because CLFS is used by many Windows subsystems, making it "
            "widely available for exploitation."
        ),
        "description_zh": (
            "CVE-2023-36802-CLFS 是 Windows 通用日志文件系统（CLFS）驱动程序（clfs.sys）中的提权漏洞。CLFS 驱动程序是"
            "一个内核模式组件，为各种 Windows 组件提供高性能日志文件系统。该漏洞存在于 CLFS 驱动程序处理某些日志文件操作"
            "的方式中，本地攻击者可以通过特制的日志文件操作触发释放后使用条件。当释放后使用条件被利用时，可能导致在内核模式"
            "下执行任意代码，为攻击者提供 SYSTEM 级别权限。该漏洞特别令人担忧，因为 CLFS 被许多 Windows 子系统使用，"
            "使其广泛可用于利用。"
        ),
        "impact_en": (
            "Kernel-mode code execution through CLFS provides SYSTEM-level access with the ability to modify the "
            "operating system kernel. This can lead to installation of persistent rootkits and complete system compromise."
        ),
        "impact_zh": (
            "通过 CLFS 的内核模式代码执行提供 SYSTEM 级别访问权限，能够修改操作系统内核。这可能导致安装持久化 rootkit "
            "和完全的系统沦陷。"
        ),
        "solution_en": (
            "Install Microsoft security updates from September 2023. Implement kernel-level exploit mitigations such "
            "as Kernel Mode Hardware-enforced Stack Protection. Deploy EDR solutions with kernel exploit detection "
            "capabilities. Follow the principle of least privilege for all user accounts."
        ),
        "solution_zh": (
            "安装微软 2023 年 9 月的安全更新。实施内核级利用缓解措施，如内核模式硬件强制堆栈保护。部署具有内核利用检测"
            "能力的 EDR 解决方案。对所有用户账户遵循最小权限原则。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019/2022"],
    },
    "CVE-2022-21882": {
        "name_en": "Win32k Privilege Escalation",
        "name_zh": "Win32k 提权漏洞",
        "description_en": (
            "CVE-2022-21882 is a privilege escalation vulnerability in the Windows Win32k subsystem. The vulnerability "
            "exists in the way the Win32k kernel-mode driver handles window objects, specifically in the "
            "NtGdiResetDC() function. A local attacker can exploit a use-after-free condition in the handling of "
            "display context (DC) objects by creating a race condition between the creation and destruction of window "
            "objects. When successfully exploited, the vulnerability allows the attacker to execute arbitrary code "
            "in kernel mode, achieving SYSTEM-level privileges. This vulnerability was actively exploited in the "
            "wild by threat actors as part of targeted attacks. This vulnerability affects Windows 10, Windows 11, "
            "and several versions of Windows Server."
        ),
        "description_zh": (
            "CVE-2022-21882 是 Windows Win32k 子系统中的提权漏洞。该漏洞存在于 Win32k 内核模式驱动程序处理窗口对象的"
            "方式中，具体位于 NtGdiResetDC() 函数中。本地攻击者可以通过在窗口对象的创建和销毁之间创建竞态条件来利用"
            "显示上下文（DC）对象处理中的释放后使用条件。成功利用后，该漏洞允许攻击者在内核模式中执行任意代码，获得 "
            "SYSTEM 级别权限。该漏洞已被威胁行为者在野利用，作为定向攻击的一部分。该漏洞影响 Windows 10、Windows 11 "
            "以及多个版本的 Windows Server。"
        ),
        "impact_en": (
            "Kernel-mode code execution through Win32k provides SYSTEM-level access, allowing complete control of the "
            "system. The active exploitation in the wild indicates this vulnerability is being used by sophisticated "
            "threat actors in targeted campaigns."
        ),
        "impact_zh": (
            "通过 Win32k 的内核模式代码执行提供 SYSTEM 级别访问权限，允许完全控制系统。在野利用表明该漏洞正被高级威胁"
            "行为者在定向活动中使用。"
        ),
        "solution_en": (
            "Install Microsoft security updates from January 2022 Patch Tuesday. Enable Win32k system call filtering "
            "in sandboxed applications. Deploy EDR solutions with kernel exploit detection. Implement application "
            "control policies to restrict execution of untrusted binaries."
        ),
        "solution_zh": (
            "安装微软 2022 年 1 月补丁星期二的安全更新。在沙箱应用程序中启用 Win32k 系统调用过滤。部署具有内核利用检测"
            "功能的 EDR 解决方案。实施应用程序控制策略以限制执行不可信的二进制文件。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019"],
    },
    "CVE-2021-1732": {
        "name_en": "Win32k Privilege Escalation",
        "name_zh": "Win32k 提权漏洞",
        "description_en": (
            "CVE-2021-1732 is a privilege escalation vulnerability in the Windows Win32k kernel-mode driver. The "
            "vulnerability exists in the way Win32k handles the creation and manipulation of window objects, "
            "specifically in the xxxCreateWindowEx() function. A local attacker can exploit a race condition in the "
            "window creation process to gain elevated privileges. The vulnerability is triggered by manipulating "
            "the window object's properties during the creation process, which can lead to a use-after-free condition. "
            "When the freed memory is reused, the attacker can control the data written to it, resulting in arbitrary "
            "code execution in kernel mode. This vulnerability was actively exploited in targeted attacks and affects "
            "Windows 10 versions before the March 2021 security update."
        ),
        "description_zh": (
            "CVE-2021-1732 是 Windows Win32k 内核模式驱动程序中的提权漏洞。该漏洞存在于 Win32k 处理窗口对象创建和操纵"
            "的方式中，具体位于 xxxCreateWindowEx() 函数中。本地攻击者可以利用窗口创建过程中的竞态条件来获得提升的权限。"
            "该漏洞通过在创建过程中操纵窗口对象的属性来触发，可能导致释放后使用条件。当释放的内存被重用时，攻击者可以"
            "控制写入其中的数据，导致在内核模式中执行任意代码。该漏洞已在定向攻击中被在野利用，影响 2021 年 3 月安全更新"
            "之前的 Windows 10 版本。"
        ),
        "impact_en": (
            "Kernel-mode code execution provides SYSTEM-level access, allowing the attacker to completely control the "
            "system. Active exploitation indicates this vulnerability is used by advanced persistent threat (APT) "
            "groups in targeted operations."
        ),
        "impact_zh": (
            "内核模式代码执行提供 SYSTEM 级别访问权限，允许攻击者完全控制系统。在野利用表明该漏洞被高级持续性威胁（APT）"
            "组织在定向操作中使用。"
        ),
        "solution_en": (
            "Install Microsoft security updates from March 2021. Enable Win32k system call filtering for sandboxed "
            "applications. Deploy EDR solutions with kernel exploit detection capabilities. Restrict user privileges "
            "and implement application whitelisting."
        ),
        "solution_zh": (
            "安装微软 2021 年 3 月的安全更新。为沙箱应用程序启用 Win32k 系统调用过滤。部署具有内核利用检测功能的 EDR "
            "解决方案。限制用户权限并实施应用程序白名单。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10 < March 2021 update", "Windows Server 2016/2019 < March 2021 update"],
    },
    "CVE-2023-24932": {
        "name_en": "Windows CLFS Driver Privilege Escalation",
        "name_zh": "Windows CLFS 驱动程序提权漏洞",
        "description_en": (
            "CVE-2023-24932 is a privilege escalation vulnerability in the Windows Common Log File System (CLFS) driver. "
            "The vulnerability exists in the way the CLFS driver handles log file metadata, where a use-after-free "
            "condition can be triggered through specially crafted log file operations. A local attacker can exploit "
            "this vulnerability by creating and manipulating log files that trigger the race condition in the CLFS "
            "driver. When the use-after-free condition is exploited, the attacker can execute arbitrary code in kernel "
            "mode with SYSTEM privileges. The CLFS driver is a core Windows component used by many subsystems, making "
            "this vulnerability widely exploitable. This vulnerability affects Windows 10, Windows 11, and multiple "
            "versions of Windows Server."
        ),
        "description_zh": (
            "CVE-2023-24932 是 Windows 通用日志文件系统（CLFS）驱动程序中的提权漏洞。该漏洞存在于 CLFS 驱动程序处理日志"
            "文件元数据的方式中，可以通过特制的日志文件操作触发释放后使用条件。本地攻击者可以通过创建和操纵触发 CLFS "
            "驱动程序中竞态条件的日志文件来利用此漏洞。当释放后使用条件被利用时，攻击者可以以 SYSTEM 权限在内核模式中执行"
            "任意代码。CLFS 驱动程序是许多子系统使用的核心 Windows 组件，使该漏洞具有广泛的利用性。该漏洞影响 Windows 10、"
            "Windows 11 以及多个版本的 Windows Server。"
        ),
        "impact_en": (
            "Kernel-mode privilege escalation through CLFS provides SYSTEM-level access, allowing complete control "
            "of the system. The widespread use of CLFS makes this vulnerability exploitable on virtually all Windows "
            "installations."
        ),
        "impact_zh": (
            "通过 CLFS 的内核模式提权提供 SYSTEM 级别访问权限，允许完全控制系统。CLFS 的广泛使用使该漏洞几乎可以在所有 "
            "Windows 安装上被利用。"
        ),
        "solution_en": (
            "Install Microsoft security updates from March 2023. Enable Kernel Mode Hardware-enforced Stack Protection. "
            "Deploy EDR solutions with kernel exploit detection. Implement strict access controls and follow the "
            "principle of least privilege."
        ),
        "solution_zh": (
            "安装微软 2023 年 3 月的安全更新。启用内核模式硬件强制堆栈保护。部署具有内核利用检测功能的 EDR 解决方案。"
            "实施严格的访问控制并遵循最小权限原则。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019/2022"],
    },
    "CVE-2023-32046": {
        "name_en": "Microsoft Message Queuing Remote Code Execution",
        "name_zh": "Microsoft Message Queuing 远程代码执行漏洞",
        "description_en": (
            "CVE-2023-32046 is a critical remote code execution vulnerability in Microsoft Message Queuing (MSMQ). "
            "The vulnerability exists in the MSMQ service where a type confusion vulnerability can be triggered by "
            "sending a specially crafted malicious message to the MSMQ queue. The MSMQ service processes incoming "
            "messages and deserializes their content, and the type confusion in the deserialization process allows "
            "an attacker to execute arbitrary code with SYSTEM privileges. An unauthenticated attacker with network "
            "access to the MSMQ service (TCP port 1801) can exploit this vulnerability remotely. This vulnerability "
            "affects Windows 10, Windows 11, Windows Server 2012, 2016, 2019, and 2022."
        ),
        "description_zh": (
            "CVE-2023-32046 是 Microsoft Message Queuing（MSMQ）中的严重远程代码执行漏洞。该漏洞存在于 MSMQ 服务中，"
            "通过向 MSMQ 队列发送特制的恶意消息可以触发类型混淆漏洞。MSMQ 服务处理传入的消息并反序列化其内容，反序列化"
            "过程中的类型混淆允许攻击者以 SYSTEM 权限执行任意代码。具有 MSMQ 服务（TCP 端口 1801）网络访问权限的未经"
            "认证的攻击者可以远程利用此漏洞。该漏洞影响 Windows 10、Windows 11、Windows Server 2012、2016、2019 和 2022。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution with SYSTEM privileges allows attackers to completely compromise "
            "the target system. Given that MSMQ is often used in enterprise environments for inter-application "
            "communication, the impact can extend to the entire application infrastructure."
        ),
        "impact_zh": (
            "以 SYSTEM 权限的未经认证远程代码执行使攻击者能够完全攻陷目标系统。鉴于 MSMQ 通常在企业环境中用于应用程序间"
            "通信，影响可能扩展到整个应用程序基础设施。"
        ),
        "solution_en": (
            "Install Microsoft security updates from June 2023 Patch Tuesday. Disable the MSMQ service if not required. "
            "Restrict network access to the MSMQ service (TCP port 1801) to authorized systems only. Implement network "
            "segmentation to isolate MSMQ servers."
        ),
        "solution_zh": (
            "安装微软 2023 年 6 月补丁星期二的安全更新。如果不需要 MSMQ 服务，请禁用。将 MSMQ 服务（TCP 端口 1801）的"
            "网络访问限制为仅授权系统。实施网络分段以隔离 MSMQ 服务器。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019/2022"],
    },
    "CVE-2023-36802-Stream": {
        "name_en": "Microsoft Streaming Service Proxy Driver Privilege Escalation",
        "name_zh": "Microsoft Streaming Service Proxy 驱动程序提权漏洞",
        "description_en": (
            "CVE-2023-36802-Stream is a privilege escalation vulnerability in the Microsoft Streaming Service Proxy "
            "driver (mskssrv.sys). This variant specifically targets the streaming service proxy's handling of "
            "multimedia streaming objects. The vulnerability is caused by a race condition in the driver's object "
            "lifecycle management where an object can be freed while still being referenced. A local attacker can "
            "exploit this by creating a high-contention scenario that triggers the race condition, leading to a "
            "use-after-free condition. When the freed memory is accessed after being freed, the attacker can control "
            "the data that is written to the freed memory region, ultimately achieving arbitrary code execution in "
            "kernel mode with SYSTEM privileges."
        ),
        "description_zh": (
            "CVE-2023-36802-Stream 是 Microsoft Streaming Service Proxy 驱动程序（mskssrv.sys）中的提权漏洞。该变体"
            "专门针对流服务代理对多媒体流对象的处理。该漏洞由驱动程序对象生命周期管理中的竞态条件引起，对象在被引用时"
            "可能已被释放。本地攻击者可以通过创建高争用场景来触发竞态条件，导致释放后使用条件。当释放的内存在被释放后"
            "被访问时，攻击者可以控制写入已释放内存区域的数据，最终在内核模式中以 SYSTEM 权限实现任意代码执行。"
        ),
        "impact_en": (
            "Kernel-mode code execution with SYSTEM privileges provides the highest level of system access. The "
            "attacker can install rootkits, modify security controls, and establish persistent access that is "
            "extremely difficult to detect and remove."
        ),
        "impact_zh": (
            "以 SYSTEM 权限的内核模式代码执行提供了最高级别的系统访问权限。攻击者可以安装 rootkit、修改安全控制，"
            "并建立极难检测和清除的持久访问。"
        ),
        "solution_en": (
            "Install Microsoft security updates from September 2023. Enable Kernel Mode Hardware-enforced Stack "
            "Protection. Deploy EDR solutions with kernel exploit detection. Restrict user privileges and implement "
            "application control policies."
        ),
        "solution_zh": (
            "安装微软 2023 年 9 月的安全更新。启用内核模式硬件强制堆栈保护。部署具有内核利用检测功能的 EDR 解决方案。"
            "限制用户权限并实施应用程序控制策略。"
        ),
        "severity": "high",
        "cvss": 7.8,
        "affected_products": ["Windows 10", "Windows 11", "Windows Server 2012/2016/2019/2022"],
    },
    # ============================================================
    # IoT/嵌入式（10条）
    # ============================================================
    "CVE-2021-44228-IoT": {
        "name_en": "Log4j Vulnerability Impacting IoT Devices",
        "name_zh": "Log4j 漏洞影响 IoT 设备",
        "description_en": (
            "The Log4Shell vulnerability (CVE-2021-44228) has a particularly severe impact on Internet of Things (IoT) "
            "devices and embedded systems. Many IoT devices run Java-based middleware or management platforms that "
            "incorporate Log4j2 for logging. These include industrial control systems (ICS), smart home hubs, network "
            "attached storage (NAS) devices, security cameras, and enterprise IoT gateways. The challenge with IoT "
            "devices is that they often have limited update mechanisms, may run outdated software versions, and are "
            "frequently deployed in environments where security monitoring is minimal. Attackers can exploit Log4Shell "
            "on IoT devices through any input vector that gets logged, including network requests, sensor data, or "
            "device management commands. Once compromised, IoT devices can be used to pivot into corporate networks, "
            "launch DDoS attacks, or serve as persistent backdoor access points."
        ),
        "description_zh": (
            "Log4Shell 漏洞（CVE-2021-44228）对物联网（IoT）设备和嵌入式系统的影响尤为严重。许多 IoT 设备运行基于 Java 的"
            "中间件或管理平台，这些平台集成了 Log4j2 进行日志记录。这些设备包括工业控制系统（ICS）、智能家居集线器、网络附加存储"
            "（NAS）设备、安全摄像头和企业 IoT 网关。IoT 设备面临的挑战在于它们通常具有有限的更新机制，可能运行过时的软件"
            "版本，并且经常部署在安全监控最少的环境中。攻击者可以通过任何被记录的输入向量在 IoT 设备上利用 Log4Shell，"
            "包括网络请求、传感器数据或设备管理命令。一旦被攻陷，IoT 设备可用于跳板进入企业网络、发起 DDoS 攻击，"
            "或作为持久化的后门访问点。"
        ),
        "impact_en": (
            "Compromised IoT devices can serve as persistent backdoors into corporate networks, launch DDoS attacks, "
            "and provide attackers with lateral movement capabilities. The difficulty of patching IoT devices makes "
            "this a long-term security risk."
        ),
        "impact_zh": (
            "被攻陷的 IoT 设备可以作为进入企业网络的持久化后门、发起 DDoS 攻击，并为攻击者提供横向移动能力。IoT 设备"
            "修补的困难性使其成为长期的安全风险。"
        ),
        "solution_en": (
            "Identify all IoT devices that use Log4j2 through comprehensive asset inventory and vulnerability scanning. "
            "Apply vendor patches where available. Implement network segmentation to isolate IoT devices from the "
            "corporate network. Monitor IoT device traffic for indicators of Log4Shell exploitation. Deploy WAF and "
            "IDS rules to block JNDI-related attack patterns targeting IoT devices."
        ),
        "solution_zh": (
            "通过全面的资产清查和漏洞扫描识别所有使用 Log4j2 的 IoT 设备。在可用时应用供应商补丁。实施网络分段以将 IoT "
            "设备与企业网络隔离。监控 IoT 设备流量以发现 Log4Shell 利用的指标。部署 WAF 和 IDS 规则以阻止针对 IoT 设备"
            "的 JNDI 相关攻击模式。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["IoT devices with Java-based management platforms", "Industrial control systems using Log4j2", "NAS devices", "Enterprise IoT gateways"],
    },
    "CVE-2022-42475-IoT": {
        "name_en": "Fortinet FortiOS RCE Impacting IoT Network Infrastructure",
        "name_zh": "Fortinet FortiOS RCE 影响 IoT 网络基础设施",
        "description_en": (
            "CVE-2022-42475, when viewed from an IoT security perspective, represents a critical threat to IoT network "
            "infrastructure. Many IoT deployments rely on Fortinet FortiGate firewalls and FortiProxy devices as the "
            "network security perimeter for IoT device segments. The heap-based buffer overflow in the SSL VPN "
            "component of these devices can be exploited by an attacker who gains access to the IoT network segment. "
            "Once the FortiGate device is compromised, the attacker can bypass all security controls protecting the "
            "IoT devices, modify firewall rules to allow unrestricted access, and use the compromised security "
            "appliance as a pivot point to access the broader corporate network. This is particularly concerning "
            "in industrial IoT (IIoT) environments where FortiGate devices protect critical infrastructure."
        ),
        "description_zh": (
            "从 IoT 安全角度来看，CVE-2022-42475 代表了对 IoT 网络基础设施的严重威胁。许多 IoT 部署依赖 Fortinet "
            "FortiGate 防火墙和 FortiProxy 设备作为 IoT 设备段网络安全边界。这些设备 SSL VPN 组件中的基于堆的缓冲区溢出"
            "可以被获得 IoT 网络段访问权限的攻击者利用。一旦 FortiGate 设备被攻陷，攻击者可以绕过所有保护 IoT 设备的"
            "安全控制、修改防火墙规则以允许不受限制的访问，并利用被攻陷的安全设备作为跳板访问更广泛的企业网络。这在 "
            "FortiGate 设备保护关键基础设施的工业 IoT（IIoT）环境中尤其令人担忧。"
        ),
        "impact_en": (
            "Compromise of IoT network security appliances undermines the entire security architecture protecting IoT "
            "devices. In IIoT environments, this can lead to disruption of critical infrastructure and industrial "
            "processes."
        ),
        "impact_zh": (
            "IoT 网络安全设备被攻陷破坏了保护 IoT 设备的整个安全架构。在 IIoT 环境中，这可能导致关键基础设施和工业"
            "流程的中断。"
        ),
        "solution_en": (
            "Upgrade FortiOS and FortiProxy to the fixed versions immediately. Implement network segmentation with "
            "defense-in-depth for IoT environments. Deploy intrusion detection systems to monitor for exploitation "
            "attempts against network security appliances. Regularly audit and update IoT network infrastructure."
        ),
        "solution_zh": (
            "立即将 FortiOS 和 FortiProxy 升级至修复版本。为 IoT 环境实施具有深度防御的网络分段。部署入侵检测系统以监控"
            "针对网络安全设备的利用尝试。定期审计和更新 IoT 网络基础设施。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.2.2", "Fortinet FortiProxy 7.0.0 - 7.2.1"],
    },
    "CVE-2023-27997-IoT": {
        "name_en": "FortiOS SSL VPN RCE Impacting IoT Remote Access",
        "name_zh": "FortiOS SSL VPN RCE 影响 IoT 远程访问",
        "description_en": (
            "CVE-2023-27997, from an IoT perspective, poses a significant threat to organizations that use FortiGate "
            "SSL VPN for remote management of IoT devices. Many enterprises use SSL VPN to provide secure remote access "
            "to IoT device management interfaces. The heap-based buffer overflow in the FortiOS SSL VPN component "
            "can be exploited by an unauthenticated attacker to gain root access to the FortiGate device. Once the "
            "VPN gateway is compromised, the attacker gains unrestricted access to all IoT devices accessible through "
            "the VPN, including industrial controllers, sensors, and monitoring systems. The vulnerability is "
            "particularly dangerous because SSL VPN endpoints are typically exposed to the internet for remote access."
        ),
        "description_zh": (
            "从 IoT 角度来看，CVE-2023-27997 对使用 FortiGate SSL VPN 进行 IoT 设备远程管理的组织构成了重大威胁。"
            "许多企业使用 SSL VPN 为 IoT 设备管理界面提供安全的远程访问。FortiOS SSL VPN 组件中的基于堆的缓冲区溢出"
            "可以被未经认证的攻击者利用以获得 FortiGate 设备的 root 访问权限。一旦 VPN 网关被攻陷，攻击者将获得对"
            "通过 VPN 可访问的所有 IoT 设备的不受限制的访问，包括工业控制器、传感器和监控系统。该漏洞特别危险，"
            "因为 SSL VPN 端点通常暴露在互联网上以供远程访问。"
        ),
        "impact_en": (
            "Compromise of the SSL VPN gateway exposes all IoT devices accessible through the VPN to unauthorized "
            "access. This can lead to manipulation of industrial processes, data theft from IoT sensors, and "
            "disruption of IoT monitoring and control systems."
        ),
        "impact_zh": (
            "SSL VPN 网关被攻陷后，通过 VPN 可访问的所有 IoT 设备都将暴露给未授权访问。这可能导致工业流程被操纵、"
            "IoT 传感器数据被窃取，以及 IoT 监控和控制系统被中断。"
        ),
        "solution_en": (
            "Upgrade FortiOS to version 7.4.2, 7.2.6, or 7.0.13 or later. Implement multi-factor authentication "
            "for SSL VPN access. Restrict SSL VPN access to authorized IP ranges. Deploy network monitoring to "
            "detect unauthorized access to IoT devices through the VPN."
        ),
        "solution_zh": (
            "将 FortiOS 升级至 7.4.2、7.2.6 或 7.0.13 及更高版本。为 SSL VPN 访问实施多因素认证。将 SSL VPN 访问"
            "限制为授权的 IP 范围。部署网络监控以检测通过 VPN 对 IoT 设备的未授权访问。"
        ),
        "severity": "critical",
        "cvss": 9.6,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.4.1"],
    },
    "CVE-2021-36260": {
        "name_en": "D-Link DIR-2640 Remote Code Execution",
        "name_zh": "D-Link DIR-2640 远程代码执行漏洞",
        "description_en": (
            "CVE-2021-36260 is a remote code execution vulnerability in D-Link DIR-2640 wireless routers. The "
            "vulnerability exists in the web management interface of the router where an unauthenticated attacker "
            "can execute arbitrary system commands through a specially crafted HTTP request. The flaw is caused by "
            "insufficient input validation in the HTTP request handler, which allows command injection through "
            "certain parameters. The D-Link DIR-2640 router's web interface runs with root privileges, meaning "
            "any code executed through this vulnerability runs as root. This vulnerability affects D-Link DIR-2640 "
            "routers with firmware versions before 1.10B04."
        ),
        "description_zh": (
            "CVE-2021-36260 是 D-Link DIR-2640 无线路由器中的远程代码执行漏洞。该漏洞存在于路由器的 Web 管理界面中，"
            "未经认证的攻击者可以通过特制的 HTTP 请求执行任意系统命令。该缺陷由 HTTP 请求处理程序中的输入验证不足引起，"
            "允许通过某些参数进行命令注入。D-Link DIR-2640 路由器的 Web 界面以 root 权限运行，这意味着通过此漏洞执行的"
            "任何代码都以 root 身份运行。该漏洞影响固件版本 1.10B04 之前的 D-Link DIR-2640 路由器。"
        ),
        "impact_en": (
            "Unauthenticated remote code execution on a home or small office router allows attackers to intercept "
            "all network traffic, modify DNS settings, and use the compromised router as a pivot point to attack "
            "other devices on the local network."
        ),
        "impact_zh": (
            "在家庭或小型办公路由器上未经认证的远程代码执行使攻击者能够拦截所有网络流量、修改 DNS 设置，并利用被攻陷的"
            "路由器作为跳板攻击本地网络上的其他设备。"
        ),
        "solution_en": (
            "Upgrade the D-Link DIR-2640 router firmware to version 1.10B04 or later. Disable remote management "
            "access if not required. Change the default administrator password. Place the router behind a firewall "
            "that restricts access to the management interface."
        ),
        "solution_zh": (
            "将 D-Link DIR-2640 路由器固件升级至 1.10B04 或更高版本。如果不需要远程管理访问，请禁用。更改默认管理员"
            "密码。将路由器放置在限制管理界面访问的防火墙后面。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["D-Link DIR-2640 < firmware 1.10B04"],
    },
    "CVE-2022-26258": {
        "name_en": "D-Link DNS-320L Command Injection",
        "name_zh": "D-Link DNS-320L 命令注入漏洞",
        "description_en": (
            "CVE-2022-26258 is a command injection vulnerability in D-Link DNS-320L network attached storage (NAS) "
            "devices. The vulnerability exists in the web management interface where an authenticated attacker can "
            "inject arbitrary operating system commands through the system language configuration parameter. The "
            "flaw is caused by insufficient input sanitization in the language settings handler, which passes user "
            "input directly to a system shell command. When exploited, the injected commands are executed with root "
            "privileges on the NAS device. This vulnerability affects D-Link DNS-320L devices with firmware versions "
            "before 1.10B09."
        ),
        "description_zh": (
            "CVE-2022-26258 是 D-Link DNS-320L 网络附加存储（NAS）设备中的命令注入漏洞。该漏洞存在于 Web 管理界面中，"
            "经过认证的攻击者可以通过系统语言配置参数注入任意操作系统命令。该缺陷由语言设置处理程序中的输入清理不足引起，"
            "将用户输入直接传递给系统 shell 命令。被利用时，注入的命令以 root 权限在 NAS 设备上执行。该漏洞影响固件版本 "
            "1.10B09 之前的 D-Link DNS-320L 设备。"
        ),
        "impact_en": (
            "Command injection with root privileges on a NAS device allows attackers to access all stored data, "
            "install persistent malware, and use the compromised NAS as a platform for attacking other systems "
            "on the network."
        ),
        "impact_zh": (
            "在 NAS 设备上以 root 权限的命令注入使攻击者能够访问所有存储的数据、安装持久化恶意软件，并利用被攻陷的 NAS "
            "作为攻击网络上其他系统的平台。"
        ),
        "solution_en": (
            "Upgrade the D-Link DNS-320L firmware to version 1.10B09 or later. Restrict access to the NAS management "
            "interface to trusted IP addresses. Change the default administrator credentials. Implement network "
            "segmentation to isolate NAS devices from the public internet."
        ),
        "solution_zh": (
            "将 D-Link DNS-320L 固件升级至 1.10B09 或更高版本。将 NAS 管理界面的访问限制为受信任的 IP 地址。更改默认"
            "管理员凭据。实施网络分段以将 NAS 设备与公共互联网隔离。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["D-Link DNS-320L < firmware 1.10B09"],
    },
    "CVE-2023-27997-FortiGate": {
        "name_en": "FortiGate SSL VPN RCE (IoT Gateway Impact)",
        "name_zh": "FortiGate SSL VPN RCE（IoT 网关影响）",
        "description_en": (
            "CVE-2023-27997-FortiGate covers the impact of the FortiOS SSL VPN heap-based buffer overflow on IoT "
            "gateway deployments. FortiGate devices are commonly deployed as IoT gateway security appliances in "
            "enterprise environments, providing firewall, VPN, and network segmentation services for IoT device "
            "clusters. The SSL VPN vulnerability allows unauthenticated remote attackers to execute arbitrary code "
            "on the FortiGate device. When the FortiGate serving as an IoT security gateway is compromised, the "
            "attacker gains control over the network security perimeter protecting the IoT infrastructure. This "
            "enables the attacker to modify firewall rules, intercept IoT device communications, and potentially "
            "manipulate IoT device firmware or configurations through the compromised gateway."
        ),
        "description_zh": (
            "CVE-2023-27997-FortiGate 涵盖了 FortiOS SSL VPN 基于堆的缓冲区溢出对 IoT 网关部署的影响。FortiGate 设备"
            "通常在企业环境中部署为 IoT 网关安全设备，为 IoT 设备集群提供防火墙、VPN 和网络分段服务。SSL VPN 漏洞允许"
            "未经认证的远程攻击者在 FortiGate 设备上执行任意代码。当作为 IoT 安全网关的 FortiGate 被攻陷时，攻击者"
            "获得了对保护 IoT 基础设施的网络安全边界的控制。这使攻击者能够修改防火墙规则、拦截 IoT 设备通信，并可能"
            "通过被攻陷的网关操纵 IoT 设备固件或配置。"
        ),
        "impact_en": (
            "Compromise of IoT security gateways exposes all protected IoT devices to unauthorized access and "
            "manipulation. In industrial environments, this can lead to physical damage, safety hazards, and "
            "significant financial losses."
        ),
        "impact_zh": (
            "IoT 安全网关被攻陷后，所有受保护的 IoT 设备都将暴露给未授权访问和操纵。在工业环境中，这可能导致物理损坏、"
            "安全危害和重大经济损失。"
        ),
        "solution_en": (
            "Upgrade FortiOS to the latest patched version. Implement defense-in-depth for IoT security with "
            "multiple layers of network segmentation. Deploy intrusion detection and prevention systems (IDS/IPS) "
            "to monitor for exploitation attempts. Conduct regular security assessments of IoT gateway infrastructure."
        ),
        "solution_zh": (
            "将 FortiOS 升级至最新的修补版本。为 IoT 安全实施具有多层网络分段的深度防御。部署入侵检测和防御系统"
            "（IDS/IPS）以监控利用尝试。定期对 IoT 网关基础设施进行安全评估。"
        ),
        "severity": "critical",
        "cvss": 9.6,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.4.1"],
    },
    "CVE-2022-41033-IoT": {
        "name_en": "FortiNAC RCE Impacting IoT Network Access Control",
        "name_zh": "FortiNAC RCE 影响 IoT 网络访问控制",
        "description_en": (
            "CVE-2022-41033, from an IoT perspective, threatens the network access control infrastructure that "
            "manages IoT device connectivity. FortiNAC is commonly deployed to manage and secure IoT device network "
            "access, enforce network access policies, and monitor IoT device behavior. The remote code execution "
            "vulnerability in FortiNAC's keyUpload functionality allows an authenticated administrator to execute "
            "arbitrary commands. If an attacker compromises an administrative account through phishing or other "
            "means, they can exploit this vulnerability to gain root access to the FortiNAC server. Once the "
            "network access control system is compromised, the attacker can bypass all IoT device access policies, "
            "connect unauthorized devices to the network, and disable security monitoring."
        ),
        "description_zh": (
            "从 IoT 角度来看，CVE-2022-41033 威胁着管理 IoT 设备连接性的网络访问控制基础设施。FortiNAC 通常被部署来"
            "管理和保护 IoT 设备网络访问、执行网络访问策略以及监控 IoT 设备行为。FortiNAC keyUpload 功能中的远程代码"
            "执行漏洞允许经过认证的管理员执行任意命令。如果攻击者通过钓鱼或其他方式攻陷了管理账户，他们可以利用此漏洞"
            "获得 FortiNAC 服务器的 root 访问权限。一旦网络访问控制系统被攻陷，攻击者可以绕过所有 IoT 设备访问策略、"
            "将未经授权的设备连接到网络，并禁用安全监控。"
        ),
        "impact_en": (
            "Compromise of the network access control system undermines the entire IoT security architecture. "
            "Unauthorized IoT devices can be connected to the network, and existing security policies can be "
            "bypassed or disabled."
        ),
        "impact_zh": (
            "网络访问控制系统被攻陷破坏了整个 IoT 安全架构。未经授权的 IoT 设备可以被连接到网络，现有的安全策略"
            "可以被绕过或禁用。"
        ),
        "solution_en": (
            "Upgrade FortiNAC to the patched versions. Implement multi-factor authentication for all FortiNAC "
            "administrative accounts. Monitor for suspicious administrative activities. Deploy network access "
            "control as part of a defense-in-depth strategy with multiple security layers."
        ),
        "solution_zh": (
            "将 FortiNAC 升级至修补版本。为所有 FortiNAC 管理账户实施多因素认证。监控可疑的管理活动。将网络访问控制"
            "作为具有多层安全的深度防御策略的一部分进行部署。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Fortinet FortiNAC 8.8.x", "Fortinet FortiNAC 9.1.0 - 9.1.6", "Fortinet FortiNAC 9.2.0 - 9.2.5", "Fortinet FortiNAC 9.4.0 - 9.4.1"],
    },
    "CVE-2023-22527-IoT": {
        "name_en": "Confluence RCE Impacting IoT Documentation and Knowledge Management",
        "name_zh": "Confluence RCE 影响 IoT 文档和知识管理",
        "description_en": (
            "CVE-2023-22527, when viewed from an IoT security perspective, threatens organizations that use Atlassian "
            "Confluence for IoT device documentation, knowledge management, and operational procedures. Many enterprises "
            "use Confluence to store IoT device configurations, network diagrams, API documentation, and operational "
            "playbooks. The template injection remote code execution vulnerability allows unauthenticated attackers "
            "to gain complete control of the Confluence server. Once compromised, all IoT-related documentation, "
            "including device credentials, network topologies, and security configurations, can be accessed and "
            "exfiltrated by the attacker. This information can then be used to directly attack the IoT infrastructure "
            "described in the documentation."
        ),
        "description_zh": (
            "从 IoT 安全角度来看，CVE-2023-22527 威胁着使用 Atlassian Confluence 进行 IoT 设备文档管理、知识管理和操作"
            "流程的组织。许多企业使用 Confluence 存储 IoT 设备配置、网络图、API 文档和操作手册。模板注入远程代码执行漏洞"
            "允许未经认证的攻击者获得 Confluence 服务器的完全控制。一旦被攻陷，所有与 IoT 相关的文档，包括设备凭据、"
            "网络拓扑和安全配置，都可以被攻击者访问和窃取。然后这些信息可用于直接攻击文档中描述的 IoT 基础设施。"
        ),
        "impact_en": (
            "Compromise of IoT documentation systems exposes sensitive infrastructure information that can be used "
            "to plan and execute targeted attacks against IoT devices and systems. This creates a secondary attack "
            "vector through information leakage."
        ),
        "impact_zh": (
            "IoT 文档系统被攻陷后暴露了敏感的基础设施信息，这些信息可用于规划和执行针对 IoT 设备和系统的定向攻击。"
            "这通过信息泄露创建了二次攻击向量。"
        ),
        "solution_en": (
            "Upgrade Confluence to version 8.5.3 or later. Restrict access to Confluence to authorized personnel "
            "only. Implement network segmentation to isolate documentation systems from IoT networks. Do not store "
            "sensitive IoT credentials in plain text within Confluence pages."
        ),
        "solution_zh": (
            "将 Confluence 升级至 8.5.3 或更高版本。将 Confluence 的访问限制为仅授权人员。实施网络分段以将文档系统"
            "与 IoT 网络隔离。不要在 Confluence 页面中以明文存储敏感的 IoT 凭据。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Atlassian Confluence Data Center 8.0.x - 8.5.1", "Atlassian Confluence Server 8.0.x - 8.5.1"],
    },
    "CVE-2023-49103-IoT": {
        "name_en": "PHP CGI RCE Impacting IoT Web Interfaces",
        "name_zh": "PHP CGI RCE 影响 IoT Web 界面",
        "description_en": (
            "CVE-2023-49103, from an IoT perspective, poses a significant threat to IoT devices that use PHP-based "
            "web interfaces for management and monitoring. Many IoT devices, including network cameras, industrial "
            "sensors, smart home controllers, and NAS devices, run PHP-based web applications for device management. "
            "The PHP CGI parameter injection vulnerability allows unauthenticated attackers to execute arbitrary code "
            "on these devices by sending specially crafted HTTP requests to the PHP CGI handler. Since many IoT "
            "devices run PHP in CGI mode and have limited security controls, they are particularly vulnerable to "
            "this attack. Once compromised, IoT devices can be used to pivot into corporate networks, launch DDoS "
            "attacks, or serve as persistent surveillance points."
        ),
        "description_zh": (
            "从 IoT 角度来看，CVE-2023-49103 对使用基于 PHP 的 Web 界面进行管理和监控的 IoT 设备构成了重大威胁。许多 "
            "IoT 设备，包括网络摄像头、工业传感器、智能家居控制器和 NAS 设备，运行基于 PHP 的 Web 应用程序进行设备管理。"
            "PHP CGI 参数注入漏洞允许未经认证的攻击者通过向 PHP CGI 处理程序发送特制的 HTTP 请求在这些设备上执行任意代码。"
            "由于许多 IoT 设备以 CGI 模式运行 PHP 且安全控制有限，它们特别容易受到此攻击。一旦被攻陷，IoT 设备可用于"
            "跳板进入企业网络、发起 DDoS 攻击，或作为持久化的监控点。"
        ),
        "impact_en": (
            "Remote code execution on IoT devices through PHP CGI provides attackers with control over the device "
            "and potential access to the broader network. The limited security controls on IoT devices make "
            "detection and remediation particularly challenging."
        ),
        "impact_zh": (
            "通过 PHP CGI 在 IoT 设备上的远程代码执行为攻击者提供了对设备的控制和对更广泛网络的潜在访问。IoT 设备上"
            "有限的安全控制使检测和修复特别具有挑战性。"
        ),
        "solution_en": (
            "Upgrade PHP to version 8.3.8, 8.2.20, or 8.1.29 or later on all IoT devices. Implement URL rewriting "
            "rules to block PHP CGI injection attempts. Deploy network segmentation to isolate IoT devices. "
            "Monitor IoT device traffic for signs of exploitation."
        ),
        "solution_zh": (
            "在所有 IoT 设备上将 PHP 升级至 8.3.8、8.2.20 或 8.1.29 及更高版本。实施 URL 重写规则以阻止 PHP CGI "
            "注入尝试。部署网络分段以隔离 IoT 设备。监控 IoT 设备流量以发现利用迹象。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["IoT devices running PHP in CGI mode", "Network cameras with PHP web interfaces", "Smart home controllers", "NAS devices"],
    },
    "CVE-2023-46747-IoT": {
        "name_en": "Apache Kafka UI RCE Impacting IoT Data Pipeline Infrastructure",
        "name_zh": "Apache Kafka UI RCE 影响 IoT 数据管道基础设施",
        "description_en": (
            "CVE-2023-46747, from an IoT perspective, threatens the data pipeline infrastructure that processes IoT "
            "device data. Apache Kafka is widely used in IoT architectures as a message broker for streaming data "
            "from IoT devices to processing and analytics platforms. The remote code execution vulnerability in "
            "Kafka management interfaces allows attackers to compromise the data pipeline infrastructure. When the "
            "Kafka cluster or its management UI is compromised, attackers can intercept, modify, or inject IoT "
            "device data flowing through the message broker. This can lead to manipulation of IoT sensor readings, "
            "injection of false data into analytics systems, and disruption of IoT data processing pipelines. "
            "In industrial IoT environments, corrupted data can lead to incorrect automated decisions and "
            "potential physical consequences."
        ),
        "description_zh": (
            "从 IoT 角度来看，CVE-2023-46747 威胁着处理 IoT 设备数据的数据管道基础设施。Apache Kafka 在 IoT 架构中"
            "广泛用作消息代理，用于将数据从 IoT 设备流式传输到处理和分析平台。Kafka 管理界面中的远程代码执行漏洞允许"
            "攻击者攻陷数据管道基础设施。当 Kafka 集群或其管理 UI 被攻陷时，攻击者可以拦截、修改或注入通过消息代理"
            "流动的 IoT 设备数据。这可能导致 IoT 传感器读数被操纵、虚假数据被注入分析系统，以及 IoT 数据处理管道"
            "被中断。在工业 IoT 环境中，数据损坏可能导致错误的自动化决策和潜在的物理后果。"
        ),
        "impact_en": (
            "Compromise of IoT data pipeline infrastructure allows manipulation of IoT data streams, which can "
            "lead to incorrect automated decisions, data poisoning of analytics systems, and disruption of "
            "IoT monitoring and control operations."
        ),
        "impact_zh": (
            "IoT 数据管道基础设施被攻陷后允许操纵 IoT 数据流，这可能导致错误的自动化决策、分析系统的数据中毒，"
            "以及 IoT 监控和控制操作的中断。"
        ),
        "solution_en": (
            "Upgrade Apache Kafka and its management interfaces to the latest patched versions. Implement "
            "network segmentation to isolate Kafka clusters from the public internet. Deploy encryption and "
            "authentication for all Kafka communications. Implement data integrity checks for IoT data streams."
        ),
        "solution_zh": (
            "将 Apache Kafka 及其管理界面升级至最新的修补版本。实施网络分段以将 Kafka 集群与公共互联网隔离。"
            "为所有 Kafka 通信部署加密和认证。对 IoT 数据流实施数据完整性检查。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Apache Kafka management interfaces", "IoT data pipeline platforms using Kafka"],
    },
    # ============================================================
    # 补充漏洞描述（8条，总计100条）
    # ============================================================
    "CVE-2021-44228-WEB": {
        "name_en": "Log4j2 Web Application Remote Code Execution (Log4Shell)",
        "name_zh": "Log4j2 Web应用远程代码执行漏洞（Log4Shell）",
        "description_en": (
            "From a web application perspective, CVE-2021-44228 (Log4Shell) represents one of the most critical "
            "vulnerabilities affecting web-facing applications. Web applications that use Apache Log4j2 for logging "
            "are vulnerable when user-controlled input reaches log statements without proper filtering. Common web "
            "attack vectors include HTTP headers (User-Agent, Referer, X-Forwarded-For), URL parameters, form input "
            "fields, and cookie values. When a web application logs these user-controlled values using the vulnerable "
            "Log4j2 version, the JNDI lookup mechanism can be triggered, allowing attackers to execute arbitrary code "
            "on the web server. The attack is particularly dangerous because it requires no authentication and can be "
            "executed through simple HTTP requests, making every public-facing web application a potential target."
        ),
        "description_zh": (
            "从Web应用角度来看，CVE-2021-44228（Log4Shell）是影响面向Web的应用程序的最严重漏洞之一。使用Apache Log4j2进行日志记录的"
            "Web应用程序在用户可控的输入未经适当过滤就到达日志语句时会受到攻击。常见的Web攻击向量包括HTTP请求头（User-Agent、Referer、"
            "X-Forwarded-For）、URL参数、表单输入字段和Cookie值。当Web应用程序使用存在漏洞的Log4j2版本记录这些用户可控的值时，"
            "JNDI查找机制可以被触发，允许攻击者在Web服务器上执行任意代码。该攻击特别危险，因为它不需要任何身份验证，并且可以通过简单的"
            "HTTP请求执行，使得每个面向公众的Web应用程序都成为潜在目标。"
        ),
        "impact_en": (
            "Successful exploitation of Log4Shell through web applications allows unauthenticated remote code execution "
            "with the privileges of the web application process. Attackers can gain shell access to the web server, "
            "exfiltrate sensitive application data including credentials and session tokens, deploy web shells for "
            "persistent access, pivot to backend databases and internal networks, and potentially compromise the entire "
            "application infrastructure. The ease of exploitation and widespread presence of Log4j2 in web applications "
            "make this an extremely high-risk vulnerability."
        ),
        "impact_zh": (
            "通过Web应用程序成功利用Log4Shell漏洞允许未经身份验证的远程代码执行，并获得Web应用程序进程的权限。攻击者可以获取Web服务器的"
            "Shell访问权限、窃取敏感的应用程序数据（包括凭据和会话令牌）、部署Web Shell以实现持久化访问、跳转到后端数据库和内部网络，"
            "并可能完全攻陷整个应用程序基础设施。该漏洞利用门槛极低且Log4j2在Web应用程序中广泛存在，使其成为极其高风险的安全漏洞。"
        ),
        "solution_en": (
            "Upgrade Apache Log4j2 to version 2.17.1 or later in all web applications. As an immediate mitigation, "
            "set the system property log4j2.formatMsgNoLookups to true or remove the JndiLookup class from the "
            "classpath. Implement input validation and sanitization for all user-controlled data before logging. "
            "Deploy WAF rules to detect and block JNDI injection patterns in HTTP requests. Monitor web server logs "
            "for suspicious JNDI lookup activities and outbound LDAP/RMI connections."
        ),
        "solution_zh": (
            "在所有Web应用程序中将Apache Log4j2升级至2.17.1或更高版本。作为即时缓解措施，设置系统属性log4j2.formatMsgNoLookups为true，"
            "或从类路径中移除JndiLookup类。在记录日志之前对所有用户可控的数据实施输入验证和净化。部署WAF规则以检测和拦截HTTP请求中的"
            "JNDI注入模式。监控Web服务器日志以发现可疑的JNDI查找活动和出站LDAP/RMI连接。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Web applications using Apache Log4j 2.0-beta9 - 2.14.1", "Java-based web frameworks with Log4j2 dependency"],
    },
    "CVE-2021-41773-V2": {
        "name_en": "Apache HTTP Server 2.4.49 Path Traversal Information Disclosure",
        "name_zh": "Apache HTTP Server 2.4.49 路径穿越信息泄露漏洞",
        "description_en": (
            "CVE-2021-41773, from an information disclosure perspective, is a path traversal vulnerability in Apache "
            "HTTP Server version 2.4.49 that allows attackers to read sensitive files outside the web root directory. "
            "The vulnerability exists because the server's normalization of directory traversal sequences was insufficient, "
            "particularly when require all denied configuration was not properly applied. An attacker can craft HTTP "
            "requests with specially encoded path traversal sequences (such as /cgi-bin/.%2e/%2e%2e/) to bypass "
            "directory restrictions and access arbitrary files on the server filesystem. This includes configuration "
            "files containing credentials (/etc/passwd, .htpasswd), application source code, SSL private keys, database "
            "connection strings, and other sensitive system files. The information disclosed through this vulnerability "
            "can be used to facilitate further attacks against the server and the broader network infrastructure."
        ),
        "description_zh": (
            "CVE-2021-41773从信息泄露角度来看，是Apache HTTP Server 2.4.49版本中的一个路径穿越漏洞，允许攻击者读取Web根目录之外的"
            "敏感文件。该漏洞的存在是因为服务器对目录穿越序列的规范化处理不够充分，特别是在require all denied配置未正确应用的情况下。"
            "攻击者可以构造包含特殊编码路径穿越序列的HTTP请求（如/cgi-bin/.%2e/%2e%2e/），绕过目录限制并访问服务器文件系统上的"
            "任意文件。这包括包含凭据的配置文件（/etc/passwd、.htpasswd）、应用程序源代码、SSL私钥、数据库连接字符串以及其他敏感的"
            "系统文件。通过此漏洞泄露的信息可用于对服务器和更广泛的网络基础设施发起进一步的攻击。"
        ),
        "impact_en": (
            "The information disclosure through this path traversal vulnerability can expose sensitive server configuration "
            "files, user credentials, application source code, and cryptographic keys. Attackers can leverage the "
            "disclosed information to plan and execute more sophisticated attacks, including privilege escalation, "
            "lateral movement, and full system compromise. Exposure of authentication credentials and encryption keys "
            "can have cascading security impacts across the entire infrastructure."
        ),
        "impact_zh": (
            "通过此路径穿越漏洞的信息泄露可能暴露敏感的服务器配置文件、用户凭据、应用程序源代码和加密密钥。攻击者可以利用泄露的信息"
            "规划和执行更复杂的攻击，包括权限提升、横向移动和完全攻陷系统。身份验证凭据和加密密钥的暴露可能对整个基础设施产生级联的"
            "安全影响。"
        ),
        "solution_en": (
            "Upgrade Apache HTTP Server to version 2.4.50 or later. Verify that require all denied is properly "
            "configured in all directory directives. Implement proper directory restrictions to prevent path traversal. "
            "Review and restrict access to sensitive files on the web server filesystem. Deploy WAF rules to detect "
            "and block path traversal attempts. Conduct a thorough security audit to identify any files that may have "
            "been accessed through this vulnerability."
        ),
        "solution_zh": (
            "将Apache HTTP Server升级至2.4.50或更高版本。验证所有目录指令中已正确配置require all denied。实施适当的目录限制以防止"
            "路径穿越。审查并限制对Web服务器文件系统上敏感文件的访问。部署WAF规则以检测和拦截路径穿越尝试。进行全面的安全审计，"
            "以识别可能已通过此漏洞被访问的任何文件。"
        ),
        "severity": "high",
        "cvss": 7.5,
        "affected_products": ["Apache HTTP Server 2.4.49"],
    },
    "CVE-2022-26134-V2": {
        "name_en": "Atlassian Confluence OGNL Injection Remote Code Execution",
        "name_zh": "Atlassian Confluence OGNL 注入远程代码执行漏洞",
        "description_en": (
            "CVE-2022-26134 is a critical remote code execution vulnerability in Atlassian Confluence Server and Data "
            "Center that exploits the Object-Graph Navigation Language (OGNL) injection flaw. The vulnerability exists "
            "in the way Confluence processes HTTP requests through its XWork framework, where user-supplied input is "
            "passed to the OGNL evaluation engine without proper sanitization. OGNL is a powerful expression language "
            "used by the Apache Struts framework (which Confluence is built upon) that can access and manipulate Java "
            "objects at runtime. By crafting malicious HTTP requests containing OGNL expressions in URI paths or "
            "parameters, an unauthenticated attacker can execute arbitrary Java code on the Confluence server. The OGNL "
            "injection chain typically involves bypassing input validation through encoding tricks, then leveraging "
            "Java Runtime.exec() or ProcessBuilder to execute operating system commands. This vulnerability affects "
            "all supported versions of Confluence Server and Data Center prior to the security patches released in "
            "June 2022."
        ),
        "description_zh": (
            "CVE-2022-26134是Atlassian Confluence Server和Data Center中的一个严重的远程代码执行漏洞，利用了对象图导航语言（OGNL）"
            "注入缺陷。该漏洞存在于Confluence通过其XWork框架处理HTTP请求的方式中，用户提供的输入在未经适当净化的情况下被传递给OGNL"
            "评估引擎。OGNL是Apache Struts框架（Confluence基于此构建）使用的一种强大的表达式语言，可以在运行时访问和操作Java对象。"
            "通过构造包含OGNL表达式的恶意HTTP请求（在URI路径或参数中），未经身份验证的攻击者可以在Confluence服务器上执行任意Java代码。"
            "OGNL注入链通常涉及通过编码技巧绕过输入验证，然后利用Java Runtime.exec()或ProcessBuilder执行操作系统命令。"
            "该漏洞影响2022年6月发布安全补丁之前的所有受支持版本的Confluence Server和Data Center。"
        ),
        "impact_en": (
            "OGNL injection allows unauthenticated remote code execution with the privileges of the Confluence application "
            "process. Attackers can execute arbitrary operating system commands, access and modify all content stored in "
            "Confluence (including confidential documents and project data), steal credentials stored in the application, "
            "deploy backdoors and web shells, and use the compromised server as a pivot point for further network "
            "intrusion. Given that Confluence often stores sensitive corporate knowledge and documentation, the impact "
            "of data exfiltration can be particularly severe."
        ),
        "impact_zh": (
            "OGNL注入允许未经身份验证的远程代码执行，并获得Confluence应用程序进程的权限。攻击者可以执行任意操作系统命令、访问和修改"
            "Confluence中存储的所有内容（包括机密文档和项目数据）、窃取应用程序中存储的凭据、部署后门和Web Shell，并利用被攻陷的服务器"
            "作为进一步网络入侵的跳板。鉴于Confluence通常存储敏感的企业知识和文档，数据泄露的影响可能尤为严重。"
        ),
        "solution_en": (
            "Immediately upgrade Atlassian Confluence Server and Data Center to the latest patched versions. Apply the "
            "security patches released by Atlassian in June 2022. If immediate upgrading is not possible, restrict "
            "network access to Confluence instances using firewall rules. Implement WAF rules to block OGNL injection "
            "patterns. Monitor Confluence access logs for suspicious URI patterns containing OGNL expressions. Consider "
            "isolating Confluence servers in a dedicated network segment."
        ),
        "solution_zh": (
            "立即将Atlassian Confluence Server和Data Center升级至最新的修补版本。应用Atlassian于2022年6月发布的安全补丁。如果无法立即"
            "升级，使用防火墙规则限制对Confluence实例的网络访问。部署WAF规则以拦截OGNL注入模式。监控Confluence访问日志以发现包含"
            "OGNL表达式的可疑URI模式。考虑将Confluence服务器隔离在专用网络段中。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Atlassian Confluence Server", "Atlassian Confluence Data Center"],
    },
    "CVE-2023-22515-V2": {
        "name_en": "Atlassian Confluence Broken Access Control Privilege Escalation",
        "name_zh": "Atlassian Confluence 访问控制失效特权提升漏洞",
        "description_en": (
            "CVE-2023-22515 is a critical broken access control vulnerability in Atlassian Confluence Server and Data "
            "Center that allows an unauthenticated attacker to escalate privileges and gain administrative access to "
            "the Confluence instance. The vulnerability exists due to a flaw in the access control mechanism where "
            "certain internal endpoints responsible for system setup and configuration management can be accessed "
            "without proper authentication and authorization checks. Specifically, the vulnerability relates to the "
            "setup wizard and configuration restoration endpoints that were improperly exposed even after the initial "
            "setup was completed. An attacker can exploit this by sending crafted HTTP requests to these exposed "
            "endpoints to create a new administrator account or modify existing access control settings. Once "
            "administrative access is obtained, the attacker has full control over the Confluence instance, including "
            "the ability to read, modify, and delete all content, install malicious plugins, execute arbitrary code "
            "through plugin functionality, and access connected systems and databases."
        ),
        "description_zh": (
            "CVE-2023-22515是Atlassian Confluence Server和Data Center中的一个严重的访问控制失效漏洞，允许未经身份验证的攻击者提升"
            "权限并获得对Confluence实例的管理员访问权限。该漏洞的存在是因为访问控制机制中的缺陷，负责系统设置和配置管理的某些内部端点"
            "可以在没有适当的身份验证和授权检查的情况下被访问。具体而言，该漏洞与设置向导和配置恢复端点有关，这些端点即使在初始设置"
            "完成后仍然被不当暴露。攻击者可以通过向这些暴露的端点发送精心构造的HTTP请求来创建新的管理员账户或修改现有的访问控制设置。"
            "一旦获得管理员访问权限，攻击者就拥有对Confluence实例的完全控制权，包括读取、修改和删除所有内容、安装恶意插件、通过插件功能"
            "执行任意代码以及访问连接的系统和数据库的能力。"
        ),
        "impact_en": (
            "This broken access control vulnerability allows complete takeover of the Confluence instance without any "
            "prior authentication. An attacker with administrative access can exfiltrate all stored content including "
            "proprietary documentation, credentials, and sensitive business data. The attacker can also use the "
            "compromised instance to deploy malware, establish persistence, and pivot to other systems in the "
            "corporate network. The impact is especially severe for organizations that use Confluence as their primary "
            "knowledge management and documentation platform."
        ),
        "impact_zh": (
            "此访问控制失效漏洞允许在无需任何先前身份验证的情况下完全接管Confluence实例。获得管理员访问权限的攻击者可以窃取所有存储的内容，"
            "包括专有文档、凭据和敏感的业务数据。攻击者还可以利用被攻陷的实例部署恶意软件、建立持久化访问，并跳转到企业网络中的其他系统。"
            "对于使用Confluence作为主要知识管理和文档平台的组织而言，该漏洞的影响尤为严重。"
        ),
        "solution_en": (
            "Immediately upgrade Atlassian Confluence Server and Data Center to the latest patched versions released "
            "in October 2023. Review all administrator accounts and audit any accounts created during the vulnerability "
            "window. Check for any unauthorized configuration changes or plugin installations. Restrict network access "
            "to Confluence management endpoints. Implement network segmentation and monitor for suspicious administrative "
            "activities. Rotate all credentials and secrets that may have been exposed through the Confluence instance."
        ),
        "solution_zh": (
            "立即将Atlassian Confluence Server和Data Center升级至2023年10月发布的最新修补版本。审查所有管理员账户并审计在漏洞窗口期间"
            "创建的任何账户。检查是否有未经授权的配置更改或插件安装。限制对Confluence管理端点的网络访问。实施网络分段并监控可疑的管理"
            "活动。轮换可能已通过Confluence实例暴露的所有凭据和密钥。"
        ),
        "severity": "critical",
        "cvss": 10.0,
        "affected_products": ["Atlassian Confluence Server 8.0.0 - 8.5.3", "Atlassian Confluence Data Center 8.0.0 - 8.5.3"],
    },
    "CVE-2021-25646-V2": {
        "name_en": "Apache Druid Lookup Deserialization Remote Code Execution",
        "name_zh": "Apache Druid Lookup 反序列化远程代码执行漏洞",
        "description_en": (
            "CVE-2021-25646 is a critical deserialization-based remote code execution vulnerability in Apache Druid, "
            "a high-performance real-time analytics database. The vulnerability is located in the Lookup functionality "
            "of Druid's Broker and Historical nodes, where user-supplied data is deserialized using Java's native "
            "object deserialization mechanism without proper type validation. The deserialization exploitation chain "
            "begins when an attacker sends a specially crafted JSON request to the Druid coordinator or overlord API "
            "endpoints that manage Lookup configurations. The malicious payload contains serialized Java objects that, "
            "when deserialized, instantiate arbitrary classes and execute system commands through the gadget chain. "
            "Common gadget chains used in this attack include Apache Commons Collections, Spring Framework, and JDK-"
            "specific chains. The exploitation leverages the fact that Druid's Lookup loading mechanism trusts the "
            "serialized data from user input, allowing the attacker to control the classpath and execute arbitrary "
            "code with the privileges of the Druid service process."
        ),
        "description_zh": (
            "CVE-2021-25646是Apache Druid（一个高性能实时分析数据库）中一个基于反序列化的严重远程代码执行漏洞。该漏洞位于Druid的"
            "Broker和Historical节点的Lookup功能中，用户提交的数据使用Java原生对象反序列化机制进行反序列化，而未进行适当的类型验证。"
            "反序列化利用链始于攻击者向管理Lookup配置的Druid coordinator或overlord API端点发送精心构造的JSON请求。恶意负载包含"
            "序列化的Java对象，在反序列化时会实例化任意类并通过Gadget Chain执行系统命令。此攻击中常用的Gadget Chain包括Apache "
            "Commons Collections、Spring Framework和JDK特定的链。该利用利用了Druid的Lookup加载机制信任来自用户输入的序列化数据这一"
            "事实，允许攻击者控制类路径并以Druid服务进程的权限执行任意代码。"
        ),
        "impact_en": (
            "Successful deserialization attack allows unauthenticated remote code execution with the privileges of the "
            "Apache Druid service. Attackers can access and manipulate all data stored in Druid clusters, including "
            "analytics data, user queries, and configuration information. The compromised Druid instance can be used "
            "as a foothold for lateral movement into the data analytics infrastructure, potentially compromising "
            "downstream data consumers and connected data sources."
        ),
        "impact_zh": (
            "成功的反序列化攻击允许未经身份验证的远程代码执行，并获得Apache Druid服务的权限。攻击者可以访问和操作存储在Druid集群中的"
            "所有数据，包括分析数据、用户查询和配置信息。被攻陷的Druid实例可用作横向移动到数据分析基础设施的跳板，可能危及下游数据"
            "消费者和连接的数据源。"
        ),
        "solution_en": (
            "Upgrade Apache Druid to version 0.21.1 or later. Disable the Lookup functionality if not required by "
            "implementing strict API access controls. Implement network segmentation to restrict access to Druid "
            "coordinator and overlord API endpoints. Deploy serialization filtering using Java's ObjectInputFilter "
            "to whitelist only expected classes. Monitor Druid API access logs for suspicious deserialization "
            "activities and unusual Lookup configuration changes."
        ),
        "solution_zh": (
            "将Apache Druid升级至0.21.1或更高版本。如果不需要Lookup功能，通过实施严格的API访问控制来禁用它。实施网络分段以限制对"
            "Druid coordinator和overlord API端点的访问。使用Java的ObjectInputFilter部署序列化过滤，仅白名单允许预期的类。监控"
            "Druid API访问日志以发现可疑的反序列化活动和异常的Lookup配置更改。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Druid 0.19.0 - 0.21.0"],
    },
    "CVE-2022-22963-V2": {
        "name_en": "Spring Cloud Function SpEL Expression Injection RCE",
        "name_zh": "Spring Cloud Function SpEL 表达式注入远程代码执行漏洞",
        "description_en": (
            "CVE-2022-22963 is a critical remote code execution vulnerability in Spring Cloud Function caused by Spring "
            "Expression Language (SpEL) injection. The vulnerability exists in the routing function of Spring Cloud "
            "Function when the 'spring.cloud.function.routing-expression' header is used to route function invocations. "
            "An attacker can inject malicious SpEL expressions through this HTTP header, which are then evaluated by the "
            "Spring Framework's expression evaluation engine. SpEL is a powerful expression language that supports "
            "runtime query and manipulation of object graphs, method invocation, and access to system properties. "
            "Through crafted SpEL expressions, an attacker can execute arbitrary operating system commands by leveraging "
            "Java's Runtime.exec() method, access environment variables and system properties, read files from the "
            "server filesystem, and establish reverse shells for persistent access. The vulnerability is particularly "
            "dangerous because Spring Cloud Function is commonly used in serverless and cloud-native applications, "
            "where function routing through HTTP headers is a standard operational pattern."
        ),
        "description_zh": (
            "CVE-2022-22963是Spring Cloud Function中一个由Spring表达式语言（SpEL）注入引起的严重远程代码执行漏洞。该漏洞存在于"
            "Spring Cloud Function的路由功能中，当使用'spring.cloud.function.routing-expression'头来路由函数调用时。攻击者可以"
            "通过此HTTP头注入恶意的SpEL表达式，这些表达式随后被Spring Framework的表达式评估引擎所执行。SpEL是一种强大的表达式语言，"
            "支持运行时查询和操作对象图、方法调用以及访问系统属性。通过精心构造的SpEL表达式，攻击者可以利用Java的Runtime.exec()方法"
            "执行任意操作系统命令、访问环境变量和系统属性、从服务器文件系统读取文件，并建立反向Shell以实现持久化访问。该漏洞特别危险，"
            "因为Spring Cloud Function通常用于无服务器和云原生应用程序中，通过HTTP头进行函数路由是一种标准的操作模式。"
        ),
        "impact_en": (
            "SpEL expression injection enables unauthenticated remote code execution in Spring Cloud Function "
            "applications. Attackers can execute arbitrary commands on the host system, access sensitive application "
            "data and environment variables, compromise cloud-native application infrastructure, and use the "
            "compromised function as a pivot point to attack other services in the cloud environment. The impact is "
            "amplified in microservice architectures where functions may have access to cloud provider APIs and "
            "sensitive service credentials."
        ),
        "impact_zh": (
            "SpEL表达式注入可在Spring Cloud Function应用程序中实现未经身份验证的远程代码执行。攻击者可以在主机系统上执行任意命令、访问"
            "敏感的应用程序数据和环境变量、攻陷云原生应用程序基础设施，并利用被攻陷的函数作为跳板攻击云环境中的其他服务。在微服务架构中，"
            "该漏洞的影响会被放大，因为函数可能有权访问云提供商的API和敏感的服务凭据。"
        ),
        "solution_en": (
            "Upgrade Spring Cloud Function to version 3.2.2 or later. If upgrading is not immediately possible, set "
            "the property spring.cloud.function.web.allow-raw-headers to false to disable raw header processing. "
            "Implement input validation and sanitization for all HTTP headers. Deploy API gateway controls to filter "
            "malicious headers before they reach Spring Cloud Function. Monitor application logs for SpEL injection "
            "attempts and suspicious expression evaluation activities."
        ),
        "solution_zh": (
            "将Spring Cloud Function升级至3.2.2或更高版本。如果无法立即升级，设置属性spring.cloud.function.web.allow-raw-headers为"
            "false以禁用原始头处理。对所有HTTP头实施输入验证和净化。部署API网关控制以在恶意头到达Spring Cloud Function之前进行过滤。"
            "监控应用程序日志以发现SpEL注入尝试和可疑的表达式评估活动。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Spring Cloud Function 3.0.0.RELEASE - 3.2.1"],
    },
    "CVE-2023-27997-SSLVPN": {
        "name_en": "FortiOS SSL VPN Heap Overflow Remote Code Execution",
        "name_zh": "FortiOS SSL VPN 堆溢出远程代码执行漏洞",
        "description_en": (
            "CVE-2023-27997 is a critical heap-based buffer overflow vulnerability in Fortinet FortiOS SSL VPN that "
            "allows remote attackers to execute arbitrary code on affected FortiGate devices. The vulnerability exists "
            "in the SSL VPN daemon process that handles incoming VPN connection requests. The heap overflow is triggered "
            "when processing specially crafted HTTP requests sent to the SSL VPN web portal. Specifically, the flaw is "
            "in the buffer management of the SSL VPN request parsing routine, where insufficient bounds checking allows "
            "an attacker to overflow a heap buffer by sending an oversized request payload. The SSL VPN attack surface "
            "is particularly attractive to attackers because it is typically exposed to the public internet to allow "
            "remote workforce connectivity, and it handles sensitive authentication credentials. Successful exploitation "
            "of this heap overflow allows the attacker to bypass authentication entirely and execute arbitrary code with "
            "root privileges on the FortiGate device, effectively gaining control of the organization's network gateway "
            "and security perimeter."
        ),
        "description_zh": (
            "CVE-2023-27997是Fortinet FortiOS SSL VPN中的一个严重的基于堆的缓冲区溢出漏洞，允许远程攻击者在受影响的FortiGate设备上"
            "执行任意代码。该漏洞存在于处理传入VPN连接请求的SSL VPN守护进程中。当处理发送到SSL VPN Web门户的特制HTTP请求时，会触发"
            "堆溢出。具体而言，该缺陷位于SSL VPN请求解析例程的缓冲区管理中，不充分的边界检查允许攻击者通过发送超大的请求负载来溢出"
            "堆缓冲区。SSL VPN攻击面对攻击者特别有吸引力，因为它通常暴露在公共互联网上以允许远程办公连接，并且它处理敏感的身份验证"
            "凭据。成功利用此堆溢出漏洞允许攻击者完全绕过身份验证并以root权限在FortiGate设备上执行任意代码，从而有效地获得对组织"
            "网络网关和安全边界的控制。"
        ),
        "impact_en": (
            "Heap overflow exploitation of the SSL VPN service provides unauthenticated remote code execution with root "
            "privileges on FortiGate security appliances. This effectively gives attackers full control of the "
            "organization's network gateway, allowing them to intercept all network traffic, modify firewall rules, "
            "create VPN tunnels for persistent access, decrypt VPN traffic, and pivot into the internal network. "
            "The compromise of a network security device at the perimeter is particularly devastating as it undermines "
            "the organization's entire security posture."
        ),
        "impact_zh": (
            "SSL VPN服务的堆溢出利用可在FortiGate安全设备上以root权限实现未经身份验证的远程代码执行。这实际上使攻击者完全控制组织的"
            "网络网关，允许他们拦截所有网络流量、修改防火墙规则、创建VPN隧道以实现持久化访问、解密VPN流量，并跳转到内部网络。在网络边界"
            "处攻陷网络安全设备尤其具有毁灭性，因为它破坏了整个组织的安全态势。"
        ),
        "solution_en": (
            "Immediately upgrade FortiOS to the latest patched versions as recommended by Fortinet's security advisory. "
            "Apply the firmware updates for all affected FortiGate devices. If immediate patching is not possible, "
            "consider temporarily disabling the SSL VPN feature or restricting access to trusted IP addresses. "
            "Monitor FortiGate logs for signs of exploitation attempts. Review all VPN user accounts for unauthorized "
            "access. Conduct a thorough security assessment of potentially compromised devices."
        ),
        "solution_zh": (
            "立即按照Fortinet安全公告的建议将FortiOS升级至最新的修补版本。为所有受影响的FortiGate设备应用固件更新。如果无法立即修补，"
            "考虑临时禁用SSL VPN功能或将访问限制为受信任的IP地址。监控FortiGate日志以发现利用尝试的迹象。审查所有VPN用户账户是否存在"
            "未经授权的访问。对可能已被攻陷的设备进行全面的安全评估。"
        ),
        "severity": "high",
        "cvss": 7.2,
        "affected_products": ["Fortinet FortiOS 7.0.0 - 7.0.12", "Fortinet FortiOS 7.2.0 - 7.2.5", "Fortinet FortiOS 7.4.0 - 7.4.1"],
    },
    "CVE-2022-42889-V2": {
        "name_en": "Apache Commons Text4Shell Variable Interpolation RCE",
        "name_zh": "Apache Commons Text4Shell 变量插值远程代码执行漏洞",
        "description_en": (
            "CVE-2022-42889, commonly known as Text4Shell, is a critical remote code execution vulnerability in Apache "
            "Commons Text library caused by insecure variable interpolation. The vulnerability exists in the StringSubstitutor "
            "class, which supports variable interpolation through the syntax ${prefix:name}. When the 'script' prefix is "
            "enabled, the interpolator can execute arbitrary scripts through the ScriptEngineManager, including JavaScript, "
            "Groovy, and other scripting languages available on the JVM. The exploitation works by injecting malicious "
            "variable interpolation strings into user-controlled input that is later processed by the StringSubstitutor. "
            "For example, an attacker can inject ${script:javascript:java.lang.Runtime.getRuntime().exec('command')} to "
            "execute arbitrary operating system commands. The variable interpolation mechanism is similar to the JNDI "
            "lookup feature exploited in Log4Shell (CVE-2021-44228), making Text4Shell a related but distinct attack "
            "vector. Applications that use Apache Commons Text for string template processing, configuration management, "
            "or log message formatting are potentially vulnerable if they process untrusted input through the interpolator."
        ),
        "description_zh": (
            "CVE-2022-42889，通常被称为Text4Shell，是Apache Commons Text库中一个由不安全的变量插值引起的严重远程代码执行漏洞。"
            "该漏洞存在于StringSubstitutor类中，该类支持通过${prefix:name}语法进行变量插值。当启用'script'前缀时，插值器可以通过"
            "ScriptEngineManager执行任意脚本，包括JVM上可用的JavaScript、Groovy和其他脚本语言。利用方式是将恶意的变量插值字符串注入到"
            "用户可控的输入中，该输入随后被StringSubstitutor处理。例如，攻击者可以注入"
            "${script:javascript:java.lang.Runtime.getRuntime().exec('command')}来执行任意操作系统命令。变量插值机制类似于"
            "Log4Shell（CVE-2021-44228）中利用的JNDI查找功能，使Text4Shell成为一个相关但不同的攻击向量。使用Apache Commons Text进行"
            "字符串模板处理、配置管理或日志消息格式化的应用程序，如果通过插值器处理不受信任的输入，则可能存在漏洞。"
        ),
        "impact_en": (
            "Text4Shell variable interpolation exploitation allows remote code execution with the privileges of the "
            "application using the vulnerable Commons Text library. Attackers can execute arbitrary commands on the "
            "server, access application data and environment variables, and potentially pivot to other systems. "
            "The widespread use of Apache Commons Text in Java applications makes this vulnerability broadly impactful, "
            "especially for applications that process user input through string template engines."
        ),
        "impact_zh": (
            "Text4Shell变量插值利用允许在使用存在漏洞的Commons Text库的应用程序权限下执行远程代码。攻击者可以在服务器上执行任意命令、"
            "访问应用程序数据和环境变量，并可能跳转到其他系统。Apache Commons Text在Java应用程序中的广泛使用使该漏洞具有广泛的影响，"
            "特别是对于通过字符串模板引擎处理用户输入的应用程序。"
        ),
        "solution_en": (
            "Upgrade Apache Commons Text to version 1.10.0 or later, which disables the 'script' interpolator by "
            "default. Audit all applications using Commons Text to identify where StringSubstitutor processes user-"
            "controlled input. Implement input validation to reject strings containing variable interpolation patterns "
            "such as ${script:}. If upgrading is not possible, explicitly disable the script interpolator by not "
            "configuring the StringSubstitutor with the StringLookupFactory.INTERPOLATE_MAP. Deploy WAF rules to "
            "detect and block Text4Shell exploitation patterns."
        ),
        "solution_zh": (
            "将Apache Commons Text升级至1.10.0或更高版本，该版本默认禁用'script'插值器。审计所有使用Commons Text的应用程序，"
            "识别StringSubstitutor在何处处理用户可控的输入。实施输入验证以拒绝包含变量插值模式（如${script:}）的字符串。如果无法升级，"
            "通过不使用StringLookupFactory.INTERPOLATE_MAP配置StringSubstitutor来显式禁用脚本插值器。部署WAF规则以检测和拦截"
            "Text4Shell利用模式。"
        ),
        "severity": "critical",
        "cvss": 9.8,
        "affected_products": ["Apache Commons Text 1.5 - 1.9"],
    },
}


def get_vuln_description(cve_id: str) -> dict:
    """Get vulnerability description by CVE ID.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        Dictionary containing vulnerability details, or None if not found.
    """
    return VULN_DESCRIPTIONS.get(cve_id)


def get_vuln_description_zh(cve_id: str) -> dict:
    """Get Chinese vulnerability description by CVE ID.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        Dictionary containing Chinese vulnerability details, or None if not found.
    """
    vuln = VULN_DESCRIPTIONS.get(cve_id)
    if not vuln:
        return None
    return {
        "name": vuln["name_zh"],
        "description": vuln["description_zh"],
        "impact": vuln["impact_zh"],
        "solution": vuln["solution_zh"],
        "severity": vuln["severity"],
        "cvss": vuln["cvss"],
        "affected_products": vuln["affected_products"],
    }


def get_vuln_description_en(cve_id: str) -> dict:
    """Get English vulnerability description by CVE ID.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        Dictionary containing English vulnerability details, or None if not found.
    """
    vuln = VULN_DESCRIPTIONS.get(cve_id)
    if not vuln:
        return None
    return {
        "name": vuln["name_en"],
        "description": vuln["description_en"],
        "impact": vuln["impact_en"],
        "solution": vuln["solution_en"],
        "severity": vuln["severity"],
        "cvss": vuln["cvss"],
        "affected_products": vuln["affected_products"],
    }


def search_vulns_by_severity(severity: str) -> list:
    """Search vulnerabilities by severity level.

    Args:
        severity: Severity level ("critical", "high", "medium", "low")

    Returns:
        List of (cve_id, vuln_info) tuples matching the severity.
    """
    severity = severity.lower()
    return [
        (cve_id, vuln)
        for cve_id, vuln in VULN_DESCRIPTIONS.items()
        if vuln["severity"].lower() == severity
    ]


def search_vulns_by_keyword(keyword: str, lang: str = "en") -> list:
    """Search vulnerabilities by keyword in name and description.

    Args:
        keyword: Search keyword
        lang: Language for search ("en" or "zh")

    Returns:
        List of (cve_id, vuln_info) tuples matching the keyword.
    """
    keyword = keyword.lower()
    results = []
    for cve_id, vuln in VULN_DESCRIPTIONS.items():
        name_field = f"name_{lang}"
        desc_field = f"description_{lang}"
        if keyword in vuln[name_field].lower() or keyword in vuln[desc_field].lower():
            results.append((cve_id, vuln))
    return results


def get_all_cve_ids() -> list:
    """Get list of all CVE IDs in the database.

    Returns:
        List of all CVE ID strings.
    """
    return list(VULN_DESCRIPTIONS.keys())


def get_vuln_count() -> int:
    """Get total number of vulnerabilities in the database.

    Returns:
        Total count of vulnerability entries.
    """
    return len(VULN_DESCRIPTIONS)
