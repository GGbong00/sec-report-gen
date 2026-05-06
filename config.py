import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ============================================================
# 文件路径配置
# 便携版通过环境变量 SEC_REPORT_DATA_DIR 指定数据目录
# 如果环境变量不存在，尝试从 .data_dir 配置文件读取（便携版双重保障）
# 默认使用项目根目录下的 data/、uploads/、exports/
# ============================================================
def _resolve_data_dir():
    """解析数据目录，优先级：环境变量 > .data_dir配置文件 > 默认路径。"""
    # 1. 环境变量（Electron 传入）
    env_dir = os.environ.get('SEC_REPORT_DATA_DIR')
    if env_dir:
        return env_dir

    # 2. .data_dir 配置文件（便携版 exe 同级）
    # 向上查找：当前目录 → 父目录（因为 cwd 可能是 resources/）
    for search_dir in [BASE_DIR, os.path.dirname(BASE_DIR), os.path.dirname(os.path.dirname(BASE_DIR))]:
        config_file = os.path.join(search_dir, '.data_dir')
        if os.path.isfile(config_file):
            try:
                with open(config_file, 'r') as f:
                    data_dir = f.read().strip()
                if data_dir and os.path.isdir(data_dir):
                    return data_dir
            except Exception:
                pass

    # 3. 默认路径
    return os.path.join(BASE_DIR, 'data')

DATA_DIR = _resolve_data_dir()
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
EXPORT_FOLDER = os.path.join(DATA_DIR, 'exports')

# 确保文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXPORT_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ============================================================
# Flask 安全配置
# ============================================================
# SECRET_KEY 持久化：优先从环境变量获取，否则从文件加载或生成
def _get_or_create_secret_key():
    """获取或创建持久化的 SECRET_KEY，避免每次重启随机生成导致 session 失效。"""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    key_file = os.path.join(DATA_DIR, '.secret_key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            return f.read().strip()
    key = os.urandom(32).hex()
    with open(key_file, 'w') as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key

SECRET_KEY = _get_or_create_secret_key()
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB

# ============================================================
# 支持的扫描器列表及其导入格式
# ============================================================
SUPPORTED_SCANNERS = {
    'nmap': {
        'name': 'Nmap',
        'import_formats': ['xml'],
        'description': 'Nmap 网络扫描器',
    },
    'nessus': {
        'name': 'Nessus',
        'import_formats': ['csv', 'nessus'],
        'description': 'Tenable Nessus 漏洞扫描器',
    },
    'burpsuite': {
        'name': 'BurpSuite',
        'import_formats': ['xml', 'html'],
        'description': 'PortSwigger BurpSuite Web 安全测试工具',
    },
    'awvs': {
        'name': 'AWVS',
        'import_formats': ['json', 'xml'],
        'description': 'Acunetix Web 漏洞扫描器',
    },
    'zap': {
        'name': 'OWASP ZAP',
        'import_formats': ['xml', 'json', 'html'],
        'description': 'OWASP Zed Attack Proxy',
    },
    'xray': {
        'name': 'Xray',
        'import_formats': ['json', 'html'],
        'description': '长亭 Xray 安全评估工具',
    },
    'nuclei': {
        'name': 'Nuclei',
        'import_formats': ['json'],
        'description': 'ProjectDiscovery Nuclei 漏洞扫描器',
    },
    'sqlmap': {
        'name': 'SQLMap',
        'import_formats': ['json', 'csv'],
        'description': 'SQLMap 自动化 SQL 注入工具',
    },
    'nsfocus': {
        'name': 'NSFocus',
        'import_formats': ['html', 'xml', 'xlsx'],
        'description': '绿盟科技 RSAS 漏洞扫描器',
    },
    'anheng': {
        'name': 'Anheng',
        'import_formats': ['html', 'xlsx'],
        'description': '安恒信息明鉴漏洞扫描器',
    },
    'venustech': {
        'name': 'Venustech',
        'import_formats': ['html', 'xml', 'xlsx'],
        'description': '启明星辰天镜漏洞扫描器',
    },
}

# ============================================================
# 支持的导出格式列表
# ============================================================
SUPPORTED_EXPORT_FORMATS = {
    'docx': {
        'name': 'Word 文档',
        'extension': '.docx',
        'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    },
    'pdf': {
        'name': 'PDF 文档',
        'extension': '.pdf',
        'mime_type': 'application/pdf',
    },
    'xlsx': {
        'name': 'Excel 表格',
        'extension': '.xlsx',
        'mime_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    },
    'html': {
        'name': 'HTML 网页',
        'extension': '.html',
        'mime_type': 'text/html',
    },
    'xml': {
        'name': 'XML 数据',
        'extension': '.xml',
        'mime_type': 'application/xml',
    },
    'json': {
        'name': 'JSON 数据',
        'extension': '.json',
        'mime_type': 'application/json',
    },
    'csv': {
        'name': 'CSV 表格',
        'extension': '.csv',
        'mime_type': 'text/csv',
    },
    'txt': {
        'name': 'TXT 文本',
        'extension': '.txt',
        'mime_type': 'text/plain',
    },
    'md': {
        'name': 'Markdown 文档',
        'extension': '.md',
        'mime_type': 'text/markdown',
    },
}

# ============================================================
# 国际化语言包
# ============================================================
I18N = {
    'zh': {
        # 通用
        'app_title': '安全报告生成器',
        'app_subtitle': '漏洞扫描报告自动化生成与管理工具',
        'loading': '加载中...',
        'error': '错误',
        'success': '成功',
        'warning': '警告',
        'confirm': '确认',
        'cancel': '取消',
        'login': '登录',
        'login_desc': '请输入密码以继续操作',
        'login_password': '密码',
        'login_password_placeholder': '请输入密码',
        'save': '保存',
        'delete': '删除',
        'edit': '编辑',
        'add': '添加',
        'import': '导入',
        'export': '导出',
        'search': '搜索',
        'filter': '筛选',
        'reset': '重置',
        'back': '返回',
        'next': '下一步',
        'previous': '上一步',
        'close': '关闭',
        'download': '下载',
        'upload': '上传',
        'preview': '预览',
        'generate': '生成',
        'actions': '操作',
        'no_data': '暂无数据',
        'required': '此项为必填项',

        # 导航
        'nav_home': '首页',
        'nav_import': '导入扫描结果',
        'nav_vulns': '漏洞管理',
        'nav_report': '报告生成',
        'nav_settings': '设置',
        'nav_logs': '日志',
        'log_source_app': '应用日志',
        'log_source_electron': '客户端日志',
        'log_source_all': '全部',
        'log_search': '搜索关键词...',
        'log_search_btn': '搜索',
        'log_auto_refresh': '自动刷新',
        'log_clear': '清除日志',
        'log_entries': '条记录',
        'log_empty': '点击搜索加载日志',

        # 首页
        'home_welcome': '欢迎使用安全报告生成器',
        'home_description': '本工具可帮助安全测试人员快速导入多种扫描器的扫描结果，统一管理漏洞数据，并自动生成专业的安全测试报告。',
        'home_quick_start': '快速开始',
        'home_step1': '导入扫描结果',
        'home_step1_desc': '上传来自 Nmap、Nessus、BurpSuite 等扫描器的扫描文件',
        'home_step2': '编辑漏洞信息',
        'home_step2_desc': '查看、编辑和管理导入的漏洞数据，补充验证信息',
        'home_step3': '生成报告',
        'home_step3_desc': '选择模板和格式，一键生成专业的安全测试报告',

        # 导入
        'import_title': '导入扫描结果',
        'import_select_scanner': '选择扫描器来源',
        'import_select_file': '选择扫描文件',
        'import_drag_hint': '拖拽文件到此处，或点击选择文件',
        'import_uploading': '正在上传...',
        'import_parsing': '正在解析...',
        'import_result': '导入结果',
        'import_total': '共发现漏洞',
        'import_critical': '严重',
        'import_high': '高危',
        'import_medium': '中危',
        'import_low': '低危',
        'import_info': '信息',
        'import_confirm': '确认导入',
        'import_failed': '导入失败',
        'import_unsupported_format': '不支持的文件格式',
        'import_file_too_large': '文件大小超过限制（最大 50MB）',
        'import_batch_hint': '支持多文件批量上传，可一次选择多个扫描结果文件',
        'import_batch_progress': '批量导入进度',
        'import_filename': '文件名',
        'import_scanner_type': '扫描器类型',
        'import_vuln_count': '漏洞数量',
        'import_status': '状态',
        'import_batch_select_individual': '选择导入',
        'import_batch_import_all': '全部导入',
        'import_supported_formats': '各扫描器支持导入的格式',
        'import_auto_detect_hint': '💡 导入时系统会根据文件内容自动识别扫描器类型，无需手动选择。',
        'import_manual_scanner': '扫描器类型',
        'import_auto_detect': '自动检测（推荐）',
        'import_manual_hint': '默认自动识别，识别错误时可手动指定',

        # 漏洞管理
        'vuln_list': '漏洞列表',
        'vuln_detail': '漏洞详情',
        'vuln_id': 'CVE 编号',
        'vuln_name': '漏洞名称',
        'vuln_severity': '风险等级',
        'vuln_target': '受影响目标',
        'vuln_port': '端口',
        'vuln_protocol': '协议',
        'vuln_description': '漏洞描述',
        'vuln_impact': '影响分析',
        'vuln_solution': '修复建议',
        'vuln_poc_steps': '验证步骤',
        'vuln_evidence': '验证证据',
        'vuln_source': '来源扫描器',
        'vuln_tags': '自定义标签',
        'vuln_created_at': '创建时间',
        'vuln_batch_delete': '批量删除',
        'vuln_batch_export': '批量导出',
        'vuln_select_all': '全选',

        # 风险等级
        'severity_critical': '严重',
        'severity_high': '高危',
        'severity_medium': '中危',
        'severity_low': '低危',
        'severity_info': '信息',

        # 报告
        'report_title': '报告生成',
        'report_project_info': '项目信息',
        'report_project_name': '项目名称',
        'report_client_name': '客户名称',
        'report_tester_name': '测试人员',
        'report_test_date': '测试日期',
        'report_test_type': '测试类型',
        'report_test_type_blackbox': '黑盒测试',
        'report_test_type_whitebox': '白盒测试',
        'report_test_type_graybox': '灰盒测试',
        'report_scope': '测试范围',
        'report_tools_used': '使用工具',
        'report_tools_all': '全部',
        'report_scanner_source': '扫描器来源',
        'report_scanner_source_all': '全部来源',
        'report_filter_by_source': '按来源筛选',
        'vuln_filter_source': '来源筛选',
        'vuln_filter_source_all': '全部来源',
        'report_summary': '测试概述',
        'report_select_template': '选择报告模板',
        'report_select_format': '选择导出格式',
        'report_select_language': '报告语言',
        'report_language_zh': '中文',
        'report_language_en': 'English',
        'report_generate': '生成报告',
        'report_generating': '正在生成报告...',
        'report_download': '下载报告',
        'report_template_professional': '专业模板',
        'report_template_simple': '简洁模板',
        'report_template_detailed': '详细模板',

        # 统计
        'stats_total_vulns': '漏洞总数',
        'stats_severity_distribution': '风险等级分布',
        'stats_top_targets': '受影响目标排行',
        'stats_scanner_distribution': '扫描器来源分布',

        # 设置
        'settings_title': '系统设置',
        'settings_language': '界面语言',
        'settings_theme': '主题',
        'settings_clear_data': '清除所有数据',

        # 翻译相关
        'translate_all': '一键翻译',
        'translate': '翻译',
        'auto_translate': '自动翻译为中文',
        'translate_hint': '使用离线术语字典翻译漏洞内容',
        'translation_settings': '翻译设置',
        'translation_mode': '翻译模式',
        'mode_offline': '离线翻译',
        'mode_offline_desc': '本地术语字典，无需网络',
        'mode_online': '在线翻译',
        'mode_online_desc': '调用在线 API，翻译质量更高',
        'mode_hybrid': '混合翻译',
        'mode_hybrid_desc': '离线优先，在线补充',
        'translation_api_list': '翻译 API',
        'add_custom_api': '添加自定义 API',
        'translation_api_config': '翻译 API 配置',
        'api_name': 'API 名称',
        'api_name_placeholder': '例如：我的翻译 API',
        'api_name_required': 'API 名称不能为空',
        'api_type': 'API 类型',
        'custom_api': '自定义 API',
        'api_key_optional': '可选，部分 API 需要',
        'source_lang': '源语言',
        'target_lang': '目标语言',
        'response_path': '响应提取路径',
        'response_path_hint': '从 JSON 响应中提取翻译结果的路径，如 data.translatedText',
        'request_body_template': '请求体模板',
        'body_template_hint': '可用占位符: {{text}}, {{source_lang}}, {{target_lang}}, {{api_key}}',
        'test_connection': '测试连接',
        'testing': '测试中',
        'test_failed': '测试失败',
        'activate': '激活',
        'builtin': '内置',
        'confirm_delete_api': '确定删除此翻译 API 配置？',
        'loading': '加载中',

        # 历史与导入
        'report_history': '生成历史',
        'recent_imports': '最近导入',
        'translation_mgr': '翻译字典管理',

        # 去重
        'dedup_title': '漏洞去重',
        'dedup_confirm': '确认合并',

        # CVSS 与状态
        'cvss_score': 'CVSS 评分',
        'vuln_status': '漏洞状态',
        'status_discovered': '已发现',
        'status_confirmed': '已确认',
        'status_fixing': '修复中',
        'status_fixed': '已修复',
        'status_verified': '已验证',
        'status_closed': '已关闭',

        # 视图
        'kanban_view': '看板视图',
        'list_view': '列表视图',

        # 批量操作
        'batch_import': '批量导入',
        'preview': '在线预览',

        # 报告模板
        'report_template': '报告模板',
        'template_professional': '企业合规版',
        'template_pentest': '渗透实战版',
        'template_simple': '简洁摘要版',

        # API 与 Webhook
        'api_key': 'API 密钥',
        'webhook': 'Webhook 通知',
        'settings_api_keys': 'API 密钥管理',
        'settings_general': '通用设置',
        'close_behavior': '关闭窗口行为',
        'close_behavior_desc': '点击窗口关闭按钮时的行为',
        'cb_minimize': '最小化到托盘',
        'cb_minimize_desc': '关闭窗口，后台继续运行',
        'cb_ask': '每次询问',
        'cb_ask_desc': '弹出确认对话框',
        'cb_quit': '直接退出',
        'cb_quit_desc': '关闭窗口并退出程序',
        'keep_login': '关闭后保持登录',
        'keep_login_desc': '关闭程序后不自动退出登录，下次打开无需重新输入密码',
        'settings_webhooks': 'Webhook 配置',
        'password_settings': '密码管理',
        'current_password': '当前密码',
        'new_password': '新密码',
        'change_password': '修改密码',
        'reset_password': '重置为默认',
        'reset_password_hint': '重置将把密码恢复为 admin',
        'min_4_chars': '至少4位',
        'update_settings': '版本更新',
        'update_check': '检查更新',
        'update_checking': '检查中...',
        'update_download': '下载更新',
        'update_install': '重启安装',
        'update_ready': '就绪',
        'update_electron_only': '此功能仅支持桌面客户端使用',
        'settings_proxy': '网络代理',
        'proxy_enable': '启用代理',
        'proxy_type': '代理类型',
        'proxy_host': '服务器地址',
        'proxy_port': '端口',
        'proxy_auth': '认证（可选）',
        'proxy_username': '用户名',
        'proxy_password': '密码',
        'proxy_test': '测试连接',
        'proxy_testing': '测试中...',
        'proxy_desc': '代理将应用于所有外部网络请求（翻译API、Webhook等）',
        'generate_key': '生成密钥',
        'webhook_url': 'Webhook URL',
        'webhook_events': '通知事件',

        # 导出格式
        'defectdojo_format': 'DefectDojo 格式',
        'jira_format': 'Jira 格式',
    },
    'en': {
        # General
        'app_title': 'Security Report Generator',
        'app_subtitle': 'Automated Vulnerability Scan Report Generation & Management Tool',
        'loading': 'Loading...',
        'error': 'Error',
        'success': 'Success',
        'warning': 'Warning',
        'confirm': 'Confirm',
        'cancel': 'Cancel',
        'login': 'Login',
        'login_desc': 'Enter password to continue',
        'login_password': 'Password',
        'login_password_placeholder': 'Enter password',
        'save': 'Save',
        'delete': 'Delete',
        'edit': 'Edit',
        'add': 'Add',
        'import': 'Import',
        'export': 'Export',
        'search': 'Search',
        'filter': 'Filter',
        'reset': 'Reset',
        'back': 'Back',
        'next': 'Next',
        'previous': 'Previous',
        'close': 'Close',
        'download': 'Download',
        'upload': 'Upload',
        'preview': 'Preview',
        'generate': 'Generate',
        'actions': 'Actions',
        'no_data': 'No data available',
        'required': 'This field is required',

        # Navigation
        'nav_home': 'Home',
        'nav_import': 'Import Scan Results',
        'nav_vulns': 'Vulnerability Management',
        'nav_report': 'Report Generation',
        'nav_settings': 'Settings',
        'nav_logs': 'Logs',
        'log_source_app': 'App Logs',
        'log_source_electron': 'Electron Logs',
        'log_source_all': 'All',
        'log_search': 'Search...',
        'log_search_btn': 'Search',
        'log_auto_refresh': 'Auto Refresh',
        'log_clear': 'Clear',
        'log_entries': 'entries',
        'log_empty': 'Click search to load logs',

        # Home
        'home_welcome': 'Welcome to Security Report Generator',
        'home_description': 'This tool helps security testers quickly import scan results from various scanners, manage vulnerability data in a unified way, and automatically generate professional security test reports.',
        'home_quick_start': 'Quick Start',
        'home_step1': 'Import Scan Results',
        'home_step1_desc': 'Upload scan files from Nmap, Nessus, BurpSuite and other scanners',
        'home_step2': 'Edit Vulnerability Info',
        'home_step2_desc': 'View, edit and manage imported vulnerability data, supplement verification evidence',
        'home_step3': 'Generate Report',
        'home_step3_desc': 'Select template and format, generate professional security test reports with one click',

        # Import
        'import_title': 'Import Scan Results',
        'import_select_scanner': 'Select Scanner Source',
        'import_select_file': 'Select Scan File',
        'import_drag_hint': 'Drag and drop files here, or click to select',
        'import_uploading': 'Uploading...',
        'import_parsing': 'Parsing...',
        'import_result': 'Import Results',
        'import_total': 'Total vulnerabilities found',
        'import_critical': 'Critical',
        'import_high': 'High',
        'import_medium': 'Medium',
        'import_low': 'Low',
        'import_info': 'Info',
        'import_confirm': 'Confirm Import',
        'import_failed': 'Import Failed',
        'import_unsupported_format': 'Unsupported file format',
        'import_file_too_large': 'File size exceeds limit (max 50MB)',
        'import_batch_hint': 'Supports batch upload, select multiple scan result files at once',
        'import_batch_progress': 'Batch Import Progress',
        'import_filename': 'Filename',
        'import_scanner_type': 'Scanner Type',
        'import_vuln_count': 'Vulnerability Count',
        'import_status': 'Status',
        'import_batch_select_individual': 'Select to Import',
        'import_batch_import_all': 'Import All',
        'import_supported_formats': 'Supported Import Formats',
        'import_auto_detect_hint': '💡 The system automatically detects the scanner type based on file content. No manual selection needed.',
        'import_manual_scanner': 'Scanner Type',
        'import_auto_detect': 'Auto Detect (Recommended)',
        'import_manual_hint': 'Auto by default, manually specify if detection fails',

        # Vulnerability Management
        'vuln_list': 'Vulnerability List',
        'vuln_detail': 'Vulnerability Details',
        'vuln_id': 'CVE ID',
        'vuln_name': 'Vulnerability Name',
        'vuln_severity': 'Severity',
        'vuln_target': 'Affected Target',
        'vuln_port': 'Port',
        'vuln_protocol': 'Protocol',
        'vuln_description': 'Description',
        'vuln_impact': 'Impact Analysis',
        'vuln_solution': 'Remediation',
        'vuln_poc_steps': 'Proof of Concept Steps',
        'vuln_evidence': 'Evidence',
        'vuln_source': 'Scanner Source',
        'vuln_tags': 'Custom Tags',
        'vuln_created_at': 'Created At',
        'vuln_batch_delete': 'Batch Delete',
        'vuln_batch_export': 'Batch Export',
        'vuln_select_all': 'Select All',

        # Severity Levels
        'severity_critical': 'Critical',
        'severity_high': 'High',
        'severity_medium': 'Medium',
        'severity_low': 'Low',
        'severity_info': 'Info',

        # Report
        'report_title': 'Report Generation',
        'report_project_info': 'Project Information',
        'report_project_name': 'Project Name',
        'report_client_name': 'Client Name',
        'report_tester_name': 'Tester Name',
        'report_test_date': 'Test Date',
        'report_test_type': 'Test Type',
        'report_test_type_blackbox': 'Black Box Testing',
        'report_test_type_whitebox': 'White Box Testing',
        'report_test_type_graybox': 'Gray Box Testing',
        'report_scope': 'Test Scope',
        'report_tools_used': 'Tools Used',
        'report_tools_all': 'All',
        'report_scanner_source': 'Scanner Source',
        'report_scanner_source_all': 'All Sources',
        'report_filter_by_source': 'Filter by Source',
        'vuln_filter_source': 'Source Filter',
        'vuln_filter_source_all': 'All Sources',
        'report_summary': 'Test Summary',
        'report_select_template': 'Select Report Template',
        'report_select_format': 'Select Export Format',
        'report_select_language': 'Report Language',
        'report_language_zh': 'Chinese',
        'report_language_en': 'English',
        'report_generate': 'Generate Report',
        'report_generating': 'Generating report...',
        'report_download': 'Download Report',
        'report_template_professional': 'Professional Template',
        'report_template_simple': 'Simple Template',
        'report_template_detailed': 'Detailed Template',

        # Statistics
        'stats_total_vulns': 'Total Vulnerabilities',
        'stats_severity_distribution': 'Severity Distribution',
        'stats_top_targets': 'Top Affected Targets',
        'stats_scanner_distribution': 'Scanner Source Distribution',

        # Settings
        'settings_title': 'System Settings',
        'settings_language': 'Interface Language',
        'settings_theme': 'Theme',
        'settings_clear_data': 'Clear All Data',

        # Translation
        'translate_all': 'Translate All',
        'translate': 'Translate',
        'auto_translate': 'Auto translate to Chinese',
        'translate_hint': 'Uses offline glossary to translate vulnerability content',
        'translation_settings': 'Translation Settings',
        'translation_mode': 'Translation Mode',
        'mode_offline': 'Offline',
        'mode_offline_desc': 'Local glossary, no network needed',
        'mode_online': 'Online',
        'mode_online_desc': 'Online API, higher quality',
        'mode_hybrid': 'Hybrid',
        'mode_hybrid_desc': 'Offline first, online supplement',
        'translation_api_list': 'Translation APIs',
        'add_custom_api': 'Add Custom API',
        'translation_api_config': 'Translation API Config',
        'api_name': 'API Name',
        'api_name_placeholder': 'e.g. My Translation API',
        'api_name_required': 'API name is required',
        'api_type': 'API Type',
        'custom_api': 'Custom API',
        'api_key_optional': 'Optional, required by some APIs',
        'source_lang': 'Source Language',
        'target_lang': 'Target Language',
        'response_path': 'Response Path',
        'response_path_hint': 'Path to extract translation from JSON response, e.g. data.translatedText',
        'request_body_template': 'Request Body Template',
        'body_template_hint': 'Available placeholders: {{text}}, {{source_lang}}, {{target_lang}}, {{api_key}}',
        'test_connection': 'Test Connection',
        'testing': 'Testing',
        'test_failed': 'Test Failed',
        'activate': 'Activate',
        'builtin': 'Built-in',
        'confirm_delete_api': 'Delete this translation API config?',
        'loading': 'Loading',

        # History & Import
        'report_history': 'Report History',
        'recent_imports': 'Recent Imports',
        'translation_mgr': 'Translation Manager',

        # Deduplication
        'dedup_title': 'Deduplicate',
        'dedup_confirm': 'Confirm Merge',

        # CVSS & Status
        'cvss_score': 'CVSS Score',
        'vuln_status': 'Vulnerability Status',
        'status_discovered': 'Discovered',
        'status_confirmed': 'Confirmed',
        'status_fixing': 'Fixing',
        'status_fixed': 'Fixed',
        'status_verified': 'Verified',
        'status_closed': 'Closed',

        # Views
        'kanban_view': 'Kanban View',
        'list_view': 'List View',

        # Batch Operations
        'batch_import': 'Batch Import',
        'preview': 'Online Preview',

        # Report Templates
        'report_template': 'Report Template',
        'template_professional': 'Professional',
        'template_pentest': 'Pentest',
        'template_simple': 'Simple',

        # API & Webhook
        'api_key': 'API Key',
        'webhook': 'Webhook Notification',
        'settings_api_keys': 'API Key Management',
        'settings_general': 'General Settings',
        'close_behavior': 'Window Close Behavior',
        'close_behavior_desc': 'Action when clicking the window close button',
        'cb_minimize': 'Minimize to Tray',
        'cb_minimize_desc': 'Close window, keep running',
        'cb_ask': 'Always Ask',
        'cb_ask_desc': 'Show confirmation dialog',
        'cb_quit': 'Quit Directly',
        'cb_quit_desc': 'Close window and exit',
        'keep_login': 'Stay Logged In',
        'keep_login_desc': 'Keep login session after closing the app',
        'settings_webhooks': 'Webhook Configuration',
        'password_settings': 'Password',
        'current_password': 'Current Password',
        'new_password': 'New Password',
        'change_password': 'Change Password',
        'reset_password': 'Reset to Default',
        'reset_password_hint': 'Reset will restore password to admin',
        'min_4_chars': 'Min 4 chars',
        'update_settings': 'Update',
        'update_check': 'Check for Updates',
        'update_checking': 'Checking...',
        'update_download': 'Download Update',
        'update_install': 'Restart & Install',
        'update_ready': 'Ready',
        'update_electron_only': 'This feature is only available in the desktop app',
        'settings_proxy': 'Network Proxy',
        'proxy_enable': 'Enable Proxy',
        'proxy_type': 'Proxy Type',
        'proxy_host': 'Host',
        'proxy_port': 'Port',
        'proxy_auth': 'Authentication (Optional)',
        'proxy_username': 'Username',
        'proxy_password': 'Password',
        'proxy_test': 'Test Connection',
        'proxy_testing': 'Testing...',
        'proxy_desc': 'Proxy applies to all external requests (Translation API, Webhooks, etc.)',
        'generate_key': 'Generate Key',
        'webhook_url': 'Webhook URL',
        'webhook_events': 'Notification Events',

        # Export Formats
        'defectdojo_format': 'DefectDojo Format',
        'jira_format': 'Jira Format',
    },
}


def get_i18n_text(language='zh', key=''):
    """根据语言和键获取国际化文本。

    Args:
        language: 语言代码，支持 'zh' 和 'en'。
        key: 国际化文本的键名。

    Returns:
        对应的翻译文本。如果语言或键不存在，返回键名本身。
    """
    lang_pack = I18N.get(language, I18N.get('zh', {}))
    return lang_pack.get(key, key)
