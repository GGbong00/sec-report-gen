"""
Flask 应用工厂模块。

提供 create_app() 工厂函数来创建和配置 Flask 应用实例，
包括注册蓝图、配置文件路径和安全参数等。
"""

import os
import logging
import uuid
import secrets
from collections import defaultdict

from flask import Flask, request, g, session

from config import (
    UPLOAD_FOLDER,
    EXPORT_FOLDER,
    SECRET_KEY,
    MAX_CONTENT_LENGTH,
    I18N,
    get_i18n_text,
)


# 速率限制和认证相关的导入在 create_app 内部使用


def create_app(config_override: dict = None) -> Flask:
    """创建并配置 Flask 应用实例。

    Args:
        config_override: 可选的配置覆盖字典，用于测试或自定义部署场景。
            键名与 Flask 标准配置键一致，例如 {'TESTING': True}。

    Returns:
        配置完成的 Flask 应用实例。
    """
    _app_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(_app_dir, 'templates'),
        static_folder=os.path.join(_app_dir, 'static'),
    )

    # ----------------------------------------------------------
    # 基础配置
    # ----------------------------------------------------------
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['EXPORT_FOLDER'] = EXPORT_FOLDER
    app.config['JSON_AS_ASCII'] = False  # 支持中文 JSON 响应
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # 开发阶段禁用缓存
    # Session 安全配置
    app.config['SESSION_COOKIE_SECURE'] = False  # 开发环境设为 False，生产环境应为 True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 小时

    # ----------------------------------------------------------
    # 应用自定义配置覆盖
    # ----------------------------------------------------------
    if config_override:
        app.config.update(config_override)

    # ----------------------------------------------------------
    # 初始化数据库
    # ----------------------------------------------------------
    from app.database import Database
    db = Database()
    db.init_db()
    app.db = db

    # ----------------------------------------------------------
    # 注册蓝图
    # ----------------------------------------------------------
    _register_blueprints(app)

    # ----------------------------------------------------------
    # 配置日志
    # ----------------------------------------------------------
    _configure_logging(app)

    # ----------------------------------------------------------
    # 注册错误处理
    # ----------------------------------------------------------
    _register_error_handlers(app)

    # ----------------------------------------------------------
    # 注入模板上下文处理器
    # ----------------------------------------------------------
    _register_context_processors(app)

    # ----------------------------------------------------------
    # 简易速率限制（基于内存，无需外部依赖）
    # ----------------------------------------------------------
    from collections import defaultdict
    import time as _time
    _rate_limit_store = defaultdict(list)
    RATE_LIMIT_REQUESTS = 60  # 每分钟最大请求数
    RATE_LIMIT_WINDOW = 60    # 时间窗口（秒）

    def _check_rate_limit(client_ip):
        """检查客户端 IP 是否超过速率限制。"""
        now = _time.time()
        # 清理过期记录
        _rate_limit_store[client_ip] = [
            t for t in _rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW
        ]
        if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False
        _rate_limit_store[client_ip].append(now)
        return True

    @app.before_request
    def rate_limit_handler():
        """API 速率限制。"""
        if request.path.startswith('/api/'):
            client_ip = request.remote_addr or 'unknown'
            if not _check_rate_limit(client_ip):
                return {'error': 'Too Many Requests', 'message': f'Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s.'}, 429

    # ----------------------------------------------------------
    # 统一安全中间件：认证 + CSRF + Content-Type
    # ----------------------------------------------------------
    # 公开路径（不需要认证）
    PUBLIC_PATHS = {
        '/', '/import', '/vulnerabilities', '/report', '/settings',
        '/api/language', '/api/stats',
    }
    PUBLIC_PREFIXES = ('/api/stats', '/api/language', '/static/',
                   '/api/auth/', '/api/translation/config')

    @app.before_request
    def security_handler():
        """统一安全处理：认证 → CSRF → Content-Type。"""
        path = request.path

        # 生成请求 ID 并记录
        g.request_id = uuid.uuid4().hex[:12]
        app.logger.info('[%s] %s %s', g.request_id, request.method, request.full_path)

        # 生成 CSRF token
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        g.csrf_token = session['csrf_token']

        # 测试模式跳过所有安全检查
        if app.testing:
            return None

        is_api = path.startswith('/api/')
        is_write = request.method in ('POST', 'PUT', 'DELETE')
        is_public = path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)

        # ---- 认证检查 ----
        authenticated = False
        if is_public or request.method == 'GET':
            authenticated = True
        else:
            # 检查 session
            try:
                if session.get('authenticated'):
                    authenticated = True
            except RuntimeError:
                pass
            # 检查 API Key
            if not authenticated:
                api_key = request.headers.get('X-API-Key', '').strip()
                if api_key and app.db.verify_api_key(api_key):
                    authenticated = True

        if not authenticated and is_api and is_write:
            return {'success': False, 'message': 'Authentication required'}, 401

        # ---- CSRF 检查（仅对非公开的已认证浏览器请求） ----
        if is_api and is_write and authenticated and not is_public:
            content_type = (request.content_type or '').lower()
            # 文件上传跳过
            if 'multipart/form-data' in content_type:
                return None
            # API Key 认证跳过 CSRF（必须验证 Key 有效）
            api_key = request.headers.get('X-API-Key', '').strip()
            if api_key and app.db.verify_api_key(api_key):
                return None
            # 验证 Origin 或 Referer（提取 hostname 比较）
            origin = request.headers.get('Origin', '')
            referer = request.headers.get('Referer', '')
            host = request.host  # e.g. 'localhost:5000'
            valid = False
            for header in (origin, referer):
                if not header:
                    continue
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(header)
                    header_host = parsed.netloc  # e.g. '127.0.0.1:5000'
                    if not header_host:
                        continue
                    # 比较时忽略端口号差异（仅当一方缺省端口时）
                    h_host = host.split(':')[0]
                    h_port = host.split(':')[1] if ':' in host else ('443' if parsed.scheme == 'https' else '80')
                    o_host = header_host.split(':')[0]
                    o_port = header_host.split(':')[1] if ':' in header_host else ('443' if parsed.scheme == 'https' else '80')
                    if h_host == o_host and h_port == o_port:
                        valid = True
                        break
                    # 也允许简单的 netloc 包含检查作为兜底
                    if host in header_host or header_host in host:
                        valid = True
                        break
                except Exception:
                    pass
            if not valid and request.content_length and request.content_length > 0:
                return {'error': 'Forbidden', 'message': 'CSRF validation failed'}, 403

        # ---- Content-Type 检查 ----
        if is_api and is_write:
            content_type = (request.content_type or '').lower()
            if 'multipart/form-data' not in content_type and 'application/json' not in content_type:
                if request.content_length and request.content_length > 0:
                    if 'application/x-www-form-urlencoded' in content_type:
                        app.logger.warning('[%s] Rejected form-encoded request: %s', g.request_id, path)
                        return {'error': 'Bad Request', 'message': 'API endpoints require JSON content type'}, 400

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-src 'self' blob:; "
        )
        return response

    return app


def _register_blueprints(app: Flask) -> None:
    """注册所有蓝图模块。"""
    blueprints = [
        ('app.routes.main', 'main_bp'),
        ('app.routes.import_route', 'import_bp'),
        ('app.routes.vuln', 'vuln_bp'),
        ('app.routes.report', 'report_bp'),
        ('app.routes.settings', 'settings_bp'),
        ('app.routes.log', 'log_bp'),
    ]

    for module_path, bp_name in blueprints:
        try:
            module = __import__(module_path, fromlist=[bp_name])
            bp = getattr(module, bp_name, None)
            if bp is not None:
                app.register_blueprint(bp)
                app.logger.info('Registered blueprint: %s', bp_name)
            else:
                app.logger.warning('Blueprint %s not found in %s', bp_name, module_path)
        except Exception as e:
            app.logger.error(
                'Failed to register blueprint %s from %s: %s',
                bp_name, module_path, e, exc_info=True,
            )


def _configure_logging(app: Flask) -> None:
    """配置应用日志。

    设置日志格式和级别，同时输出到控制台和文件。
    """
    from config import DATA_DIR

    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'

    # 确保日志目录存在
    log_dir = DATA_DIR
    os.makedirs(log_dir, exist_ok=True)

    # 根日志器：控制台 + 文件
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # 清除默认 handler，避免重复
    root_logger.handlers.clear()

    # 控制台 handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level, logging.INFO))
    console_handler.setFormatter(logging.Formatter(log_format, datefmt=datefmt))
    root_logger.addHandler(console_handler)

    # 文件 handler（追加模式，最大 5MB，保留 3 个备份）
    log_file = os.path.join(log_dir, 'app.log')
    try:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8',
        )
        file_handler.setLevel(getattr(logging, log_level, logging.INFO))
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=datefmt))
        root_logger.addHandler(file_handler)
    except Exception as e:
        root_logger.warning('无法创建日志文件 %s: %s', log_file, e)

    app.logger.setLevel(getattr(logging, log_level, logging.INFO))


def _register_error_handlers(app: Flask) -> None:
    """注册全局错误处理器。"""

    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad Request', 'message': str(error)}, 400

    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not Found', 'message': str(error)}, 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return {'error': 'Request Entity Too Large', 'message': 'File size exceeds the maximum limit of 50MB.'}, 413

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error(f'Internal Server Error: {error}', exc_info=True)
        return {'error': 'Internal Server Error', 'message': 'An unexpected error occurred.'}, 500


def _register_context_processors(app: Flask) -> None:
    """注册模板上下文处理器，注入全局变量。"""

    @app.context_processor
    def inject_globals():
        # 从 session 获取语言，默认中文
        try:
            from flask import session
            lang = session.get('lang', 'zh')
        except RuntimeError:
            lang = 'zh'
        if not lang:
            lang = 'zh'
        lang_pack = I18N.get(lang, I18N.get('zh', {}))
        return {
            'lang': lang,
            'i18n': lambda key: lang_pack.get(key, key),
            'I18N': lang_pack,
            'csrf_token': g.get('csrf_token', ''),
        }
