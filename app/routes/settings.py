"""
设置蓝图 (settings_bp)

提供系统设置页面、API 密钥管理和 Webhook 管理功能。
"""

import hashlib
import hmac
import json
import time
from functools import wraps
from flask import Blueprint, render_template, request, jsonify, session, current_app

settings_bp = Blueprint('settings', __name__)


def require_api_key(f):
    """API 密钥认证装饰器。

    检查请求头中的 X-API-Key 是否有效。
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key', '').strip()
        if not api_key:
            return jsonify({
                'success': False,
                'message': 'API key is required. Provide X-API-Key header.',
            }), 401

        db = current_app.db
        key_info = db.verify_api_key(api_key)
        if not key_info:
            return jsonify({
                'success': False,
                'message': 'Invalid or revoked API key.',
            }), 403

        return f(*args, **kwargs)
    return decorated_function


@settings_bp.route('/settings')
def settings_page():
    """设置页面。"""
    lang = session.get('lang', 'zh')
    return render_template('settings.html', lang=lang)


# ============================================================
# API Key 管理
# ============================================================

@settings_bp.route('/api/settings/api-keys', methods=['POST'])
def create_api_key():
    """创建新的 API 密钥。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()

    if not name:
        return jsonify({
            'success': False,
            'message': 'API key name is required',
        }), 400

    key_id, raw_key = db.create_api_key(name)

    current_app.logger.info(f"[Settings] API密钥创建: name={name}, key_id={key_id}")

    return jsonify({
        'success': True,
        'message': 'API key created successfully',
        'key_id': key_id,
        'key': raw_key,
        'name': name,
    }), 201


@settings_bp.route('/api/settings/api-keys', methods=['GET'])
def list_api_keys():
    """列出所有 API 密钥。"""
    db = current_app.db
    keys = db.list_api_keys()

    return jsonify({
        'success': True,
        'total': len(keys),
        'keys': keys,
    })


@settings_bp.route('/api/settings/api-keys/<key_id>', methods=['DELETE'])
def revoke_api_key(key_id):
    """吊销 API 密钥。"""
    db = current_app.db
    success = db.revoke_api_key(key_id)

    if success:
        current_app.logger.info(f"[Settings] API密钥吊销: key_id={key_id}")
        return jsonify({
            'success': True,
            'message': 'API key revoked successfully',
        })
    else:
        return jsonify({
            'success': False,
            'message': 'API key not found',
        }), 404


# ============================================================
# Webhook 管理
# ============================================================

@settings_bp.route('/api/settings/webhooks', methods=['POST'])
def create_webhook():
    """创建新的 Webhook。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    events = data.get('events', [])
    secret = data.get('secret', '')

    if not url:
        return jsonify({
            'success': False,
            'message': 'Webhook URL is required',
        }), 400

    # 基本 URL 验证
    if not url.startswith(('http://', 'https://')):
        return jsonify({
            'success': False,
            'message': 'Webhook URL must start with http:// or https://',
        }), 400

    webhook_id = db.create_webhook(url=url, events=events, secret=secret)

    current_app.logger.info(f"[Settings] Webhook创建: webhook_id={webhook_id}, url={url}, events={events}")

    return jsonify({
        'success': True,
        'message': 'Webhook created successfully',
        'webhook_id': webhook_id,
    }), 201


@settings_bp.route('/api/settings/webhooks', methods=['GET'])
def list_webhooks():
    """列出所有 Webhook。"""
    db = current_app.db
    webhooks = db.list_webhooks()

    # 隐藏 secret 字段
    safe_webhooks = []
    for wh in webhooks:
        safe = dict(wh)
        if safe.get('secret'):
            safe['secret'] = '********'
        safe_webhooks.append(safe)

    return jsonify({
        'success': True,
        'total': len(safe_webhooks),
        'webhooks': safe_webhooks,
    })


@settings_bp.route('/api/settings/webhooks/<webhook_id>', methods=['DELETE'])
def delete_webhook(webhook_id):
    """删除 Webhook。"""
    db = current_app.db
    success = db.delete_webhook(webhook_id)

    if success:
        current_app.logger.info(f"[Settings] Webhook删除: webhook_id={webhook_id}")
        return jsonify({
            'success': True,
            'message': 'Webhook deleted successfully',
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Webhook not found',
        }), 404


@settings_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    """本地认证登录（桌面版/单用户场景）。"""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    auth_password = _get_auth_password()
    if password == auth_password:
        session['authenticated'] = True
        session.permanent = True
        current_app.logger.info(f"[Auth] 用户登录成功: ip={request.remote_addr}")
        return jsonify({'success': True, 'message': 'Login successful'})
    current_app.logger.warning(f"[Auth] 用户登录失败: ip={request.remote_addr}, reason=密码错误")
    return jsonify({'success': False, 'message': 'Invalid password'}), 401


def _get_auth_password():
    """获取当前认证密码。优先级：数据库 > 环境变量 > 默认值。"""
    import os
    db = current_app.db
    stored = db.get_setting('auth_password', '')
    if stored:
        return stored
    return os.environ.get('AUTH_PASSWORD', 'admin')


@settings_bp.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """退出登录。"""
    session.clear()
    current_app.logger.info(f"[Auth] 用户退出登录: ip={request.remote_addr}")
    return jsonify({'success': True, 'message': 'Logged out'})


@settings_bp.route('/api/auth/change-password', methods=['POST'])
def api_change_password():
    """修改密码。需要提供当前密码和新密码。"""
    if not session.get('authenticated'):
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')

    if not old_password or not new_password:
        return jsonify({'success': False, 'message': '请填写当前密码和新密码'}), 400
    if len(new_password) < 4:
        return jsonify({'success': False, 'message': '新密码长度不能少于4位'}), 400
    if new_password == old_password:
        return jsonify({'success': False, 'message': '新密码不能与当前密码相同'}), 400

    current_password = _get_auth_password()
    if old_password != current_password:
        return jsonify({'success': False, 'message': '当前密码错误'}), 401

    db = current_app.db
    db.set_setting('auth_password', new_password)
    current_app.logger.info(f"[Settings] 密码修改成功: ip={request.remote_addr}")
    return jsonify({'success': True, 'message': '密码修改成功'})


@settings_bp.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    """重置密码。需要提供当前密码，重置为默认密码 admin。"""
    data = request.get_json(silent=True) or {}
    current = data.get('password', '')

    if not current:
        return jsonify({'success': False, 'message': '请输入当前密码'}), 400

    auth_password = _get_auth_password()
    if current != auth_password:
        return jsonify({'success': False, 'message': '密码错误'}), 401

    db = current_app.db
    db.set_setting('auth_password', 'admin')
    current_app.logger.info(f"[Settings] 密码重置为默认值: ip={request.remote_addr}")
    return jsonify({'success': True, 'message': '密码已重置为 admin'})


@settings_bp.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    """检查认证状态。"""
    authenticated = session.get('authenticated', False)
    has_api_keys = len(current_app.db.list_api_keys()) > 0
    return jsonify({'authenticated': authenticated, 'has_api_keys': has_api_keys})


def _is_safe_url(url):
    """检查 URL 是否安全（不允许内网地址和危险协议）"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # 阻止内网地址
    blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal']
    if hostname in blocked or hostname.endswith('.local'):
        return False
    # 阻止私有 IP 段
    import ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        pass  # hostname is not an IP, that's ok
    return True


@settings_bp.route('/api/settings/webhooks/test', methods=['POST'])
def test_webhook():
    """发送测试 Webhook 通知。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    secret = data.get('secret', '')
    webhook_id = data.get('webhook_id', '')

    if not url:
        return jsonify({
            'success': False,
            'message': 'Webhook URL is required',
        }), 400

    if not _is_safe_url(url):
        return jsonify({'success': False, 'message': 'Internal or invalid URLs are not allowed'}), 400

    # 如果提供了 webhook_id，验证 secret 是否与存储的匹配
    if webhook_id and secret:
        from app.database import _verify_webhook_secret
        webhooks = db.list_webhooks()
        stored_wh = next((wh for wh in webhooks if wh.get('id') == webhook_id), None)
        if stored_wh and stored_wh.get('has_secret'):
            # 需要从数据库获取存储的哈希
            import sqlite3
            from app.database import DB_PATH
            try:
                conn = sqlite3.connect(DB_PATH, timeout=10)
                row = conn.execute('SELECT secret FROM webhooks WHERE id = ?', (webhook_id,)).fetchone()
                conn.close()
                if row and row[0]:
                    if not _verify_webhook_secret(secret, row[0]):
                        return jsonify({'success': False, 'message': 'Webhook secret verification failed'}), 403
            except Exception:
                pass

    # 构造测试 payload
    payload = {
        'event': 'test',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'message': 'Webhook test from Security Report Generator',
    }

    # 计算签名
    headers = {'Content-Type': 'application/json'}
    if secret:
        payload_json = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(
            secret.encode(), payload_json.encode(), hashlib.sha256
        ).hexdigest()
        headers['X-Webhook-Signature'] = f'sha256={signature}'

    # 发送测试请求
    try:
        from app.utils.proxy import proxy_urlopen
        resp = proxy_urlopen(
            url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method='POST',
            timeout=10,
        )
        status_code = resp.getcode()
        return jsonify({
            'success': True,
            'message': f'Test webhook sent successfully (HTTP {status_code})',
            'status_code': status_code,
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to send test webhook: {str(e)}',
        }), 500


# ============================================================
# 代理配置管理
# ============================================================

@settings_bp.route('/api/settings/proxy', methods=['GET'])
def get_proxy_config():
    """获取代理配置。"""
    from app.utils.proxy import get_proxy_config as _get_proxy_config
    db = current_app.db
    config = _get_proxy_config(db)
    # 隐藏密码
    safe_config = {**config}
    if safe_config.get('password'):
        safe_config['password'] = '********'
    return jsonify({
        'success': True,
        'config': safe_config,
    })


@settings_bp.route('/api/settings/proxy', methods=['POST'])
def save_proxy_config():
    """保存代理配置。"""
    from app.utils.proxy import save_proxy_config as _save_proxy_config
    db = current_app.db
    data = request.get_json(silent=True) or {}

    config = {
        'enabled': bool(data.get('enabled', False)),
        'type': data.get('type', 'http'),
        'host': data.get('host', '').strip(),
        'port': int(data.get('port', 0)) if data.get('port') else 0,
        'username': data.get('username', '').strip(),
        'password': data.get('password', ''),
    }

    # 验证
    if config['enabled']:
        if not config['host']:
            return jsonify({'success': False, 'message': 'Proxy host is required'}), 400
        if not config['port'] or not (1 <= config['port'] <= 65535):
            return jsonify({'success': False, 'message': 'Valid port (1-65535) is required'}), 400
        if config['type'] not in ('http', 'socks5'):
            return jsonify({'success': False, 'message': 'Proxy type must be http or socks5'}), 400

    _save_proxy_config(db, config)
    current_app.logger.info(f"[Settings] 代理配置变更: enabled={config['enabled']}, type={config['type']}, host={config['host']}, port={config['port']}")
    return jsonify({
        'success': True,
        'message': 'Proxy config saved',
    })


@settings_bp.route('/api/settings/proxy/test', methods=['POST'])
def test_proxy():
    """测试代理连接。"""
    from app.utils.proxy import test_proxy_connection
    data = request.get_json(silent=True) or {}

    config = {
        'enabled': True,
        'type': data.get('type', 'http'),
        'host': data.get('host', '').strip(),
        'port': int(data.get('port', 0)) if data.get('port') else 0,
        'username': data.get('username', '').strip(),
        'password': data.get('password', ''),
    }

    if not config['host'] or not config['port']:
        return jsonify({'success': False, 'message': 'Proxy host and port are required'}), 400

    success, message = test_proxy_connection(config)
    return jsonify({
        'success': success,
        'message': message,
    })
