"""
全局网络代理工具模块。

统一管理代理配置，为所有外部请求（翻译API、Webhook等）提供代理支持。
支持 HTTP(S) 和 SOCKS5 代理，支持用户名/密码认证。
"""

import json
import os
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)

# 代理配置缓存（避免每次请求都查数据库）
_proxy_config = None


def get_proxy_config(db=None):
    """获取代理配置。

    Args:
        db: 数据库实例，如果为 None 则从缓存读取。

    Returns:
        dict: 代理配置字典，格式：
            {
                'enabled': True/False,
                'type': 'http'|'socks5',
                'host': '127.0.0.1',
                'port': 7890,
                'username': '',
                'password': ''
            }
    """
    global _proxy_config

    if db is not None:
        raw = db.get_setting('proxy_config', '')
        if raw:
            try:
                _proxy_config = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                _proxy_config = None
        else:
            _proxy_config = None

    if _proxy_config is None:
        _proxy_config = {
            'enabled': False,
            'type': 'http',
            'host': '',
            'port': '',
            'username': '',
            'password': '',
        }

    return _proxy_config


def save_proxy_config(db, config):
    """保存代理配置。

    Args:
        db: 数据库实例。
        config: 代理配置字典。
    """
    global _proxy_config
    _proxy_config = config
    db.set_setting('proxy_config', json.dumps(config))
    logger.info('Proxy config saved: enabled=%s, type=%s, host=%s:%s',
                config.get('enabled'), config.get('type'),
                config.get('host'), config.get('port'))


def get_proxy_handler():
    """构建 urllib 代理 handler。

    Returns:
        urllib.request.OpenerDirector 或 None（如果代理未启用）。
    """
    config = get_proxy_config()
    if not config.get('enabled') or not config.get('host') or not config.get('port'):
        return None

    proxy_type = config.get('type', 'http').lower()
    host = config['host']
    port = config['port']
    username = config.get('username', '')
    password = config.get('password', '')

    # 构建代理 URL
    if proxy_type == 'socks5':
        # SOCKS5 需要 PySocks
        try:
            import socks
        except ImportError:
            logger.warning('SOCKS5 proxy requires PySocks package. Install: pip install PySocks')
            return None

        auth = f'{username}:{password}@' if username else ''
        proxy_url = f'socks5://{auth}{host}:{port}'
        handler = socks.sockshandler.SOCKSProxyHandler({
            'http': proxy_url,
            'https': proxy_url,
        })
        return urllib.request.build_opener(handler)

    # HTTP(S) 代理
    auth = f'{username}:{password}@' if username else ''
    proxy_url = f'http://{auth}{host}:{port}'

    handler = urllib.request.ProxyHandler({
        'http': proxy_url,
        'https': proxy_url,
    })
    return urllib.request.build_opener(handler)


def proxy_urlopen(url, data=None, headers=None, method=None, timeout=30):
    """通过代理发送 HTTP 请求（替代 urllib.request.urlopen）。

    Args:
        url: 请求 URL。
        data: 请求体（bytes，POST 请求时使用）。
        headers: 请求头字典。
        method: HTTP 方法（GET/POST 等）。
        timeout: 超时秒数。

    Returns:
        http.client.HTTPResponse 响应对象。
    """
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    opener = get_proxy_handler()

    if opener:
        logger.debug('Using proxy for request: %s', url)
        return opener.open(req, timeout=timeout)
    else:
        return urllib.request.urlopen(req, timeout=timeout)


def test_proxy_connection(config):
    """测试代理连接是否可用。

    Args:
        config: 代理配置字典。

    Returns:
        tuple: (success: bool, message: str)
    """
    if not config.get('host') or not config.get('port'):
        return False, 'Proxy host and port are required'

    proxy_type = config.get('type', 'http').lower()
    host = config['host']
    port = config['port']
    username = config.get('username', '')
    password = config.get('password', '')

    # 测试目标：访问 httpbin.org/ip 或一个简单的 IP 查询
    test_url = 'http://httpbin.org/ip'

    try:
        if proxy_type == 'socks5':
            try:
                import socks
            except ImportError:
                return False, 'SOCKS5 requires PySocks package (pip install PySocks)'

            auth = f'{username}:{password}@' if username else ''
            proxy_url = f'socks5://{auth}{host}:{port}'
            handler = socks.sockshandler.SOCKSProxyHandler({
                'http': proxy_url,
                'https': proxy_url,
            })
            opener = urllib.request.build_opener(handler)
        else:
            auth = f'{username}:{password}@' if username else ''
            proxy_url = f'http://{auth}{host}:{port}'
            handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url,
            })
            opener = urllib.request.build_opener(handler)

        req = urllib.request.Request(test_url)
        resp = opener.open(req, timeout=10)
        body = resp.read().decode('utf-8')
        return True, f'Proxy connection successful. Response: {body[:100]}'
    except Exception as e:
        return False, f'Proxy connection failed: {str(e)}'
