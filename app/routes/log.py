"""
日志查看路由。

提供日志页面和日志读取/清除 API。
"""

import os
import logging
from flask import Blueprint, render_template, jsonify, request, current_app

log_bp = Blueprint('log', __name__)


@log_bp.route('/logs')
def logs_page():
    """日志查看页面。"""
    return render_template('logs.html')


@log_bp.route('/api/logs/read', methods=['GET'])
def api_read_logs():
    """读取日志内容。

    Query params:
        source: 'app' (Flask日志) | 'electron' (Electron日志) | 'all'
        level: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'ALL'
        tail: 读取最后 N 行，默认 500
        keyword: 关键词过滤
    """
    source = request.args.get('source', 'app')
    level = request.args.get('level', 'ALL').upper()
    tail = min(int(request.args.get('tail', 500)), 5000)
    keyword = request.args.get('keyword', '').strip()

    lines = []

    # 读取 Flask 应用日志
    if source in ('app', 'all'):
        app_lines = _read_app_logs(level, keyword)
        lines.extend(app_lines)

    # 读取 Electron 日志
    if source in ('electron', 'all'):
        electron_lines = _read_electron_logs(level, keyword)
        lines.extend(electron_lines)

    # 按时间排序（最新在前）
    lines.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # 截取最后 tail 行
    lines = lines[:tail]

    return jsonify({
        'success': True,
        'total': len(lines),
        'lines': lines,
    })


@log_bp.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """清除日志文件。"""
    data = request.get_json(silent=True) or {}
    source = data.get('source', 'app')

    cleared = []
    if source in ('app', 'all'):
        cleared.append(_clear_app_logs())
    if source in ('electron', 'all'):
        cleared.append(_clear_electron_logs())

    cleared_sources = [c for c in cleared if c]
    current_app.logger.info(f"[Log] 清除日志: source={source}, cleared={cleared_sources}")

    return jsonify({
        'success': True,
        'message': f'已清除: {", ".join(c for c in cleared if c)}',
    })


@log_bp.route('/api/logs/sources', methods=['GET'])
def api_log_sources():
    """获取可用的日志源及其状态。"""
    from config import DATA_DIR

    sources = []

    # Flask 日志
    sources.append({
        'id': 'app',
        'name': '应用日志 (Flask)',
        'icon': 'fa-server',
        'size': _get_file_size(os.path.join(DATA_DIR, 'app.log')),
    })

    # Electron 日志
    electron_log = _find_electron_log()
    sources.append({
        'id': 'electron',
        'name': '客户端日志 (Electron)',
        'icon': 'fa-desktop',
        'size': _get_file_size(electron_log) if electron_log else 0,
    })

    return jsonify({'success': True, 'sources': sources})


def _read_app_logs(level='ALL', keyword=''):
    """读取 Flask 应用日志文件。"""
    from config import DATA_DIR
    log_file = os.path.join(DATA_DIR, 'app.log')

    if not os.path.isfile(log_file):
        return []

    lines = []
    level_priority = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3, 'CRITICAL': 4}

    try:
        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line.strip():
                    continue

                # 解析日志级别
                log_level = 'INFO'
                for lv in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
                    if f' [{lv}] ' in line:
                        log_level = lv
                        break

                # 过滤级别
                if level != 'ALL' and level_priority.get(log_level, 0) < level_priority.get(level, 0):
                    continue

                # 关键词过滤
                if keyword and keyword.lower() not in line.lower():
                    continue

                # 提取时间戳
                timestamp = ''
                if line.startswith('20'):
                    timestamp = line[:19]

                lines.append({
                    'timestamp': timestamp,
                    'level': log_level,
                    'message': line,
                    'source': 'app',
                })
    except Exception as e:
        current_app.logger.debug(f'读取应用日志失败: {e}')

    return lines


def _read_electron_logs(level='ALL', keyword=''):
    """读取 Electron debug.log。"""
    log_file = _find_electron_log()
    if not log_file or not os.path.isfile(log_file):
        return []

    lines = []
    level_priority = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3, 'CRITICAL': 4}

    try:
        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line.strip():
                    continue

                log_level = 'INFO'
                for lv in ['ERROR', 'WARNING', 'INFO', 'DEBUG']:
                    if lv in line.upper():
                        log_level = lv
                        break

                if level != 'ALL' and level_priority.get(log_level, 0) < level_priority.get(level, 0):
                    continue

                if keyword and keyword.lower() not in line.lower():
                    continue

                # 提取时间戳 [2026-04-16T12:00:00.000Z]
                timestamp = ''
                if line.startswith('[') and 'T' in line:
                    end = line.find(']')
                    if end > 0:
                        timestamp = line[1:end]

                lines.append({
                    'timestamp': timestamp,
                    'level': log_level,
                    'message': line,
                    'source': 'electron',
                })
    except Exception as e:
        current_app.logger.debug(f'读取Electron日志失败: {e}')

    return lines


def _find_electron_log():
    """查找 Electron debug.log 位置。"""
    from config import DATA_DIR
    # 便携版：userData 目录
    candidates = [
        os.path.join(DATA_DIR, '..', 'debug.log'),
        os.path.join(DATA_DIR, 'debug.log'),
    ]
    # 开发模式
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    candidates.append(os.path.join(app_root, 'debug.log'))

    for p in candidates:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def _clear_app_logs():
    """清除应用日志。"""
    from config import DATA_DIR
    log_file = os.path.join(DATA_DIR, 'app.log')
    if os.path.isfile(log_file):
        try:
            open(log_file, 'w').close()
            return 'app.log'
        except Exception as e:
            current_app.logger.debug(f'清除应用日志失败: {e}')
    return ''


def _clear_electron_logs():
    """清除 Electron 日志。"""
    log_file = _find_electron_log()
    if log_file and os.path.isfile(log_file):
        try:
            open(log_file, 'w').close()
            return 'debug.log'
        except Exception as e:
            current_app.logger.debug(f'清除Electron日志失败: {e}')
    return ''


def _get_file_size(filepath):
    """获取文件大小（人类可读）。"""
    if not filepath or not os.path.isfile(filepath):
        return '0 B'
    size = os.path.getsize(filepath)
    if size < 1024:
        return f'{size} B'
    elif size < 1024 * 1024:
        return f'{size / 1024:.1f} KB'
    else:
        return f'{size / (1024 * 1024):.1f} MB'
