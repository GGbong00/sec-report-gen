"""
主页蓝图 (main_bp)

提供首页仪表盘、语言切换和统计数据 API。
"""

from flask import Blueprint, render_template, request, jsonify, session, current_app
from config import get_i18n_text

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """首页，显示仪表盘概览。"""
    lang = session.get('lang', 'zh')
    return render_template('index.html', lang=lang)


@main_bp.route('/api/language', methods=['POST'])
def switch_language():
    """切换界面语言（zh/en）。"""
    data = request.get_json(silent=True) or {}
    new_lang = data.get('lang', 'zh').strip().lower()
    if new_lang not in ('zh', 'en'):
        new_lang = 'zh'
    session['lang'] = new_lang
    return jsonify({
        'success': True,
        'lang': new_lang,
    })


@main_bp.route('/api/stats')
def get_stats():
    """获取当前漏洞统计数据，返回详细的统计信息。"""
    db = current_app.db
    vulns = db.get_all_vulns()

    # 基础严重等级统计
    stats = {
        'total': len(vulns),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
    }

    # 按目标统计
    by_target = {}
    # 按扫描器统计
    by_scanner = {}
    # 按类型统计（基于漏洞名称关键词）
    by_type = {}
    # 按端口统计
    by_port = {}
    # CVSS 分布
    cvss_distribution = {
        'none': 0,       # 0
        'low': 0,        # 0.1 - 3.9
        'medium': 0,     # 4.0 - 6.9
        'high': 0,       # 7.0 - 8.9
        'critical': 0,   # 9.0 - 10.0
        'unknown': 0,    # 未评分
    }
    # 状态分布
    status_distribution = {}

    for vuln in vulns:
        severity = vuln.get('severity', 'info').lower()
        if severity in stats:
            stats[severity] += 1

        # 按目标统计
        target = vuln.get('target', '') or 'Unknown'
        by_target[target] = by_target.get(target, 0) + 1

        # 按扫描器统计
        scanner = vuln.get('scanner_source', 'unknown') or 'unknown'
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1

        # 按类型统计（取漏洞名称前 30 字符作为粗略分类）
        name = vuln.get('name', '') or 'Unknown'
        by_type[name] = by_type.get(name, 0) + 1

        # 按端口统计
        port = str(vuln.get('port', '')) or 'N/A'
        by_port[port] = by_port.get(port, 0) + 1

        # CVSS 分布
        cvss = vuln.get('cvss_score')
        if cvss is None or cvss == 0.0:
            cvss_distribution['unknown'] += 1
        elif cvss >= 9.0:
            cvss_distribution['critical'] += 1
        elif cvss >= 7.0:
            cvss_distribution['high'] += 1
        elif cvss >= 4.0:
            cvss_distribution['medium'] += 1
        elif cvss >= 0.1:
            cvss_distribution['low'] += 1
        else:
            cvss_distribution['none'] += 1

        # 状态分布
        status = vuln.get('status', 'discovered') or 'discovered'
        status_distribution[status] = status_distribution.get(status, 0) + 1

    # 排序：取 Top 10
    top_targets = sorted(by_target.items(), key=lambda x: x[1], reverse=True)[:10]
    top_scanners = sorted(by_scanner.items(), key=lambda x: x[1], reverse=True)
    top_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ports = sorted(by_port.items(), key=lambda x: x[1], reverse=True)[:10]

    # 最近导入记录
    history = db.get_import_history(limit=5)

    # 项目信息
    project = db.get_project_info()

    return jsonify({
        'success': True,
        'stats': stats,
        'by_target': dict(top_targets),
        'by_scanner': dict(top_scanners),
        'by_type': dict(top_types),
        'by_port': dict(top_ports),
        'cvss_distribution': cvss_distribution,
        'status_distribution': status_distribution,
        'recent_imports': history,
        'project_info': project,
    })
