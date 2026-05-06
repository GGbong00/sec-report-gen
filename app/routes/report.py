"""
报告生成蓝图 (report_bp)

提供报告生成页面、项目信息管理和报告生成下载功能。
"""

import os
import uuid
import html
import re
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, current_app, send_file

report_bp = Blueprint('report', __name__)


def get_project_info():
    """获取当前项目信息。"""
    db = current_app.db
    return db.get_project_info()


@report_bp.route('/report')
def report_page():
    """报告生成页面。"""
    lang = session.get('lang', 'zh')
    from app.generators import SUPPORTED_FORMATS
    return render_template('report.html', lang=lang, supported_formats=SUPPORTED_FORMATS)


@report_bp.route('/api/report/project-info', methods=['GET'])
def api_get_project_info():
    """获取项目信息。"""
    db = current_app.db
    info = db.get_project_info()
    return jsonify({'success': True, 'project': info})


@report_bp.route('/api/report/project-info', methods=['POST'])
def save_project_info():
    """保存/更新项目信息。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}

    project_data = {
        'project_name': data.get('project_name', ''),
        'client_name': data.get('client_name', ''),
        'tester_name': data.get('tester_name', ''),
        'test_date': data.get('test_date', datetime.now().strftime('%Y-%m-%d')),
        'test_type': data.get('test_type', ''),
        'scope': data.get('scope', ''),
        'tools_used': data.get('tools_used', ''),
        'summary': data.get('summary', ''),
        'language': data.get('language', 'zh'),
        'template_type': data.get('template_type', ''),
    }

    db.save_project_info(project_data)

    return jsonify({
        'success': True,
        'message': 'Project info saved successfully',
        'project_info': project_data,
    })


@report_bp.route('/api/report/generate', methods=['POST'])
def generate_report():
    """生成报告，返回文件下载。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    format_name = data.get('format', 'pdf')
    template_type = data.get('template_type', '')
    project_info_db = db.get_project_info()
    report_lang = data.get('language', project_info_db.get('language', 'zh'))

    current_app.logger.info(f"[Report] 报告生成请求: format={format_name}, language={report_lang}, template={template_type}")

    # 获取漏洞数据
    scanner_sources = data.get('scanner_sources', [])
    if scanner_sources:
        vulns = db.get_vulns_by_sources(scanner_sources)
    else:
        vulns = db.get_all_vulns()

    if not vulns:
        return jsonify({'success': False, 'message': 'No vulnerabilities to generate report'}), 400

    # 构建项目信息字典
    project_info = {
        'name': project_info_db.get('project_name', 'Security Assessment'),
        'client': project_info_db.get('client_name', ''),
        'tester': project_info_db.get('tester_name', ''),
        'date': project_info_db.get('test_date', datetime.now().strftime('%Y-%m-%d')),
        'classification': '',
        'scope': project_info_db.get('scope', ''),
        'tools': project_info_db.get('tools_used', ''),
        'method': project_info_db.get('test_type', ''),
        'summary': project_info_db.get('summary', ''),
    }

    # 转换漏洞数据为生成器期望的格式
    vuln_dicts = []
    for v in vulns:
        vuln_dicts.append({
            'cve_id': v.get('vuln_id', ''),
            'name': v.get('name', ''),
            'risk_level': v.get('severity', 'info'),
            'description': v.get('description', ''),
            'impact': v.get('impact', ''),
            'reproduce_steps': v.get('poc_steps', ''),
            'remediation': v.get('solution', ''),
            'target': v.get('target', ''),
            'port': v.get('port', ''),
            'protocol': v.get('protocol', ''),
            'source': v.get('scanner_source', ''),
        })

    try:
        from app.generators import GeneratorFactory
        generator = GeneratorFactory.create(format_name)

        # 生成到临时目录
        import tempfile
        file_id = str(uuid.uuid4())

        ext_map = {
            'word': '.docx', 'docx': '.docx',
            'pdf': '.pdf',
            'excel': '.xlsx', 'xlsx': '.xlsx',
            'html': '.html',
            'xml': '.xml',
            'json': '.json',
            'csv': '.csv',
            'txt': '.txt',
            'markdown': '.md', 'md': '.md',
        }
        ext = ext_map.get(format_name.lower(), '.bin')
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, f'{file_id}{ext}')

        try:
            generator.generate(project_info, vuln_dicts, temp_path, lang=report_lang)

            # 读取文件内容为 base64
            with open(temp_path, 'rb') as f:
                file_data = f.read()
        finally:
            # 清理临时文件（确保所有路径都执行）
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception:
                pass

        # 记录生成历史
        suggested_filename = f'report_{project_info_db.get("project_name", "security")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}{ext}'
        db.add_report_history(
            format_name=format_name,
            language=report_lang,
            filename=suggested_filename,
            vuln_count=len(vulns),
            template=template_type,
        )

        current_app.logger.info(f"[Report] 报告生成成功: format={format_name}, language={report_lang}, vulns={len(vulns)}, filename={suggested_filename}")

        import base64
        return jsonify({
            'success': True,
            'filename': suggested_filename,
            'format': format_name,
            'file_data': base64.b64encode(file_data).decode('utf-8'),
        })

    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f'[Report] 报告生成失败: format={format_name}, language={report_lang}, error={e}', exc_info=True)
        error_msg = str(e)
        if 'weasyprint' in error_msg.lower() or type(e).__name__ == 'ImportError':
            error_msg = 'PDF 生成需要安装 weasyprint: pip install weasyprint'
        return jsonify({'success': False, 'message': f'Failed to generate report: {error_msg}'}), 500


@report_bp.route('/api/report/download/<filename>')
def download_report(filename):
    """下载生成的报告文件。"""
    export_folder = current_app.config['EXPORT_FOLDER']

    # 路径遍历防护：确保文件名不包含路径分隔符
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        return jsonify({'success': False, 'message': 'Invalid filename'}), 400

    filepath = os.path.join(export_folder, safe_filename)

    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'File not found'}), 404

    return send_file(filepath, as_attachment=True)


@report_bp.route('/api/report/preview', methods=['GET'])
def preview_report():
    """返回 HTML 报告内容作为 JSON，用于在线预览。"""
    db = current_app.db
    project_info_db = db.get_project_info()
    report_lang = project_info_db.get('language', 'zh')

    # 支持按扫描器来源筛选
    scanner_sources_param = request.args.get('scanner_sources', '')
    scanner_sources = [s.strip() for s in scanner_sources_param.split(',') if s.strip()] if scanner_sources_param else []
    if scanner_sources:
        vulns = db.get_vulns_by_sources(scanner_sources)
    else:
        vulns = db.get_all_vulns()

    if not vulns:
        return jsonify({'success': False, 'message': 'No vulnerabilities to preview'}), 400

    project_info = {
        'name': project_info_db.get('project_name', 'Security Assessment'),
        'client': project_info_db.get('client_name', ''),
        'tester': project_info_db.get('tester_name', ''),
        'date': project_info_db.get('test_date', datetime.now().strftime('%Y-%m-%d')),
        'classification': '',
        'scope': project_info_db.get('scope', ''),
        'tools': project_info_db.get('tools_used', ''),
        'method': project_info_db.get('test_type', ''),
        'summary': project_info_db.get('summary', ''),
    }

    vuln_dicts = []
    for v in vulns:
        vuln_dicts.append({
            'cve_id': v.get('vuln_id', ''),
            'name': v.get('name', ''),
            'risk_level': v.get('severity', 'info'),
            'description': v.get('description', ''),
            'impact': v.get('impact', ''),
            'reproduce_steps': v.get('poc_steps', ''),
            'remediation': v.get('solution', ''),
            'target': v.get('target', ''),
            'port': v.get('port', ''),
            'protocol': v.get('protocol', ''),
            'source': v.get('scanner_source', ''),
        })

    try:
        from app.generators.html_generator import HTMLGenerator
        generator = HTMLGenerator()
        generator.lang = report_lang
        html_content = generator._render_html(project_info, vuln_dicts)

        # 对 HTML 内容进行 XSS 防护：转义危险标签
        def _sanitize_html_for_preview(html_content):
            """清理 HTML 预览内容，移除潜在的 XSS 向量。"""
            if not html_content:
                return html_content
            # 移除 script 标签及其内容
            html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            # 移除事件处理器属性 (onclick, onerror, onload, etc.)
            html_content = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
            html_content = re.sub(r'\s+on\w+\s*=\s*\S+', '', html_content, flags=re.IGNORECASE)
            # 移除 javascript: 协议
            html_content = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', html_content, flags=re.IGNORECASE)
            # 移除 vbscript: 协议
            html_content = re.sub(r'href\s*=\s*["\']vbscript:[^"\']*["\']', 'href="#"', html_content, flags=re.IGNORECASE)
            # 移除 data: 协议（可能用于 XSS）
            html_content = re.sub(r'src\s*=\s*["\']data:text/html[^"\']*["\']', 'src=""', html_content, flags=re.IGNORECASE)
            # 移除 CSS url() 中的 data:text/html
            html_content = re.sub(r'url\s*\(\s*["\']?data:text/html[^"\')]*["\']?\s*\)', 'url("")', html_content, flags=re.IGNORECASE)
            return html_content
        
        html_content = _sanitize_html_for_preview(html_content)

        return jsonify({
            'success': True,
            'html': html_content,
            'vuln_count': len(vulns),
        })
    except Exception as e:
        current_app.logger.error(f'Failed to generate preview: {e}', exc_info=True)
        return jsonify({'success': False, 'message': f'Failed to generate preview: {str(e)}'}), 500


@report_bp.route('/api/report/history', methods=['GET'])
def report_history():
    """获取报告生成历史记录。"""
    db = current_app.db
    limit = request.args.get('limit', 50, type=int)
    if limit < 1:
        limit = 50
    if limit > 200:
        limit = 200

    history = db.get_report_history(limit=limit)

    return jsonify({
        'success': True,
        'total': len(history),
        'history': history,
    })
