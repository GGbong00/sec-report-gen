"""
导入蓝图 (import_bp)

提供扫描器报告文件上传、自动检测扫描器类型、解析和确认导入功能。
"""

import os
import uuid
import time
import threading
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, current_app

import_bp = Blueprint('import', __name__)

# 内存存储：解析结果暂存（带超时清理）
_parsed_results = {}
_parsed_results_lock = threading.Lock()
_PARSED_RESULT_TIMEOUT = 3600  # 1 小时超时

# 允许上传的文件扩展名
ALLOWED_UPLOAD_EXTENSIONS = {
    '.xml', '.csv', '.json', '.html', '.htm', '.xlsx', '.xls', '.nessus',
}


def get_import_history():
    """获取导入历史记录。"""
    db = current_app.db
    return db.get_import_history()


def _cleanup_expired_results():
    """清理超时的解析结果。"""
    now = time.time()
    with _parsed_results_lock:
        expired_keys = [
            key for key, value in _parsed_results.items()
            if now - value.get('timestamp', 0) > _PARSED_RESULT_TIMEOUT
        ]
        for key in expired_keys:
            _parsed_results.pop(key, None)

        # 限制最大缓存数量
        MAX_CACHED_RESULTS = 50
        if len(_parsed_results) > MAX_CACHED_RESULTS:
            sorted_keys = sorted(_parsed_results.keys(), key=lambda k: _parsed_results[k].get('timestamp', 0))
            for key in sorted_keys[:len(_parsed_results) - MAX_CACHED_RESULTS]:
                del _parsed_results[key]


@import_bp.route('/import')
def import_page():
    """导入页面。"""
    lang = session.get('lang', 'zh')
    from app.parsers import ParserFactory
    supported_scanners = ParserFactory.get_supported_scanners()
    return render_template('import.html', lang=lang, supported_scanners=supported_scanners)


@import_bp.route('/api/import/upload', methods=['POST'])
def upload_file():
    """上传扫描器报告文件，自动检测扫描器类型并解析。"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    # 服务端文件类型验证
    filename = file.filename
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({
            'success': False,
            'message': f'Unsupported file extension: {ext}. Allowed: {", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}',
        }), 400

    # 清理过期结果
    _cleanup_expired_results()

    # 保存上传文件
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_id = str(uuid.uuid4())
    save_path = os.path.join(upload_folder, f'{file_id}{ext}')

    # 优先获取手动指定的扫描器类型（在日志中使用）
    manual_scanner = request.form.get('scanner_type', '').strip().lower()

    try:
        file.save(save_path)
        file_size = os.path.getsize(save_path)
        current_app.logger.info(f"[Import] 文件上传成功: filename={file.filename}, size={file_size} bytes, scanner={manual_scanner or 'auto'}")
    except Exception as e:
        current_app.logger.error(f"[Import] 文件保存失败: filename={file.filename}, error={str(e)}")
        return jsonify({'success': False, 'message': f'Failed to save file: {str(e)}'}), 500

    # 自动检测扫描器类型并解析（支持手动指定）
    try:
        from app.parsers import detect_scanner, parse_report

        # 使用前面已获取的 manual_scanner
        if manual_scanner and manual_scanner != 'auto':
            scanner_type = manual_scanner
        else:
            scanner_type = detect_scanner(save_path, file.filename)

        if scanner_type == 'unknown':
            os.remove(save_path)
            return jsonify({
                'success': False,
                'message': 'Unable to detect scanner type. Please ensure the file is from a supported scanner.',
                'scanner_type': 'unknown',
            }), 400

        parsed_data = parse_report(save_path, scanner_type)

        current_app.logger.info(f"[Import] 文件解析成功: filename={file.filename}, scanner={scanner_type}, vulns={len(parsed_data)}")

        # 转换为统一的漏洞格式
        vulns = []
        for item in parsed_data:
            vuln = {
                'id': str(uuid.uuid4()),
                'vuln_id': item.get('cve', item.get('cve_id', '')),
                'name': item.get('title', item.get('name', '')),
                'severity': item.get('severity', 'info'),
                'target': item.get('host', item.get('url', item.get('target', ''))),
                'port': str(item.get('port', '')),
                'protocol': item.get('protocol', ''),
                'description': item.get('description', ''),
                'impact': item.get('impact', ''),
                'solution': item.get('solution', item.get('remediation', '')),
                'poc_steps': item.get('poc_steps', ''),
                'evidence': item.get('evidence', ''),
                'scanner_source': scanner_type,
                'custom_tags': [],
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            vulns.append(vuln)

        # 暂存解析结果（带时间戳）
        with _parsed_results_lock:
            _parsed_results[file_id] = {
                'vulns': vulns,
                'scanner_type': scanner_type,
                'filename': file.filename,
                'total': len(vulns),
                'timestamp': time.time(),
            }

        # 清理临时上传文件
        try:
            os.remove(save_path)
        except OSError:
            pass

        # 统计各等级数量
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vulns:
            sev = v.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return jsonify({
            'success': True,
            'file_id': file_id,
            'scanner_type': scanner_type,
            'filename': file.filename,
            'total': len(vulns),
            'severity_counts': severity_counts,
            'vulnerabilities': vulns,
        })

    except Exception as e:
        current_app.logger.error(f'[Import] 文件解析失败: filename={file.filename}, scanner={scanner_type}, error={e}', exc_info=True)
        if os.path.exists(save_path):
            os.remove(save_path)
        return jsonify({
            'success': False,
            'message': 'Failed to parse file',
        }), 500


@import_bp.route('/api/import/confirm', methods=['POST'])
def confirm_import():
    """确认导入解析结果，将漏洞添加到数据库。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    file_id = data.get('file_id', '')

    with _parsed_results_lock:
        if file_id not in _parsed_results:
            return jsonify({'success': False, 'message': 'Parsed results not found or expired'}), 400
        parsed = _parsed_results.pop(file_id)
    
    vulns = parsed['vulns']

    # 添加到数据库
    for vuln in vulns:
        db.add_vuln(vuln)

    # 记录导入历史
    db.add_import_history(
        filename=parsed['filename'],
        scanner_type=parsed['scanner_type'],
        total=parsed['total'],
    )

    current_app.logger.info(f"[Import] 确认导入成功: filename={parsed['filename']}, scanner={parsed['scanner_type']}, vulns={len(vulns)}")

    return jsonify({
        'success': True,
        'message': f'Successfully imported {len(vulns)} vulnerabilities',
        'imported_count': len(vulns),
    })


@import_bp.route('/api/import/upload-batch', methods=['POST'])
def upload_batch():
    """批量上传扫描器报告文件。"""
    if 'files' not in request.files:
        return jsonify({'success': False, 'message': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    if not files:
        return jsonify({'success': False, 'message': 'No files selected'}), 400

    # 清理过期结果
    _cleanup_expired_results()

    results = []
    total_imported = 0

    for file in files:
        if not file.filename:
            continue

        filename = file.filename
        _, ext = os.path.splitext(filename.lower())

        # 服务端文件类型验证
        if ext not in ALLOWED_UPLOAD_EXTENSIONS:
            results.append({
                'filename': filename,
                'success': False,
                'message': f'Unsupported file extension: {ext}',
            })
            continue

        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_id = str(uuid.uuid4())
        save_path = os.path.join(upload_folder, f'{file_id}{ext}')

        try:
            file.save(save_path)
        except Exception as e:
            results.append({
                'filename': filename,
                'success': False,
                'message': f'Failed to save file: {str(e)}',
            })
            continue

        try:
            from app.parsers import detect_scanner, parse_report
            scanner_type = detect_scanner(save_path, file.filename)

            if scanner_type == 'unknown':
                os.remove(save_path)
                results.append({
                    'filename': filename,
                    'success': False,
                    'message': 'Unable to detect scanner type',
                })
                continue

            parsed_data = parse_report(save_path, scanner_type)

            current_app.logger.info(f"[Import] 批量上传解析成功: filename={file.filename}, scanner={scanner_type}, vulns={len(parsed_data)}")

            vulns = []
            for item in parsed_data:
                vuln = {
                    'id': str(uuid.uuid4()),
                    'vuln_id': item.get('cve', item.get('cve_id', '')),
                    'name': item.get('title', item.get('name', '')),
                    'severity': item.get('severity', 'info'),
                    'target': item.get('host', item.get('url', item.get('target', ''))),
                    'port': str(item.get('port', '')),
                    'protocol': item.get('protocol', ''),
                    'description': item.get('description', ''),
                    'impact': item.get('impact', ''),
                    'solution': item.get('solution', item.get('remediation', '')),
                    'poc_steps': item.get('poc_steps', ''),
                    'evidence': item.get('evidence', ''),
                    'scanner_source': scanner_type,
                    'custom_tags': [],
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }
                vulns.append(vuln)

            # 暂存解析结果
            with _parsed_results_lock:
                _parsed_results[file_id] = {
                    'vulns': vulns,
                    'scanner_type': scanner_type,
                    'filename': file.filename,
                    'total': len(vulns),
                    'timestamp': time.time(),
                }

            # 清理临时上传文件
            try:
                os.remove(save_path)
            except OSError:
                pass

            results.append({
                'filename': filename,
                'success': True,
                'file_id': file_id,
                'scanner_type': scanner_type,
                'total': len(vulns),
            })
            total_imported += len(vulns)

        except Exception as e:
            current_app.logger.error(f'[Import] 批量上传解析失败: filename={filename}, error={e}', exc_info=True)
            if os.path.exists(save_path):
                os.remove(save_path)
            results.append({
                'filename': filename,
                'success': False,
                'message': 'Import failed',
            })

    return jsonify({
        'success': True,
        'total_files': len(files),
        'total_imported': total_imported,
        'results': results,
    })
