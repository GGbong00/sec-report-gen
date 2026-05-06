"""
漏洞管理蓝图 (vuln_bp)

提供漏洞的增删改查 API、漏洞列表页面、翻译功能（离线+在线）和自定义翻译字典管理。
"""

import os
import uuid
import re
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, session, send_file, current_app

vuln_bp = Blueprint('vuln', __name__)

# 翻译器单例
_translator = None
_online_translator = None


def _get_translator():
    """获取或创建离线翻译器单例。"""
    global _translator
    if _translator is None:
        from app.translations import OfflineTranslator
        _translator = OfflineTranslator()
    return _translator


def _get_online_translator():
    """获取或创建在线翻译器实例（根据当前配置）。"""
    global _online_translator
    db = current_app.db
    config = db.get_active_translation_config()
    if not config or not config.get('enabled'):
        return None
    # 如果配置变了，重建翻译器
    config_id = config.get('id', '')
    if _online_translator is None or getattr(_online_translator, '_config_id', '') != config_id:
        from app.translations.online import OnlineTranslator
        _online_translator = OnlineTranslator(config)
        _online_translator._config_id = config_id
    return _online_translator


def get_all_vulnerabilities():
    """获取所有漏洞数据。"""
    return current_app.db.get_all_vulns()


def add_vulnerabilities(vulns):
    """批量添加漏洞。"""
    db = current_app.db
    for vuln in vulns:
        db.add_vuln(vuln)


@vuln_bp.route('/vulnerabilities')
def vuln_list_page():
    """漏洞列表页面。"""
    lang = session.get('lang', 'zh')
    return render_template('vulnerabilities.html', lang=lang)


@vuln_bp.route('/api/vulnerabilities', methods=['GET'])
def api_get_vulnerabilities():
    """获取所有漏洞数据 JSON，支持分页。"""
    db = current_app.db
    all_vulns = db.get_all_vulns()

    # 分页参数
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 0, type=int)

    if page < 1:
        page = 1
    if page_size < 1:
        # 不分页，返回全部
        return jsonify({
            'success': True,
            'total': len(all_vulns),
            'page': 1,
            'page_size': len(all_vulns),
            'total_pages': 1,
            'vulnerabilities': all_vulns,
        })

    if page_size > 500:
        page_size = 500

    total = len(all_vulns)
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    page_vulns = all_vulns[start:end]

    return jsonify({
        'success': True,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'vulnerabilities': page_vulns,
    })


@vuln_bp.route('/api/vulnerabilities/scanner-sources', methods=['GET'])
def api_get_scanner_sources():
    """获取数据库中所有不重复的 scanner_source 值。"""
    db = current_app.db
    sources = db.get_distinct_scanner_sources()
    return jsonify({
        'success': True,
        'sources': sources,
    })


@vuln_bp.route('/api/vulnerabilities', methods=['POST'])
def api_add_vulnerability():
    """手动添加漏洞。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}

    vuln = {
        'id': data.get('id', ''),
        'vuln_id': data.get('vuln_id', ''),
        'name': data.get('name', ''),
        'severity': data.get('severity', 'info'),
        'target': data.get('target', ''),
        'port': str(data.get('port', '')),
        'protocol': data.get('protocol', ''),
        'description': data.get('description', ''),
        'impact': data.get('impact', ''),
        'solution': data.get('solution', ''),
        'poc_steps': data.get('poc_steps', ''),
        'evidence': data.get('evidence', ''),
        'scanner_source': data.get('scanner_source', 'manual'),
        'custom_tags': data.get('custom_tags', []),
        'cvss_vector': data.get('cvss_vector', ''),
        'cvss_score': data.get('cvss_score', 0.0),
        'status': data.get('status', 'discovered'),
        'created_at': data.get('created_at', ''),
    }

    if not vuln['name']:
        return jsonify({'success': False, 'message': 'Vulnerability name is required'}), 400

    # 验证 severity
    VALID_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
    if vuln.get('severity', '').lower() not in VALID_SEVERITIES:
        return jsonify({'success': False, 'message': f'Invalid severity. Must be one of: {", ".join(VALID_SEVERITIES)}'}), 400
    vuln['severity'] = vuln['severity'].lower()

    # 验证 status
    VALID_STATUSES = ('discovered', 'confirmed', 'fixing', 'fixed', 'verified', 'closed')
    if vuln.get('status') and vuln['status'].lower() not in VALID_STATUSES:
        return jsonify({'success': False, 'message': f'Invalid status. Must be one of: {", ".join(VALID_STATUSES)}'}), 400

    # Auto-calculate CVSS score from vector if not provided
    if vuln.get('cvss_vector') and not vuln.get('cvss_score'):
        try:
            from app.utils.cvss import CVSSCalculator
            calc = CVSSCalculator()
            metrics = calc.parse_vector(vuln['cvss_vector'])
            if metrics:
                vuln['cvss_score'] = calc.calculate_base_score(metrics)
        except Exception:
            pass

    if not vuln['id']:
        vuln['id'] = str(uuid.uuid4())
        vuln['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    result = db.add_vuln(vuln)

    return jsonify({
        'success': True,
        'message': 'Vulnerability added successfully',
        'vulnerability': result,
    }), 201


@vuln_bp.route('/api/vulnerabilities/<vuln_id>', methods=['GET'])
def api_get_vulnerability(vuln_id):
    """获取单个漏洞详情。"""
    db = current_app.db
    vuln = db.get_vuln(vuln_id)
    if not vuln:
        return jsonify({'success': False, 'message': 'Vulnerability not found'}), 404
    return jsonify({'success': True, 'vulnerability': vuln})


@vuln_bp.route('/api/vulnerabilities/<vuln_id>', methods=['PUT'])
def api_update_vulnerability(vuln_id):
    """更新漏洞信息。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}

    updatable_keys = [
        'vuln_id', 'name', 'severity', 'target', 'port', 'protocol',
        'description', 'impact', 'solution', 'poc_steps', 'evidence',
        'scanner_source', 'custom_tags', 'cvss_vector', 'cvss_score',
        'status', 'assigned_to', 'fix_due_date', 'fix_notes',
        'verified_by', 'verified_at',
    ]

    update_data = {k: data[k] for k in updatable_keys if k in data}

    if 'severity' in update_data and update_data['severity'].lower() not in ('critical', 'high', 'medium', 'low', 'info'):
        return jsonify({'success': False, 'message': 'Invalid severity value'}), 400
    if update_data.get('severity'):
        update_data['severity'] = update_data['severity'].lower()

    # Auto-calculate CVSS score from vector if vector updated but score not
    if 'cvss_vector' in update_data and 'cvss_score' not in update_data:
        try:
            from app.utils.cvss import CVSSCalculator
            calc = CVSSCalculator()
            metrics = calc.parse_vector(update_data['cvss_vector'])
            if metrics:
                update_data['cvss_score'] = calc.calculate_base_score(metrics)
        except Exception:
            pass

    updated = db.update_vuln(vuln_id, update_data)

    if updated:
        current_app.logger.info(f"[Vuln] 漏洞编辑成功: vuln_id={vuln_id}, updated_fields={list(update_data.keys())}")
        return jsonify({
            'success': True,
            'message': 'Vulnerability updated successfully',
            'vulnerability': updated,
        })

    return jsonify({'success': False, 'message': 'Vulnerability not found'}), 404


@vuln_bp.route('/api/vulnerabilities/<vuln_id>', methods=['DELETE'])
def api_delete_vulnerability(vuln_id):
    """删除单个漏洞。"""
    db = current_app.db
    success = db.delete_vuln(vuln_id)

    if success:
        current_app.logger.info(f"[Vuln] 删除漏洞成功: vuln_id={vuln_id}")
        return jsonify({
            'success': True,
            'message': 'Vulnerability deleted successfully',
        })
    else:
        current_app.logger.warning(f"[Vuln] 删除漏洞失败，未找到: vuln_id={vuln_id}")
        return jsonify({'success': False, 'message': 'Vulnerability not found'}), 404


@vuln_bp.route('/api/vulnerabilities', methods=['DELETE'])
def api_clear_vulnerabilities():
    """清空所有漏洞。"""
    data = request.get_json(silent=True) or {}
    if data.get('confirm') != 'yes':
        return jsonify({'success': False, 'message': 'Confirmation required. Send {"confirm": "yes"} to clear all data.'}), 400
    db = current_app.db
    count = db.clear_vulns()
    current_app.logger.info(f"[Vuln] 批量清空漏洞: count={count}")
    return jsonify({
        'success': True,
        'message': f'Cleared {count} vulnerabilities',
        'deleted_count': count,
    })


@vuln_bp.route('/api/vulnerabilities/deduplicate', methods=['POST'])
def api_deduplicate_vulnerabilities():
    """漏洞去重：根据名称+目标+端口合并重复漏洞。"""
    db = current_app.db
    all_vulns = db.get_all_vulns()

    seen = {}
    duplicates = []
    unique = []

    for vuln in all_vulns:
        key = (
            vuln.get('name', '').strip().lower(),
            vuln.get('target', '').strip().lower(),
            str(vuln.get('port', '')).strip(),
        )
        if key in seen:
            duplicates.append(vuln['id'])
        else:
            seen[key] = vuln['id']
            unique.append(vuln)

    if not duplicates:
        return jsonify({
            'success': True,
            'message': 'No duplicates found',
            'duplicate_count': 0,
            'remaining_count': len(all_vulns),
        })

    # 删除重复项
    for dup_id in duplicates:
        db.delete_vuln(dup_id)

    current_app.logger.info(f"[Vuln] 批量去重操作: duplicate_count={len(duplicates)}, remaining_count={len(all_vulns) - len(duplicates)}")

    return jsonify({
        'success': True,
        'message': f'Merged {len(duplicates)} duplicate vulnerabilities',
        'duplicate_count': len(duplicates),
        'remaining_count': len(all_vulns) - len(duplicates),
    })


@vuln_bp.route('/api/vulnerabilities/<vuln_id>/status', methods=['PUT'])
def api_update_vulnerability_status(vuln_id):
    """更新漏洞状态。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}
    status = data.get('status', '').strip().lower()

    valid_statuses = ('discovered', 'confirmed', 'fixing', 'fixed', 'verified', 'closed')
    if status not in valid_statuses:
        return jsonify({
            'success': False,
            'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}',
        }), 400

    updated = db.update_vuln(vuln_id, {'status': status})

    if updated:
        return jsonify({
            'success': True,
            'message': 'Status updated successfully',
            'vulnerability': updated,
        })

    return jsonify({'success': False, 'message': 'Vulnerability not found'}), 404


@vuln_bp.route('/api/vulnerabilities/<vuln_id>/cvss', methods=['PUT'])
def api_update_vulnerability_cvss(vuln_id):
    """更新漏洞 CVSS 评分。支持传入 cvss_vector 自动计算评分，或直接传入 cvss_score。"""
    db = current_app.db
    data = request.get_json(silent=True) or {}

    cvss_score = data.get('cvss_score')
    cvss_vector = data.get('cvss_vector', '')

    # 如果提供了 CVSS 向量，自动计算评分
    if cvss_vector and cvss_score is None:
        try:
            from app.utils.cvss import CVSSCalculator
            calc = CVSSCalculator()
            metrics = calc.parse_vector(cvss_vector)
            if metrics is None:
                return jsonify({'success': False, 'message': 'Invalid CVSS vector format'}), 400
            cvss_score = calc.calculate_base_score(metrics)
        except Exception as e:
            return jsonify({'success': False, 'message': 'CVSS calculation error'}), 400

    if cvss_score is None:
        return jsonify({'success': False, 'message': 'cvss_score or cvss_vector is required'}), 400

    try:
        cvss_score = float(cvss_score)
        if not (0.0 <= cvss_score <= 10.0):
            return jsonify({'success': False, 'message': 'CVSS score must be between 0.0 and 10.0'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'cvss_score must be a number'}), 400

    update_data = {'cvss_score': cvss_score}
    if cvss_vector:
        update_data['cvss_vector'] = cvss_vector

    updated = db.update_vuln(vuln_id, update_data)

    if updated:
        return jsonify({
            'success': True,
            'message': 'CVSS score updated successfully',
            'vulnerability': updated,
        })

    return jsonify({'success': False, 'message': 'Vulnerability not found'}), 404


@vuln_bp.route('/api/vulnerabilities/translate', methods=['POST'])
def api_translate_all_vulnerabilities():
    """翻译所有漏洞（英文 -> 中文）。

    根据当前翻译模式设置，使用离线术语字典或在线翻译 API 进行翻译。
    支持通过请求参数 mode 强制指定翻译模式（offline/online/hybrid）。

    Returns:
        JSON 响应，包含翻译统计信息。
    """
    try:
        db = current_app.db
        all_vulns = db.get_all_vulns()

        if not all_vulns:
            return jsonify({
                'success': False,
                'message': 'No vulnerabilities to translate',
            }), 400

        # 确定翻译模式
        request_mode = (request.get_json(silent=True) or {}).get('mode', '')
        if request_mode in ('offline', 'online', 'hybrid'):
            mode = request_mode
        else:
            mode = db.get_translation_mode()  # 'offline' 或 'online'

        translated_count = 0
        online_translator = _get_online_translator() if mode in ('online', 'hybrid') else None

        if not online_translator and mode in ('online', 'hybrid'):
            return jsonify({
                'success': False,
                'message': '在线翻译未配置，请在设置中配置翻译 API',
            }), 400

        for vuln in all_vulns:
            original = dict(vuln)

            if mode == 'offline':
                translated = _get_translator().translate_vulnerability(vuln)
            elif mode == 'online':
                translated = _translate_vuln_online(vuln, online_translator)
            elif mode == 'hybrid':
                # 先离线翻译，再用在线翻译补充未翻译的部分
                translated = _get_translator().translate_vulnerability(vuln)
                translated = _translate_vuln_online_supplement(translated, original, online_translator)
            else:
                translated = _get_translator().translate_vulnerability(vuln)

            # 检查是否有字段发生了变化
            changed = False
            for field in ['name', 'description', 'impact', 'solution', 'poc_steps']:
                if original.get(field, '') != translated.get(field, ''):
                    changed = True
                    break

            if changed:
                translated_count += 1
                # 在线/混合模式下，将翻译结果保存到自定义字典
                if mode in ('online', 'hybrid'):
                    _save_to_custom_dictionary(original, translated)
                update_data = {}
                for field in ['name', 'description', 'impact', 'solution', 'poc_steps']:
                    if translated.get(field) != original.get(field):
                        update_data[field] = translated[field]
                if update_data:
                    db.update_vuln(vuln['id'], update_data)

        return jsonify({
            'success': True,
            'message': f'Translated {translated_count} vulnerabilities (mode: {mode})',
            'total': len(all_vulns),
            'translated_count': translated_count,
            'mode': mode,
        })
    except Exception as e:
        current_app.logger.error(f'[Vuln] 一键翻译失败: error={e}', exc_info=True)
        return jsonify({
            'success': False,
            'message': f'翻译失败: {str(e)}',
        }), 500


@vuln_bp.route('/api/vulnerabilities/<vuln_id>/translate', methods=['POST'])
def api_translate_single_vulnerability(vuln_id):
    """翻译单个漏洞（英文 -> 中文）。

    根据当前翻译模式设置，使用离线术语字典或在线翻译 API 进行翻译。

    Args:
        vuln_id: 漏洞的唯一标识 ID

    Returns:
        JSON 响应，包含翻译后的漏洞数据。
    """
    try:
        db = current_app.db

        vuln = db.get_vuln(vuln_id)
        if not vuln:
            return jsonify({
                'success': False,
                'message': 'Vulnerability not found',
            }), 404

        # 确定翻译模式
        request_mode = (request.get_json(silent=True) or {}).get('mode', '')
        if request_mode in ('offline', 'online', 'hybrid'):
            mode = request_mode
        else:
            mode = db.get_translation_mode()

        online_translator = _get_online_translator() if mode in ('online', 'hybrid') else None

        if not online_translator and mode in ('online', 'hybrid'):
            return jsonify({
                'success': False,
                'message': '在线翻译未配置，请在设置中配置翻译 API',
            }), 400

        original = dict(vuln)

        if mode == 'offline':
            translated = _get_translator().translate_vulnerability(vuln)
        elif mode == 'online':
            translated = _translate_vuln_online(vuln, online_translator)
        elif mode == 'hybrid':
            translated = _get_translator().translate_vulnerability(vuln)
            translated = _translate_vuln_online_supplement(translated, original, online_translator)
        else:
            translated = _get_translator().translate_vulnerability(vuln)

        update_data = {}
        for field in ['name', 'description', 'impact', 'solution', 'poc_steps']:
            if translated.get(field) != vuln.get(field):
                update_data[field] = translated[field]

        if update_data:
            db.update_vuln(vuln_id, update_data)
            # 在线/混合模式下，将翻译结果保存到自定义字典
            if mode in ('online', 'hybrid'):
                _save_to_custom_dictionary(original, translated)

        updated = db.get_vuln(vuln_id)

        return jsonify({
            'success': True,
            'message': 'Vulnerability translated successfully',
            'vulnerability': updated,
            'mode': mode,
        })
    except Exception as e:
        current_app.logger.error(f'[Vuln] 单个漏洞翻译失败: vuln_id={vuln_id}, error={e}', exc_info=True)
        return jsonify({
            'success': False,
            'message': f'翻译失败: {str(e)}',
        }), 500


# ============================================================
# 在线翻译辅助函数
# ============================================================

def _translate_vuln_online(vuln: dict, online_translator) -> dict:
    """使用在线翻译 API 翻译漏洞字典。"""
    translated = dict(vuln)
    for field in ['name', 'description', 'impact', 'solution', 'poc_steps']:
        text = vuln.get(field, '')
        if text and text.strip():
            try:
                translated[field] = online_translator.translate(text)
            except Exception:
                translated[field] = text  # 失败保留原文
    return translated


def _translate_vuln_online_supplement(translated: dict, original: dict, online_translator) -> dict:
    """混合模式：对离线翻译后仍含大量英文的字段，用在线翻译补充。

    判断逻辑：如果翻译后文本中英文单词占比仍超过 60%，则用在线翻译覆盖。
    """
    for field in ['name', 'description', 'impact', 'solution', 'poc_steps']:
        text = translated.get(field, '')
        if not text or not text.strip():
            continue
        # 检查英文占比
        english_chars = sum(1 for c in text if c.isascii() and c.isalpha())
        total_chars = sum(1 for c in text if c.isalpha())
        if total_chars > 0 and english_chars / total_chars > 0.6:
            # 英文占比高，尝试在线翻译原文
            original_text = original.get(field, '')
            if original_text and original_text.strip():
                try:
                    online_result = online_translator.translate(original_text)
                    if online_result and online_result != original_text:
                        translated[field] = online_result
                except Exception:
                    pass  # 在线翻译失败，保留离线结果
    return translated


def _save_to_custom_dictionary(original: dict, translated: dict):
    """将在线翻译结果保存到自定义字典，丰富离线翻译库。

    保存漏洞名称、描述、影响、修复建议的翻译对照。
    """
    original_name = (original.get('name') or '').strip()
    if not original_name:
        return

    translations = {}
    field_map = {
        'name': 'name_zh',
        'description': 'description_zh',
        'impact': 'impact_zh',
        'solution': 'solution_zh',
    }
    for src_field, dict_field in field_map.items():
        orig_val = (original.get(src_field) or '').strip()
        trans_val = (translated.get(src_field) or '').strip()
        if orig_val and trans_val and orig_val != trans_val:
            translations[dict_field] = trans_val

    if not translations:
        return

    try:
        translator = _get_translator()
        translator.custom_dictionary.add_entry(original_name, translations)
    except Exception:
        pass  # 保存失败不影响翻译流程


# ============================================================
# 翻译配置 API
# ============================================================

@vuln_bp.route('/api/translation/config', methods=['GET'])
def api_get_translation_config():
    """获取翻译配置（模式 + API 列表）。"""
    db = current_app.db
    mode = db.get_translation_mode()
    active_api_id = db.get_setting('translation_active_api', '')
    user_configs = db.list_translation_api_configs()

    # 合并内置默认 API 和用户自定义 API
    from app.translations.online import OnlineTranslator
    all_apis = []
    builtin_ids = {c.get('id') for c in user_configs}
    for default_api in OnlineTranslator.DEFAULT_APIS:
        if default_api['id'] not in builtin_ids:
            all_apis.append(default_api)
    all_apis.extend(user_configs)

    # 标记哪个是激活的
    for api in all_apis:
        api['is_active'] = api.get('id') == active_api_id

    return jsonify({
        'success': True,
        'mode': mode,
        'active_api_id': active_api_id,
        'apis': all_apis,
    })


@vuln_bp.route('/api/translation/mode', methods=['POST'])
def api_set_translation_mode():
    """设置翻译模式（offline/online/hybrid）。"""
    data = request.get_json(silent=True) or {}
    mode = data.get('mode', '')

    if mode not in ('offline', 'online', 'hybrid'):
        return jsonify({
            'success': False,
            'message': 'Invalid mode. Must be offline, online, or hybrid.',
        }), 400

    db = current_app.db
    db.set_translation_mode(mode)

    return jsonify({
        'success': True,
        'message': f'翻译模式已设置为: {mode}',
        'mode': mode,
    })


@vuln_bp.route('/api/translation/apis', methods=['POST'])
def api_save_translation_api():
    """保存（创建或更新）翻译 API 配置。"""
    data = request.get_json(silent=True) or {}
    api_id = data.get('id', '').strip()
    name = data.get('name', '').strip()
    api_type = data.get('type', '').strip()
    api_url = data.get('api_url', '').strip()
    api_key = data.get('api_key', '').strip()
    source_lang = data.get('source_lang', 'en').strip()
    target_lang = data.get('target_lang', 'zh').strip()
    enabled = data.get('enabled', False)
    custom_headers = data.get('custom_headers', {})
    custom_body_template = data.get('custom_body_template', '')
    response_path = data.get('response_path', 'translatedText')

    if not name:
        return jsonify({'success': False, 'message': 'API 名称不能为空'}), 400
    if not api_type:
        return jsonify({'success': False, 'message': 'API 类型不能为空'}), 400
    if not api_url and api_type != 'google':
        return jsonify({'success': False, 'message': 'API 地址不能为空'}), 400

    # 为内置 API 生成默认 ID
    if not api_id:
        api_id = f'custom-{uuid.uuid4().hex[:8]}'

    config = {
        'id': api_id,
        'name': name,
        'type': api_type,
        'api_url': api_url,
        'api_key': api_key,
        'source_lang': source_lang,
        'target_lang': target_lang,
        'enabled': enabled,
        'is_builtin': data.get('is_builtin', False),
        'custom_headers': custom_headers,
        'custom_body_template': custom_body_template,
        'response_path': response_path,
    }

    db = current_app.db
    db.save_translation_api_config(config)

    return jsonify({
        'success': True,
        'message': '翻译 API 配置已保存',
        'config': config,
    })


@vuln_bp.route('/api/translation/apis/<api_id>', methods=['DELETE'])
def api_delete_translation_api(api_id):
    """删除翻译 API 配置。"""
    db = current_app.db
    success = db.delete_translation_api_config(api_id)

    if success:
        # 如果删除的是当前激活的 API，清除激活状态
        active_id = db.get_setting('translation_active_api', '')
        if active_id == api_id:
            db.set_setting('translation_active_api', '')
        return jsonify({'success': True, 'message': '翻译 API 配置已删除'})
    else:
        return jsonify({'success': False, 'message': '配置未找到'}), 404


@vuln_bp.route('/api/translation/apis/activate', methods=['POST'])
def api_activate_translation_api():
    """激活指定的翻译 API。"""
    data = request.get_json(silent=True) or {}
    api_id = data.get('id', '').strip()

    if not api_id:
        return jsonify({'success': False, 'message': 'API ID 不能为空'}), 400

    db = current_app.db
    config = db.get_translation_api_config(api_id)

    # 如果数据库中没有，检查是否是内置 API
    if not config:
        from app.translations.online_translator import OnlineTranslator
        for builtin in OnlineTranslator.DEFAULT_APIS:
            if builtin.get('id') == api_id:
                config = dict(builtin)
                config['enabled'] = True
                db.save_translation_api_config(config)
                break

    if not config:
        return jsonify({'success': False, 'message': 'API 配置未找到'}), 404

    # 标记为启用
    config['enabled'] = True
    db.save_translation_api_config(config)
    db.set_active_translation_api(api_id)

    # 清除在线翻译器缓存，下次使用时重建
    global _online_translator
    _online_translator = None

    return jsonify({
        'success': True,
        'message': f'已激活翻译 API: {config.get("name", api_id)}',
    })


@vuln_bp.route('/api/translation/apis/test', methods=['POST'])
def api_test_translation_api():
    """测试翻译 API 连接。"""
    data = request.get_json(silent=True) or {}

    # 优先使用已有配置测试
    api_id = data.get('id', '').strip()
    if api_id:
        db = current_app.db
        config = db.get_translation_api_config(api_id)
        # 如果数据库中没有，检查是否是内置 API
        if not config:
            from app.translations.online_translator import OnlineTranslator
            for builtin in OnlineTranslator.DEFAULT_APIS:
                if builtin.get('id') == api_id:
                    config = dict(builtin)
                    break
        if not config:
            return jsonify({'success': False, 'message': 'API 配置未找到'}), 404
    else:
        # 使用提交的临时配置测试
        config = data

    from app.translations.online import OnlineTranslator, TranslationAPIError
    try:
        translator = OnlineTranslator(config)
        result = translator.test_connection()
        return jsonify(result)
    except TranslationAPIError as e:
        return jsonify({
            'success': False,
            'message': f'测试失败: {str(e)}',
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'测试异常: {str(e)}',
        })


# ============================================================
# 自定义翻译字典管理 API
# ============================================================

ALLOWED_TRANSLATION_EXTENSIONS = {'.csv', '.json'}


@vuln_bp.route('/api/translations/import', methods=['POST'])
def api_import_translations():
    """导入自定义翻译字典。

    支持上传 CSV 或 JSON 格式的翻译对照表文件。
    文件通过 multipart/form-data 上传，字段名为 'file'。

    Returns:
        JSON 响应，包含导入统计信息。
    """
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'No file uploaded. Please provide a file with field name "file".',
        }), 400

    uploaded_file = request.files['file']
    if not uploaded_file.filename:
        return jsonify({
            'success': False,
            'message': 'No file selected.',
        }), 400

    # 文件类型验证
    filename = uploaded_file.filename.lower()
    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_TRANSLATION_EXTENSIONS:
        return jsonify({
            'success': False,
            'message': f'Unsupported file format. Allowed formats: {", ".join(sorted(ALLOWED_TRANSLATION_EXTENSIONS))}',
        }), 400

    # 判断文件格式
    if ext == '.csv':
        fmt = 'csv'
    elif ext == '.json':
        fmt = 'json'
    else:
        return jsonify({
            'success': False,
            'message': 'Unsupported file format. Please upload a CSV or JSON file.',
        }), 400

    # 保存到临时文件
    temp_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'uploads', 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    temp_filename = f'translation_import_{uuid.uuid4().hex[:8]}{ext}'
    temp_path = os.path.join(temp_dir, temp_filename)

    try:
        uploaded_file.save(temp_path)

        # 通过翻译器加载自定义字典
        translator = _get_translator()
        stats = translator.load_custom_dictionary(temp_path, fmt)

        if stats.get('errors'):
            return jsonify({
                'success': True,
                'message': f'Import completed with {len(stats["errors"])} errors',
                'stats': stats,
            })
        else:
            return jsonify({
                'success': True,
                'message': f'Successfully imported {stats["loaded"]} translation entries',
                'stats': stats,
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Failed to import translations',
        }), 500

    finally:
        # 清理临时文件
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@vuln_bp.route('/api/translations', methods=['GET'])
def api_get_translations():
    """获取当前自定义字典内容。

    Query Parameters:
        search: 可选的搜索关键词，用于过滤条目。
        page: 页码（从 1 开始），默认为 1。
        page_size: 每页条目数，默认为 50。

    Returns:
        JSON 响应，包含自定义字典条目列表。
    """
    translator = _get_translator()
    all_entries = translator.custom_dictionary.get_all()

    # 搜索过滤
    search = request.args.get('search', '').strip()
    if search:
        results = translator.custom_dictionary.search(search)
        entries = {r['key_en']: r['translations'] for r in results}
    else:
        entries = all_entries

    # 分页
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 50, type=int)
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 50
    if page_size > 200:
        page_size = 200

    keys = list(entries.keys())
    total = len(keys)
    start = (page - 1) * page_size
    end = start + page_size
    page_keys = keys[start:end]

    page_entries = {k: entries[k] for k in page_keys}

    return jsonify({
        'success': True,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': (total + page_size - 1) // page_size if total > 0 else 0,
        'entries': page_entries,
    })


@vuln_bp.route('/api/translations/<path:key>', methods=['DELETE'])
def api_delete_translation(key):
    """删除自定义翻译条目。

    Args:
        key: 英文键名（URL 编码）。

    Returns:
        JSON 响应，指示是否删除成功。
    """
    translator = _get_translator()
    success = translator.custom_dictionary.remove_entry(key)

    if success:
        # 使用公开方法重新编译翻译正则
        translator.rebuild_custom_patterns()

        return jsonify({
            'success': True,
            'message': f'Translation entry "{key}" deleted successfully',
        })
    else:
        return jsonify({
            'success': False,
            'message': f'Translation entry "{key}" not found',
        }), 404


@vuln_bp.route('/api/translations/export', methods=['POST'])
def api_export_translations():
    """导出自定义字典。

    Request Body (JSON):
        format: 导出格式，'json' 或 'csv'，默认为 'json'。

    Returns:
        JSON 响应，包含导出文件的下载信息。
    """
    data = request.get_json(silent=True) or {}
    fmt = data.get('format', 'json').lower()

    if fmt not in ('json', 'csv'):
        return jsonify({
            'success': False,
            'message': 'Unsupported export format. Use "json" or "csv".',
        }), 400

    translator = _get_translator()
    all_entries = translator.custom_dictionary.get_all()

    if not all_entries:
        return jsonify({
            'success': False,
            'message': 'No custom translation entries to export',
        }), 400

    # 生成导出文件
    export_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'exports',
    )
    os.makedirs(export_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    ext = '.json' if fmt == 'json' else '.csv'
    filename = f'custom_translations_{timestamp}{ext}'
    file_path = os.path.join(export_dir, filename)

    stats = translator.export_custom_dictionary(file_path, fmt)

    if stats.get('errors'):
        return jsonify({
            'success': False,
            'message': 'Export failed',
            'errors': stats['errors'],
        }), 500

    # 返回下载链接
    download_url = f'/api/translations/download/{filename}'

    return jsonify({
        'success': True,
        'message': f'Exported {stats["total"]} entries to {fmt.upper()} format',
        'download_url': download_url,
        'filename': filename,
        'format': fmt,
        'total': stats['total'],
    })


@vuln_bp.route('/api/translations/download/<filename>', methods=['GET'])
def api_download_translation(filename):
    """下载导出的翻译字典文件。

    Args:
        filename: 导出文件名。

    Returns:
        文件下载响应。
    """
    export_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'exports',
    )
    file_path = os.path.join(export_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'message': 'File not found',
        }), 404

    # 安全检查：确保文件名不包含路径遍历
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        return jsonify({
            'success': False,
            'message': 'Invalid filename',
        }), 400

    if filename.endswith('.json'):
        mime_type = 'application/json'
    elif filename.endswith('.csv'):
        mime_type = 'text/csv; charset=utf-8'
    else:
        mime_type = 'application/octet-stream'

    return send_file(
        file_path,
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename,
    )


@vuln_bp.route('/api/translations/stats', methods=['GET'])
def api_get_translation_stats():
    """获取翻译统计信息。

    Returns:
        JSON 响应，包含自定义字典和内置字典的统计信息。
    """
    translator = _get_translator()
    custom_stats = translator.custom_dictionary.get_stats()

    return jsonify({
        'success': True,
        'custom_dictionary': custom_stats,
        'builtin_stats': {
            'vuln_types': len(translator._vuln_type_sorted),
            'security_terms': len(translator._security_term_sorted),
            'remediation_phrases': len(translator._remediation_sorted),
            'phrase_patterns': len(translator._phrase_patterns),
        },
    })
