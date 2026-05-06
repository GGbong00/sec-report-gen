"""
SQLite 数据库访问层。

使用 sqlite3 标准库提供持久化存储，替代内存中的全局变量。
"""

import os
import json
import sqlite3
import uuid
import hashlib
import hmac as hmac_module
from datetime import datetime
from contextlib import contextmanager
from threading import Lock

# 从 config.py 统一获取 DATA_DIR（支持环境变量和 .data_dir 配置文件）
from config import DATA_DIR
DB_PATH = os.path.join(DATA_DIR, 'sec_report.db')

_db_lock = Lock()


# ============================================================
# Webhook Secret 加密工具
# ============================================================


def _encrypt_webhook_secret(secret: str) -> str:
    """对 webhook secret 进行 HMAC 签名存储（不可逆）。"""
    if not secret:
        return ''
    return hmac_module.new(
        b'webhook-secret-pepper',
        secret.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def _verify_webhook_secret(secret: str, stored_hash: str) -> bool:
    """验证 webhook secret。"""
    if not secret or not stored_hash:
        return False
    return hmac_module.compare_digest(
        _encrypt_webhook_secret(secret),
        stored_hash
    )


class Database:
    """SQLite 数据库封装类，提供所有数据持久化操作。"""

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    @contextmanager
    def get_connection(self):
        """获取数据库连接的上下文管理器。

        自动处理提交和回滚，返回带有 row_factory 的连接。
        """
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self):
        """创建所有数据表。"""
        with self.get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    vuln_id TEXT DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    severity TEXT DEFAULT 'info',
                    target TEXT DEFAULT '',
                    port TEXT DEFAULT '',
                    protocol TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    impact TEXT DEFAULT '',
                    solution TEXT DEFAULT '',
                    poc_steps TEXT DEFAULT '',
                    evidence TEXT DEFAULT '',
                    scanner_source TEXT DEFAULT '',
                    custom_tags TEXT DEFAULT '[]',
                    cvss_vector TEXT DEFAULT '',
                    cvss_score REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'discovered',
                    assigned_to TEXT DEFAULT '',
                    fix_due_date TEXT DEFAULT '',
                    fix_notes TEXT DEFAULT '',
                    verified_by TEXT DEFAULT '',
                    verified_at TEXT DEFAULT '',
                    created_at TEXT DEFAULT '',
                    updated_at TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS project_info (
                    key TEXT PRIMARY KEY,
                    value TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS import_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT DEFAULT '',
                    scanner_type TEXT DEFAULT '',
                    total INTEGER DEFAULT 0,
                    time TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS report_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    format TEXT DEFAULT '',
                    language TEXT DEFAULT '',
                    filename TEXT DEFAULT '',
                    time TEXT DEFAULT '',
                    vuln_count INTEGER DEFAULT 0,
                    template TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS custom_translations (
                    key_en TEXT PRIMARY KEY,
                    name_zh TEXT DEFAULT '',
                    description_zh TEXT DEFAULT '',
                    solution_zh TEXT DEFAULT '',
                    created_at TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    key_hash TEXT NOT NULL DEFAULT '',
                    created_at TEXT DEFAULT '',
                    last_used TEXT DEFAULT '',
                    is_active INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL DEFAULT '',
                    events TEXT DEFAULT '[]',
                    secret TEXT DEFAULT '',
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
                CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities(target);
                CREATE INDEX IF NOT EXISTS idx_vulns_scanner ON vulnerabilities(scanner_source);
                CREATE INDEX IF NOT EXISTS idx_vulns_cvss ON vulnerabilities(cvss_score);
            ''')

    # ============================================================
    # Vulnerability CRUD
    # ============================================================

    def add_vuln(self, vuln):
        """添加单个漏洞到数据库。

        Args:
            vuln: 漏洞字典，必须包含 name 字段。

        Returns:
            添加后的漏洞字典（含 id 和时间戳）。
        """
        if not vuln.get('id'):
            vuln['id'] = str(uuid.uuid4())
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if not vuln.get('created_at'):
            vuln['created_at'] = now
        vuln['updated_at'] = now

        custom_tags = vuln.get('custom_tags', [])
        if isinstance(custom_tags, (list, dict)):
            custom_tags = json.dumps(custom_tags, ensure_ascii=False)

        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO vulnerabilities
                    (id, vuln_id, name, severity, target, port, protocol,
                     description, impact, solution, poc_steps, evidence,
                     scanner_source, custom_tags, cvss_vector, cvss_score,
                     status, assigned_to, fix_due_date, fix_notes,
                     verified_by, verified_at, created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.get('id', ''),
                vuln.get('vuln_id', ''),
                vuln.get('name', ''),
                vuln.get('severity', 'info'),
                vuln.get('target', ''),
                str(vuln.get('port', '')),
                vuln.get('protocol', ''),
                vuln.get('description', ''),
                vuln.get('impact', ''),
                vuln.get('solution', ''),
                vuln.get('poc_steps', ''),
                vuln.get('evidence', ''),
                vuln.get('scanner_source', ''),
                custom_tags,
                vuln.get('cvss_vector', ''),
                float(vuln.get('cvss_score', 0.0) or 0.0),
                vuln.get('status', 'discovered'),
                vuln.get('assigned_to', ''),
                vuln.get('fix_due_date', ''),
                vuln.get('fix_notes', ''),
                vuln.get('verified_by', ''),
                vuln.get('verified_at', ''),
                vuln.get('created_at', ''),
                vuln.get('updated_at', ''),
            ))
        return vuln

    def get_vuln(self, vuln_id):
        """根据 ID 获取单个漏洞。

        Args:
            vuln_id: 漏洞的唯一标识。

        Returns:
            漏洞字典，未找到返回 None。
        """
        with self.get_connection() as conn:
            row = conn.execute(
                'SELECT * FROM vulnerabilities WHERE id = ?', (vuln_id,)
            ).fetchone()
            if row:
                return self._row_to_vuln(row)
        return None

    def get_all_vulns(self):
        """获取所有漏洞列表。

        Returns:
            漏洞字典列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM vulnerabilities ORDER BY created_at DESC'
            ).fetchall()
            return [self._row_to_vuln(row) for row in rows]

    def get_vulns_by_sources(self, sources_list=None):
        """按 scanner_source 筛选漏洞。

        Args:
            sources_list: 扫描器来源列表。为空或包含 'all' 时返回所有漏洞。

        Returns:
            漏洞字典列表。
        """
        if not sources_list or 'all' in [s.lower() for s in sources_list]:
            return self.get_all_vulns()

        with self.get_connection() as conn:
            placeholders = ','.join('?' * len(sources_list))
            rows = conn.execute(
                f'SELECT * FROM vulnerabilities WHERE scanner_source IN ({placeholders}) ORDER BY created_at DESC',
                sources_list
            ).fetchall()
            return [self._row_to_vuln(row) for row in rows]

    def get_distinct_scanner_sources(self):
        """获取数据库中所有不重复的 scanner_source 值。

        Returns:
            scanner_source 字符串列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT scanner_source FROM vulnerabilities WHERE scanner_source IS NOT NULL AND scanner_source != '' ORDER BY scanner_source"
            ).fetchall()
            return [row['scanner_source'] for row in rows]

    def update_vuln(self, vuln_id, data):
        """更新漏洞信息。

        Args:
            vuln_id: 漏洞 ID。
            data: 包含更新字段的字典。

        Returns:
            更新后的漏洞字典，未找到返回 None。
        """
        existing = self.get_vuln(vuln_id)
        if not existing:
            return None

        existing.update(data)
        existing['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        custom_tags = existing.get('custom_tags', [])
        if isinstance(custom_tags, (list, dict)):
            custom_tags = json.dumps(custom_tags, ensure_ascii=False)

        with self.get_connection() as conn:
            conn.execute('''
                UPDATE vulnerabilities SET
                    vuln_id = ?, name = ?, severity = ?, target = ?, port = ?,
                    protocol = ?, description = ?, impact = ?, solution = ?,
                    poc_steps = ?, evidence = ?, scanner_source = ?,
                    custom_tags = ?, cvss_vector = ?, cvss_score = ?,
                    status = ?, assigned_to = ?, fix_due_date = ?,
                    fix_notes = ?, verified_by = ?, verified_at = ?,
                    updated_at = ?
                WHERE id = ?
            ''', (
                existing.get('vuln_id', ''),
                existing.get('name', ''),
                existing.get('severity', 'info'),
                existing.get('target', ''),
                str(existing.get('port', '')),
                existing.get('protocol', ''),
                existing.get('description', ''),
                existing.get('impact', ''),
                existing.get('solution', ''),
                existing.get('poc_steps', ''),
                existing.get('evidence', ''),
                existing.get('scanner_source', ''),
                custom_tags,
                existing.get('cvss_vector', ''),
                float(existing.get('cvss_score', 0.0) or 0.0),
                existing.get('status', 'discovered'),
                existing.get('assigned_to', ''),
                existing.get('fix_due_date', ''),
                existing.get('fix_notes', ''),
                existing.get('verified_by', ''),
                existing.get('verified_at', ''),
                existing.get('updated_at', ''),
                vuln_id,
            ))
        return existing

    def delete_vuln(self, vuln_id):
        """删除单个漏洞。

        Args:
            vuln_id: 漏洞 ID。

        Returns:
            是否删除成功。
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                'DELETE FROM vulnerabilities WHERE id = ?', (vuln_id,)
            )
            return cursor.rowcount > 0

    def clear_vulns(self):
        """清空所有漏洞。

        Returns:
            被删除的漏洞数量。
        """
        with self.get_connection() as conn:
            cursor = conn.execute('DELETE FROM vulnerabilities')
            return cursor.rowcount

    def get_vuln_count(self):
        """获取漏洞总数。

        Returns:
            漏洞数量整数。
        """
        with self.get_connection() as conn:
            row = conn.execute('SELECT COUNT(*) as cnt FROM vulnerabilities').fetchone()
            return row['cnt'] if row else 0

    def _row_to_vuln(self, row):
        """将数据库行转换为漏洞字典，处理 JSON 字段。"""
        vuln = dict(row)
        try:
            vuln['custom_tags'] = json.loads(vuln.get('custom_tags', '[]'))
        except (json.JSONDecodeError, TypeError):
            vuln['custom_tags'] = []
        return vuln

    # ============================================================
    # Project Info
    # ============================================================

    def get_project_info(self):
        """获取所有项目信息。

        Returns:
            项目信息字典。
        """
        with self.get_connection() as conn:
            rows = conn.execute('SELECT key, value FROM project_info').fetchall()
            return {row['key']: row['value'] for row in rows}

    def save_project_info(self, data):
        """保存项目信息。

        Args:
            data: 项目信息字典，键值对。
        """
        with self.get_connection() as conn:
            for key, value in data.items():
                conn.execute('''
                    INSERT INTO project_info (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ''', (key, str(value) if value is not None else ''))

    # ============================================================
    # Import History
    # ============================================================

    def add_import_history(self, filename, scanner_type, total):
        """添加导入历史记录。

        Args:
            filename: 文件名。
            scanner_type: 扫描器类型。
            total: 漏洞数量。
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO import_history (filename, scanner_type, total, time)
                VALUES (?, ?, ?, ?)
            ''', (filename, scanner_type, total, now))

    def get_import_history(self, limit=50):
        """获取导入历史记录。

        Args:
            limit: 返回记录数量上限。

        Returns:
            导入历史记录列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM import_history ORDER BY id DESC LIMIT ?', (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    # ============================================================
    # Report History
    # ============================================================

    def add_report_history(self, format_name, language, filename, vuln_count, template=''):
        """添加报告生成历史记录。

        Args:
            format_name: 报告格式。
            language: 报告语言。
            filename: 文件名。
            vuln_count: 漏洞数量。
            template: 使用的模板名称。
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO report_history (format, language, filename, time, vuln_count, template)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (format_name, language, filename, now, vuln_count, template))

    def get_report_history(self, limit=50):
        """获取报告生成历史记录。

        Args:
            limit: 返回记录数量上限。

        Returns:
            报告历史记录列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM report_history ORDER BY id DESC LIMIT ?', (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    # ============================================================
    # Custom Translations
    # ============================================================

    def add_custom_translation(self, key_en, name_zh='', description_zh='', solution_zh=''):
        """添加自定义翻译条目。

        Args:
            key_en: 英文键名。
            name_zh: 中文名称翻译。
            description_zh: 中文描述翻译。
            solution_zh: 中文修复建议翻译。
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO custom_translations (key_en, name_zh, description_zh, solution_zh, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key_en) DO UPDATE SET
                    name_zh = excluded.name_zh,
                    description_zh = excluded.description_zh,
                    solution_zh = excluded.solution_zh
            ''', (key_en, name_zh, description_zh, solution_zh, now))

    def get_all_custom_translations(self):
        """获取所有自定义翻译条目。

        Returns:
            翻译条目字典列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute('SELECT * FROM custom_translations').fetchall()
            return [dict(row) for row in rows]

    def delete_custom_translation(self, key_en):
        """删除自定义翻译条目。

        Args:
            key_en: 英文键名。

        Returns:
            是否删除成功。
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                'DELETE FROM custom_translations WHERE key_en = ?', (key_en,)
            )
            return cursor.rowcount > 0

    def search_custom_translations(self, keyword):
        """搜索自定义翻译条目。

        Args:
            keyword: 搜索关键词。

        Returns:
            匹配的翻译条目列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT * FROM custom_translations
                WHERE key_en LIKE ? OR name_zh LIKE ? OR description_zh LIKE ?
            ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%')).fetchall()
            return [dict(row) for row in rows]

    # ============================================================
    # API Keys
    # ============================================================

    def create_api_key(self, name, raw_key=None):
        """创建新的 API 密钥。

        Args:
            name: 密钥名称。
            raw_key: 可选的原始密钥字符串。如不提供则自动生成。

        Returns:
            (key_id, raw_key) 元组。
        """
        key_id = str(uuid.uuid4())
        if raw_key is None:
            raw_key = uuid.uuid4().hex + uuid.uuid4().hex
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO api_keys (id, name, key_hash, created_at, is_active)
                VALUES (?, ?, ?, ?, 1)
            ''', (key_id, name, key_hash, now))

        return key_id, raw_key

    def verify_api_key(self, raw_key):
        """验证 API 密钥。

        Args:
            raw_key: 待验证的原始密钥字符串。

        Returns:
            验证通过返回 API 密钥信息字典，否则返回 None。
        """
        if not raw_key:
            return None
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_connection() as conn:
            row = conn.execute('''
                SELECT * FROM api_keys
                WHERE key_hash = ? AND is_active = 1
            ''', (key_hash,)).fetchone()
            if row:
                info = dict(row)
                del info['key_hash']
                return info
        return None

    def list_api_keys(self):
        """列出所有 API 密钥（不含原始密钥）。

        Returns:
            API 密钥信息字典列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT id, name, created_at, last_used, is_active FROM api_keys ORDER BY created_at DESC'
            ).fetchall()
            return [dict(row) for row in rows]

    def revoke_api_key(self, key_id):
        """吊销 API 密钥。

        Args:
            key_id: 密钥 ID。

        Returns:
            是否吊销成功。
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                'UPDATE api_keys SET is_active = 0 WHERE id = ?', (key_id,)
            )
            return cursor.rowcount > 0

    # ============================================================
    # Webhooks
    # ============================================================

    def create_webhook(self, url, events=None, secret=''):
        """创建新的 Webhook。

        Args:
            url: Webhook URL。
            events: 事件列表。
            secret: 签名密钥。

        Returns:
            Webhook ID。
        """
        webhook_id = str(uuid.uuid4())
        events_json = json.dumps(events or [], ensure_ascii=False)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 加密 secret 后存储
        encrypted_secret = _encrypt_webhook_secret(secret) if secret else ''

        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO webhooks (id, url, events, secret, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
            ''', (webhook_id, url, events_json, encrypted_secret, now))

        return webhook_id

    def list_webhooks(self):
        """列出所有 Webhook。

        Returns:
            Webhook 信息字典列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM webhooks ORDER BY created_at DESC'
            ).fetchall()
            result = []
            for row in rows:
                wh = dict(row)
                # 不返回 secret，只返回是否存在
                wh['has_secret'] = bool(wh.get('secret'))
                del wh['secret']
                try:
                    wh['events'] = json.loads(wh.get('events', '[]'))
                except (json.JSONDecodeError, TypeError):
                    wh['events'] = []
                result.append(wh)
            return result

    def delete_webhook(self, webhook_id):
        """删除 Webhook。

        Args:
            webhook_id: Webhook ID。

        Returns:
            是否删除成功。
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                'DELETE FROM webhooks WHERE id = ?', (webhook_id,)
            )
            return cursor.rowcount > 0

    def get_active_webhooks(self):
        """获取所有活跃的 Webhook。

        Returns:
            活跃的 Webhook 列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                'SELECT * FROM webhooks WHERE is_active = 1'
            ).fetchall()
            result = []
            for row in rows:
                wh = dict(row)
                # HMAC 不可逆，只返回是否存在 secret
                wh['has_secret'] = bool(wh.get('secret'))
                wh['secret'] = ''
                try:
                    wh['events'] = json.loads(wh.get('events', '[]'))
                except (json.JSONDecodeError, TypeError):
                    wh['events'] = []
                result.append(wh)
            return result

    # ============================================================
    # Settings
    # ============================================================

    def get_setting(self, key, default=None):
        """获取设置值。

        Args:
            key: 设置键名。
            default: 默认值。

        Returns:
            设置值字符串，未找到返回 default。
        """
        with self.get_connection() as conn:
            row = conn.execute(
                'SELECT value FROM settings WHERE key = ?', (key,)
            ).fetchone()
            if row:
                return row['value']
        return default

    def set_setting(self, key, value):
        """保存设置值。

        Args:
            key: 设置键名。
            value: 设置值。
        """
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            ''', (key, str(value) if value is not None else ''))

    # ============================================================
    # Translation API Config
    # ============================================================

    def save_translation_api_config(self, config: dict):
        """保存翻译 API 配置。

        Args:
            config: 翻译 API 配置字典，包含 id, name, type, api_url, api_key 等字段。
        """
        config_json = json.dumps(config, ensure_ascii=False)
        self.set_setting(f'translation_api_{config.get("id", "")}', config_json)

    def get_translation_api_config(self, api_id: str) -> dict:
        """获取指定翻译 API 配置。

        Args:
            api_id: API 配置 ID。

        Returns:
            配置字典，未找到返回 None。
        """
        value = self.get_setting(f'translation_api_{api_id}')
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return None

    def delete_translation_api_config(self, api_id: str) -> bool:
        """删除翻译 API 配置。

        Args:
            api_id: API 配置 ID。

        Returns:
            是否删除成功。
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                'DELETE FROM settings WHERE key = ?', (f'translation_api_{api_id}',)
            )
            return cursor.rowcount > 0

    def list_translation_api_configs(self) -> list:
        """列出所有翻译 API 配置。

        Returns:
            配置字典列表。
        """
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'translation_api_%'"
            ).fetchall()
            configs = []
            for row in rows:
                try:
                    config = json.loads(row['value'])
                    configs.append(config)
                except json.JSONDecodeError:
                    continue
            return configs

    def get_active_translation_config(self) -> dict:
        """获取当前激活的翻译 API 配置。

        Returns:
            激活的配置字典，未设置返回 None。
        """
        active_id = self.get_setting('translation_active_api')
        if not active_id:
            return None
        config = self.get_translation_api_config(active_id)
        return config

    def set_active_translation_api(self, api_id: str):
        """设置激活的翻译 API。

        Args:
            api_id: 要激活的 API 配置 ID。
        """
        self.set_setting('translation_active_api', api_id)

    def get_translation_mode(self) -> str:
        """获取当前翻译模式。

        Returns:
            'offline' 或 'online'。
        """
        return self.get_setting('translation_mode', 'offline')

    def set_translation_mode(self, mode: str):
        """设置翻译模式。

        Args:
            mode: 'offline' 或 'online'。
        """
        self.set_setting('translation_mode', mode)
