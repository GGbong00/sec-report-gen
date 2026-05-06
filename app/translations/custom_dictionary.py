# -*- coding: utf-8 -*-
"""
自定义翻译字典管理模块。

提供自定义翻译字典的加载、保存、搜索、统计等功能，
支持 CSV 和 JSON 两种格式的导入导出。
"""

import csv
import json
import os
import re
from typing import Dict, List, Optional

# 默认自定义字典存储路径
DEFAULT_DICT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data',
    'custom_translations',
)

# 支持的翻译字段
TRANSLATION_FIELDS = ['name_zh', 'description_zh', 'impact_zh', 'solution_zh']


class CustomDictionary:
    """自定义翻译字典管理器。

    管理用户自定义的漏洞名称、描述、影响、修复建议的中文翻译对照表。
    支持从 CSV / JSON 文件导入导出，并提供搜索、统计等功能。
    """

    def __init__(self, dict_path: str = None):
        """初始化自定义翻译字典管理器。

        Args:
            dict_path: 自定义字典 JSON 文件的存储路径。
                       如果为 None，则使用默认路径 data/custom_translations/dict.json。
        """
        if dict_path is None:
            os.makedirs(DEFAULT_DICT_DIR, exist_ok=True)
            dict_path = os.path.join(DEFAULT_DICT_DIR, 'dict.json')

        self._dict_path = dict_path
        self._entries: Dict[str, dict] = {}
        self._load()

    # ================================================================
    # 内部方法
    # ================================================================

    def _load(self):
        """从磁盘加载已有自定义字典。"""
        if os.path.exists(self._dict_path):
            try:
                with open(self._dict_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self._entries = data
            except (json.JSONDecodeError, IOError) as e:
                self._entries = {}

    def _save_to_disk(self):
        """将当前字典保存到磁盘。"""
        dir_path = os.path.dirname(self._dict_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(self._dict_path, 'w', encoding='utf-8') as f:
            json.dump(self._entries, f, ensure_ascii=False, indent=2)

    # ================================================================
    # 导入方法
    # ================================================================

    def load_from_csv(self, file_path: str) -> dict:
        """从 CSV 文件加载翻译对照表。

        CSV 格式（首行为表头）：
            key_en,name_zh,description_zh,impact_zh,solution_zh

        Args:
            file_path: CSV 文件路径。

        Returns:
            包含加载统计信息的字典：
            {
                'total': 总行数,
                'loaded': 成功加载条目数,
                'skipped': 跳过条目数,
                'errors': 错误信息列表
            }
        """
        stats = {'total': 0, 'loaded': 0, 'skipped': 0, 'errors': []}

        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    stats['errors'].append('CSV file is empty or has no header')
                    return stats

                # 检查是否包含 key_en 列
                if 'key_en' not in reader.fieldnames:
                    stats['errors'].append('CSV file must contain "key_en" column')
                    return stats

                for row in reader:
                    stats['total'] += 1
                    key_en = (row.get('key_en') or '').strip()
                    if not key_en:
                        stats['skipped'] += 1
                        continue

                    translations = {}
                    for field in TRANSLATION_FIELDS:
                        value = (row.get(field) or '').strip()
                        if value:
                            translations[field] = value

                    if translations:
                        self._entries[key_en] = translations
                        stats['loaded'] += 1
                    else:
                        stats['skipped'] += 1

            self._save_to_disk()

        except Exception as e:
            stats['errors'].append(str(e))

        return stats

    def load_from_json(self, file_path: str) -> dict:
        """从 JSON 文件加载翻译对照表。

        JSON 格式：
            {
                "SQL Injection": {
                    "name_zh": "SQL注入",
                    "description_zh": "...",
                    "impact_zh": "...",
                    "solution_zh": "..."
                }
            }

        Args:
            file_path: JSON 文件路径。

        Returns:
            包含加载统计信息的字典。
        """
        stats = {'total': 0, 'loaded': 0, 'skipped': 0, 'errors': []}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, dict):
                stats['errors'].append('JSON root must be an object/dict')
                return stats

            for key_en, translations in data.items():
                stats['total'] += 1
                if not isinstance(translations, dict):
                    stats['skipped'] += 1
                    continue

                valid_translations = {}
                for field in TRANSLATION_FIELDS:
                    value = translations.get(field, '')
                    if value and isinstance(value, str) and value.strip():
                        valid_translations[field] = value.strip()

                if valid_translations:
                    self._entries[key_en] = valid_translations
                    stats['loaded'] += 1
                else:
                    stats['skipped'] += 1

            self._save_to_disk()

        except Exception as e:
            stats['errors'].append(str(e))

        return stats

    # ================================================================
    # 导出方法
    # ================================================================

    def save(self, file_path: str, format: str = 'json') -> dict:
        """导出自定义字典为文件。

        Args:
            file_path: 导出文件路径。
            format: 导出格式，支持 'json' 或 'csv'。

        Returns:
            包含导出统计信息的字典：
            {
                'total': 导出条目数,
                'file_path': 导出文件路径,
                'format': 导出格式,
                'errors': 错误信息列表
            }
        """
        stats = {
            'total': len(self._entries),
            'file_path': file_path,
            'format': format,
            'errors': [],
        }

        try:
            dir_path = os.path.dirname(file_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)

            if format == 'json':
                self._export_json(file_path)
            elif format == 'csv':
                self._export_csv(file_path)
            else:
                stats['errors'].append(f'Unsupported format: {format}. Use "json" or "csv".')

        except Exception as e:
            stats['errors'].append(str(e))

        return stats

    def _export_json(self, file_path: str):
        """导出为 JSON 文件。"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self._entries, f, ensure_ascii=False, indent=2)

    def _export_csv(self, file_path: str):
        """导出为 CSV 文件（UTF-8 BOM 编码，兼容 Excel）。"""
        with open(file_path, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            # 写入表头
            writer.writerow(['key_en'] + TRANSLATION_FIELDS)
            # 写入数据
            for key_en, translations in self._entries.items():
                row = [key_en]
                for field in TRANSLATION_FIELDS:
                    row.append(translations.get(field, ''))
                writer.writerow(row)

    # ================================================================
    # 条目管理方法
    # ================================================================

    def add_entry(self, key_en: str, translations: dict):
        """添加或更新单条翻译。

        Args:
            key_en: 英文键名（漏洞名称或术语）。
            translations: 翻译字典，可包含以下键：
                          name_zh, description_zh, impact_zh, solution_zh
        """
        if not key_en or not key_en.strip():
            return

        key_en = key_en.strip()
        valid_translations = {}
        for field in TRANSLATION_FIELDS:
            value = translations.get(field, '')
            if value and isinstance(value, str) and value.strip():
                valid_translations[field] = value.strip()

        if valid_translations:
            self._entries[key_en] = valid_translations
            self._save_to_disk()

    def remove_entry(self, key_en: str) -> bool:
        """删除单条翻译。

        Args:
            key_en: 英文键名。

        Returns:
            是否成功删除。
        """
        if key_en in self._entries:
            del self._entries[key_en]
            self._save_to_disk()
            return True
        return False

    # ================================================================
    # 查询方法
    # ================================================================

    def get_translation(self, key_en: str, field: str = None) -> str:
        """获取翻译。

        Args:
            key_en: 英文键名。
            field: 翻译字段名（name_zh, description_zh 等）。
                   如果为 None，则返回 name_zh 字段。

        Returns:
            翻译文本。如果未找到返回空字符串。
        """
        entry = self._entries.get(key_en)
        if not entry:
            return ''

        if field:
            return entry.get(field, '')

        # 默认返回 name_zh
        return entry.get('name_zh', '')

    def search(self, keyword: str) -> list:
        """搜索翻译条目。

        在英文键名和所有翻译字段中搜索关键词，不区分大小写。

        Args:
            keyword: 搜索关键词。

        Returns:
            匹配的条目列表，每项为 {'key_en': ..., 'translations': ...}。
        """
        if not keyword:
            return []

        keyword_lower = keyword.lower()
        results = []

        for key_en, translations in self._entries.items():
            # 在英文键名中搜索
            if keyword_lower in key_en.lower():
                results.append({'key_en': key_en, 'translations': translations})
                continue

            # 在翻译字段中搜索
            matched = False
            for field_value in translations.values():
                if keyword_lower in field_value.lower():
                    matched = True
                    break
            if matched:
                results.append({'key_en': key_en, 'translations': translations})

        return results

    def get_all(self) -> dict:
        """获取所有自定义翻译。

        Returns:
            完整的自定义字典副本。
        """
        return dict(self._entries)

    def get_stats(self) -> dict:
        """获取统计信息。

        Returns:
            统计信息字典：
            {
                'total_entries': 总条目数,
                'field_stats': {
                    'name_zh': 有 name_zh 翻译的条目数,
                    'description_zh': 有 description_zh 翻译的条目数,
                    ...
                },
                'dict_path': 字典文件路径
            }
        """
        field_stats = {}
        for field in TRANSLATION_FIELDS:
            count = sum(1 for t in self._entries.values() if field in t)
            field_stats[field] = count

        return {
            'total_entries': len(self._entries),
            'field_stats': field_stats,
            'dict_path': self._dict_path,
        }

    def merge_with_builtin(self, builtin_dict: dict) -> dict:
        """合并自定义字典与内置字典。

        自定义字典的翻译优先级高于内置字典。对于每个键，
        如果自定义字典中存在对应的翻译字段，则使用自定义翻译；
        否则保留内置字典的值。

        Args:
            builtin_dict: 内置字典，格式为 {英文键: 中文翻译字符串}。

        Returns:
            合并后的完整字典。
        """
        merged = dict(builtin_dict)

        for key_en, translations in self._entries.items():
            # 如果自定义字典中有 name_zh，则覆盖内置字典
            name_zh = translations.get('name_zh', '')
            if name_zh:
                merged[key_en] = name_zh

        return merged
