# -*- coding: utf-8 -*-
"""
在线翻译引擎模块。

支持多种开源/免费翻译 API，内置默认配置，同时支持用户自定义 API。
支持的翻译服务类型：
  - LibreTranslate（开源免费翻译 API）
  - Google Translate（非官方免费接口）
  - DeepL（免费额度）
  - 自定义兼容 API（通用 REST 接口）
"""

from .online_translator import OnlineTranslator, TranslationAPIError

__all__ = ['OnlineTranslator', 'TranslationAPIError']
