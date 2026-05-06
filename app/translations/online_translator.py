# -*- coding: utf-8 -*-
"""
在线翻译引擎。

支持多种翻译 API 服务，通过统一接口调用：
  - LibreTranslate（默认开源 API）
  - Google Translate（非官方免费接口）
  - DeepL（免费额度）
  - 自定义兼容 API（通用 REST 接口，支持用户配置任意翻译服务）

使用方式：
    translator = OnlineTranslator({
        'type': 'libretranslate',
        'api_url': 'https://libretranslate.de',
        'api_key': '',
        'source_lang': 'en',
        'target_lang': 'zh',
    })
    result = translator.translate('Hello World')
"""

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TranslationAPIError(Exception):
    """翻译 API 调用异常。"""

    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class OnlineTranslator:
    """在线翻译器。

    通过 REST API 调用远程翻译服务，支持多种翻译引擎。
    """

    # 内置的默认翻译 API 配置
    DEFAULT_APIS = [
        {
            'id': 'sogou-default',
            'name': '搜狗翻译（免费，无需Key）',
            'type': 'sogou',
            'api_url': '',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'bing-default',
            'name': '必应翻译（免费，无需Key）',
            'type': 'bing',
            'api_url': '',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'doubao-default',
            'name': '豆包 AI（推荐，翻译质量高）',
            'type': 'ai',
            'api_url': 'https://ark.cn-beijing.volces.com/api/v3',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'deepseek-default',
            'name': 'DeepSeek AI（便宜好用）',
            'type': 'ai',
            'api_url': 'https://api.deepseek.com/v1',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'qwen-default',
            'name': '通义千问 AI（阿里云）',
            'type': 'ai',
            'api_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'baidu-default',
            'name': '百度翻译（需注册）',
            'type': 'baidu',
            'api_url': 'https://fanyi-api.baidu.com',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'google-default',
            'name': 'Google Translate (需翻墙)',
            'type': 'google',
            'api_url': 'https://translate.googleapis.com',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'deepl-default',
            'name': 'DeepL (需翻墙)',
            'type': 'deepl',
            'api_url': 'https://api-free.deepl.com',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
        {
            'id': 'libretranslate-default',
            'name': 'LibreTranslate (需翻墙)',
            'type': 'libretranslate',
            'api_url': 'https://libretranslate.com',
            'api_key': '',
            'source_lang': 'en',
            'target_lang': 'zh',
            'is_builtin': True,
            'enabled': False,
        },
    ]

    # 请求超时（秒）
    TIMEOUT = 15

    # 请求间隔（秒），避免触发速率限制
    REQUEST_INTERVAL = 0.3

    def __init__(self, config: Dict):
        """初始化在线翻译器。

        Args:
            config: 翻译 API 配置字典，包含以下字段：
                - type: API 类型 (libretranslate/google/deepl/custom)
                - api_url: API 地址
                - api_key: API 密钥（可选）
                - source_lang: 源语言代码
                - target_lang: 目标语言代码
                - custom_headers: 自定义请求头（可选，仅 custom 类型）
                - custom_body_template: 自定义请求体模板（可选，仅 custom 类型）
        """
        self.config = config
        self.type = config.get('type', 'libretranslate')
        self.api_url = config.get('api_url', '').rstrip('/')
        self.api_key = config.get('api_key', '')
        self.source_lang = config.get('source_lang', 'en')
        self.target_lang = config.get('target_lang', 'zh')
        self.custom_headers = config.get('custom_headers', {})
        self.custom_body_template = config.get('custom_body_template', '')
        self._last_request_time = 0

    def translate(self, text: str) -> str:
        """翻译单段文本。

        Args:
            text: 待翻译的英文文本。

        Returns:
            翻译后的中文文本。翻译失败时返回原文。

        Raises:
            TranslationAPIError: API 调用失败。
        """
        if not text or not text.strip():
            return text

        # 中文检测：已经是中文则跳过
        if self._is_mostly_chinese(text):
            return text

        # 速率限制
        self._rate_limit()

        try:
            if self.type == 'libretranslate':
                result = self._translate_libretranslate(text)
            elif self.type == 'google':
                result = self._translate_google(text)
            elif self.type == 'deepl':
                result = self._translate_deepl(text)
            elif self.type == 'baidu':
                result = self._translate_baidu(text)
            elif self.type == 'sogou':
                result = self._translate_sogou(text)
            elif self.type == 'bing':
                result = self._translate_bing(text)
            elif self.type == 'ai':
                result = self._translate_ai(text)
            elif self.type == 'custom':
                result = self._translate_custom(text)
            else:
                logger.warning('Unknown translation API type: %s', self.type)
                return text

            self._last_request_time = time.time()
            return result or text
        except TranslationAPIError:
            raise
        except Exception as e:
            logger.error('Translation failed: %s', e)
            raise TranslationAPIError(f'Translation failed: {str(e)}')

    def translate_batch(self, texts: List[str]) -> List[str]:
        """批量翻译文本列表。

        Args:
            texts: 待翻译的文本列表。

        Returns:
            翻译后的文本列表，与输入顺序一致。
        """
        results = []
        for text in texts:
            try:
                results.append(self.translate(text))
            except TranslationAPIError as e:
                logger.warning('Batch translation failed for text: %s, error: %s', text[:50], e)
                results.append(text)  # 失败时保留原文
        return results

    def test_connection(self) -> Dict:
        """测试 API 连接是否可用。

        Returns:
            包含测试结果的字典：
                - success: 是否成功
                - message: 描述信息
                - latency: 响应延迟（毫秒）
        """
        test_text = 'Hello'
        start = time.time()
        try:
            result = self.translate(test_text)
            latency = int((time.time() - start) * 1000)
            if result:
                # 搜狗/必应等免费引擎有时返回原文，也算连接成功
                is_free_engine = self.type in ('sogou', 'bing')
                if result != test_text or is_free_engine:
                    return {
                        'success': True,
                        'message': f'连接成功 (延迟: {latency}ms)',
                        'latency': latency,
                        'test_result': result,
                    }
            return {
                'success': False,
                'message': '连接成功但翻译结果为空',
                'latency': latency,
            }
        except TranslationAPIError as e:
            latency = int((time.time() - start) * 1000)
            return {
                'success': False,
                'message': f'连接失败: {str(e)}',
                'latency': latency,
            }

    # ================================================================
    # LibreTranslate
    # ================================================================

    def _translate_libretranslate(self, text: str) -> str:
        """通过 LibreTranslate API 翻译。"""
        url = f'{self.api_url}/translate'
        body = json.dumps({
            'q': text,
            'source': self.source_lang,
            'target': self.target_lang,
            'format': 'text',
        }).encode('utf-8')

        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'

        response = self._make_request(url, body, headers)
        data = json.loads(response)
        return data.get('translatedText', '')

    # ================================================================
    # Google Translate (非官方免费接口)
    # ================================================================

    def _translate_google(self, text: str) -> str:
        """通过 Google Translate 非官方 API 翻译。"""
        # Google 翻译的语言代码映射
        lang_map = {
            'zh': 'zh-CN',
            'en': 'en',
            'ja': 'ja',
            'ko': 'ko',
            'fr': 'fr',
            'de': 'de',
            'es': 'es',
            'ru': 'ru',
        }
        target = lang_map.get(self.target_lang, self.target_lang)
        source = lang_map.get(self.source_lang, self.source_lang)

        url = (
            f'{self.api_url}/translate_a/single'
            f'?client=gtx&sl={source}&tl={target}&dt=t&q={urllib.parse.quote(text)}'
        )

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        response = self._make_request(url, None, headers)
        data = json.loads(response)

        # Google 返回嵌套数组，提取翻译文本
        translated_parts = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, list):
                    for sub in item:
                        if isinstance(sub, list) and len(sub) > 0:
                            translated_parts.append(sub[0])
        return ''.join(translated_parts)

    # ================================================================
    # DeepL
    # ================================================================

    def _translate_deepl(self, text: str) -> str:
        """通过 DeepL API 翻译。"""
        if not self.api_key:
            raise TranslationAPIError('DeepL API requires an API key')

        # DeepL 语言代码映射
        lang_map = {
            'zh': 'ZH',
            'en': 'EN',
            'ja': 'JA',
            'ko': 'KO',
        }
        target = lang_map.get(self.target_lang, self.target_lang.upper())
        source = lang_map.get(self.source_lang, self.source_lang.upper())

        url = f'{self.api_url}/v2/translate'
        body = json.dumps({
            'text': [text],
            'source_lang': source,
            'target_lang': target,
        }).encode('utf-8')

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'DeepL-Auth-Key {self.api_key}',
        }

        response = self._make_request(url, body, headers)
        data = json.loads(response)

        translations = data.get('translations', [])
        if translations:
            return translations[0].get('text', '')
        return ''

    # ================================================================
    # 百度翻译（国内可用）
    # ================================================================

    def _translate_baidu(self, text: str) -> str:
        """通过百度翻译 API 翻译。

        百度翻译 API 文档：https://fanyi-api.baidu.com/doc/21
        需要注册百度翻译开放平台获取 APP ID 和密钥。
        标准版免费额度：每月 200 万字符。
        """
        import hashlib

        app_id = self.api_key.split(':')[0] if ':' in self.api_key else self.api_key
        secret_key = self.api_key.split(':')[1] if ':' in self.api_key else ''

        if not app_id:
            raise TranslationAPIError('百度翻译需要 APP ID，请在 API Key 中填写（格式：APPID:密钥）')

        # 百度语言代码映射
        lang_map = {
            'zh': 'zh',
            'en': 'en',
            'ja': 'jp',
            'ko': 'kor',
            'fr': 'fra',
            'de': 'de',
            'es': 'spa',
            'ru': 'ru',
        }
        target = lang_map.get(self.target_lang, self.target_lang)
        source = lang_map.get(self.source_lang, self.source_lang)

        salt = str(int(time.time() * 1000))
        sign_str = app_id + text + salt + secret_key
        sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()

        url = f'{self.api_url}/v2/translate'
        body = urllib.parse.urlencode({
            'q': text,
            'from': source,
            'to': target,
            'appid': app_id,
            'salt': salt,
            'sign': sign,
        }).encode('utf-8')

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = self._make_request(url, body, headers)
        data = json.loads(response)

        error_code = data.get('error_code', '')
        if error_code:
            error_msgs = {
                '54001': '签名错误（请检查 APP ID 和密钥）',
                '54003': '访问频率受限',
                '54004': '账户余额不足',
                '54005': '长query请求频繁',
                '58002': '服务关闭',
                '58003': 'IP 不在白名单中（请在百度翻译控制台添加 IP）',
            }
            msg = error_msgs.get(error_code, f'错误码 {error_code}')
            raise TranslationAPIError(f'百度翻译失败: {msg}')

        result = data.get('trans_result', [])
        if result:
            return result[0].get('dst', '')
        return ''

    # ================================================================
    # 搜狗翻译（国内可用，无需 API Key）
    # ================================================================

    def _translate_sogou(self, text: str) -> str:
        """通过搜狗翻译（基于 translators 库，无需 API Key）。"""
        try:
            import translators as ts
        except ImportError:
            raise TranslationAPIError(
                '搜狗翻译需要安装 translators 库: pip install translators'
            )
        try:
            result = ts.translate_text(
                text,
                from_lang=self.source_lang,
                to_lang=self.target_lang,
                translator='sogou',
            )
            if result and result.strip():
                result = result.strip()
                if result.lower() == text.lower():
                    time.sleep(0.5)
                    result2 = ts.translate_text(
                        text, from_lang=self.source_lang,
                        to_lang=self.target_lang, translator='sogou',
                    )
                    if result2 and result2.strip() and result2.strip().lower() != text.lower():
                        return result2.strip()
                return result
            return text
        except TranslationAPIError:
            raise
        except Exception as e:
            raise TranslationAPIError(f'搜狗翻译失败: {str(e)}')

    # ================================================================
    # 必应翻译（国内可用，无需 API Key）
    # ================================================================

    def _translate_bing(self, text: str) -> str:
        """通过必应翻译（基于 translators 库，无需 API Key）。"""
        try:
            import translators as ts
        except ImportError:
            raise TranslationAPIError(
                '必应翻译需要安装 translators 库: pip install translators'
            )
        try:
            result = ts.translate_text(
                text,
                from_lang=self.source_lang,
                to_lang=self.target_lang,
                translator='bing',
            )
            if result and result.strip():
                result = result.strip()
                # 必应有时返回原文（限流），重试一次
                if result.lower() == text.lower():
                    time.sleep(0.5)
                    result2 = ts.translate_text(
                        text, from_lang=self.source_lang,
                        to_lang=self.target_lang, translator='bing',
                    )
                    if result2 and result2.strip() and result2.strip().lower() != text.lower():
                        return result2.strip()
                return result
            return text
        except TranslationAPIError:
            raise
        except Exception as e:
            raise TranslationAPIError(f'必应翻译失败: {str(e)}')

    # ================================================================
    # AI 翻译（OpenAI 兼容格式，支持豆包/DeepSeek/通义千问/Kimi 等）
    # ================================================================

    # AI 翻译的系统提示词
    AI_SYSTEM_PROMPT = (
        '你是一个专业的安全漏洞翻译引擎。'
        '将用户输入的英文安全漏洞描述、影响分析、修复建议等内容翻译为中文。'
        '要求：\n'
        '1. 准确翻译专业术语（如 SQL Injection → SQL注入，XSS → 跨站脚本）\n'
        '2. 保持原文的技术准确性\n'
        '3. 只输出翻译结果，不要添加任何解释、注释或额外内容\n'
        '4. 如果输入已经是中文，直接返回原文'
    )

    def _translate_ai(self, text: str) -> str:
        """通过 AI 大模型翻译（OpenAI 兼容接口格式）。

        支持所有兼容 OpenAI Chat Completions 接口的模型：
        - 豆包（火山引擎）：https://ark.cn-beijing.volces.com/api/v3
        - DeepSeek：https://api.deepseek.com/v1
        - 通义千问：https://dashscope.aliyuncs.com/compatible-mode/v1
        - Kimi（月之暗面）：https://api.moonshot.cn/v1
        - 智谱 GLM：https://open.bigmodel.cn/api/paas/v4
        - OpenAI：https://api.openai.com/v1
        """
        if not self.api_url:
            raise TranslationAPIError('AI 翻译需要配置 API URL')
        if not self.api_key:
            raise TranslationAPIError('AI 翻译需要配置 API Key')

        # 模型名称：从 api_key 中解析，格式为 "key:model"
        model = 'doubao-pro-32k'
        if ':' in self.api_key:
            parts = self.api_key.rsplit(':', 1)
            if parts[1].strip():
                model = parts[1].strip()
                self.api_key = parts[0].strip()

        # 构建 OpenAI 兼容请求
        base_url = self.api_url.rstrip('/')
        chat_url = f'{base_url}/chat/completions'

        body = json.dumps({
            'model': model,
            'messages': [
                {'role': 'system', 'content': self.AI_SYSTEM_PROMPT},
                {'role': 'user', 'content': text},
            ],
            'temperature': 0.1,
            'max_tokens': 4096,
        }).encode('utf-8')

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
        }

        response = self._make_request(chat_url, body, headers)
        data = json.loads(response)

        # 解析 OpenAI 格式响应
        if 'error' in data:
            err = data['error']
            msg = err.get('message', str(err)) if isinstance(err, dict) else str(err)
            raise TranslationAPIError(f'AI 翻译失败: {msg}')

        choices = data.get('choices', [])
        if choices:
            content = choices[0].get('message', {}).get('content', '')
            if content:
                return content.strip()

        raise TranslationAPIError('AI 翻译返回空结果')

    # ================================================================
    # 自定义 API
    # ================================================================

    def _translate_custom(self, text: str) -> str:
        """通过自定义 API 翻译。

        支持用户配置的通用 REST 接口，请求体模板中可用占位符：
            {{text}} - 待翻译文本
            {{source_lang}} - 源语言
            {{target_lang}} - 目标语言
            {{api_key}} - API 密钥

        响应 JSON 中通过 response_path 指定翻译结果的提取路径，
        例如 "data.translatedText" 表示 response['data']['translatedText']。
        """
        if not self.api_url:
            raise TranslationAPIError('Custom API URL is required')

        # 构建请求体
        body_template = self.custom_body_template or '{"q": "{{text}}", "source": "{{source_lang}}", "target": "{{target_lang}}"}'
        body_str = (
            body_template
            .replace('{{text}}', json.dumps(text)[1:-1])  # 去掉外层引号
            .replace('{{source_lang}}', self.source_lang)
            .replace('{{target_lang}}', self.target_lang)
            .replace('{{api_key}}', self.api_key)
        )
        body = body_str.encode('utf-8')

        # 构建请求头
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        # 合并自定义请求头
        for k, v in self.custom_headers.items():
            headers[k] = v

        response = self._make_request(self.api_url, body, headers)
        data = json.loads(response)

        # 从响应中提取翻译结果
        response_path = self.config.get('response_path', 'translatedText')
        result = self._extract_by_path(data, response_path)
        return str(result) if result else ''

    # ================================================================
    # 工具方法
    # ================================================================

    def _make_request(self, url: str, body: Optional[bytes], headers: Dict) -> str:
        """发送 HTTP 请求。

        Args:
            url: 请求 URL。
            body: 请求体（GET 请求为 None）。
            headers: 请求头字典。

        Returns:
            响应体文本。

        Raises:
            TranslationAPIError: 请求失败。
        """
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method='POST' if body else 'GET')
            # 通过代理发送请求（如果已配置）
            from app.utils.proxy import proxy_urlopen
            with proxy_urlopen(url, data=body, headers=headers,
                               method='POST' if body else 'GET',
                               timeout=self.TIMEOUT) as resp:
                return resp.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            error_body = ''
            try:
                error_body = e.read().decode('utf-8')
            except Exception:
                pass
            raise TranslationAPIError(
                f'HTTP {e.code}: {error_body or e.reason}',
                status_code=e.code,
            )
        except urllib.error.URLError as e:
            raise TranslationAPIError(f'Connection error: {e.reason}')
        except Exception as e:
            raise TranslationAPIError(f'Request failed: {str(e)}')

    @staticmethod
    def _extract_by_path(data, path: str):
        """按点分隔路径从嵌套字典中提取值。

        Args:
            data: 嵌套字典/列表。
            path: 点分隔路径，如 "data.translatedText"。

        Returns:
            提取到的值，路径不存在时返回 None。
        """
        current = data
        for key in path.split('.'):
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list):
                try:
                    current = current[int(key)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if current is None:
                return None
        return current

    @staticmethod
    def _is_mostly_chinese(text: str) -> bool:
        """判断文本是否以中文为主（中文字符占字母类字符 > 50%）。"""
        if not text:
            return False
        chinese_count = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        # 只计算有意义的字符（字母、中文），排除空格和标点
        letter_count = sum(1 for c in text if c.isalpha() or ('\u4e00' <= c <= '\u9fff'))
        if letter_count == 0:
            return False
        return chinese_count / letter_count > 0.5

    def _rate_limit(self):
        """简单的速率限制控制。"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.REQUEST_INTERVAL:
            time.sleep(self.REQUEST_INTERVAL - elapsed)


# 需要在文件顶部导入
import urllib.parse
