# -*- coding: utf-8 -*-
"""
PDF 报告生成器 - 使用 weasyprint 生成专业安全测试报告

PDF Report Generator - Generate professional security assessment reports using weasyprint
"""

import os
from typing import Dict, List, Any

from jinja2.sandbox import SandboxedEnvironment
from jinja2 import FileSystemLoader, select_autoescape

from . import (
    BaseGenerator,
    count_by_level,
    get_overall_risk_level,
    get_risk_color,
    get_text,
    get_risk_level_text,
)


class PDFGenerator(BaseGenerator):
    """PDF 格式报告生成器，使用 weasyprint"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        html_content = self._render_html(project_info, vulnerabilities)
        pdf_bytes = self._html_to_pdf(html_content)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

        return output_path

    def _render_html(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> str:
        """使用 Jinja2 模板渲染 HTML"""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        env = SandboxedEnvironment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )

        # 如果模板文件不存在，使用内联模板
        template_path = os.path.join(template_dir, "report_base.html")
        if os.path.exists(template_path):
            template = env.get_template("report_base.html")
        else:
            template = env.from_string(self._get_inline_template())

        counts = count_by_level(vulnerabilities)
        total = sum(counts.values())
        overall = get_overall_risk_level(counts)

        # 按目标统计
        target_stats: Dict[str, int] = {}
        for vuln in vulnerabilities:
            target = vuln.get("target", "Unknown")
            target_stats[target] = target_stats.get(target, 0) + 1

        # 构建模板上下文
        context = {
            "lang": self.lang,
            "t": lambda key: get_text(self.lang, key),
            "risk_text": lambda level: get_risk_level_text(self.lang, level),
            "risk_color": lambda level: get_risk_color(level),
            "project_info": project_info,
            "vulnerabilities": vulnerabilities,
            "counts": counts,
            "total": total,
            "overall_risk": overall,
            "target_stats": target_stats,
            "is_pdf": True,
        }

        return template.render(**context)

    def _html_to_pdf(self, html_content: str) -> bytes:
        """将 HTML 转换为 PDF"""
        try:
            from weasyprint import HTML
        except ImportError:
            raise ImportError(
                "PDF 生成需要安装 weasyprint。\n"
                "安装方法:\n"
                "  pip install weasyprint\n"
                "Linux 用户需先安装系统依赖:\n"
                "  sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev\n"
                "macOS 用户需先安装 Xcode 命令行工具:\n"
                "  xcode-select --install"
            )

        pdf_doc = HTML(string=html_content)
        return pdf_doc.write_pdf()

    def _get_inline_template(self) -> str:
        """内联 HTML 模板（当模板文件不存在时使用）"""
        return self._build_pdf_html()

    def _build_pdf_html(self) -> str:
        """构建完整的 PDF HTML 内容"""
        return """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
<meta charset="UTF-8">
<style>
  @page {
    size: A4;
    margin: 2.5cm 2cm 2.5cm 2cm;
    @bottom-center {
      content: counter(page);
      font-size: 9pt;
      color: #666;
    }
  }
  @page :first {
    @bottom-center { content: none; }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: "Microsoft YaHei", "SimHei", "Helvetica Neue", Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
  }

  /* 封面 */
  .cover-page {
    page-break-after: always;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    min-height: 90vh;
    text-align: center;
  }
  .cover-title {
    font-size: 32pt;
    font-weight: bold;
    color: #1A237E;
    margin-bottom: 8px;
  }
  .cover-subtitle {
    font-size: 14pt;
    color: #666;
    margin-bottom: 30px;
  }
  .cover-divider {
    width: 60%;
    height: 2px;
    background: linear-gradient(to right, transparent, #1A237E, transparent);
    margin: 20px auto;
  }
  .cover-info {
    margin-top: 30px;
  }
  .cover-info-item {
    font-size: 13pt;
    margin: 8px 0;
  }
  .cover-info-item strong {
    color: #1A237E;
  }

  /* 目录 */
  .toc-page { page-break-after: always; }
  .toc-title { font-size: 20pt; color: #1A237E; margin-bottom: 20px; border-bottom: 2px solid #1A237E; padding-bottom: 8px; }
  .toc-item { font-size: 12pt; padding: 6px 0; border-bottom: 1px dotted #ccc; }

  /* 章节标题 */
  h1.chapter-title {
    font-size: 18pt;
    color: #1A237E;
    border-bottom: 2px solid #1A237E;
    padding-bottom: 8px;
    margin: 30px 0 20px 0;
    page-break-before: always;
  }
  h1.chapter-title:first-of-type { page-break-before: avoid; }
  h2 { font-size: 14pt; color: #283593; margin: 20px 0 10px 0; }
  h3 { font-size: 12pt; color: #3949AB; margin: 15px 0 8px 0; }

  /* 表格 */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 10pt;
  }
  th {
    background-color: #1A237E;
    color: #fff;
    padding: 8px 10px;
    text-align: center;
    font-weight: bold;
    border: 1px solid #1A237E;
  }
  td {
    padding: 6px 10px;
    border: 1px solid #ddd;
    text-align: center;
  }
  tr:nth-child(even) { background-color: #f8f9fa; }
  tr:hover { background-color: #e8eaf6; }

  /* 风险等级标签 */
  .risk-critical { background-color: #DC3545; color: #fff; font-weight: bold; padding: 2px 8px; border-radius: 3px; }
  .risk-high { background-color: #FD7E14; color: #fff; font-weight: bold; padding: 2px 8px; border-radius: 3px; }
  .risk-medium { background-color: #FFC107; color: #333; font-weight: bold; padding: 2px 8px; border-radius: 3px; }
  .risk-low { background-color: #0D6EFD; color: #fff; font-weight: bold; padding: 2px 8px; border-radius: 3px; }
  .risk-info { background-color: #6C757D; color: #fff; font-weight: bold; padding: 2px 8px; border-radius: 3px; }

  /* 漏洞详情卡片 */
  .vuln-card {
    border: 1px solid #ddd;
    border-radius: 6px;
    margin: 15px 0;
    padding: 15px;
    page-break-inside: avoid;
  }
  .vuln-card-header {
    font-size: 13pt;
    font-weight: bold;
    margin-bottom: 10px;
    padding-bottom: 8px;
    border-bottom: 1px solid #e0e0e0;
  }
  .vuln-info-table { margin-bottom: 10px; }
  .vuln-info-table td { text-align: left; }
  .vuln-info-table td:first-child { font-weight: bold; background-color: #E8EAF6; width: 140px; }
  .vuln-section { margin: 10px 0; }
  .vuln-section-title { font-weight: bold; color: #283593; margin-bottom: 4px; }
  .vuln-section-content { padding-left: 15px; color: #555; }

  /* 风险统计图表 */
  .stats-chart {
    display: flex;
    justify-content: center;
    gap: 30px;
    margin: 20px 0;
    flex-wrap: wrap;
  }
  .stat-bar-container { text-align: center; min-width: 80px; }
  .stat-bar {
    width: 50px;
    margin: 0 auto;
    border-radius: 4px 4px 0 0;
    display: flex;
    align-items: flex-end;
    justify-content: center;
    color: #fff;
    font-weight: bold;
    font-size: 10pt;
    min-height: 20px;
  }
  .stat-label { font-size: 9pt; margin-top: 4px; color: #666; }
  .stat-count { font-size: 12pt; font-weight: bold; margin-top: 2px; }

  /* 优先级表 */
  .priority-table td:first-child { font-weight: bold; }

  /* 页脚 */
  .footer-note {
    margin-top: 40px;
    padding-top: 15px;
    border-top: 1px solid #ddd;
    font-size: 9pt;
    color: #999;
    text-align: center;
  }
</style>
</head>
<body>

<!-- 封面页 -->
<div class="cover-page">
  <div class="cover-title">{{ t('cover_title') }}</div>
  <div class="cover-subtitle">{{ t('cover_subtitle') }}</div>
  <div class="cover-divider"></div>
  <div class="cover-info">
    <div class="cover-info-item"><strong>{{ t('cover_project') }}:</strong> {{ project_info.get('name', t('unknown')) }}</div>
    <div class="cover-info-item"><strong>{{ t('cover_client') }}:</strong> {{ project_info.get('client', t('unknown')) }}</div>
    <div class="cover-info-item"><strong>{{ t('cover_tester') }}:</strong> {{ project_info.get('tester', t('unknown')) }}</div>
    <div class="cover-info-item"><strong>{{ t('cover_date') }}:</strong> {{ project_info.get('date', '') }}</div>
    <div class="cover-info-item"><strong>{{ t('cover_classification') }}:</strong> {{ project_info.get('classification', t('unknown')) }}</div>
  </div>
</div>

<!-- 目录页 -->
<div class="toc-page">
  <div class="toc-title">{{ t('toc_title') }}</div>
  <div class="toc-item">1. {{ t('ch1_title') }}</div>
  <div class="toc-item">2. {{ t('ch2_title') }}</div>
  <div class="toc-item">3. {{ t('ch3_title') }}</div>
  <div class="toc-item">4. {{ t('ch4_title') }}</div>
  <div class="toc-item">5. {{ t('ch5_title') }}</div>
  <div class="toc-item">6. {{ t('appendix_title') }}</div>
</div>

<!-- 第一章：项目概述 -->
<h1 class="chapter-title">{{ t('ch1_title') }}</h1>

<h2>{{ t('ch1_test_objective') }}</h2>
<p>{{ t('ch1_test_objective_desc') }}</p>

<h2>{{ t('ch1_test_scope') }}</h2>
{% if project_info.get('scope') is string %}
<p>{{ project_info.scope }}</p>
{% elif project_info.get('scope') is iterable %}
<ul>
{% for item in project_info.get('scope', []) %}
<li>{{ item }}</li>
{% endfor %}
</ul>
{% else %}
<p>{{ t('ch1_test_scope_desc') }}</p>
{% endif %}

<h2>{{ t('ch1_test_method') }}</h2>
{% if project_info.get('method') is string %}
<p>{{ project_info.method }}</p>
{% elif project_info.get('method') is iterable %}
<ul>
{% for item in project_info.get('method', []) %}
<li>{{ item }}</li>
{% endfor %}
</ul>
{% else %}
<p>{{ t('ch1_test_method_desc') }}</p>
{% endif %}

<h2>{{ t('ch1_test_tools') }}</h2>
{% if project_info.get('tools') is string %}
<p>{{ project_info.tools }}</p>
{% elif project_info.get('tools') is iterable %}
<ul>
{% for item in project_info.get('tools', []) %}
<li>{{ item }}</li>
{% endfor %}
</ul>
{% else %}
<p>{{ t('ch1_test_tools_desc') }}</p>
{% endif %}

<!-- 第二章：风险统计概览 -->
<h1 class="chapter-title">{{ t('ch2_title') }}</h1>
<p>{{ t('ch2_desc') }}</p>

<div class="stats-chart">
  {% for level_key, level_label in [('critical', t('ch2_critical')), ('high', t('ch2_high')), ('medium', t('ch2_medium')), ('low', t('ch2_low')), ('info', t('ch2_info'))] %}
  <div class="stat-bar-container">
    <div class="stat-count">{{ counts[level_key] }}</div>
    <div class="stat-bar" style="height: {{ [counts[level_key] * 15, 20] | max }}px; background-color: #{{ risk_color(level_key) }};">
    </div>
    <div class="stat-label">{{ level_label }}</div>
  </div>
  {% endfor %}
</div>

<table>
  <tr>
    <th>{{ t('ch2_level') }}</th>
    <th>{{ t('ch2_count') }}</th>
    <th>{{ t('ch2_percentage') }}</th>
  </tr>
  {% for level_key, level_label in [('critical', t('ch2_critical')), ('high', t('ch2_high')), ('medium', t('ch2_medium')), ('low', t('ch2_low')), ('info', t('ch2_info'))] %}
  <tr>
    <td><span class="risk-{{ level_key }}">{{ level_label }}</span></td>
    <td>{{ counts[level_key] }}</td>
    <td>{{ (counts[level_key] / total * 100) | round(1) if total > 0 else 0 }}%</td>
  </tr>
  {% endfor %}
  <tr style="background-color: #E8EAF6; font-weight: bold;">
    <td>{{ t('ch2_total') }}</td>
    <td>{{ total }}</td>
    <td>100.0%</td>
  </tr>
</table>

<!-- 第三章：漏洞详情 -->
<h1 class="chapter-title">{{ t('ch3_title') }}</h1>

{% if not vulnerabilities %}
<p>{{ t('html_no_vulns') }}</p>
{% endif %}

{% for vuln in vulnerabilities %}
{% set risk_level = vuln.get('risk_level', 'info') | string | lower %}
<div class="vuln-card">
  <div class="vuln-card-header">
    {{ loop.index }}. {{ vuln.get('name', t('unknown')) }}
    <span class="risk-{{ risk_level }}">{{ risk_text(risk_level) }}</span>
  </div>
  <table class="vuln-info-table">
    <tr><td>{{ t('ch3_vuln_id') }}</td><td>{{ '%04d' | format(loop.index) }}</td></tr>
    <tr><td>{{ t('ch3_cve_id') }}</td><td>{{ vuln.get('cve_id', t('na')) }}</td></tr>
    <tr><td>{{ t('ch3_vuln_name') }}</td><td>{{ vuln.get('name', t('unknown')) }}</td></tr>
    <tr><td>{{ t('ch3_risk_level') }}</td><td><span class="risk-{{ risk_level }}">{{ risk_text(risk_level) }}</span></td></tr>
    <tr><td>{{ t('ch3_target') }}</td><td>{{ vuln.get('target', t('na')) }}</td></tr>
    <tr><td>{{ t('ch3_port') }}</td><td>{{ vuln.get('port', t('na')) }}</td></tr>
    <tr><td>{{ t('ch3_protocol') }}</td><td>{{ vuln.get('protocol', t('na')) }}</td></tr>
  </table>

  <div class="vuln-section">
    <div class="vuln-section-title">{{ t('ch3_description') }}</div>
    <div class="vuln-section-content">{{ vuln.get('description', t('na')) }}</div>
  </div>

  <div class="vuln-section">
    <div class="vuln-section-title">{{ t('ch3_impact') }}</div>
    <div class="vuln-section-content">{{ vuln.get('impact', t('na')) }}</div>
  </div>

  {% if vuln.get('reproduce_steps') %}
  <div class="vuln-section">
    <div class="vuln-section-title">{{ t('ch3_reproduce') }}</div>
    <div class="vuln-section-content">
      {% if vuln.reproduce_steps is string %}
      {{ vuln.reproduce_steps }}
      {% else %}
      <ol>
      {% for step in vuln.reproduce_steps %}
        <li>{{ step }}</li>
      {% endfor %}
      </ol>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <div class="vuln-section">
    <div class="vuln-section-title">{{ t('ch3_remediation') }}</div>
    <div class="vuln-section-content">{{ vuln.get('remediation', t('na')) }}</div>
  </div>
</div>
{% endfor %}

<!-- 第四章：综合风险评估 -->
<h1 class="chapter-title">{{ t('ch4_title') }}</h1>

<h2>{{ t('ch4_overall_risk') }}</h2>
<p style="text-align: center; font-size: 18pt; font-weight: bold;">
  <span class="risk-{{ overall_risk }}">{{ risk_text(overall_risk) }}</span>
</p>

<h2>{{ t('ch4_risk_summary') }}</h2>
<p>{{ t('ch4_risk_summary_desc') }}</p>

{% for level_key, desc_key in [('critical', 'ch4_critical_desc'), ('high', 'ch4_high_desc'), ('medium', 'ch4_medium_desc'), ('low', 'ch4_low_desc'), ('info', 'ch4_info_desc')] %}
{% if counts[level_key] > 0 %}
<h3><span class="risk-{{ level_key }}">{{ risk_text(level_key) }}</span> ({{ counts[level_key] }})</h3>
<p>{{ t(desc_key) }}</p>
{% endif %}
{% endfor %}

<h2>{{ t('ch4_recommendation') }}</h2>
<p>{{ t('ch4_recommendation_desc') }}</p>

<!-- 第五章：修复优先级建议 -->
<h1 class="chapter-title">{{ t('ch5_title') }}</h1>
<p>{{ t('ch5_desc') }}</p>

<table class="priority-table">
  <tr>
    <th>{{ t('ch5_priority') }}</th>
    <th>{{ t('ch5_level') }}</th>
    <th>{{ t('ch5_count') }}</th>
    <th>{{ t('ch5_suggestion') }}</th>
  </tr>
  <tr>
    <td>{{ t('ch5_p1') }}</td>
    <td><span class="risk-critical">{{ t('ch2_critical') }}</span></td>
    <td>{{ counts.critical }}</td>
    <td>{{ t('ch5_p1_desc') }}</td>
  </tr>
  <tr>
    <td>{{ t('ch5_p2') }}</td>
    <td><span class="risk-high">{{ t('ch2_high') }}</span></td>
    <td>{{ counts.high }}</td>
    <td>{{ t('ch5_p2_desc') }}</td>
  </tr>
  <tr>
    <td>{{ t('ch5_p3') }}</td>
    <td><span class="risk-medium">{{ t('ch2_medium') }}</span></td>
    <td>{{ counts.medium }}</td>
    <td>{{ t('ch5_p3_desc') }}</td>
  </tr>
  <tr>
    <td>{{ t('ch5_p4') }}</td>
    <td><span class="risk-low">{{ t('ch2_low') }}/{{ t('ch2_info') }}</span></td>
    <td>{{ counts.low + counts.info }}</td>
    <td>{{ t('ch5_p4_desc') }}</td>
  </tr>
</table>

<!-- 附录 -->
<h1 class="chapter-title">{{ t('appendix_title') }}</h1>

{% if vulnerabilities %}
<table>
  <tr>
    <th>{{ t('appendix_index') }}</th>
    <th>{{ t('appendix_cve') }}</th>
    <th>{{ t('appendix_name') }}</th>
    <th>{{ t('appendix_level') }}</th>
    <th>{{ t('appendix_target') }}</th>
    <th>{{ t('appendix_port') }}</th>
    <th>{{ t('appendix_protocol') }}</th>
    <th>{{ t('appendix_source') }}</th>
  </tr>
  {% for vuln in vulnerabilities %}
  {% set risk_level = vuln.get('risk_level', 'info') | string | lower %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ vuln.get('cve_id', t('na')) }}</td>
    <td>{{ vuln.get('name', t('unknown')) }}</td>
    <td><span class="risk-{{ risk_level }}">{{ risk_text(risk_level) }}</span></td>
    <td>{{ vuln.get('target', t('na')) }}</td>
    <td>{{ vuln.get('port', t('na')) }}</td>
    <td>{{ vuln.get('protocol', t('na')) }}</td>
    <td>{{ vuln.get('source', t('na')) }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p>{{ t('html_no_vulns') }}</p>
{% endif %}

<div class="footer-note">
  {{ t('html_generated_by') }} | {{ project_info.get('date', '') }}
</div>

</body>
</html>"""
