# -*- coding: utf-8 -*-
"""
HTML 报告生成器 - 使用 Jinja2 模板生成完整 HTML 安全测试报告

HTML Report Generator - Generate complete HTML security assessment reports using Jinja2
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


class HTMLGenerator(BaseGenerator):
    """HTML 格式报告生成器"""

    def generate(
        self,
        project_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        lang: str = "zh",
    ) -> str:
        self.lang = lang
        html_content = self._render_html(project_info, vulnerabilities)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _render_html(self, project_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> str:
        """使用 Jinja2 模板渲染 HTML"""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        env = SandboxedEnvironment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )

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
            "is_pdf": False,
        }

        return template.render(**context)

    def _get_inline_template(self) -> str:
        """内联 HTML 模板（当模板文件不存在时使用）"""
        return self._build_html_template()

    def _build_html_template(self) -> str:
        """构建完整的 HTML 模板"""
        return """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ t('report_title') }} - {{ project_info.get('name', '') }}</title>
<style>
  :root {
    --primary: #1A237E;
    --primary-light: #283593;
    --primary-dark: #0D1642;
    --bg: #F5F7FA;
    --card-bg: #FFFFFF;
    --text: #333333;
    --text-light: #666666;
    --border: #E0E0E0;
    --critical: #DC3545;
    --high: #FD7E14;
    --medium: #FFC107;
    --low: #0D6EFD;
    --info: #6C757D;
    --shadow: 0 2px 8px rgba(0,0,0,0.08);
    --shadow-hover: 0 4px 16px rgba(0,0,0,0.12);
    --radius: 8px;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }

  /* 导航栏 */
  .navbar {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, var(--primary), var(--primary-light));
    color: #fff;
    padding: 0 30px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    z-index: 1000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
  }
  .navbar-brand {
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 1px;
  }
  .navbar-nav {
    display: flex;
    gap: 5px;
    list-style: none;
    flex-wrap: wrap;
  }
  .navbar-nav a {
    color: rgba(255,255,255,0.85);
    text-decoration: none;
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 13px;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .navbar-nav a:hover, .navbar-nav a.active {
    background: rgba(255,255,255,0.15);
    color: #fff;
  }

  /* 主内容 */
  .main-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 80px 20px 40px;
  }

  /* 封面 */
  .cover-section {
    background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 50%, #3949AB 100%);
    color: #fff;
    border-radius: var(--radius);
    padding: 60px 40px;
    margin-bottom: 30px;
    text-align: center;
    box-shadow: var(--shadow);
    position: relative;
    overflow: hidden;
  }
  .cover-section::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%);
    animation: coverPulse 8s ease-in-out infinite;
  }
  @keyframes coverPulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
  }
  .cover-title {
    font-size: 36px;
    font-weight: 700;
    margin-bottom: 8px;
    position: relative;
  }
  .cover-subtitle {
    font-size: 16px;
    opacity: 0.8;
    margin-bottom: 30px;
    position: relative;
  }
  .cover-divider {
    width: 80px;
    height: 3px;
    background: rgba(255,255,255,0.5);
    margin: 0 auto 30px;
    border-radius: 2px;
  }
  .cover-info {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 30px;
    position: relative;
  }
  .cover-info-item {
    text-align: center;
  }
  .cover-info-label {
    font-size: 12px;
    opacity: 0.7;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }
  .cover-info-value {
    font-size: 16px;
    font-weight: 600;
  }

  /* 章节卡片 */
  .section-card {
    background: var(--card-bg);
    border-radius: var(--radius);
    padding: 30px;
    margin-bottom: 25px;
    box-shadow: var(--shadow);
    transition: box-shadow 0.3s;
  }
  .section-card:hover {
    box-shadow: var(--shadow-hover);
  }
  .section-title {
    font-size: 22px;
    color: var(--primary);
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 2px solid var(--primary);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-title .icon {
    width: 32px;
    height: 32px;
    background: var(--primary);
    color: #fff;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    flex-shrink: 0;
  }
  .sub-title {
    font-size: 16px;
    color: var(--primary-light);
    margin: 18px 0 10px;
    font-weight: 600;
  }

  /* 表格 */
  .table-responsive {
    overflow-x: auto;
    margin: 15px 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }
  th {
    background: var(--primary);
    color: #fff;
    padding: 12px 15px;
    text-align: center;
    font-weight: 600;
    white-space: nowrap;
  }
  th:first-child { border-radius: 6px 0 0 0; }
  th:last-child { border-radius: 0 6px 0 0; }
  td {
    padding: 10px 15px;
    border-bottom: 1px solid var(--border);
    text-align: center;
  }
  tr:hover td { background-color: #F0F2FF; }
  tr:nth-child(even) td { background-color: #FAFBFF; }
  tr:nth-child(even):hover td { background-color: #E8EBFF; }

  /* 风险等级标签 */
  .risk-badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    color: #fff;
    white-space: nowrap;
  }
  .risk-critical { background-color: var(--critical); }
  .risk-high { background-color: var(--high); }
  .risk-medium { background-color: var(--medium); color: #333; }
  .risk-low { background-color: var(--low); }
  .risk-info { background-color: var(--info); }

  /* 统计图表区域 */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin: 20px 0;
  }
  .stat-card {
    background: var(--card-bg);
    border-radius: var(--radius);
    padding: 20px;
    text-align: center;
    box-shadow: var(--shadow);
    border-top: 4px solid var(--border);
    transition: transform 0.2s, box-shadow 0.2s;
  }
  .stat-card:hover {
    transform: translateY(-3px);
    box-shadow: var(--shadow-hover);
  }
  .stat-card.critical { border-top-color: var(--critical); }
  .stat-card.high { border-top-color: var(--high); }
  .stat-card.medium { border-top-color: var(--medium); }
  .stat-card.low { border-top-color: var(--low); }
  .stat-card.info { border-top-color: var(--info); }
  .stat-card.total { border-top-color: var(--primary); }
  .stat-number {
    font-size: 32px;
    font-weight: 700;
    margin: 5px 0;
  }
  .stat-label {
    font-size: 13px;
    color: var(--text-light);
  }

  /* CSS 柱状图 */
  .bar-chart {
    display: flex;
    align-items: flex-end;
    justify-content: center;
    gap: 20px;
    height: 200px;
    padding: 20px 0;
    margin: 20px 0;
    border-bottom: 2px solid var(--border);
  }
  .bar-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    flex: 1;
    max-width: 100px;
  }
  .bar {
    width: 50px;
    border-radius: 4px 4px 0 0;
    transition: height 0.5s ease;
    min-height: 4px;
    position: relative;
  }
  .bar-value {
    position: absolute;
    top: -22px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 12px;
    font-weight: 600;
    color: var(--text);
  }
  .bar-label {
    font-size: 12px;
    color: var(--text-light);
    text-align: center;
    white-space: nowrap;
  }

  /* CSS 饼图 */
  .pie-chart-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 40px;
    margin: 20px 0;
    flex-wrap: wrap;
  }
  .pie-chart {
    width: 180px;
    height: 180px;
    border-radius: 50%;
    position: relative;
  }
  .pie-legend {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .pie-legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
  }
  .pie-legend-color {
    width: 14px;
    height: 14px;
    border-radius: 3px;
    flex-shrink: 0;
  }

  /* 漏洞详情卡片 */
  .vuln-card {
    background: var(--card-bg);
    border-radius: var(--radius);
    margin: 15px 0;
    box-shadow: var(--shadow);
    overflow: hidden;
    border-left: 4px solid var(--border);
    transition: box-shadow 0.2s;
  }
  .vuln-card:hover { box-shadow: var(--shadow-hover); }
  .vuln-card.critical { border-left-color: var(--critical); }
  .vuln-card.high { border-left-color: var(--high); }
  .vuln-card.medium { border-left-color: var(--medium); }
  .vuln-card.low { border-left-color: var(--low); }
  .vuln-card.info { border-left-color: var(--info); }

  .vuln-card-header {
    padding: 15px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    border-bottom: 1px solid var(--border);
  }
  .vuln-card-title {
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
  }
  .vuln-card-body {
    padding: 15px 20px;
  }
  .vuln-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
    margin-bottom: 15px;
    padding-bottom: 12px;
    border-bottom: 1px dashed var(--border);
  }
  .vuln-meta-item {
    font-size: 13px;
  }
  .vuln-meta-label {
    color: var(--text-light);
    margin-right: 6px;
  }
  .vuln-section {
    margin: 12px 0;
  }
  .vuln-section-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--primary-light);
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .vuln-section-title::before {
    content: '';
    width: 3px;
    height: 14px;
    background: var(--primary);
    border-radius: 2px;
  }
  .vuln-section-content {
    font-size: 13px;
    color: var(--text-light);
    padding-left: 12px;
    line-height: 1.8;
  }
  .vuln-steps {
    padding-left: 20px;
    font-size: 13px;
    color: var(--text-light);
  }
  .vuln-steps li {
    margin: 4px 0;
    line-height: 1.6;
  }

  /* 整体风险 */
  .overall-risk {
    text-align: center;
    padding: 30px;
    margin: 20px 0;
    background: linear-gradient(135deg, #F5F7FA, #E8EAF6);
    border-radius: var(--radius);
  }
  .overall-risk-label {
    font-size: 14px;
    color: var(--text-light);
    margin-bottom: 10px;
  }
  .overall-risk-value {
    font-size: 36px;
    font-weight: 700;
  }

  /* 优先级表 */
  .priority-item {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 15px;
    margin: 10px 0;
    background: #FAFBFF;
    border-radius: 6px;
    border-left: 4px solid var(--border);
  }
  .priority-item.p1 { border-left-color: var(--critical); }
  .priority-item.p2 { border-left-color: var(--high); }
  .priority-item.p3 { border-left-color: var(--medium); }
  .priority-item.p4 { border-left-color: var(--low); }
  .priority-badge {
    padding: 6px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 14px;
    color: #fff;
    white-space: nowrap;
  }
  .priority-detail { flex: 1; }
  .priority-level { font-weight: 600; font-size: 14px; }
  .priority-desc { font-size: 13px; color: var(--text-light); margin-top: 2px; }
  .priority-count {
    font-size: 24px;
    font-weight: 700;
    color: var(--primary);
  }

  /* 页脚 */
  .footer {
    text-align: center;
    padding: 30px;
    color: var(--text-light);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 30px;
  }

  /* 响应式 */
  @media (max-width: 768px) {
    .navbar { padding: 0 15px; height: auto; min-height: 60px; flex-wrap: wrap; padding-top: 10px; padding-bottom: 10px; }
    .navbar-nav { gap: 2px; }
    .navbar-nav a { padding: 6px 10px; font-size: 12px; }
    .cover-section { padding: 40px 20px; }
    .cover-title { font-size: 24px; }
    .cover-info { gap: 15px; }
    .section-card { padding: 20px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .bar-chart { gap: 10px; height: 150px; }
    .bar { width: 35px; }
    .vuln-meta { grid-template-columns: 1fr; }
    .main-content { padding: 70px 10px 20px; }
  }
  @media (max-width: 480px) {
    .stats-grid { grid-template-columns: 1fr; }
    .cover-info { flex-direction: column; gap: 10px; }
  }

  /* 打印样式 */
  @media print {
    .navbar { display: none; }
    .main-content { padding-top: 0; }
    .section-card { break-inside: avoid; box-shadow: none; border: 1px solid var(--border); }
    .vuln-card { break-inside: avoid; box-shadow: none; border: 1px solid var(--border); }
  }
</style>
</head>
<body>

<!-- 导航栏 -->
<nav class="navbar">
  <div class="navbar-brand">{{ t('report_title') }}</div>
  <ul class="navbar-nav">
    <li><a href="#home">{{ t('html_nav_home') }}</a></li>
    <li><a href="#overview">{{ t('html_nav_overview') }}</a></li>
    <li><a href="#statistics">{{ t('html_nav_stats') }}</a></li>
    <li><a href="#details">{{ t('html_nav_details') }}</a></li>
    <li><a href="#assessment">{{ t('html_nav_assessment') }}</a></li>
    <li><a href="#priority">{{ t('html_nav_priority') }}</a></li>
  </ul>
</nav>

<div class="main-content">

<!-- 封面 -->
<section id="home" class="cover-section">
  <div class="cover-title">{{ t('cover_title') }}</div>
  <div class="cover-subtitle">{{ t('cover_subtitle') }}</div>
  <div class="cover-divider"></div>
  <div class="cover-info">
    <div class="cover-info-item">
      <div class="cover-info-label">{{ t('cover_project') }}</div>
      <div class="cover-info-value">{{ project_info.get('name', t('unknown')) }}</div>
    </div>
    <div class="cover-info-item">
      <div class="cover-info-label">{{ t('cover_client') }}</div>
      <div class="cover-info-value">{{ project_info.get('client', t('unknown')) }}</div>
    </div>
    <div class="cover-info-item">
      <div class="cover-info-label">{{ t('cover_tester') }}</div>
      <div class="cover-info-value">{{ project_info.get('tester', t('unknown')) }}</div>
    </div>
    <div class="cover-info-item">
      <div class="cover-info-label">{{ t('cover_date') }}</div>
      <div class="cover-info-value">{{ project_info.get('date', '') }}</div>
    </div>
    <div class="cover-info-item">
      <div class="cover-info-label">{{ t('cover_classification') }}</div>
      <div class="cover-info-value">{{ project_info.get('classification', t('unknown')) }}</div>
    </div>
  </div>
</section>

<!-- 第一章：项目概述 -->
<section id="overview" class="section-card">
  <h2 class="section-title"><span class="icon">1</span> {{ t('ch1_title') }}</h2>

  <h3 class="sub-title">{{ t('ch1_test_objective') }}</h3>
  <p>{{ t('ch1_test_objective_desc') }}</p>

  <h3 class="sub-title">{{ t('ch1_test_scope') }}</h3>
  {% if project_info.get('scope') is string %}
  <p>{{ project_info.scope }}</p>
  {% elif project_info.get('scope') is iterable %}
  <ul style="padding-left: 20px; margin: 8px 0;">
  {% for item in project_info.get('scope', []) %}
  <li>{{ item }}</li>
  {% endfor %}
  </ul>
  {% else %}
  <p>{{ t('ch1_test_scope_desc') }}</p>
  {% endif %}

  <h3 class="sub-title">{{ t('ch1_test_method') }}</h3>
  {% if project_info.get('method') is string %}
  <p>{{ project_info.method }}</p>
  {% elif project_info.get('method') is iterable %}
  <ul style="padding-left: 20px; margin: 8px 0;">
  {% for item in project_info.get('method', []) %}
  <li>{{ item }}</li>
  {% endfor %}
  </ul>
  {% else %}
  <p>{{ t('ch1_test_method_desc') }}</p>
  {% endif %}

  <h3 class="sub-title">{{ t('ch1_test_tools') }}</h3>
  {% if project_info.get('tools') is string %}
  <p>{{ project_info.tools }}</p>
  {% elif project_info.get('tools') is iterable %}
  <ul style="padding-left: 20px; margin: 8px 0;">
  {% for item in project_info.get('tools', []) %}
  <li>{{ item }}</li>
  {% endfor %}
  </ul>
  {% else %}
  <p>{{ t('ch1_test_tools_desc') }}</p>
  {% endif %}
</section>

<!-- 第二章：风险统计概览 -->
<section id="statistics" class="section-card">
  <h2 class="section-title"><span class="icon">2</span> {{ t('ch2_title') }}</h2>
  <p>{{ t('ch2_desc') }}</p>

  <!-- 统计卡片 -->
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-label">{{ t('ch2_total') }}</div>
      <div class="stat-number" style="color: var(--primary);">{{ total }}</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">{{ t('ch2_critical') }}</div>
      <div class="stat-number" style="color: var(--critical);">{{ counts.critical }}</div>
    </div>
    <div class="stat-card high">
      <div class="stat-label">{{ t('ch2_high') }}</div>
      <div class="stat-number" style="color: var(--high);">{{ counts.high }}</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-label">{{ t('ch2_medium') }}</div>
      <div class="stat-number" style="color: #E6A800;">{{ counts.medium }}</div>
    </div>
    <div class="stat-card low">
      <div class="stat-label">{{ t('ch2_low') }}</div>
      <div class="stat-number" style="color: var(--low);">{{ counts.low }}</div>
    </div>
    <div class="stat-card info">
      <div class="stat-label">{{ t('ch2_info') }}</div>
      <div class="stat-number" style="color: var(--info);">{{ counts.info }}</div>
    </div>
  </div>

  <!-- 柱状图 -->
  <h3 class="sub-title">{{ t('ch2_title') }}</h3>
  {% set max_count = [counts.critical, counts.high, counts.medium, counts.low, counts.info, 1] | max %}
  <div class="bar-chart">
    <div class="bar-item">
      <div class="bar" style="height: {{ (counts.critical / max_count * 160) | int }}px; background-color: var(--critical);">
        <span class="bar-value">{{ counts.critical }}</span>
      </div>
      <span class="bar-label">{{ t('ch2_critical') }}</span>
    </div>
    <div class="bar-item">
      <div class="bar" style="height: {{ (counts.high / max_count * 160) | int }}px; background-color: var(--high);">
        <span class="bar-value">{{ counts.high }}</span>
      </div>
      <span class="bar-label">{{ t('ch2_high') }}</span>
    </div>
    <div class="bar-item">
      <div class="bar" style="height: {{ (counts.medium / max_count * 160) | int }}px; background-color: var(--medium);">
        <span class="bar-value">{{ counts.medium }}</span>
      </div>
      <span class="bar-label">{{ t('ch2_medium') }}</span>
    </div>
    <div class="bar-item">
      <div class="bar" style="height: {{ (counts.low / max_count * 160) | int }}px; background-color: var(--low);">
        <span class="bar-value">{{ counts.low }}</span>
      </div>
      <span class="bar-label">{{ t('ch2_low') }}</span>
    </div>
    <div class="bar-item">
      <div class="bar" style="height: {{ (counts.info / max_count * 160) | int }}px; background-color: var(--info);">
        <span class="bar-value">{{ counts.info }}</span>
      </div>
      <span class="bar-label">{{ t('ch2_info') }}</span>
    </div>
  </div>

  <!-- 统计表 -->
  <div class="table-responsive">
    <table>
      <thead>
        <tr>
          <th>{{ t('ch2_level') }}</th>
          <th>{{ t('ch2_count') }}</th>
          <th>{{ t('ch2_percentage') }}</th>
        </tr>
      </thead>
      <tbody>
        {% for level_key, level_label in [('critical', t('ch2_critical')), ('high', t('ch2_high')), ('medium', t('ch2_medium')), ('low', t('ch2_low')), ('info', t('ch2_info'))] %}
        <tr>
          <td><span class="risk-badge risk-{{ level_key }}">{{ level_label }}</span></td>
          <td>{{ counts[level_key] }}</td>
          <td>{{ (counts[level_key] / total * 100) | round(1) if total > 0 else 0 }}%</td>
        </tr>
        {% endfor %}
        <tr style="background-color: #E8EAF6; font-weight: bold;">
          <td>{{ t('ch2_total') }}</td>
          <td>{{ total }}</td>
          <td>100.0%</td>
        </tr>
      </tbody>
    </table>
  </div>
</section>

<!-- 第三章：漏洞详情 -->
<section id="details" class="section-card">
  <h2 class="section-title"><span class="icon">3</span> {{ t('ch3_title') }}</h2>

  {% if not vulnerabilities %}
  <p style="text-align: center; color: var(--text-light); padding: 30px;">{{ t('html_no_vulns') }}</p>
  {% endif %}

  {% for vuln in vulnerabilities %}
  {% set risk_level = vuln.get('risk_level', 'info') | string | lower %}
  <div class="vuln-card {{ risk_level }}">
    <div class="vuln-card-header">
      <div class="vuln-card-title">{{ loop.index }}. {{ vuln.get('name', t('unknown')) }}</div>
      <span class="risk-badge risk-{{ risk_level }}">{{ risk_text(risk_level) }}</span>
    </div>
    <div class="vuln-card-body">
      <div class="vuln-meta">
        <div class="vuln-meta-item"><span class="vuln-meta-label">{{ t('ch3_cve_id') }}:</span>{{ vuln.get('cve_id', t('na')) }}</div>
        <div class="vuln-meta-item"><span class="vuln-meta-label">{{ t('ch3_target') }}:</span>{{ vuln.get('target', t('na')) }}</div>
        <div class="vuln-meta-item"><span class="vuln-meta-label">{{ t('ch3_port') }}:</span>{{ vuln.get('port', t('na')) }}</div>
        <div class="vuln-meta-item"><span class="vuln-meta-label">{{ t('ch3_protocol') }}:</span>{{ vuln.get('protocol', t('na')) }}</div>
        <div class="vuln-meta-item"><span class="vuln-meta-label">{{ t('ch3_source') }}:</span>{{ vuln.get('source', t('na')) }}</div>
      </div>

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
        {% if vuln.reproduce_steps is string %}
        <div class="vuln-section-content">{{ vuln.reproduce_steps }}</div>
        {% else %}
        <ol class="vuln-steps">
        {% for step in vuln.reproduce_steps %}
          <li>{{ step }}</li>
        {% endfor %}
        </ol>
        {% endif %}
      </div>
      {% endif %}

      <div class="vuln-section">
        <div class="vuln-section-title">{{ t('ch3_remediation') }}</div>
        <div class="vuln-section-content">{{ vuln.get('remediation', t('na')) }}</div>
      </div>
    </div>
  </div>
  {% endfor %}
</section>

<!-- 第四章：综合风险评估 -->
<section id="assessment" class="section-card">
  <h2 class="section-title"><span class="icon">4</span> {{ t('ch4_title') }}</h2>

  <div class="overall-risk">
    <div class="overall-risk-label">{{ t('ch4_overall_risk') }}</div>
    <div class="overall-risk-value">
      <span class="risk-badge risk-{{ overall_risk }}" style="font-size: 24px; padding: 8px 24px;">
        {{ risk_text(overall_risk) }}
      </span>
    </div>
  </div>

  <h3 class="sub-title">{{ t('ch4_risk_summary') }}</h3>
  <p>{{ t('ch4_risk_summary_desc') }}</p>

  {% for level_key, desc_key in [('critical', 'ch4_critical_desc'), ('high', 'ch4_high_desc'), ('medium', 'ch4_medium_desc'), ('low', 'ch4_low_desc'), ('info', 'ch4_info_desc')] %}
  {% if counts[level_key] > 0 %}
  <div style="margin: 12px 0; padding: 12px; background: #FAFBFF; border-radius: 6px; border-left: 3px solid var(--{{ level_key }});">
    <strong><span class="risk-badge risk-{{ level_key }}">{{ risk_text(level_key) }}</span> ({{ counts[level_key] }})</strong>
    <p style="margin-top: 6px; font-size: 13px; color: var(--text-light);">{{ t(desc_key) }}</p>
  </div>
  {% endif %}
  {% endfor %}

  <h3 class="sub-title">{{ t('ch4_recommendation') }}</h3>
  <p>{{ t('ch4_recommendation_desc') }}</p>
</section>

<!-- 第五章：修复优先级建议 -->
<section id="priority" class="section-card">
  <h2 class="section-title"><span class="icon">5</span> {{ t('ch5_title') }}</h2>
  <p>{{ t('ch5_desc') }}</p>

  <div class="priority-item p1">
    <span class="priority-badge" style="background-color: var(--critical);">{{ t('ch5_p1') }}</span>
    <div class="priority-detail">
      <div class="priority-level">{{ t('ch2_critical') }}</div>
      <div class="priority-desc">{{ t('ch5_p1_desc') }}</div>
    </div>
    <div class="priority-count">{{ counts.critical }}</div>
  </div>

  <div class="priority-item p2">
    <span class="priority-badge" style="background-color: var(--high);">{{ t('ch5_p2') }}</span>
    <div class="priority-detail">
      <div class="priority-level">{{ t('ch2_high') }}</div>
      <div class="priority-desc">{{ t('ch5_p2_desc') }}</div>
    </div>
    <div class="priority-count">{{ counts.high }}</div>
  </div>

  <div class="priority-item p3">
    <span class="priority-badge" style="background-color: var(--medium); color: #333;">{{ t('ch5_p3') }}</span>
    <div class="priority-detail">
      <div class="priority-level">{{ t('ch2_medium') }}</div>
      <div class="priority-desc">{{ t('ch5_p3_desc') }}</div>
    </div>
    <div class="priority-count">{{ counts.medium }}</div>
  </div>

  <div class="priority-item p4">
    <span class="priority-badge" style="background-color: var(--low);">{{ t('ch5_p4') }}</span>
    <div class="priority-detail">
      <div class="priority-level">{{ t('ch2_low') }} / {{ t('ch2_info') }}</div>
      <div class="priority-desc">{{ t('ch5_p4_desc') }}</div>
    </div>
    <div class="priority-count">{{ counts.low + counts.info }}</div>
  </div>
</section>

<!-- 附录 -->
<section class="section-card">
  <h2 class="section-title"><span class="icon">A</span> {{ t('appendix_title') }}</h2>

  {% if vulnerabilities %}
  <div class="table-responsive">
    <table>
      <thead>
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
      </thead>
      <tbody>
        {% for vuln in vulnerabilities %}
        {% set risk_level = vuln.get('risk_level', 'info') | string | lower %}
        <tr>
          <td>{{ loop.index }}</td>
          <td>{{ vuln.get('cve_id', t('na')) }}</td>
          <td style="text-align: left;">{{ vuln.get('name', t('unknown')) }}</td>
          <td><span class="risk-badge risk-{{ risk_level }}">{{ risk_text(risk_level) }}</span></td>
          <td>{{ vuln.get('target', t('na')) }}</td>
          <td>{{ vuln.get('port', t('na')) }}</td>
          <td>{{ vuln.get('protocol', t('na')) }}</td>
          <td>{{ vuln.get('source', t('na')) }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p style="text-align: center; color: var(--text-light); padding: 30px;">{{ t('html_no_vulns') }}</p>
  {% endif %}
</section>

<!-- 页脚 -->
<div class="footer">
  {{ t('html_generated_by') }} | {{ project_info.get('date', '') }}
</div>

</div>

<script>
// 导航栏滚动高亮
(function() {
  var sections = document.querySelectorAll('section[id]');
  var navLinks = document.querySelectorAll('.navbar-nav a');

  function highlightNav() {
    var scrollPos = window.scrollY + 100;
    sections.forEach(function(section) {
      var top = section.offsetTop;
      var height = section.offsetHeight;
      var id = section.getAttribute('id');
      if (scrollPos >= top && scrollPos < top + height) {
        navLinks.forEach(function(link) {
          link.classList.remove('active');
          if (link.getAttribute('href') === '#' + id) {
            link.classList.add('active');
          }
        });
      }
    });
  }

  window.addEventListener('scroll', highlightNav);
  highlightNav();

  // 平滑滚动
  navLinks.forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      var target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
})();
</script>

</body>
</html>"""
