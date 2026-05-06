# 🔒 安全报告自动生成器 (Security Report Generator)

> 渗透测试安全报告自动化生成与管理工具 — 支持 11 款扫描器、14 种导出格式、CVSS v3.1 评分、离线英中翻译

---

## 📋 目录

- [功能亮点](#功能亮点)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [桌面应用](#桌面应用)
- [功能说明](#功能说明)
- [使用流程](#使用流程)
- [支持的扫描器](#支持的扫描器)
- [支持的导出格式](#支持的导出格式)
- [CVSS v3.1 评分](#cvss-v31-评分)
- [漏洞去重](#漏洞去重)
- [漏洞状态跟踪](#漏洞状态跟踪)
- [报告模板](#报告模板)
- [离线翻译功能](#离线翻译功能)
- [在线翻译功能](#在线翻译功能)
- [自定义翻译库](#自定义翻译库)
- [API 密钥与 Webhook](#api-密钥与-webhook)
- [登录认证](#登录认证)
- [API 接口文档](#api-接口文档)
- [配置说明](#配置说明)
- [常见问题](#常见问题)
- [技术栈](#技术栈)
- [项目结构](#项目结构)

---

## 功能亮点

| 特性 | 说明 |
|------|------|
| 📥 **11 款扫描器** | Nmap、Nessus、Burp Suite、AWVS、ZAP、Xray、Nuclei、Sqlmap、绿盟、安恒、启明星辰 |
| 📄 **14 种导出格式** | Word、PDF、Excel、HTML、XML、JSON、CSV、TXT、Markdown、DefectDojo、Jira 等 |
| 📊 **CVSS v3.1 评分** | 输入向量自动计算评分，符合 NVD 标准 |
| 🔍 **漏洞去重** | 多扫描器导入时自动识别并合并重复漏洞 |
| 📋 **状态看板** | 6 种状态拖拽管理（已发现→已确认→修复中→已修复→已验证→已关闭） |
| 🌐 **翻译引擎** | 内置 ~10,957 条离线术语 + 在线翻译 API（LibreTranslate/Google/DeepL/自定义），支持离线/在线/混合三种模式 |
| 🗄️ **数据持久化** | SQLite 数据库存储，重启不丢失 |
| 📈 **交互式仪表盘** | Chart.js 可视化图表，支持导出 PNG |
| 🎨 **多主题报告** | 企业合规版 / 渗透实战版 / 简洁摘要版 |
| 👁️ **在线预览** | 浏览器内预览 HTML 报告，支持实时编辑 |
| 📁 **批量导入** | 多文件同时上传，自动识别扫描器类型 |
| 🔐 **API 认证** | API Key 管理 + Webhook 事件通知 |
| 🔒 **登录认证** | 密码保护，防止未授权访问，支持自定义密码 |
| 🖥️ **桌面应用** | Electron 桌面客户端，系统托盘、原生菜单、文件拖拽 |
| 🌐 **中英双语** | 界面和报告均支持中英文切换 |

---

## 环境要求

| 项目 | 要求 |
|------|------|
| Python | 3.8 及以上版本 |
| 操作系统 | Windows / macOS / Linux |
| 浏览器 | Chrome / Edge / Firefox（推荐现代浏览器） |
| 磁盘空间 | 至少 500MB（含漏洞描述数据库） |
| PDF 功能 | 可选，需安装 [weasyprint](#q-安装依赖时-weasyprint-报错怎么办)（需要 C 编译环境） |

---

## 快速开始

### 第一步：安装 Python

如果还没有安装 Python，前往 [https://www.python.org/downloads/](https://www.python.org/downloads/) 下载安装。

> ⚠️ 安装时务必勾选 **"Add Python to PATH"**

验证安装：
```bash
python --version
# 应显示 Python 3.8 或更高版本
```

### 第二步：打开项目文件夹

在电脑上找到 `sec-report-generator` 文件夹，在**该文件夹内**打开命令行终端：

- **Windows**：在文件夹地址栏输入 `cmd` 后回车
- **macOS**：在 Finder 中打开该文件夹，右键选择"在终端中打开"
- **Linux**：直接 `cd` 到项目目录

### 第三步：安装依赖

```bash
pip install -r requirements.txt
```

> 如果提示权限问题，Windows 用户尝试：`pip install -r requirements.txt --user`
> macOS/Linux 用户尝试：`pip3 install -r requirements.txt --break-system-packages`

### 第四步：启动应用

```bash
python app.py
```

看到以下输出说明启动成功：
```
 * Running on http://127.0.0.1:5000
```

### 第五步：打开浏览器

在浏览器中访问：**http://localhost:5000**

---

## 桌面应用

除了浏览器访问，本工具还提供 **Electron 桌面客户端**，提供更接近原生应用的体验。

### 功能特性

| 特性 | 说明 |
|------|------|
| **系统托盘** | 最小化到托盘，后台运行不碍事，双击托盘图标重新打开 |
| **关闭行为** | 可设置关闭窗口时的行为：最小化到托盘 / 弹出确认 / 直接退出 |
| **保持登录** | 可设置关闭程序后保持登录状态，下次打开无需重新输入密码 |
| **原生菜单** | 菜单栏快捷操作（检查更新、打开导出目录、切换语言、关于） |
| **自动更新** | 支持检查新版本、下载并安装更新 |
| **文件拖拽** | 直接拖拽扫描报告文件到窗口即可导入 |
| **快捷键** | `Ctrl+N` 新建漏洞、`Ctrl+I` 导入、`Ctrl+R` 生成报告 |
| **桌面通知** | 操作完成后系统级通知提醒 |
| **自动启动** | 开机自动启动（可选） |
| **日志查看** | 内置日志查看页面，支持按级别/关键词过滤、自动刷新 |
| **代理支持** | 支持配置 HTTP/SOCKS5 代理，适用于需要通过代理访问翻译 API 的环境 |
| **跨平台** | 支持 Windows / macOS / Linux |

### 启动方式

#### 方式一：Python 启动器（推荐）

```bash
# Windows
start_desktop.bat

# macOS / Linux
bash start_desktop.sh
```

#### 方式二：命令行启动

```bash
python start_desktop.py
```

启动后会自动打开桌面窗口，Flask 服务在后台运行，无需手动打开浏览器。

### 打包为安装包

> ⚠️ 打包前请确保已安装 [Node.js](https://nodejs.org/)（v16+）和 Python 3.8+。

#### 安装 Node.js（npm）

npm 随 Node.js 一起安装，无需单独安装。

1. 访问 https://nodejs.org/ 下载 **LTS（长期支持）** 版本
2. 双击 `.msi` 安装包，一路"下一步"（确保勾选 "Add to PATH"）
3. 打开**新的**命令行窗口，验证安装：
   ```bash
   node -v    # 应显示 v20.x.x 或更高
   npm -v     # 应显示 10.x.x 或更高
   ```

> 💡 国内下载慢可使用镜像：https://npmmirror.com/mirrors/node/

#### 前置准备

```bash
# 1. 安装 Python 依赖
pip install -r requirements.txt

# 2. 安装 Node.js 依赖
npm install
```

#### Windows 打包

```bash
# 生成 .exe 安装包 + 便携版（两个文件）
npm run build:win
```

输出文件位于 `dist-electron/` 目录：

| 文件 | 说明 |
|------|------|
| `安全报告生成器-2.0.0-x64.exe` | NSIS 安装包（可选择安装目录，创建桌面快捷方式） |
| `安全报告生成器-2.0.0-便携版.exe` | 便携版（单文件，双击直接运行，无需安装） |

#### macOS 打包

```bash
npm run build:mac
```

输出：`.dmg` 安装包 + `.zip` 压缩包

#### Linux 打包

```bash
npm run build:linux
```

输出：`.AppImage` + `.deb`

#### 其他打包命令

```bash
# 仅打包不生成安装包（快速测试）
npm run pack:win

# 仅打包便携版
npm run pack:portable

# 打包所有平台
npm run build:all
```

#### 打包输出文件

打包完成后，在 `dist-electron/` 目录下生成：

| 文件 | 说明 |
|------|------|
| `安全报告生成器-{version}-x64.exe` | 安装包（可选安装目录，创建快捷方式） |
| `安全报告生成器-{version}-便携版.exe` | 便携版（单文件，双击直接运行） |
| `win-unpacked/` | 解压后的程序目录（用于调试） |

#### 网络问题解决

如果下载 Electron 或依赖时超时，设置国内镜像：

```bash
# Windows CMD
set ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/
set ELECTRON_BUILDER_BINARIES_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/
npm run build:win

# Windows PowerShell
$env:ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"
$env:ELECTRON_BUILDER_BINARIES_MIRROR="https://npmmirror.com/mirrors/electron-builder-binaries/"
npm run build:win

# macOS/Linux
export ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/
export ELECTRON_BUILDER_BINARIES_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/
npm run build:win
```

#### 符号链接权限问题

如果报错 `Cannot create symbolic link`，需要开启 Windows 开发者模式：

1. 打开「设置」→「隐私和安全性」→「开发者选项」
2. 开启「开发人员模式」
3. 重新执行打包命令

#### 自定义图标

图标文件位于 `electron/assets/` 目录：

| 文件 | 用途 |
|------|------|
| `icon.ico` | Windows 应用图标 |
| `icon.icns` | macOS 应用图标 |
| `icon.png` | Linux 应用图标 |

替换这些文件后重新打包即可更换图标。建议使用 256x256 或更大尺寸的 PNG 图片转换为 ico 格式。

#### 分发注意事项

桌面版依赖用户本地安装的 Python 环境。分发时需要告知用户：

1. 安装 [Python 3.8+](https://www.python.org/downloads/)（安装时勾选 "Add to PATH"）
2. 安装 Python 依赖：`pip install flask python-docx openpyxl beautifulsoup4 pdfplumber jinja2`
3. 运行安装包或便携版

> 💡 **纯单文件方案**：如果需要完全不依赖 Python 的单文件 exe，可以使用 [PyInstaller](https://pyinstaller.org/) 将 Flask 后端打包为 exe，再配合 Electron 前端。详见下方 FAQ。

---

## 功能说明

### 🏠 首页仪表盘
- 查看项目基本信息和漏洞统计
- **交互式图表**：严重程度分布（环形图）、扫描器来源分布（柱状图）、Top 10 受影响目标、CVSS 评分分布、漏洞状态分布
- 图表支持**导出为 PNG**，可直接粘贴到报告中
- 快捷入口：导入扫描结果、漏洞管理、生成报告

### 📥 导入扫描结果
- 支持 **11 款主流扫描器**的报告文件导入
- 自动检测扫描器类型
- **批量导入**：支持同时上传多个文件，自动识别并分别解析
- 导入后可预览解析结果，确认后添加到漏洞列表

### 🐛 漏洞管理
- **列表视图**：查看、搜索、筛选、排序漏洞列表，支持分页
- **看板视图**：按状态分列展示漏洞，支持拖拽改变状态
- 手动添加 / 编辑 / 删除漏洞
- 支持批量操作（全选、批量删除、清空）
- **CVSS v3.1 评分**：输入 CVSS 向量自动计算评分
- **漏洞去重**：一键检测并合并重复漏洞
- **状态跟踪**：6 种状态流转管理
- 每个漏洞包含：CVE 编号、名称、风险等级、目标、端口、描述、影响分析、修复建议、验证步骤、CVSS 评分、状态等

### 📄 报告生成
- 填写项目信息（项目名称、客户、测试人员、日期等）
- **3 种报告模板**：企业合规版 / 渗透实战版 / 简洁摘要版
- 选择报告语言（中文 / English）
- 选择导出格式（14 种）
- **在线预览**：生成前可在浏览器中预览 HTML 报告
- 一键生成并下载
  - **桌面版**：生成后弹出"另存为"对话框，自由选择保存路径和文件名
  - **浏览器版**：自动下载到默认下载目录
- 报告文件名自动包含项目名和时间戳（如 `report_项目名_20260417_143025.pdf`）
- 生成历史记录
- 菜单栏"打开导出目录"可快速打开上次保存报告的文件夹

### ⚙️ 系统设置
- **登录认证**：密码保护，防止未授权访问（默认密码 `admin`）
- **密码管理**：修改密码、重置为默认密码
- **API 密钥管理**：创建、查看、吊销 API Key
- **Webhook 配置**：创建事件通知（报告生成、漏洞导入等），支持企业微信/钉钉/飞书/Slack
- **翻译设置**：翻译模式切换（离线/在线/混合）、翻译 API 配置与管理
- **代理设置**：配置 HTTP/SOCKS5 代理，支持启用/禁用开关
- **桌面版设置**（仅桌面版）：
  - **关闭行为**：选择关闭窗口时的行为（最小化到托盘 / 弹出确认对话框 / 直接退出）
  - **保持登录**：开启后关闭程序不自动退出登录，下次打开无需重新输入密码
  - **检查更新**：手动检查新版本，支持下载和安装
  - **打开导出目录**：快速打开报告保存目录

### 📜 日志查看
- 内置日志查看页面，实时查看应用和客户端日志
- 支持按日志源过滤（应用日志 / 客户端日志 / 全部）
- 支持按级别过滤（DEBUG / INFO / WARNING / ERROR）
- 支持关键词搜索和高亮
- 支持自动刷新（每 3 秒）
- 支持清除日志

### 🌐 中英双语
- 界面支持中英文切换（点击右上角语言按钮）
- 生成的报告也支持中英文模板

### 🌐 离线翻译
- 一键将英文漏洞报告翻译为中文，无需联网
- 支持一键翻译全部漏洞或逐条翻译
- 报告生成时可勾选「自动翻译为中文」
- 详见 [离线翻译功能](#离线翻译功能)

---

## 使用流程

### 方式一：导入扫描器报告（推荐）

```
1. 打开浏览器访问 http://localhost:5000
2. 点击顶部导航栏「导入扫描结果」
3. 拖拽上传扫描器导出的报告文件（支持多文件批量上传）
4. 系统自动检测扫描器类型并解析
5. 预览解析结果，确认导入
6. 进入「漏洞管理」查看和编辑漏洞
7. （可选）点击「去重」合并重复漏洞
8. （可选）输入 CVSS 向量自动计算评分
9. （可选）点击「一键翻译全部」将英文内容翻译为中文
10. 进入「报告生成」填写项目信息
11. 选择报告模板和导出格式
12. （可选）点击「在线预览」预览报告效果
13. 点击「生成报告」并下载
```

### 方式二：手动录入漏洞

```
1. 进入「漏洞管理」页面
2. 点击「添加漏洞」按钮
3. 填写漏洞信息表单（可输入 CVSS 向量自动计算评分）
4. 保存后重复添加更多漏洞
5. 使用看板视图拖拽管理漏洞状态
6. 进入「报告生成」生成报告
```

### 方式三：导入 Nessus 等英文报告并翻译

```
1. 导入 Nessus/AWVS 等扫描器的英文报告
2. 确认导入后，在漏洞管理页面点击「一键翻译全部」
3. 系统自动将漏洞名称、描述、影响分析、修复建议翻译为中文
4. 检查翻译结果，可手动微调
5. 生成中文安全报告
```

### 方式四：导出到漏洞管理平台

```
1. 完成漏洞录入和编辑
2. 进入「报告生成」页面
3. 选择 DefectDojo 格式 → 生成 JSON 文件 → 导入 DefectDojo
4. 选择 Jira 格式 → 生成 CSV 文件 → 导入 Jira
```

---

## 支持的扫描器

### 国际工具（8 款）

| 扫描器 | 支持导入格式 | 说明 |
|--------|-------------|------|
| **Nmap** | XML | 网络扫描器，使用 `nmap -oX output.xml` 导出 |
| **Burp Suite** | XML | Web 渗透工具，导出 Issues 为 XML 格式 |
| **Nessus** | CSV / JSON | 漏洞扫描器，导出扫描结果为 CSV 或 JSON |
| **AWVS** | XML / JSON | Web 漏洞扫描器，导出报告为 XML 或 JSON |
| **OWASP ZAP** | XML / JSON | 开源 Web 安全测试工具 |
| **Xray** | JSON | 长亭安全评估工具，使用 `--json-output` 导出 |
| **Nuclei** | JSON | POC 漏洞扫描框架 |
| **Sqlmap** | JSON / CSV | SQL 注入自动化检测工具 |

### 国内设备（3 款）

| 扫描器 | 厂商 | 支持导入格式 |
|--------|------|-------------|
| **RSAS** | 绿盟 | HTML / XML / Excel |
| **明鉴** | 安恒 | HTML / Excel |
| **天镜** | 启明星辰 | HTML / XML / Excel |

---

## 支持的导出格式

### 标准报告格式（9 种）

| 格式 | 扩展名 | 用途 | 说明 |
|------|--------|------|------|
| **Word** | .docx | 客户交付 | 最常用格式，方便编辑批注，含封面/目录/正文/附录 |
| **PDF** | .pdf | 正式归档 | 不可篡改，适合正式交付 |
| **Excel** | .xlsx | 漏洞跟踪 | 含漏洞清单、风险统计、目标统计三个表 |
| **HTML** | .html | 在线查看 | 可直接在浏览器中打开查看，响应式布局 |
| **XML** | .xml | 平台集成 | 结构化数据，可导入其他平台 |
| **JSON** | .json | API / 开发 | 适合二次开发和数据交换 |
| **CSV** | .csv | 数据导入 | 可直接用 Excel 打开，兼容性好 |
| **TXT** | .txt | 快速查看 | 纯文本格式，轻量简洁 |
| **Markdown** | .md | 技术文档 | 适合 Git 仓库和知识库 |

### 平台集成格式（2 种）

| 格式 | 扩展名 | 目标平台 | 说明 |
|------|--------|---------|------|
| **DefectDojo** | .json | DefectDojo | 生成兼容的 Finding JSON，可直接导入 DefectDojo |
| **Jira** | .csv | Jira | 生成 Jira CSV 导入格式，含优先级/标签/截止日期映射 |

### 其他格式（3 种）

| 格式 | 扩展名 | 说明 |
|------|--------|------|
| **SARIF** | .json | Microsoft 静态分析结果交换格式 |
| **HTML 简报** | .html | 仅包含统计摘要和严重漏洞的简报页面 |

---

## CVSS v3.1 评分

系统内置了完整的 CVSS v3.1 基础评分计算引擎，符合 [NVD 官方标准](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)。

### 使用方式

1. 在添加/编辑漏洞时，填写 **CVSS 向量**字段
2. 系统自动计算 CVSS 基础评分（0.0 - 10.0）
3. 评分以彩色徽章显示在漏洞列表中

### 向量格式

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### 指标说明

| 指标 | 全称 | 可选值 |
|------|------|--------|
| AV | Attack Vector（攻击向量） | N(Network) / A(Adjacent) / L(Local) / P(Physical) |
| AC | Attack Complexity（攻击复杂度） | L(Low) / H(High) |
| PR | Privileges Required（所需权限） | N(None) / L(Low) / H(High) |
| UI | User Interaction（用户交互） | N(None) / R(Required) |
| S | Scope（影响范围） | U(Unchanged) / C(Changed) |
| C | Confidentiality（机密性影响） | H(High) / L(Low) / N(None) |
| I | Integrity（完整性影响） | H(High) / L(Low) / N(None) |
| A | Availability（可用性影响） | H(High) / L(Low) / N(None) |

### 评分与颜色

| 评分范围 | 等级 | 颜色 |
|---------|------|------|
| 9.0 - 10.0 | 严重 (Critical) | 🔴 红色 |
| 7.0 - 8.9 | 高危 (High) | 🟠 橙色 |
| 4.0 - 6.9 | 中危 (Medium) | 🟡 黄色 |
| 0.1 - 3.9 | 低危 (Low) | 🔵 蓝色 |
| 0.0 | 无 (None) | ⚪ 灰色 |

### API 更新 CVSS 评分

```bash
# 通过 CVSS 向量自动计算评分
curl -X PUT http://localhost:5000/api/vulnerabilities/<id>/cvss \
  -H "Content-Type: application/json" \
  -d '{"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
# 返回: {"cvss_score": 9.8}

# 直接指定评分
curl -X PUT http://localhost:5000/api/vulnerabilities/<id>/cvss \
  -H "Content-Type: application/json" \
  -d '{"cvss_score": 9.8}'
```

---

## 漏洞去重

导入多个扫描器的报告时，经常会出现同一漏洞被多个工具重复发现的情况。去重功能可以自动识别并合并这些重复项。

### 匹配策略

系统按以下优先级进行匹配：

| 优先级 | 匹配规则 | 说明 |
|--------|---------|------|
| 1 | 精确匹配 | 相同 CVE 编号 + 相同目标地址 |
| 2 | 高相似度 | 相同目标 + 相同端口 + 名称相似度 > 80% |
| 3 | 中相似度 | 相同目标 + 名称相似度 > 70% |

### 合并规则

- **描述**：保留最完整的描述（最长非空内容）
- **严重等级**：保留最高等级
- **扫描器来源**：合并所有来源（如 "Nessus, BurpSuite"）
- **CVE 编号**：合并所有 CVE 编号
- **创建时间**：保留最早的

### 使用方式

1. 在「漏洞管理」页面，点击工具栏的「去重」按钮
2. 系统自动检测重复漏洞并显示结果
3. 确认后自动合并

```bash
# API 调用
curl -X POST http://localhost:5000/api/vulnerabilities/deduplicate
```

---

## 漏洞状态跟踪

每个漏洞支持完整的生命周期状态管理。

### 状态流转

```
已发现 (Discovered) → 已确认 (Confirmed) → 修复中 (Fixing) → 已修复 (Fixed) → 已验证 (Verified) → 已关闭 (Closed)
```

### 看板视图

在「漏洞管理」页面切换到看板视图，可以：
- 按状态分列展示所有漏洞
- **拖拽卡片**改变漏洞状态
- 每列显示漏洞数量统计

### API 更新状态

```bash
curl -X PUT http://localhost:5000/api/vulnerabilities/<id>/status \
  -H "Content-Type: application/json" \
  -d '{"status": "fixing"}'
```

---

## 报告模板

系统提供 3 种报告模板，适用于不同场景。

### 企业合规版（Professional）

- 完整的封面页（项目名称、客户、日期、版本）
- 自动生成目录
- 章节：概述 → 测试范围 → 漏洞详情 → 风险评估 → 修复建议 → 附录
- 适合正式交付给客户

### 渗透实战版（Pentest）

- 简洁封面
- 重点突出漏洞利用步骤和 PoC
- 章节：目标信息 → 漏洞清单 → 漏洞详情（含 PoC）→ 修复优先级
- 适合内部安全团队使用

### 简洁摘要版（Simple）

- 无封面，直接进入内容
- 仅包含漏洞统计和严重/高危漏洞详情
- 适合快速汇报和管理层阅览

### 在线预览

在报告生成页面点击「在线预览」按钮，可以在浏览器中直接预览 HTML 报告效果，确认无误后再生成最终文件。

---

## 离线翻译功能

本工具内置了完整的离线翻译引擎，可以将 Nessus、AWVS 等扫描器导出的英文报告内容自动翻译为中文，**无需联网、无需 API Key**。

### 翻译资源

| 资源 | 数量 | 说明 |
|------|:----:|------|
| **TOP 100 高频漏洞描述库** | 100 条 | 手写高质量中英文对照，覆盖 Log4Shell、EternalBlue、Spring4Shell 等经典漏洞 |
| **漏洞数据库** | 10,000 条 | 50 种漏洞类型 × 243 种产品自动生成，覆盖面极广 |
| **漏洞类型术语字典** | 313 条 | SQL注入、XSS、SSRF、RCE 等漏洞类型名称 |
| **通用安全术语字典** | 319 条 | 漏洞、攻击、加密、协议、框架等通用术语 |
| **修复建议句型** | 75 条 | 完整句子级匹配（如 "Apply the latest security patches" → "应用最新的安全补丁"） |
| **短语模式规则** | 150+ 条 | 动词短语、介词短语、句型模板的正则匹配 |
| **总计** | **~10,957 条** | 完全离线，无需网络 |

### 翻译优先级

```
1. 短语模式匹配（正则）           → 句子级翻译
2. CVE 精确匹配（100条手写库）   → 完美翻译
3. 漏洞名称匹配（10000条数据库） → 高质量翻译
4. 自定义字典匹配                → 用户自定义翻译
5. 术语字典逐词替换              → 基础翻译兜底
```

### 使用方式

#### 一键翻译全部漏洞

1. 进入「漏洞管理」页面
2. 点击顶部操作栏的「一键翻译全部」按钮
3. 等待翻译完成（通常几秒钟）
4. 查看翻译结果，可手动微调未翻译的部分

#### 翻译单个漏洞

1. 在漏洞列表中找到目标漏洞
2. 点击该行右侧的「翻译」按钮
3. 仅该条漏洞会被翻译

#### 报告生成时自动翻译

1. 进入「报告生成」页面
2. 勾选「自动翻译为中文」复选框
3. 选择报告格式并点击生成
4. 系统会先翻译所有漏洞内容，再生成中文报告

### 翻译示例

| 英文原文 | 中文翻译 |
|---------|---------|
| SQL Injection | SQL注入 |
| Cross-Site Scripting (XSS) | 跨站脚本攻击(XSS) |
| Remote Code Execution | 远程代码执行 |
| Apply the latest security patches to fix this issue. | 应用最新的安全补丁 要修复此问题， |
| The remote host is affected by a vulnerability. | 远程主机 受到一个漏洞的影响。 |

> ⚠️ **说明**：离线翻译基于术语字典和规则匹配，对于常见安全术语和标准句型覆盖率很高，但无法达到 AI 翻译的完美效果。未匹配的部分会保留英文原文，你可以手动编辑修正，或通过[自定义翻译库](#自定义翻译库)扩展翻译覆盖范围。也可以使用[在线翻译功能](#在线翻译功能)获得更高质量的翻译效果。

---

## 在线翻译功能

除了内置的离线翻译引擎，本工具还支持**在线翻译 API**，提供更高质量的翻译效果。支持三种翻译模式灵活切换。

### 翻译模式

| 模式 | 说明 | 适用场景 |
|------|------|---------|
| **离线翻译** | 使用本地术语字典，无需网络 | 快速翻译、无网络环境、常见安全术语 |
| **在线翻译** | 调用在线翻译 API | 需要高质量翻译、复杂描述内容 |
| **混合翻译** | 离线优先，对未翻译部分自动用在线翻译补充 | 兼顾速度和质量（推荐） |

### 内置翻译 API

本工具预置了 3 个常用的开源/免费翻译 API，无需额外安装：

| API | 说明 | 需要 API Key |
|-----|------|:---:|
| **LibreTranslate** | 开源免费翻译引擎，支持多种语言 | 可选 |
| **Google Translate** | 谷歌翻译非官方免费接口 | 否 |
| **DeepL** | 高质量翻译引擎，免费额度每月 50 万字符 | 是 |

### 配置在线翻译

1. 进入「设置」页面
2. 在「翻译设置」区域选择翻译模式（离线/在线/混合）
3. 在翻译 API 列表中，点击「激活」按钮启用所需的 API
4. 如需 API Key，点击编辑按钮填入密钥
5. 点击「测试连接」验证 API 是否可用

### 添加自定义翻译 API

支持接入任意兼容 REST 接口的翻译服务：

1. 在设置页面的翻译 API 区域，点击「添加自定义 API」
2. 填写配置信息：
   - **API 名称**：自定义名称
   - **API 类型**：选择「自定义 API」
   - **API URL**：翻译服务的接口地址
   - **API Key**：可选
   - **源语言 / 目标语言**：翻译语言对
   - **响应提取路径**：从 JSON 响应中提取翻译结果的路径（如 `data.translatedText`）
   - **请求体模板**：自定义请求体格式，支持占位符 `{{text}}`、`{{source_lang}}`、`{{target_lang}}`、`{{api_key}}`
3. 点击「测试连接」验证配置
4. 点击「保存」

#### 自定义 API 请求体模板示例

```json
{"q": "{{text}}", "source": "{{source_lang}}", "target": "{{target_lang}}"}
```

### 翻译模式对比

| 特性 | 离线翻译 | 在线翻译 | 混合翻译 |
|------|:---:|:---:|:---:|
| 需要网络 | ❌ | ✅ | ✅ |
| 翻译速度 | ⚡ 极快 | 🐢 较慢 | ⚡ 较快 |
| 翻译质量 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 术语准确性 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 覆盖范围 | 有限 | 极广 | 极广 |

---

## 自定义翻译库

除了内置的翻译资源，你还可以导入自己的翻译对照表，扩展翻译覆盖范围。

### 支持的格式

- **CSV 格式**（推荐，兼容 Excel）
- **JSON 格式**（适合程序化处理）

### CSV 模板格式

```csv
key_en,name_zh,description_zh,impact_zh,solution_zh
SQL Injection,SQL注入,登录页面存在SQL注入漏洞。攻击者可以通过构造恶意SQL语句获取数据库敏感信息。,可能导致数据库数据泄露，包括用户密码、个人信息等敏感数据。,"1. 使用参数化查询替代字符串拼接
2. 对用户输入进行严格的输入验证
3. 使用ORM框架"
```

> 模板文件位于 `sample_reports/custom_translation_template.csv`，可直接下载编辑。

### JSON 模板格式

```json
{
    "SQL Injection": {
        "name_zh": "SQL注入",
        "description_zh": "登录页面存在SQL注入漏洞...",
        "impact_zh": "可能导致数据库数据泄露...",
        "solution_zh": "1. 使用参数化查询..."
    }
}
```

> 模板文件位于 `sample_reports/custom_translation_template.json`。

### 导入自定义翻译库

1. 进入「漏洞管理」页面
2. 点击顶部操作栏的「翻译管理」按钮
3. 在弹出的翻译管理面板中，点击「导入」按钮
4. 选择准备好的 CSV 或 JSON 文件上传
5. 导入成功后会显示新增的翻译条目数量

### 导出/备份翻译库

1. 在翻译管理面板中，点击「导出」按钮
2. 选择导出格式（JSON 或 CSV）
3. 系统会自动下载当前自定义翻译库文件

---

## API 密钥与 Webhook

### API 密钥管理

用于保护 API 接口，适合团队协作和自动化集成。

1. 进入「设置」页面
2. 在 API 密钥管理区域点击「生成密钥」
3. 输入密钥名称，点击创建
4. **立即复制密钥**（仅显示一次）
5. 使用时在请求头中添加：`X-API-Key: your-api-key`

### Webhook 通知

当关键事件发生时，自动向配置的 URL 发送通知。

**支持的事件：**
- `report_generated` — 报告生成完成
- `vuln_imported` — 漏洞导入完成

**配置步骤：**
1. 进入「设置」页面
2. 在 Webhook 配置区域填写 URL
3. 选择需要通知的事件
4. 点击「创建」保存
5. 点击「测试」发送测试通知

**兼容平台：** 企业微信机器人、钉钉机器人、飞书机器人、Slack、自定义 Webhook

---

## 登录认证

系统内置了登录认证机制，保护 API 接口和敏感操作不被未授权访问。

### 默认密码

| 项目 | 值 |
|------|------|
| 默认密码 | `admin` |
| 修改方式 | 环境变量 `AUTH_PASSWORD` |

### 认证机制

系统支持两种认证方式：

| 方式 | 说明 | 使用场景 |
|------|------|---------|
| **Session 认证** | 浏览器登录后保持会话 | 前端页面操作 |
| **API Key 认证** | 请求头携带 `X-API-Key` | API 调用、自动化脚本 |

> API Key 认证可绕过 CSRF 检查，适合服务端调用。

### 修改密码

通过环境变量设置自定义密码：

```bash
# Linux/macOS
AUTH_PASSWORD=your_password python app.py

# Windows (CMD)
set AUTH_PASSWORD=your_password && python app.py

# Windows (PowerShell)
$env:AUTH_PASSWORD="your_password"; python app.py
```

### API 调用认证

```bash
# 方式一：先登录获取 Session
curl -c cookies.txt -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "admin"}'

# 后续请求携带 Cookie
curl -b cookies.txt http://localhost:5000/api/vulnerabilities

# 方式二：使用 API Key
curl -H "X-API-Key: your-api-key" http://localhost:5000/api/vulnerabilities
```

---

## API 接口文档

所有接口返回 JSON 格式数据。需要认证的接口请在请求头中添加 `X-API-Key`。

### 基础接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/stats` | 获取增强统计数据（含 CVSS/状态分布） |
| POST | `/api/language` | 切换界面语言 |

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录认证（`{"password": "xxx"}`） |
| POST | `/api/auth/logout` | 登出 |
| GET | `/api/auth/status` | 获取当前认证状态 |

### 漏洞管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/vulnerabilities` | 获取漏洞列表（支持分页 `page`/`page_size`、搜索 `search`、筛选 `severity`/`status`/`scanner_source`） |
| POST | `/api/vulnerabilities` | 添加漏洞 |
| PUT | `/api/vulnerabilities/<id>` | 更新指定漏洞 |
| DELETE | `/api/vulnerabilities/<id>` | 删除指定漏洞 |
| DELETE | `/api/vulnerabilities` | 清空所有漏洞 |

### CVSS 与状态

| 方法 | 路径 | 说明 |
|------|------|------|
| PUT | `/api/vulnerabilities/<id>/cvss` | 更新 CVSS 评分（支持传入 `cvss_vector` 自动计算或直接传入 `cvss_score`） |
| PUT | `/api/vulnerabilities/<id>/status` | 更新漏洞状态 |
| POST | `/api/vulnerabilities/deduplicate` | 漏洞去重检测与合并 |

### 漏洞翻译

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/vulnerabilities/translate` | 翻译所有漏洞 |
| POST | `/api/vulnerabilities/<id>/translate` | 翻译单个漏洞 |

### 翻译库管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/translations/import` | 导入自定义翻译字典（CSV/JSON 文件上传） |
| GET | `/api/translations` | 获取自定义字典内容（支持 `search`、`page`、`page_size`） |
| DELETE | `/api/translations/<key>` | 删除指定翻译条目 |
| POST | `/api/translations/export` | 导出自定义字典（JSON/CSV） |
| GET | `/api/translations/stats` | 获取翻译统计信息 |

### 翻译配置（在线翻译）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/translation/config` | 获取翻译配置（模式 + API 列表） |
| POST | `/api/translation/mode` | 设置翻译模式（`offline`/`online`/`hybrid`） |
| POST | `/api/translation/apis` | 保存翻译 API 配置 |
| DELETE | `/api/translation/apis/<id>` | 删除翻译 API 配置 |
| POST | `/api/translation/apis/activate` | 激活指定翻译 API |
| POST | `/api/translation/apis/test` | 测试翻译 API 连接 |

### 导入扫描报告

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/import/upload` | 上传单个扫描器报告文件 |
| POST | `/api/import/upload-batch` | 批量上传多个扫描器报告文件 |
| POST | `/api/import/confirm` | 确认导入解析结果 |

### 报告生成

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/report/generate` | 生成报告（指定格式和模板） |
| POST | `/api/report/project-info` | 保存项目信息（含 `template_type`） |
| GET | `/api/report/preview` | 在线预览 HTML 报告 |
| GET | `/api/report/history` | 获取报告生成历史 |
| GET | `/api/report/download/<filename>` | 下载已生成的报告 |

### API 密钥管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/settings/api-keys` | 创建 API 密钥 |
| GET | `/api/settings/api-keys` | 列出所有 API 密钥 |
| DELETE | `/api/settings/api-keys/<id>` | 吊销 API 密钥 |

### Webhook 管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/settings/webhooks` | 创建 Webhook |
| GET | `/api/settings/webhooks` | 列出所有 Webhook |
| DELETE | `/api/settings/webhooks/<id>` | 删除 Webhook |
| POST | `/api/settings/webhooks/test` | 测试 Webhook |

### 请求/响应示例

#### 添加漏洞（含 CVSS 向量）

```bash
curl -X POST http://localhost:5000/api/vulnerabilities \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_id": "CVE-2024-0001",
    "name": "SQL Injection",
    "severity": "critical",
    "target": "http://example.com/login",
    "port": "443",
    "protocol": "HTTPS",
    "description": "A SQL injection vulnerability was found in the login page.",
    "impact": "Database compromise, data leakage",
    "solution": "Use parameterized queries",
    "poc_steps": "1. Navigate to /login\n2. Enter '\'' OR 1=1--\n3. Observe error",
    "scanner_source": "Burp Suite",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "discovered"
  }'
```

响应：
```json
{
  "success": true,
  "message": "Vulnerability added successfully",
  "vulnerability": {
    "id": "uuid-string",
    "name": "SQL Injection",
    "severity": "critical",
    "cvss_score": 9.8,
    "status": "discovered",
    ...
  }
}
```

#### 分页查询漏洞

```bash
curl "http://localhost:5000/api/vulnerabilities?page=1&page_size=10&severity=high&search=SQL"
```

响应：
```json
{
  "success": true,
  "vulnerabilities": [...],
  "total": 42,
  "page": 1,
  "page_size": 10,
  "total_pages": 5
}
```

#### 漏洞去重

```bash
curl -X POST http://localhost:5000/api/vulnerabilities/deduplicate
```

响应：
```json
{
  "success": true,
  "duplicate_count": 5,
  "merged_count": 3,
  "groups": [
    {
      "canonical": {...},
      "duplicates": [{...}, {...}],
      "match_type": "exact",
      "similarity": 1.0
    }
  ]
}
```

#### 生成 DefectDojo 格式报告

```bash
curl -X POST http://localhost:5000/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{
    "format": "defectdojo",
    "language": "zh",
    "template_type": "professional"
  }'
```

---

## 配置说明

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FLASK_DEBUG` | `False` | 调试模式（生产环境请保持 False） |
| `FLASK_HOST` | `127.0.0.1` | 监听地址（`0.0.0.0` 允许外部访问） |
| `FLASK_PORT` | `5000` | 监听端口 |
| `SECRET_KEY` | 自动生成 | 会话签名密钥（自动持久化到 `data/.secret_key`） |
| `AUTH_PASSWORD` | `admin` | 登录认证密码 |

### 数据存储

| 数据 | 存储位置 | 说明 |
|------|---------|------|
| 漏洞数据 | `data/sec_report.db` | SQLite 数据库，重启不丢失 |
| 上传文件 | `uploads/` 或 `data/uploads/` | 扫描器报告文件 |
| 应用日志 | `data/app.log` | Flask 应用日志（自动轮转，最大 5MB × 3） |
| 客户端日志 | `debug.log` | Electron 主进程日志 |
| 自定义翻译 | `data/custom_translations/` | 导入的翻译字典 |
| 用户设置 | `settings.json` | 桌面版用户配置（关闭行为、保持登录等） |

---

## 常见问题

### Q: 启动时提示 "No module named flask"
**A:** 依赖未安装成功，请重新执行：
```bash
pip install -r requirements.txt
```

### Q: pip 安装依赖时报错
**A:** 尝试以下方案：
```bash
# 方案1：升级 pip
python -m pip install --upgrade pip

# 方案2：使用国内镜像
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 方案3：macOS/Linux 用户
pip3 install -r requirements.txt --break-system-packages
```

### Q: 端口 5000 被占用怎么办？
**A:** 通过环境变量修改端口：
```bash
# Linux/macOS
FLASK_PORT=8080 python app.py

# Windows (CMD)
set FLASK_PORT=8080 && python app.py

# Windows (PowerShell)
$env:FLASK_PORT="8080"; python app.py
```

### Q: 如何让局域网其他电脑访问？
**A:** 启动时监听所有网络接口：
```bash
FLASK_HOST=0.0.0.0 python app.py
```
然后其他电脑访问 `http://你的IP:5000`

> ⚠️ 生产环境请同时配置防火墙规则和 API 密钥认证。

### Q: 上传文件后解析结果为空？
**A:** 请确认：
1. 文件格式与扫描器匹配（如 Nmap 需要导出 XML 格式）
2. 文件不是空文件或损坏文件
3. 系统支持该扫描器类型

### Q: 生成的 PDF 中文显示为方块？
**A:** PDF 生成依赖系统字体。

**Linux：**
```bash
# Ubuntu/Debian
sudo apt install fonts-wqy-microhei

# CentOS/RHEL
sudo yum install wqy-microhei-fonts
```

**macOS：**
```bash
# 安装 Xcode 命令行工具（包含基础字体）
xcode-select --install
```

**Windows：**
> Windows 系统默认包含中文字体（微软雅黑、宋体等），通常不会出现此问题。

### Q: 安装依赖时 weasyprint 报错怎么办？
**A:** `weasyprint` 是 PDF 生成的可选依赖，需要 C 编译环境。安装失败不影响其他功能（Word/Excel/HTML 等格式正常使用）。

**如果需要 PDF 功能，按以下方式安装：**

**Linux：**
```bash
# 先安装系统依赖
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev

# 再安装 weasyprint
pip install weasyprint
```

**macOS：**
```bash
# 先安装 Xcode 命令行工具
xcode-select --install

# 再安装 weasyprint
pip install weasyprint
```

**Windows：**
1. 下载安装 [GTK 运行时](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer)（`gtk3-runtime-xxx-win64.exe`），安装时勾选 "Add to PATH"
2. 重启命令行窗口
3. `pip install weasyprint`

> 💡 **不想折腾？** 直接使用 Word (.docx) 格式生成报告即可，功能完全一致，兼容性更好。

### Q: 翻译效果不理想怎么办？
**A:** 可以通过以下方式改善：
1. **导入自定义翻译库**：按照模板格式准备 CSV/JSON 翻译对照表
2. **手动编辑**：在漏洞管理页面直接编辑翻译后的内容
3. **扩展术语字典**：在 `app/translations/security_glossary.py` 中添加更多术语

### Q: 如何重新生成 10000 条漏洞数据库？
**A:** 运行生成脚本：
```bash
cd sec-report-generator
python -m app.translations.generate_vuln_db
```

### Q: 数据重启后还在吗？
**A:** 是的。所有数据存储在 SQLite 数据库中（`data/sec_report.db`），重启服务不会丢失。如需清空数据，删除该文件后重启即可。

### Q: 如何停止服务？
**A:** 在终端中按 `Ctrl + C` 即可停止。

### Q: 默认登录密码是什么？如何修改？
**A:** 默认密码为 `admin`。通过环境变量修改：
```bash
AUTH_PASSWORD=your_new_password python app.py
```

### Q: 在线翻译 API 连接失败怎么办？
**A:** 请检查：
1. 网络是否通畅，能否访问翻译 API 地址
2. API Key 是否正确（DeepL 等需要 API Key 的服务）
3. 在设置页面点击「测试连接」诊断问题
4. Google Translate 非官方接口可能不稳定，可换用 LibreTranslate 或 DeepL
5. 也可使用「混合翻译」模式，离线兜底保证基本翻译效果

### Q: 如何使用桌面版？
**A:** 运行 `start_desktop.bat`（Windows）或 `bash start_desktop.sh`（macOS/Linux），会自动启动 Electron 桌面窗口。需要先安装 Node.js 依赖：`npm install`。

### Q: 桌面版和浏览器版有什么区别？
**A:** 功能完全一致，桌面版额外提供系统托盘、文件拖拽、桌面通知、快捷键、自动更新、保持登录等原生体验。数据互通，可以同时使用两种方式访问。

### Q: 桌面版关闭窗口后程序还在运行吗？
**A:** 默认行为是关闭窗口后最小化到系统托盘，程序继续在后台运行。可以在「设置 → 桌面版设置 → 关闭行为」中修改为"弹出确认"或"直接退出"。双击托盘图标可重新打开窗口。

### Q: 桌面版如何设置关闭后保持登录？
**A:** 在「设置 → 桌面版设置」中开启"关闭后保持登录"开关。开启后关闭程序不会自动退出登录，下次打开无需重新输入密码。关闭此开关后，每次关闭程序都会自动退出登录。

### Q: 桌面版报告保存在哪里？
**A:** 桌面版生成报告后会弹出"另存为"对话框，由用户自由选择保存位置。菜单栏的"打开导出目录"会打开上次保存报告的文件夹。如果从未保存过报告，则打开系统"文档"目录。

### Q: 桌面版如何检查更新？
**A:** 点击菜单栏「帮助 → 检查更新」，系统会自动检测是否有新版本。如有新版本，可选择下载并安装。也可在「设置 → 桌面版设置」中检查更新。

### Q: 支持哪些文件类型上传？
**A:** 系统会校验文件扩展名，支持的扩展名包括：`.xml`, `.json`, `.csv`, `.html`, `.xlsx`, `.xls`, `.pdf`, `.docx`, `.doc`, `.txt`, `.sarif`。其他类型将被拒绝。

---

## 技术栈

| 层级 | 技术 |
|------|------|
| **后端框架** | Python + Flask |
| **数据库** | SQLite（标准库，零依赖） |
| **前端** | HTML + Tailwind CSS + JavaScript + Chart.js |
| **报告生成** | python-docx / weasyprint / openpyxl / Jinja2 |
| **报告解析** | BeautifulSoup4 / lxml / openpyxl |
| **CVSS 计算** | 内置 CVSS v3.1 引擎（纯 Python 实现） |
| **去重引擎** | difflib.SequenceMatcher 模糊匹配 |
| **离线翻译** | 内置术语字典 + 正则模式匹配 + 漏洞描述数据库 |
| **在线翻译** | LibreTranslate / Google Translate / DeepL / 自定义 REST API |
| **桌面客户端** | Electron（跨平台桌面应用） |
| **安全** | 登录认证 / CSRF 防护 / CSP 安全头 / API Key / 速率限制 / XSS 防护 |

---

## 项目结构

```
sec-report-generator/
├── app.py                          # 应用入口（启动这个）
├── start_desktop.py                # 桌面应用启动器
├── start_desktop.bat               # Windows 桌面启动脚本
├── start_desktop.sh                # macOS/Linux 桌面启动脚本
├── config.py                       # 配置文件（扫描器/格式/I18N）
├── requirements.txt                # Python 依赖
├── package.json                    # Electron 依赖与打包配置
├── electron/                       # Electron 桌面客户端
│   ├── main.js                     # Electron 主进程
│   ├── preload.js                  # IPC 安全桥接
│   └── desktop-enhance.js          # 桌面增强（托盘/拖拽/通知/SRI）
├── app/
│   ├── __init__.py                 # Flask 应用工厂 + 数据库初始化
│   ├── database.py                 # SQLite 数据库层（8 张表）
│   ├── models/                     # 数据模型
│   │   └── vulnerability.py        # 统一漏洞模型 + 项目信息
│   ├── parsers/                    # 扫描器报告解析器（11 款）
│   │   ├── nmap_parser.py          # Nmap (XML)
│   │   ├── nessus_parser.py        # Nessus (CSV/JSON)
│   │   ├── burp_parser.py          # Burp Suite (XML)
│   │   ├── awvs_parser.py          # AWVS (XML/JSON)
│   │   ├── zap_parser.py           # OWASP ZAP (XML/JSON)
│   │   ├── xray_parser.py          # Xray (JSON)
│   │   ├── nuclei_parser.py        # Nuclei (JSON)
│   │   ├── sqlmap_parser.py        # Sqlmap (JSON/CSV)
│   │   ├── nsfocus_parser.py       # 绿盟 RSAS (HTML/XML/Excel)
│   │   ├── anheng_parser.py        # 安恒明鉴 (HTML/Excel)
│   │   └── venustech_parser.py     # 启明星辰天镜 (HTML/XML/Excel)
│   ├── generators/                 # 报告生成器（14 种格式）
│   │   ├── word_generator.py       # Word (.docx)
│   │   ├── pdf_generator.py        # PDF
│   │   ├── excel_generator.py      # Excel (.xlsx)
│   │   ├── html_generator.py       # HTML
│   │   ├── xml_generator.py        # XML
│   │   ├── json_generator.py       # JSON
│   │   ├── csv_generator.py        # CSV
│   │   ├── txt_generator.py        # TXT
│   │   ├── markdown_generator.py   # Markdown
│   │   ├── defectdojo_generator.py # DefectDojo (JSON)
│   │   └── jira_generator.py       # Jira (CSV)
│   ├── utils/                      # 工具模块
│   │   ├── cvss.py                 # CVSS v3.1 评分计算引擎
│   │   └── dedup.py                # 漏洞去重引擎
│   ├── translations/               # 翻译模块
│   │   ├── security_glossary.py    # 术语字典（700+ 条）
│   │   ├── vuln_descriptions.py    # TOP 100 高频漏洞描述翻译库
│   │   ├── vuln_db_10000.json      # 10000 条漏洞数据库
│   │   ├── generate_vuln_db.py     # 数据库生成脚本
│   │   ├── translator.py           # 离线翻译引擎
│   │   ├── online_translator.py    # 在线翻译引擎（LibreTranslate/Google/DeepL/自定义）
│   │   ├── online.py               # 在线翻译模块入口
│   │   └── custom_dictionary.py    # 自定义翻译字典管理
│   ├── routes/                     # Web 路由和 API
│   │   ├── main.py                 # 首页 + 统计 API
│   │   ├── import_route.py         # 导入（单文件 + 批量）
│   │   ├── vuln.py                 # 漏洞 CRUD + CVSS + 去重 + 翻译
│   │   ├── report.py               # 报告生成 + 预览 + 历史
│   │   ├── settings.py             # 设置（认证/API Key/Webhook/代理）
│   │   └── log.py                  # 日志查看与管理
│   ├── templates/                  # HTML 页面模板
│   └── static/                     # CSS 和 JS 静态文件
├── sample_reports/                 # 示例报告文件（17 个）
│   ├── sample_nmap.xml
│   ├── sample_nessus.csv / .json
│   ├── sample_burp.xml
│   ├── sample_awvs.xml / .json
│   ├── sample_zap.xml / .json
│   ├── sample_xray.json
│   ├── sample_nuclei.json
│   ├── sample_sqlmap.json
│   ├── sample_nsfocus.html / .xlsx
│   ├── sample_anheng.html / .xlsx
│   ├── sample_venustech.html / .xlsx
│   ├── custom_translation_template.csv
│   └── custom_translation_template.json
├── data/                           # 数据目录
│   ├── sec_report.db               # SQLite 数据库
│   └── custom_translations/        # 自定义翻译字典
├── uploads/                        # 上传文件存放目录
└── exports/                        # 生成的报告存放目录
```
