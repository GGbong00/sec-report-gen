const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell, Notification, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const net = require('net');
const fs = require('fs');

// ============================================================
// 配置
// ============================================================
const CONFIG = {
  appName: '安全报告生成器',
  appVersion: '2.0.0',
  flaskPort: 53789,  // 使用非标准端口避免冲突
  flaskHost: '127.0.0.1',
  windowWidth: 1400,
  windowHeight: 900,
  minWidth: 1024,
  minHeight: 700,
  trayIcon: null,
};

// ============================================================
// 全局状态
// ============================================================
let mainWindow = null;
let tray = null;
let flaskProcess = null;
let isQuitting = false;
let lastReportDir = null; // 最后保存报告的目录
let resolvedDataDir = null; // 统一的数据目录路径
let isFlaskReady = false;

// ============================================================
// Flask 后端管理
// ============================================================

/**
 * 查找可用端口
 */
function findAvailablePort(startPort) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(startPort, CONFIG.flaskHost, () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', () => {
      resolve(findAvailablePort(startPort + 1));
    });
  });
}

/**
 * 检测端口是否可用
 */
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, CONFIG.flaskHost, () => {
      server.close(() => resolve(true));
    });
    server.on('error', () => resolve(false));
  });
}

/**
 * 等待 Flask 服务启动
 */
function waitForFlask(port, maxRetries = 30, interval = 1000) {
  return new Promise((resolve, reject) => {
    let retries = 0;
    const check = () => {
      const socket = net.createConnection(port, CONFIG.flaskHost);
      socket.on('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.on('error', () => {
        retries++;
        if (retries >= maxRetries) {
          reject(new Error('Flask 服务启动超时'));
        } else {
          setTimeout(check, interval);
        }
      });
      socket.setTimeout(interval);
      socket.on('timeout', () => {
        socket.destroy();
        retries++;
        if (retries >= maxRetries) {
          reject(new Error('Flask 服务启动超时'));
        } else {
          setTimeout(check, interval);
        }
      });
    };
    check();
  });
}

/**
 * 在应用内打开文档窗口
 */
function openDocWindow(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');

  const docWin = new BrowserWindow({
    title: '使用文档',
    width: 900,
    height: 700,
    minWidth: 600,
    minHeight: 400,
    parent: mainWindow,
    modal: false,
    backgroundColor: '#0f172a',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  // 简单的 Markdown 转 HTML（不依赖外部库）
  let html = content
    // 代码块
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code class="lang-$1">$2</code></pre>')
    // 标题（添加锚点 id）
    .replace(/^### (.+)$/gm, (_, text) => {
      const id = text.replace(/[^\w\u4e00-\u9fff]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
      return `<h3 id="${id}">${text}</h3>`;
    })
    .replace(/^## (.+)$/gm, (_, text) => {
      const id = text.replace(/[^\w\u4e00-\u9fff]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
      return `<h2 id="${id}">${text}</h2>`;
    })
    .replace(/^# (.+)$/gm, (_, text) => {
      const id = text.replace(/[^\w\u4e00-\u9fff]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
      return `<h1 id="${id}">${text}</h1>`;
    })
    // 粗体、斜体、行内代码
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code class="inline">$1</code>')
    // 链接（锚点链接不加 target="_blank"）
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, href) => {
      if (href.startsWith('#')) {
        return `<a href="${href}">${text}</a>`;
      }
      return `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
    })
    // 图片
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width:100%;border-radius:8px;margin:12px 0;">')
    // 表格
    .replace(/^\|(.+)\|$/gm, (match, content) => {
      const cells = content.split('|').map(c => c.trim());
      if (cells.every(c => /^[-:]+$/.test(c))) return '';
      const isHeader = false;
      const tag = isHeader ? 'th' : 'td';
      return '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
    })
    // 无序列表
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    // 引用
    .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
    // 水平线
    .replace(/^---$/gm, '<hr>')
    // 段落（两个换行）
    .replace(/\n\n/g, '</p><p>')
    // 单换行
    .replace(/\n/g, '<br>');

  // 包裹列表
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
  html = html.replace(/<\/ul>\s*<ul>/g, '');

  // 包裹表格
  html = html.replace(/(<tr>[\s\S]*?<\/tr>)/g, '<table>$1</table>');
  html = html.replace(/<\/table>\s*<table>/g, '');

  const fullHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>使用文档</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
    background-color: #0f172a;
    color: #e2e8f0;
    line-height: 1.7;
    padding: 2rem 3rem;
    font-size: 15px;
  }
  h1 { color: #f8fafc; font-size: 1.8rem; margin: 1.5rem 0 0.75rem; padding-bottom: 0.5rem; border-bottom: 2px solid #334155; }
  h2 { color: #f1f5f9; font-size: 1.4rem; margin: 1.5rem 0 0.5rem; padding-bottom: 0.3rem; border-bottom: 1px solid #334155; }
  h3 { color: #e2e8f0; font-size: 1.15rem; margin: 1.2rem 0 0.4rem; }
  a { color: #60a5fa; text-decoration: none; }
  a:hover { text-decoration: underline; }
  code.inline {
    background-color: #1e293b;
    color: #fbbf24;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.9em;
    font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
  }
  pre {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    overflow-x: auto;
    margin: 0.75rem 0 1rem;
    font-size: 0.875rem;
    line-height: 1.5;
  }
  pre code {
    color: #e2e8f0;
    font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.75rem 0 1rem;
    font-size: 0.9rem;
  }
  th, td {
    padding: 0.6rem 1rem;
    border: 1px solid #334155;
    text-align: left;
  }
  th { background-color: #1e293b; color: #cbd5e1; font-weight: 600; }
  td { color: #94a3b8; }
  tr:hover td { background-color: rgba(51, 65, 85, 0.3); }
  blockquote {
    border-left: 4px solid #3b82f6;
    padding: 0.5rem 1rem;
    margin: 0.75rem 0;
    background-color: rgba(59, 130, 246, 0.08);
    color: #cbd5e1;
    border-radius: 0 6px 6px 0;
  }
  ul { padding-left: 1.5rem; margin: 0.5rem 0; }
  li { color: #cbd5e1; margin: 0.25rem 0; }
  hr { border: none; border-top: 1px solid #334155; margin: 1.5rem 0; }
  strong { color: #f1f5f9; }
  em { color: #94a3b8; }
  img { max-width: 100%; }
  html { scroll-behavior: smooth; }
  h1, h2, h3 { scroll-margin-top: 1.5rem; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: #0f172a; }
  ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: #475569; }
</style>
</head>
<body>
<div style="max-width: 900px; margin: 0 auto;">
  <p>${html}</p>
</div>
</body>
</html>`;

  docWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(fullHtml));

  // 页面加载完成后注入锚点跳转脚本
  docWin.webContents.on('did-finish-load', () => {
    docWin.webContents.executeJavaScript(`
      document.addEventListener('click', function(e) {
        var link = e.target.closest('a');
        if (link && link.getAttribute('href') && link.getAttribute('href').startsWith('#')) {
          e.preventDefault();
          var target = document.querySelector(link.getAttribute('href'));
          if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }
      });
    `);
  });

  // 阻止新窗口打开，外部链接用系统浏览器
  docWin.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });
}

/**
 * 写入调试日志
 */
function writeDebugLog(msg) {
  const logPath = path.join(process.resourcesPath || path.dirname(process.execPath), 'debug.log');
  const timestamp = new Date().toISOString();
  fs.appendFileSync(logPath, `[${timestamp}] ${msg}\n`);
  console.log(msg);
}

/**
 * 获取 Python 可执行文件路径
 */
function getPythonPath() {
  const { execSync } = require('child_process');

  writeDebugLog('[Debug] 开始搜索 Python...');

  // 优先使用虚拟环境
  const venvPaths = [
    path.join(process.resourcesPath, 'python', 'python.exe'),
    path.join(process.resourcesPath, 'python', 'bin', 'python'),
    path.join(__dirname, 'venv', 'Scripts', 'python.exe'),
    path.join(__dirname, 'venv', 'bin', 'python'),
    path.join(__dirname, '.venv', 'Scripts', 'python.exe'),
    path.join(__dirname, '.venv', 'bin', 'python'),
  ];

  for (const p of venvPaths) {
    writeDebugLog(`[Debug] 检查虚拟环境: ${p}`);
    if (fs.existsSync(p)) {
      writeDebugLog(`[Debug] 找到虚拟环境 Python: ${p}`);
      return p;
    }
  }

  // Windows 下优先尝试 py launcher（更可靠）
  if (process.platform === 'win32') {
    try {
      writeDebugLog('[Debug] 尝试 py launcher...');
      // py launcher 会自动找到已安装的 Python
      execSync('py --version', { encoding: 'utf-8', timeout: 5000 });
      writeDebugLog('[Debug] py launcher 可用，使用 py');
      return 'py';
    } catch (e) {
      writeDebugLog(`[Debug] py launcher 不可用: ${e.message}`);
    }
  }

  // 通过 where/which 命令搜索系统 Python 完整路径
  try {
    const cmd = process.platform === 'win32' ? 'where python' : 'which python3 || which python';
    writeDebugLog(`[Debug] 执行命令: ${cmd}`);
    const result = execSync(cmd, { encoding: 'utf-8', timeout: 5000 }).trim();
    if (result) {
      const lines = result.split('\n');
      for (const line of lines) {
        const pythonPath = line.trim();
        if (!pythonPath) continue;
        writeDebugLog(`[Debug] 检查 Python 路径: ${pythonPath}`);
        // 跳过 Windows Store 的 AppExecutionAlias（虚假路径）
        if (pythonPath.includes('WindowsApps') || pythonPath.includes('Microsoft')) {
          writeDebugLog(`[Debug] 跳过 Windows Store 路径: ${pythonPath}`);
          continue;
        }
        // 验证文件真实存在
        try {
          const stats = fs.statSync(pythonPath);
          if (stats.isFile()) {
            writeDebugLog(`[Debug] 找到有效 Python: ${pythonPath}`);
            return pythonPath;
          }
        } catch (statErr) {
          writeDebugLog(`[Debug] 路径不存在或无法访问: ${pythonPath}, error: ${statErr.message}`);
        }
      }
    }
  } catch (e) {
    writeDebugLog(`[Debug] where/which python failed: ${e.message}`);
  }

  // 尝试常见安装路径
  const commonPaths = [
    'C:\\Python312\\python.exe',
    'C:\\Python311\\python.exe',
    'C:\\Python310\\python.exe',
    'C:\\Python39\\python.exe',
    'C:\\Python38\\python.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python312', 'python.exe'),
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python311', 'python.exe'),
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python310', 'python.exe'),
  ];
  for (const p of commonPaths) {
    writeDebugLog(`[Debug] 检查常见路径: ${p}`);
    try {
      if (fs.existsSync(p)) {
        writeDebugLog(`[Debug] 找到常见路径 Python: ${p}`);
        return p;
      }
    } catch (e) {}
  }

  // 回退到系统 Python
  writeDebugLog('[Debug] 回退到系统 Python');
  return process.platform === 'win32' ? 'python' : 'python3';
}

/**
 * 获取项目根目录
 */
function getAppRoot() {
  writeDebugLog('[Debug] 开始搜索项目根目录...');
  writeDebugLog(`[Debug] process.resourcesPath: ${process.resourcesPath}`);
  writeDebugLog(`[Debug] process.execPath: ${process.execPath}`);
  writeDebugLog(`[Debug] __dirname: ${__dirname}`);

  // 安装版/便携版: extraResources 复制到 resources/ 根目录
  const resourcesDir = process.resourcesPath;
  if (fs.existsSync(path.join(resourcesDir, 'app.py'))) {
    writeDebugLog(`[Debug] 找到项目根目录 (resources): ${resourcesDir}`);
    return resourcesDir;
  }

  // 开发模式
  if (fs.existsSync(path.join(__dirname, 'app.py'))) {
    writeDebugLog(`[Debug] 找到项目根目录 (__dirname): ${__dirname}`);
    return __dirname;
  }

  // 当前工作目录
  if (fs.existsSync(path.join(process.cwd(), 'app.py'))) {
    writeDebugLog(`[Debug] 找到项目根目录 (cwd): ${process.cwd()}`);
    return process.cwd();
  }

  // 最后回退
  writeDebugLog(`[Debug] 项目根目录 (默认回退): ${resourcesDir}`);
  return resourcesDir;
}

/**
 * 启动 Flask 后端
 */
async function startFlask() {
  const port = await findAvailablePort(CONFIG.flaskPort);
  CONFIG.flaskPort = port;

  const appRoot = getAppRoot();
  const python = getPythonPath();

  // 提前判断运行模式（后面多处需要用到）
  const exeDir = path.dirname(process.execPath);
  const isInstalled = fs.existsSync(path.join(exeDir, 'uninstall.exe'));
  const isDevMode = fs.existsSync(path.join(__dirname, 'app.py'));

  // ============================================================
  // 内置 Python 依赖（打包时预装，完全离线可用）
  // ============================================================
  const builtinLibsDir = path.join(appRoot, 'python_libs');
  const hasBuiltinLibs = fs.existsSync(builtinLibsDir);
  if (hasBuiltinLibs) {
    writeDebugLog(`[GUI] 检测到内置依赖目录: ${builtinLibsDir}`);
  }

  writeDebugLog(`[Debug] exeDir: ${exeDir}`);
  writeDebugLog(`[Debug] process.execPath: ${process.execPath}`);
  writeDebugLog(`[Debug] process.resourcesPath: ${process.resourcesPath}`);
  writeDebugLog(`[Debug] isInstalled: ${isInstalled}`);
  writeDebugLog(`[Debug] isDevMode: ${isDevMode}`);
  writeDebugLog(`[Debug] hasBuiltinLibs: ${hasBuiltinLibs}`);

  // ============================================================
  // 自动安装 Python 依赖（仅在没有内置依赖时）
  // ============================================================
  if (!isDevMode && !hasBuiltinLibs) {
    const requirementsFile = path.join(appRoot, 'requirements.txt');
    const depInstalledFlag = path.join(app.getPath('userData'), '.deps_prompted');

    if (fs.existsSync(requirementsFile) && !fs.existsSync(depInstalledFlag)) {
      writeDebugLog('[GUI] 首次启动，询问用户是否安装依赖...');

      const { response } = await dialog.showMessageBox({
        type: 'info',
        title: '安装依赖',
        message: '是否自动安装 Python 依赖？',
        detail: '应用需要安装 Python 依赖库才能正常运行。\n\n点击"自动安装"将自动下载并安装所有依赖（需要联网）。\n点击"跳过"将直接打开应用，请稍后自行运行 pip install -r requirements.txt。',
        buttons: ['自动安装', '跳过'],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      });

      if (response === 1) {
        // 用户选择跳过，标记已提示过，下次不再弹窗
        writeDebugLog('[GUI] 用户选择跳过依赖安装');
        try { fs.writeFileSync(depInstalledFlag, 'skipped'); } catch (e) { /* ignore */ }
      } else {
        // 用户确认自动安装
        writeDebugLog('[GUI] 用户确认自动安装，开始安装...');
        try {
          const { spawn } = require('child_process');

          const installWin = new BrowserWindow({
              width: 560,
              height: 320,
              resizable: false,
              minimizable: false,
              maximizable: false,
              title: '正在安装依赖...',
              backgroundColor: '#0f172a',
              show: true,
              webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
              },
            });

            // 辅助函数：安全更新页面 DOM
            function updateInstallPage(jsCode) {
              try {
                if (installWin && !installWin.isDestroyed()) {
                  installWin.webContents.executeJavaScript(jsCode);
                }
              } catch (e) { /* ignore */ }
            }

            // 加载安装进度页面
            installWin.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(`
              <!DOCTYPE html>
              <html>
              <head><style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { display: flex; flex-direction: column; height: 100vh; background: #0f172a;
                       color: #e2e8f0; font-family: -apple-system, 'Segoe UI', sans-serif; padding: 24px 28px; }
                .header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
                .spinner { width: 28px; height: 28px; border: 3px solid #334155; border-top-color: #3b82f6;
                           border-radius: 50%; animation: spin 0.8s linear infinite; flex-shrink: 0; }
                @keyframes spin { to { transform: rotate(360deg); } }
                .title { font-size: 15px; font-weight: 600; }
                .progress-wrap { width: 100%; height: 6px; background: #1e293b; border-radius: 3px;
                                 overflow: hidden; margin-bottom: 12px; }
                .progress-bar { width: 0%; height: 100%; background: linear-gradient(90deg, #3b82f6, #6366f1);
                                border-radius: 3px; transition: width 0.4s ease; }
                .status { font-size: 13px; color: #94a3b8; margin-bottom: 14px; min-height: 20px; }
                .log-area { flex: 1; overflow-y: auto; background: #1e293b; border-radius: 8px;
                            padding: 10px 12px; font-size: 11px; color: #64748b; line-height: 1.7; }
                .log-area .pkg { color: #94a3b8; }
                .log-area .ok { color: #4ade80; }
                .log-area .err { color: #f87171; }
                .log-area .info { color: #60a5fa; }
              </style></head>
              <body>
                <div class="header">
                  <div class="spinner" id="spinner"></div>
                  <div class="title">正在安装 Python 依赖，请稍候...</div>
                </div>
                <div class="progress-wrap"><div class="progress-bar" id="progress"></div></div>
                <div class="status" id="status">准备中...</div>
                <div class="log-area" id="log"></div>
              </body></html>
            `)}`);

            // 用 Promise 等待安装完成，阻塞 startFlask 的后续流程
            await new Promise((resolve) => {
              installWin.webContents.on('did-finish-load', () => {
                try {
                  const { spawn } = require('child_process');

                  // 读取 requirements.txt 获取总包数
                  let totalPkgs = 0;
                  try {
                    const reqContent = fs.readFileSync(requirementsFile, 'utf-8');
                    totalPkgs = reqContent.split('\n').filter(l => l.trim() && !l.startsWith('#')).length;
                  } catch (e) { /* ignore */ }

                  let installedCount = 0;
                  const logLines = [];

                  function addLog(text, cls) {
                    logLines.push({ text, cls });
                    if (logLines.length > 50) logLines.shift();
                    const html = logLines.map(l => `<div class="${l.cls}">${l.text}</div>`).join('');
                    updateInstallPage(`document.getElementById('log').innerHTML = ${JSON.stringify(html)};document.getElementById('log').scrollTop=99999;`);
                  }

                  function updateStatus(text) {
                    updateInstallPage(`document.getElementById('status').textContent = ${JSON.stringify(text)};`);
                  }

                  function updateProgress(current, total) {
                    const pct = total > 0 ? Math.min(Math.round((current / total) * 100), 100) : 0;
                    updateInstallPage(`document.getElementById('progress').style.width = '${pct}%';`);
                  }

                  updateStatus(`共 ${totalPkgs} 个依赖包，正在安装...`);
                  addLog('开始安装 Python 依赖...', 'info');

                  const pip = spawn(python, [
                    '-m', 'pip', 'install', '-r', requirementsFile,
                    '--break-system-packages',
                  ], {
                    timeout: 300000,
                    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
                  });

                  pip.stdout.on('data', (data) => {
                    const lines = data.toString().split('\n');
                    for (const line of lines) {
                      const trimmed = line.trim();
                      if (!trimmed) continue;

                      const collecting = trimmed.match(/Collecting (.+)/);
                      if (collecting) {
                        const pkg = collecting[1].split(' (')[0].split('>=')[0].split('==')[0];
                        updateStatus(`正在安装: ${pkg}`);
                        addLog(`📦 ${pkg}`, 'pkg');
                      }

                      const downloading = trimmed.match(/Downloading (.+)/);
                      if (downloading) {
                        const fname = downloading[1].split('/').pop().substring(0, 50);
                        addLog(`⬇ ${fname}`, '');
                      }

                      const success = trimmed.match(/Successfully installed (.+)/);
                      if (success) {
                        installedCount++;
                        updateProgress(installedCount, totalPkgs);
                        addLog(`✅ 安装完成 (${installedCount}/${totalPkgs})`, 'ok');
                      }
                    }
                  });

                  pip.stderr.on('data', (data) => {
                    const lines = data.toString().split('\n');
                    for (const line of lines) {
                      const trimmed = line.trim();
                      if (!trimmed || trimmed.includes('WARNING: Retrying') || trimmed.includes('WARNING: There is')) continue;
                      if (trimmed.includes('already satisfied') || trimmed.includes('Requirement already satisfied')) {
                        const pkg = trimmed.match(/already satisfied:\s*(.+)/);
                        if (pkg) {
                          installedCount++;
                          updateProgress(installedCount, totalPkgs);
                          addLog(`⏭ 已安装: ${pkg[1].split(' (')[0].split('>=')[0].split('==')[0]}`, 'pkg');
                        }
                      }
                    }
                  });

                  pip.on('close', (code) => {
                    if (code === 0) {
                      updateStatus(`全部依赖安装完成 (${installedCount}/${totalPkgs})`);
                      updateProgress(totalPkgs, totalPkgs);
                      addLog('🎉 所有依赖安装完成，即将启动应用...', 'ok');
                      try { fs.writeFileSync(depInstalledFlag, 'installed'); } catch (e) { /* ignore */ }
                      updateInstallPage(`
                        document.getElementById('spinner').style.display = 'none';
                        document.querySelector('.title').textContent = '安装完成！';
                        document.querySelector('.title').style.color = '#4ade80';
                      `);
                      setTimeout(() => { installWin.close(); resolve(); }, 1500);
                    } else {
                      updateStatus(`安装遇到问题（退出码 ${code}），应用仍会尝试启动`);
                      addLog(`❌ 安装退出码: ${code}`, 'err');
                      addLog('', '');
                      addLog('请进入应用后手动安装依赖，或运行:', 'info');
                      addLog('  pip install -r requirements.txt --break-system-packages', 'info');
                      updateInstallPage(`
                        document.getElementById('spinner').style.borderTopColor = '#f87171';
                      `);
                      setTimeout(() => { installWin.close(); resolve(); }, 3000);
                    }
                  });

                  pip.on('error', (err) => {
                    addLog(`❌ 启动失败: ${err.message}`, 'err');
                    updateStatus('无法启动 pip，请检查 Python 环境');
                    setTimeout(() => { installWin.close(); resolve(); }, 3000);
                  });
                } catch (installErr) {
                  writeDebugLog(`[GUI] 依赖安装失败: ${installErr.message?.substring(0, 200)}`);
                  installWin.close();
                  resolve();
                }
              });
            });

            writeDebugLog('[GUI] Python 依赖安装流程结束');
        } catch (depErr) {
          // 依赖安装失败，记录日志但不阻止启动
          writeDebugLog(`[GUI] 依赖安装流程异常: ${depErr.message?.substring(0, 300)}`);
        }
      } // end if (response === 1) ... else
    }
  }

  // ============================================================
  // 数据目录解析（统一逻辑）
  // ============================================================
  // 便携版：使用 Electron userData 目录（跨平台可靠路径）
  //   Windows: C:\Users\xxx\AppData\Roaming\sec-report-generator\data\
  //   Linux:   ~/.config/sec-report-generator/data/
  //   macOS:   ~/Library/Application Support/sec-report-generator/data/
  // 安装版：exe 同级的 data/（卸载不丢失）
  // 开发模式：项目根目录下的 data/
  // ============================================================
  // exeDir / isInstalled / isDevMode 已在函数开头定义
  writeDebugLog(`[Debug] isDevMode: ${isDevMode}`);

  let dataDir;
  if (isDevMode) {
    // 开发模式：项目根目录下的 data/
    dataDir = path.join(appRoot, 'data');
  } else if (isInstalled) {
    // 安装版：安装根目录下的 data/
    dataDir = path.join(exeDir, 'data');
  } else {
    // 便携版：使用 Electron userData 目录（最可靠的持久化路径）
    dataDir = path.join(app.getPath('userData'), 'data');
  }

  writeDebugLog(`[Debug] dataDir (resolved): ${dataDir}`);
  resolvedDataDir = dataDir; // 保存到全局变量

  // 确保数据目录存在
  if (!fs.existsSync(dataDir)) {
    try {
      fs.mkdirSync(dataDir, { recursive: true });
      writeDebugLog(`[GUI] 创建数据目录: ${dataDir}`);
    } catch (err) {
      writeDebugLog(`[GUI] 创建数据目录失败: ${dataDir} - ${err.message}`);
    }
  }

  console.log(`[GUI] 启动 Flask: python=${python}, port=${port}, root=${appRoot}, data=${dataDir}`);

  const env = {
    ...process.env,
    FLASK_DEBUG: 'false',
    FLASK_HOST: CONFIG.flaskHost,
    FLASK_PORT: String(port),
    PYTHONIOENCODING: 'utf-8',
    SEC_REPORT_DATA_DIR: dataDir,
  };

  // 如果有内置依赖，加入 PYTHONPATH 优先加载
  if (hasBuiltinLibs) {
    const existingPath = env.PYTHONPATH || '';
    env.PYTHONPATH = builtinLibsDir + (existingPath ? path.delimiter + existingPath : '');
    writeDebugLog(`[GUI] PYTHONPATH: ${env.PYTHONPATH}`);
  }

  flaskProcess = spawn(python, ['app.py'], {
    cwd: appRoot,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });

  flaskProcess.stdout.on('data', (data) => {
    const msg = data.toString().trim();
    console.log(`[Flask] ${msg}`);
    if (msg.includes('Running on')) {
      isFlaskReady = true;
    }
  });

  flaskProcess.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) console.error(`[Flask:ERR] ${msg}`);
  });

  flaskProcess.on('error', (err) => {
    console.error(`[Flask] 启动失败: ${err.message}`);
    dialog.showErrorBox('启动失败',
      `无法启动后端服务: ${err.message}\n\n` +
      `请确认:\n` +
      `1. 已安装 Python 3.8+（python --version 验证）\n` +
      `2. 已安装依赖: pip install -r requirements.txt\n` +
      `3. Python 已添加到系统 PATH 环境变量\n\n` +
      `Python 路径: ${python}\n` +
      `工作目录: ${appRoot}`
    );
    app.quit();
  });

  flaskProcess.on('close', (code) => {
    console.log(`[Flask] 进程退出, code=${code}`);
    flaskProcess = null;
    isFlaskReady = false;
    if (!isQuitting) {
      // 非主动退出时尝试重启
      setTimeout(startFlask, 3000);
    }
  });

  try {
    await waitForFlask(port);
    isFlaskReady = true;
    console.log(`[GUI] Flask 已就绪: http://${CONFIG.flaskHost}:${port}`);
  } catch (err) {
    console.error(`[GUI] ${err.message}`);
    dialog.showErrorBox('启动超时', '后端服务启动超时，请检查 Python 环境和依赖。');
    app.quit();
  }
}

/**
 * 停止 Flask 后端
 */
function stopFlask() {
  if (flaskProcess) {
    flaskProcess.kill('SIGTERM');
    // Windows 下 SIGTERM 可能无效，使用 taskkill
    if (process.platform === 'win32') {
      try {
        execSync(`taskkill /pid ${flaskProcess.pid} /T /F`, { stdio: 'ignore' });
      } catch (e) { /* ignore */ }
    }
    flaskProcess = null;
  }
}

// ============================================================
// 窗口管理
// ============================================================

/**
 * 创建主窗口
 */
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: CONFIG.windowWidth,
    height: CONFIG.windowHeight,
    minWidth: CONFIG.minWidth,
    minHeight: CONFIG.minHeight,
    title: CONFIG.appName,
    icon: getWindowIcon(),
    backgroundColor: '#0f172a',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: true,
    },
  });

  // 窗口准备好后显示（避免白闪）
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (process.platform === 'darwin') {
      mainWindow.setRepresentedFilename(getAppRoot());
    }
  });

  // 加载 Flask 页面
  mainWindow.loadURL(`http://${CONFIG.flaskHost}:${CONFIG.flaskPort}?electron=1`);

  // 窗口关闭行为：根据设置决定是最小化、询问还是直接退出
  mainWindow.on('close', async (event) => {
    if (isQuitting) return;

    const behavior = appSettings.closeBehavior || 'minimize';
    console.log('[Window] Close behavior:', behavior, '| appSettings:', JSON.stringify(appSettings));

    if (behavior === 'minimize') {
      // 直接最小化到托盘
      event.preventDefault();
      mainWindow.hide();
      if (Notification.isSupported()) {
        new Notification({
          title: CONFIG.appName,
          body: '应用已最小化到系统托盘，双击图标可重新打开',
          silent: true,
        }).show();
      }
    } else if (behavior === 'ask') {
      // 弹出确认对话框
      event.preventDefault();
      dialog.showMessageBox(mainWindow, {
        type: 'question',
        title: CONFIG.appName,
        message: '确定要退出程序吗？',
        detail: '选择"最小化到托盘"将关闭窗口但保持后台运行。',
        buttons: ['直接退出', '最小化到托盘', '取消'],
        defaultId: 2,
        cancelId: 2,
        noLink: true,
      }).then(async ({ response }) => {
        if (response === 0) {
          // 先清除登录状态，再退出
          await _clearLoginBeforeQuit();
          isQuitting = true;
          app.quit();
        } else if (response === 1) {
          // 最小化到托盘
          mainWindow.hide();
          if (Notification.isSupported()) {
            new Notification({
              title: CONFIG.appName,
              body: '应用已最小化到系统托盘，双击图标可重新打开',
              silent: true,
            }).show();
          }
        }
        // response === 2: 取消，什么都不做
      }).catch(() => {});
    } else if (behavior === 'quit') {
      // 直接退出前弹出确认
      event.preventDefault();
      dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: CONFIG.appName,
        message: '确定要退出程序吗？',
        detail: '关闭窗口后程序将完全退出。',
        buttons: ['确定退出', '取消'],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      }).then(async ({ response }) => {
        if (response === 0) {
          // 先清除登录状态，再退出
          await _clearLoginBeforeQuit();
          isQuitting = true;
          app.quit();
        }
      }).catch(() => {});
    }
  });

  // 外部链接用系统浏览器打开
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        shell.openExternal(url);
      }
    } catch (e) { /* ignore */ }
    return { action: 'deny' };
  });

  // 开发模式打开 DevTools
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }
}

/**
 * 获取窗口图标
 */
function getWindowIcon() {
  const iconPaths = [
    path.join(__dirname, 'assets', 'icon.png'),
    path.join(__dirname, 'assets', 'icon.ico'),
    path.join(__dirname, 'icon.png'),
  ];
  for (const p of iconPaths) {
    if (fs.existsSync(p)) return p;
  }
  return undefined;
}

/**
 * 获取托盘图标
 */
function getTrayIcon() {
  const iconPath = getWindowIcon();
  if (iconPath && fs.existsSync(iconPath)) {
    return nativeImage.createFromPath(iconPath);
  }
  // 创建一个简单的 16x16 占位图标
  return nativeImage.createEmpty();
}

// ============================================================
// 系统托盘
// ============================================================

function createTray() {
  const icon = getTrayIcon();
  tray = new Tray(icon.resize({ width: 16, height: 16 }));
  tray.setToolTip(CONFIG.appName);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: '打开主窗口',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    { type: 'separator' },
    {
      label: '漏洞管理',
      click: () => navigateTo('/vulnerabilities'),
    },
    {
      label: '导入扫描结果',
      click: () => navigateTo('/import'),
    },
    {
      label: '生成报告',
      click: () => navigateTo('/report'),
    },
    { type: 'separator' },
    {
      label: '系统设置',
      click: () => navigateTo('/settings'),
    },
    { type: 'separator' },
    {
      label: '退出',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);

  // 双击托盘图标打开窗口
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

/**
 * 导航到指定页面
 */
function navigateTo(urlPath) {
  if (mainWindow) {
    // 验证路径安全
    if (!urlPath || !urlPath.startsWith('/') || urlPath.startsWith('//')) {
      console.warn(`[GUI] Blocked unsafe navigation: ${urlPath}`);
      return;
    }
    mainWindow.show();
    mainWindow.focus();
    mainWindow.loadURL(`http://${CONFIG.flaskHost}:${CONFIG.flaskPort}${urlPath}?electron=1`);
  }
}

// ============================================================
// 应用菜单
// ============================================================

function createMenu() {
  const isMac = process.platform === 'darwin';

  const template = [
    ...(isMac ? [{
      label: app.name,
      submenu: [
        { role: 'about', label: `关于 ${CONFIG.appName}` },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit', label: '退出' },
      ],
    }] : []),
    {
      label: '文件',
      submenu: [
        {
          label: '导入扫描结果',
          accelerator: 'CmdOrCtrl+O',
          click: () => navigateTo('/import'),
        },
        {
          label: '生成报告',
          accelerator: 'CmdOrCtrl+G',
          click: () => navigateTo('/report'),
        },
        { type: 'separator' },
        {
          label: '打开数据目录',
          click: () => {
            const dataDir = resolvedDataDir || path.join(getAppRoot(), 'data');
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            shell.openPath(dataDir);
          },
        },
        {
          label: '打开导出目录',
          click: () => {
            // 优先打开最后保存报告的目录，否则打开默认文档目录
            const dir = lastReportDir || app.getPath('documents');
            shell.openPath(dir);
          },
        },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit', label: '退出' },
      ],
    },
    {
      label: '编辑',
      submenu: [
        { role: 'undo', label: '撤销' },
        { role: 'redo', label: '重做' },
        { type: 'separator' },
        { role: 'cut', label: '剪切' },
        { role: 'copy', label: '复制' },
        { role: 'paste', label: '粘贴' },
        { role: 'selectAll', label: '全选' },
      ],
    },
    {
      label: '视图',
      submenu: [
        {
          label: '首页仪表盘',
          accelerator: 'CmdOrCtrl+1',
          click: () => navigateTo('/'),
        },
        {
          label: '漏洞管理',
          accelerator: 'CmdOrCtrl+2',
          click: () => navigateTo('/vulnerabilities'),
        },
        {
          label: '导入扫描结果',
          accelerator: 'CmdOrCtrl+3',
          click: () => navigateTo('/import'),
        },
        {
          label: '生成报告',
          accelerator: 'CmdOrCtrl+4',
          click: () => navigateTo('/report'),
        },
        {
          label: '系统设置',
          accelerator: 'CmdOrCtrl+5',
          click: () => navigateTo('/settings'),
        },
        { type: 'separator' },
        { role: 'reload', label: '刷新页面' },
        { role: 'toggleDevTools', label: '开发者工具' },
        { type: 'separator' },
        { role: 'resetZoom', label: '重置缩放' },
        { role: 'zoomIn', label: '放大' },
        { role: 'zoomOut', label: '缩小' },
        { type: 'separator' },
        { role: 'togglefullscreen', label: '全屏' },
      ],
    },
    {
      label: '帮助',
      submenu: [
        {
          label: '使用文档',
          click: () => {
            const readme = path.join(getAppRoot(), 'README.md');
            if (fs.existsSync(readme)) {
              openDocWindow(readme);
            } else {
              dialog.showMessageBox(mainWindow, {
                type: 'warning',
                title: '提示',
                message: '未找到使用文档',
                detail: `文档路径: ${readme}\n\n请确认 README.md 文件存在。`
              });
            }
          },
        },
        {
          label: '示例报告',
          click: () => {
            const sampleDir = path.join(getAppRoot(), 'sample_reports');
            if (fs.existsSync(sampleDir)) {
              shell.openPath(sampleDir);
            }
          },
        },
        { type: 'separator' },
        {
          label: '检查更新',
          click: () => doManualCheckUpdate(),
        },
        { type: 'separator' },
        {
          label: `关于 ${CONFIG.appName}`,
          click: () => showAboutDialog(),
        },
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

/**
 * 显示关于对话框
 */
function showAboutDialog() {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: `关于 ${CONFIG.appName}`,
    message: CONFIG.appName,
    detail: [
      `版本: v${CONFIG.appVersion}`,
      '',
      '渗透测试安全报告自动化生成与管理工具',
      '',
      '功能特性:',
      '  • 支持 11 款主流扫描器报告导入',
      '  • 14 种报告导出格式',
      '  • CVSS v3.1 自动评分',
      '  • 漏洞去重与状态跟踪',
      '  • 离线英中翻译 (~10,957 条术语)',
      '  • 交互式可视化仪表盘',
      '',
      '技术栈: Python + Flask + Electron',
    ].join('\n'),
    buttons: ['确定'],
  });
}

// ============================================================
// 本地设置管理（JSON 文件持久化）
// ============================================================

const SETTINGS_FILE = path.join(app.getPath('userData'), 'settings.json');

const DEFAULT_SETTINGS = {
  closeBehavior: 'minimize',  // 'minimize' | 'ask' | 'quit'
};

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const data = fs.readFileSync(SETTINGS_FILE, 'utf-8');
      return { ...DEFAULT_SETTINGS, ...JSON.parse(data) };
    }
  } catch (e) {
    console.error('Failed to load settings:', e);
  }
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(settings) {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
  } catch (e) {
    console.error('Failed to save settings:', e);
  }
}

let appSettings = loadSettings();

/**
 * 检查更新
 * @param {boolean} isManual - 是否手动触发（手动触发会弹窗提示）
 */
function checkForUpdates(isManual = false) {
  if (!app.isPackaged) {
    if (isManual) {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: '检查更新',
        message: '开发模式',
        detail: `当前为开发模式，无法检查更新。\n当前版本: v${CONFIG.appVersion}`,
      });
    }
    return;
  }
  autoUpdater.checkForUpdates().catch((err) => {
    writeDebugLog(`[Update] 检查更新失败: ${err.message}`);
  });
}

/**
 * 向 Web 端发送更新状态
 */
function sendToWeb(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

/**
 * 格式化字节数
 */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

// ============================================================
// IPC 通信处理
// ============================================================

// 手动检查更新（菜单栏和设置页面共用，必须在 setupIPC 和 createMenu 之前定义）
async function doManualCheckUpdate() {
  if (!app.isPackaged) {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: '检查更新',
      message: '开发模式',
      detail: `当前为开发模式，无法检查更新。\n当前版本: v${CONFIG.appVersion}`,
    });
    return;
  }

  const checkingWin = new BrowserWindow({
    width: 360, height: 140, resizable: false, minimizable: false, maximizable: false,
    modal: true, parent: mainWindow, title: '检查更新', backgroundColor: '#0f172a', show: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });
  checkingWin.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(`
    <!DOCTYPE html><html><head><style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { display: flex; align-items: center; justify-content: center; height: 100vh;
             background: #0f172a; color: #e2e8f0; font-family: -apple-system, 'Segoe UI', sans-serif; }
      .spinner { width: 24px; height: 24px; border: 3px solid #334155; border-top-color: #3b82f6;
                 border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 12px; flex-shrink: 0; }
      @keyframes spin { to { transform: rotate(360deg); } }
      .text { font-size: 14px; }
    </style></head><body>
      <div class="spinner"></div><div class="text">正在检查更新，请稍候...</div>
    </body></html>
  `)}`);

  return new Promise((resolve) => {
    let settled = false;
    const cleanup = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      autoUpdater.removeListener('update-available', onAvailable);
      autoUpdater.removeListener('update-not-available', onNotAvailable);
      autoUpdater.removeListener('error', onError);
      // 安全关闭 loading 窗口（用户可能已手动关闭）
      try {
        if (checkingWin && !checkingWin.isDestroyed()) {
          checkingWin.close();
        }
      } catch (e) { /* ignore */ }
      // 安全显示结果弹窗
      try {
        if (mainWindow && !mainWindow.isDestroyed()) {
          dialog.showMessageBox(mainWindow, result);
        }
      } catch (e) { /* ignore */ }
      resolve({ started: true });
    };

    // 用户手动关闭 loading 窗口时，静默取消检查
    checkingWin.on('closed', () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        autoUpdater.removeListener('update-available', onAvailable);
        autoUpdater.removeListener('update-not-available', onNotAvailable);
        autoUpdater.removeListener('error', onError);
        resolve({ started: true, cancelled: true });
      }
    });

    const timer = setTimeout(() => {
      cleanup({ type: 'warning', title: '检查超时', message: '更新检查超时',
        detail: '无法连接到更新服务器，请检查网络连接后重试。' });
    }, 15000);

    const onAvailable = (info) => {
      clearTimeout(timer);
      autoUpdater.removeListener('update-available', onAvailable);
      autoUpdater.removeListener('update-not-available', onNotAvailable);
      autoUpdater.removeListener('error', onError);
      cleanup({ type: 'info', title: '发现新版本', message: `新版本 v${info.version} 可用`,
        detail: `当前版本: v${CONFIG.appVersion}\n最新版本: v${info.version}` });
    };

    const onNotAvailable = () => {
      clearTimeout(timer);
      autoUpdater.removeListener('update-available', onAvailable);
      autoUpdater.removeListener('update-not-available', onNotAvailable);
      autoUpdater.removeListener('error', onError);
      cleanup({ type: 'info', title: '检查更新', message: '当前已是最新版本',
        detail: `当前版本: v${CONFIG.appVersion}` });
    };

    const onError = (err) => {
      clearTimeout(timer);
      autoUpdater.removeListener('update-available', onAvailable);
      autoUpdater.removeListener('update-not-available', onNotAvailable);
      autoUpdater.removeListener('error', onError);
      cleanup({ type: 'error', title: '检查失败', message: '更新检查失败',
        detail: err.message || '未知错误，请检查网络连接或更新服务器配置后重试。' });
    };

    autoUpdater.on('update-available', onAvailable);
    autoUpdater.on('update-not-available', onNotAvailable);
    autoUpdater.on('error', onError);

    autoUpdater.checkForUpdates().then(() => {
      setTimeout(() => {
        if (!settled) {
          clearTimeout(timer);
          cleanup({ type: 'info', title: '检查更新', message: '当前已是最新版本',
            detail: `当前版本: v${CONFIG.appVersion}` });
        }
      }, 3000);
    }).catch((err) => {
      clearTimeout(timer);
      autoUpdater.removeListener('update-available', onAvailable);
      autoUpdater.removeListener('update-not-available', onNotAvailable);
      autoUpdater.removeListener('error', onError);
      cleanup({ type: 'error', title: '检查失败', message: '更新检查失败',
        detail: err.message || '未知错误，请检查网络连接或更新服务器配置后重试。' });
    });
  });
}

// 退出前清除登录状态（确保 cookie 删除完成后再退出）
async function _clearLoginBeforeQuit() {
  const keepLogin = appSettings && appSettings.keepLogin;
  if (keepLogin || !mainWindow || mainWindow.isDestroyed()) return;
  try {
    const cookies = await mainWindow.webContents.session.cookies.get({
      url: `http://${CONFIG.flaskHost}:${CONFIG.flaskPort}`
    });
    for (const cookie of cookies) {
      await mainWindow.webContents.session.cookies.remove(`http://${CONFIG.flaskHost}`, cookie.name);
    }
    await mainWindow.webContents.session.cookies.flushStore();
    writeDebugLog('[Quit] 已清除登录 cookie');
  } catch (e) {
    writeDebugLog('[Quit] 清除 cookie 失败: ' + e.message);
  }
}

function setupIPC() {
  // 获取应用信息
  ipcMain.handle('get-app-info', () => ({
    name: CONFIG.appName,
    version: CONFIG.appVersion,
    isElectron: true,
    isPackaged: app.isPackaged,
    platform: process.platform,
  }));

  // ================================================================
  // 自动更新（electron-updater）
  // ================================================================

  // 配置 autoUpdater
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.setFeedURL({
    provider: 'github',
    owner: 'example-user',
    repo: 'sec-report-generator',
  });

  // 更新事件
  autoUpdater.on('checking-for-update', () => {
    sendToWeb('update-status', { status: 'checking', message: '正在检查更新...' });
  });

  autoUpdater.on('update-available', (info) => {
    sendToWeb('update-status', {
      status: 'available',
      message: `发现新版本 v${info.version}`,
      version: info.version,
      releaseNotes: info.releaseNotes,
      releaseDate: info.releaseDate,
      currentVersion: CONFIG.appVersion,
    });
  });

  autoUpdater.on('update-not-available', (info) => {
    sendToWeb('update-status', {
      status: 'not-available',
      message: `当前已是最新版本 v${CONFIG.appVersion}`,
      currentVersion: CONFIG.appVersion,
    });
  });

  autoUpdater.on('download-progress', (progress) => {
    const percent = Math.round(progress.percent);
    sendToWeb('update-status', {
      status: 'downloading',
      message: `正在下载更新: ${percent}%`,
      percent: percent,
      transferred: formatBytes(progress.transferred),
      total: formatBytes(progress.total),
      speed: formatBytes(progress.bytesPerSecond) + '/s',
    });
  });

  autoUpdater.on('update-downloaded', (info) => {
    sendToWeb('update-status', {
      status: 'downloaded',
      message: `更新下载完成 v${info.version}，将在重启后安装`,
      version: info.version,
    });
    // 通知用户
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: '更新就绪',
      message: `新版本 v${info.version} 已下载完成`,
      detail: '点击"立即重启"安装更新，或稍后退出应用时自动安装。',
      buttons: ['立即重启', '稍后'],
      defaultId: 0,
      cancelId: 1,
    }).then(({ response }) => {
      if (response === 0) {
        autoUpdater.quitAndInstall();
      }
    });
  });

  autoUpdater.on('error', (err) => {
    sendToWeb('update-status', {
      status: 'error',
      message: `更新检查失败: ${err.message}`,
    });
  });

  ipcMain.handle('check-for-update', () => doManualCheckUpdate());

  // IPC: 下载更新
  ipcMain.handle('download-update', () => {
    autoUpdater.downloadUpdate();
    return { started: true };
  });

  // IPC: 安装更新
  ipcMain.handle('install-update', () => {
    autoUpdater.quitAndInstall();
    return { started: true };
  });

  // IPC: 获取更新状态
  ipcMain.handle('get-update-status', () => {
    return {
      currentVersion: CONFIG.appVersion,
      isPackaged: app.isPackaged,
    };
  });

  // 启动时自动检查更新（静默，不弹窗）
  setTimeout(() => checkForUpdates(false), 5000);

  // 获取 Flask 服务地址
  ipcMain.handle('get-server-url', () => `http://${CONFIG.flaskHost}:${CONFIG.flaskPort}`);

  // 获取设置
  ipcMain.handle('get-settings', () => appSettings);

  // 保存设置
  ipcMain.handle('save-settings', (_, settings) => {
    console.log('[Settings] Saving:', settings);
    appSettings = { ...appSettings, ...settings };
    saveSettings(appSettings);
    console.log('[Settings] Current appSettings:', JSON.stringify(appSettings));
    return { success: true };
  });

  // 打开外部链接
  ipcMain.handle('open-external', (_, url) => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        shell.openExternal(url);
      }
    } catch (e) { /* ignore invalid URLs */ }
  });

  // 打开文件选择对话框
  ipcMain.handle('open-file-dialog', (_, options) => {
    return dialog.showOpenDialog(mainWindow, options);
  });

  // 打开保存对话框
  ipcMain.handle('save-file-dialog', (_, options) => {
    return dialog.showSaveDialog(mainWindow, options);
  });

  ipcMain.handle('save-report-file', async (_, { filename, fileDataBase64 }) => {
    const ext = filename.split('.').pop().toLowerCase();
    const filters = [];
    if (ext === 'pdf') filters.push({ name: 'PDF', extensions: ['pdf'] });
    else if (ext === 'docx') filters.push({ name: 'Word', extensions: ['docx'] });
    else if (ext === 'xlsx') filters.push({ name: 'Excel', extensions: ['xlsx'] });
    else if (ext === 'html') filters.push({ name: 'HTML', extensions: ['html'] });
    else if (ext === 'json') filters.push({ name: 'JSON', extensions: ['json'] });
    else if (ext === 'csv') filters.push({ name: 'CSV', extensions: ['csv'] });
    else if (ext === 'xml') filters.push({ name: 'XML', extensions: ['xml'] });
    else if (ext === 'md') filters.push({ name: 'Markdown', extensions: ['md'] });
    else if (ext === 'txt') filters.push({ name: 'Text', extensions: ['txt'] });
    else filters.push({ name: 'File', extensions: [ext] });

    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: '保存报告',
      defaultPath: lastReportDir ? path.join(lastReportDir, filename) : filename,
      filters,
    });

    if (canceled || !filePath) return false;

    try {
      const buffer = Buffer.from(fileDataBase64, 'base64');
      fs.writeFileSync(filePath, buffer);
      lastReportDir = path.dirname(filePath); // 记录最后保存目录
      writeDebugLog(`[Report] 报告已保存: ${filePath} (${(buffer.length / 1024).toFixed(1)} KB)`);
      return true;
    } catch (err) {
      writeDebugLog(`[Report] 保存失败: ${err.message}`);
      return { success: false, error: err.message };
    }
  });

  // 获取最后保存的报告目录
  ipcMain.handle('get-last-report-dir', () => lastReportDir);

  // 显示消息框
  ipcMain.handle('show-message', (_, { type, title, message, buttons }) => {
    return dialog.showMessageBox(mainWindow, { type, title, message, buttons });
  });

  // 打开目录
  ipcMain.handle('open-directory', (_, dirPath) => {
    shell.openPath(dirPath);
  });

  // 下载文件（通过系统文件管理器打开）
  ipcMain.handle('reveal-file', (_, filePath) => {
    shell.showItemInFolder(filePath);
  });
  // 获取应用路径
  ipcMain.handle('get-app-path', (_, name) => {
    switch (name) {
      case 'home': return app.getPath('home');
      case 'appData': return app.getPath('appData');
      case 'userData': return app.getPath('userData');
      case 'documents': return app.getPath('documents');
      case 'downloads': return app.getPath('downloads');
      case 'appRoot': return getAppRoot();
      case 'data': return resolvedDataDir || path.join(getAppRoot(), 'data');
      case 'exports': return resolvedDataDir ? path.join(resolvedDataDir, 'exports') : path.join(getAppRoot(), 'exports');
      case 'uploads': return resolvedDataDir ? path.join(resolvedDataDir, 'uploads') : path.join(getAppRoot(), 'uploads');
      default: return getAppRoot();
    }
  });

  // 发送系统通知
  ipcMain.handle('send-notification', (_, { title, body }) => {
    if (Notification.isSupported()) {
      const notification = new Notification({ title, body, silent: false });
      notification.show();
      return true;
    }
    return false;
  });

  // 窗口控制
  ipcMain.handle('window-minimize', () => mainWindow?.minimize());
  ipcMain.handle('focus-window', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      // Windows 上需要先 blur 再 focus 来强制激活 IME
      if (process.platform === 'win32') {
        mainWindow.blur();
        mainWindow.showInactive();
        setTimeout(() => {
          mainWindow.focus();
          mainWindow.moveTop();
        }, 50);
      } else {
        mainWindow.focus();
      }
    }
  });
  ipcMain.handle('window-maximize', () => {
    if (mainWindow?.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow?.maximize();
    }
  });
  ipcMain.handle('window-close', async () => {
    await _clearLoginBeforeQuit();
    isQuitting = true;
    mainWindow.close();
  });
  ipcMain.handle('window-is-maximized', () => mainWindow?.isMaximized() ?? false);

  // 页面导航
  ipcMain.handle('navigate-to', (_, urlPath) => navigateTo(urlPath));

  // 重启 Flask
  ipcMain.handle('restart-server', async () => {
    stopFlask();
    await startFlask();
    mainWindow?.loadURL(`http://${CONFIG.flaskHost}:${CONFIG.flaskPort}?electron=1`);
    return true;
  });
}

// ============================================================
// 应用生命周期
// ============================================================

app.whenReady().then(async () => {
  // 创建菜单
  createMenu();

  // 设置 IPC
  setupIPC();

  // 创建托盘
  createTray();

  // 启动 Flask 后端
  await startFlask();

  // 创建主窗口
  createMainWindow();

  // macOS 激活应用时显示窗口
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    } else if (mainWindow) {
      mainWindow.show();
    }
  });
});

// 所有窗口关闭时不退出（托盘模式）
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // Windows/Linux: 保持运行（托盘模式）
  }
});

// 应用退出前清理
app.on('before-quit', () => {
  isQuitting = true;
  // 尽力清除登录 cookie（兜底：托盘菜单退出时不经过 close 事件对话框路径）
  _clearLoginBeforeQuit().catch(() => {});
  stopFlask();
});

// 未捕获异常处理
process.on('uncaughtException', (err) => {
  console.error(`[Uncaught] ${err.message}`);
  dialog.showErrorBox('运行错误', `发生未预期的错误:\n${err.message}`);
});

process.on('unhandledRejection', (reason) => {
  console.error(`[Unhandled] ${reason}`);
});
