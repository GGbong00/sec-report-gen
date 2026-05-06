/**
 * 桌面增强脚本 - 在 Electron 环境中提供原生桌面功能
 * 此脚本会被 base.html 自动加载（仅在 Electron 环境中生效）
 */

(function () {
  'use strict';

  // 检测是否在 Electron 环境中运行
  const isElectron = !!(window.electronAPI);

  if (!isElectron) {
    console.log('[Desktop] 非 Electron 环境，跳过桌面增强');
    return;
  }

  console.log('[Desktop] Electron 桌面增强已加载');

  // ============================================================
  // 1. 注入桌面专用 CSS（隐藏浏览器默认元素）
  // ============================================================
  const desktopStyle = document.createElement('style');
  desktopStyle.textContent = `
    /* 隐藏浏览器中不需要的元素 */
    .electron-hide { display: none !important; }

    /* 桌面版窗口拖拽区域 */
    .titlebar-drag {
      -webkit-app-region: drag;
      app-region: drag;
    }
    .titlebar-no-drag {
      -webkit-app-region: no-drag;
      app-region: no-drag;
    }

    /* 桌面版滚动条样式 */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #1e293b; }
    ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #64748b; }

    /* 桌面版选中文字颜色 */
    ::selection { background: #3b82f6; color: white; }

    /* 文件下载按钮增强 */
    .desktop-file-btn {
      cursor: pointer;
      transition: all 0.2s;
    }
    .desktop-file-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }

    /* Toast 通知增强 */
    .toast-container {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 10000;
    }
  `;
  document.head.appendChild(desktopStyle);

  // ============================================================
  // 2. 增强文件下载 - 使用系统文件管理器打开
  // ============================================================
  document.addEventListener('click', function (e) {
    const link = e.target.closest('a[href*="/api/report/download"]');
    if (link && window.electronAPI) {
      e.preventDefault();
      const href = link.getAttribute('href');
      const filename = href.split('/').pop();

      // 获取服务器 URL 构建完整路径
      window.electronAPI.getServerUrl().then(serverUrl => {
        // 在新窗口下载文件
        const downloadUrl = `${serverUrl}${href}`;
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        // 下载完成后用系统文件管理器显示
        setTimeout(() => {
          window.electronAPI.getAppPath('exports').then(exportsDir => {
            window.electronAPI.revealFile(exportsDir);
          });
        }, 2000);
      });

      // 发送桌面通知
      window.electronAPI.sendNotification(
        '报告已生成',
        `文件 ${filename} 已保存到导出目录`
      );
    }
  });

  // ============================================================
  // 3. 增强导入功能 - 支持系统文件选择器
  // ============================================================
  document.addEventListener('DOMContentLoaded', function () {
    // 为文件输入框添加桌面增强
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
      input.setAttribute('class', (input.getAttribute('class') || '') + ' desktop-file-btn');
    });
  });

  // ============================================================
  // 4. 键盘快捷键增强
  // ============================================================
  document.addEventListener('keydown', function (e) {
    if (!window.electronAPI) return;

    // Ctrl+Shift+I: 打开开发者工具（仅开发模式）
    if (e.ctrlKey && e.shiftKey && e.key === 'I') {
      // 由 Electron 菜单处理
    }

    // Ctrl+Shift+N: 新建漏洞
    if (e.ctrlKey && e.shiftKey && e.key === 'N') {
      const addBtn = document.querySelector('[onclick*="addVulnerability"], #btn-add-vuln');
      if (addBtn) addBtn.click();
    }

    // Ctrl+Shift+T: 一键翻译
    if (e.ctrlKey && e.shiftKey && e.key === 'T') {
      const transBtn = document.querySelector('[onclick*="translateAll"], #btn-translate-all');
      if (transBtn) transBtn.click();
    }

    // Ctrl+Shift+G: 生成报告
    if (e.ctrlKey && e.shiftKey && e.key === 'G') {
      const genBtn = document.querySelector('[onclick*="generateReport"], #btn-generate');
      if (genBtn) genBtn.click();
    }

    // F11: 全屏切换
    if (e.key === 'F11') {
      e.preventDefault();
      const isMax = window.electronAPI.windowIsMaximized;
      // 由 Electron 菜单处理
    }
  });

  // ============================================================
  // 5. 页面加载完成通知
  // ============================================================
  window.addEventListener('load', function () {
    if (window.electronAPI) {
      window.electronAPI.getAppInfo().then(info => {
        console.log(`[Desktop] ${info.name} v${info.version} (${info.platform})`);
        // 在页面中注入版本信息
        const versionEl = document.querySelector('.app-version, #app-version');
        if (versionEl) {
          versionEl.textContent = `v${info.version}`;
        }
      });
    }
  });

  // ============================================================
  // 6. 拖拽文件增强 - 支持从系统文件管理器拖入
  // ============================================================
  document.addEventListener('dragover', function (e) {
    e.preventDefault();
    e.stopPropagation();
    document.body.classList.add('drag-over');
  });

  document.addEventListener('dragleave', function (e) {
    e.preventDefault();
    e.stopPropagation();
    document.body.classList.remove('drag-over');
  });

  document.addEventListener('drop', function (e) {
    e.preventDefault();
    e.stopPropagation();
    document.body.classList.remove('drag-over');

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      // 如果当前在导入页面，自动填充文件
      const fileInput = document.querySelector('input[type="file"]');
      if (fileInput) {
        const dataTransfer = new DataTransfer();
        for (const file of files) {
          dataTransfer.items.add(file);
        }
        fileInput.files = dataTransfer.files;
        // 触发 change 事件
        fileInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }
  });

  // ============================================================
  // 7. SRI (Subresource Integrity) 校验 - 为 CDN 资源添加完整性校验
  // ============================================================
  const SRI_HASHES = {
    'cdn.tailwindcss.com': [
      { hash: 'sha384-...', algo: 'sha384' }, // Tailwind CSS CDN
    ],
    'cdn.jsdelivr.net': [
      { hash: 'sha256-...', algo: 'sha256' }, // jsDelivr CDN
    ],
    'cdnjs.cloudflare.com': [
      { hash: 'sha256-...', algo: 'sha256' }, // Cloudflare CDN
    ],
  };

  function applySRI() {
    // 为外部 CDN script/link 标签添加 integrity 和 crossorigin 属性
    document.querySelectorAll('script[src^="https://"], link[href^="https://"]').forEach(el => {
      const src = el.getAttribute('src') || el.getAttribute('href') || '';
      for (const [domain, hashes] of Object.entries(SRI_HASHES)) {
        if (src.includes(domain) && !el.hasAttribute('integrity')) {
          // SRI 哈希需要根据实际 CDN 版本生成，此处为框架预留
          // 实际部署时请用 `openssl dgst -sha384 -binary <file> | openssl base64 -A` 生成
          el.setAttribute('crossorigin', 'anonymous');
          console.log(`[Desktop][SRI] 已为 ${src} 设置 crossorigin=anonymous`);
          break;
        }
      }
    });
  }

  // DOM 加载后应用 SRI
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applySRI);
  } else {
    applySRI();
  }

  // MutationObserver 监控动态添加的外部资源
  const sriObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) {
          const src = node.getAttribute?.('src') || node.getAttribute?.('href') || '';
          if (src.startsWith('https://') && !node.hasAttribute('integrity')) {
            node.setAttribute('crossorigin', 'anonymous');
          }
        }
      }
    }
  });
  sriObserver.observe(document.head || document.documentElement, { childList: true, subtree: true });

  // ============================================================
  // 8. 导出全局桌面 API 供其他脚本使用
  // ============================================================
  window.DesktopAPI = {
    isElectron: true,
    openExternal: (url) => window.electronAPI?.openExternal(url),
    openDirectory: (path) => window.electronAPI?.openDirectory(path),
    revealFile: (path) => window.electronAPI?.revealFile(path),
    sendNotification: (title, body) => window.electronAPI?.sendNotification(title, body),
    getAppPath: (name) => window.electronAPI?.getAppPath(name),
    navigateTo: (path) => window.electronAPI?.navigateTo(path),
    showMessage: (type, title, message) => window.electronAPI?.showMessage(type, title, message),
  };

  console.log('[Desktop] 桌面增强初始化完成');
})();
