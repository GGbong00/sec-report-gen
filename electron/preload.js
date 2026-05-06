const { contextBridge, ipcRenderer } = require('electron');

// preload 在页面渲染前执行，立即标记为 Electron 环境
// 确保 documentElement 存在后再添加类
if (document.documentElement) {
  document.documentElement.classList.add('electron-app');
} else {
  document.addEventListener('DOMContentLoaded', function() {
    document.documentElement.classList.add('electron-app');
  });
}

/**
 * 预加载脚本 - 安全地暴露 Electron API 给渲染进程
 * 通过 contextBridge 暴露，确保 contextIsolation 生效
 */
contextBridge.exposeInMainWorld('electronAPI', {
  // ============================================================
  // 应用信息
  // ============================================================
  getAppInfo: () => ipcRenderer.invoke('get-app-info'),
  getServerUrl: () => ipcRenderer.invoke('get-server-url'),

  // ============================================================
  // 文件操作
  // ============================================================
  openFileDialog: (options) => ipcRenderer.invoke('open-file-dialog', options),
  saveFileDialog: (options) => ipcRenderer.invoke('save-file-dialog', options),
  saveReportFile: (filename, fileDataBase64) =>
    ipcRenderer.invoke('save-report-file', { filename, fileDataBase64 }),
  revealFile: (filePath) => ipcRenderer.invoke('reveal-file', filePath),
  openDirectory: (dirPath) => ipcRenderer.invoke('open-directory', dirPath),

  // ============================================================
  // 路径获取
  // ============================================================
  getAppPath: (name) => ipcRenderer.invoke('get-app-path', name),
  focusWindow: () => ipcRenderer.invoke('focus-window'),

  // ============================================================
  // 对话框
  // ============================================================
  showMessage: (type, title, message, buttons) =>
    ipcRenderer.invoke('show-message', { type, title, message, buttons }),

  // ============================================================
  // 通知
  // ============================================================
  sendNotification: (title, body) =>
    ipcRenderer.invoke('send-notification', { title, body }),

  // ============================================================
  // 窗口控制
  // ============================================================
  windowMinimize: () => ipcRenderer.invoke('window-minimize'),
  windowMaximize: () => ipcRenderer.invoke('window-maximize'),
  windowClose: () => ipcRenderer.invoke('window-close'),
  windowIsMaximized: () => ipcRenderer.invoke('window-is-maximized'),

  // ============================================================
  // 导航
  // ============================================================
  navigateTo: (urlPath) => ipcRenderer.invoke('navigate-to', urlPath),

  // ============================================================
  // 外部链接
  // ============================================================
  openExternal: (url) => ipcRenderer.invoke('open-external', url),

  // ============================================================
  // 服务管理
  // ============================================================
  restartServer: () => ipcRenderer.invoke('restart-server'),

  // ============================================================
  // 设置管理
  // ============================================================
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

  // ============================================================
  // 自动更新
  // ============================================================
  checkForUpdate: () => ipcRenderer.invoke('check-for-update'),
  downloadUpdate: () => ipcRenderer.invoke('download-update'),
  installUpdate: () => ipcRenderer.invoke('install-update'),
  getUpdateStatus: () => ipcRenderer.invoke('get-update-status'),
  onUpdateStatus: (callback) => {
    ipcRenderer.on('update-status', (_event, data) => callback(data));
  },

  // ============================================================
  // 平台检测
  // ============================================================
  isMac: process.platform === 'darwin',
  isWindows: process.platform === 'win32',
  isLinux: process.platform === 'linux',
});
