/**
 * 安全报告生成器 - 前端 JavaScript
 *
 * 提供语言切换、文件拖拽上传、漏洞 CRUD、模态框管理、
 * 表单验证、报告生成下载、Toast 通知、表格排序搜索等功能。
 */

// ============================================================
// 全局变量
// ============================================================
let currentLang = document.documentElement.lang || 'zh';
let isAuthenticated = false;
let pendingActionAfterLogin = null; // 登录成功后自动重试的操作

// ============================================================
// 登录认证
// ============================================================

// 全局 fetch 拦截：检测 401 自动弹出登录框
const originalFetch = window.fetch;
window.fetch = function(url, options) {
    return originalFetch.apply(this, arguments).then(response => {
        if (response.status === 401) {
            isAuthenticated = false;
            updateAuthUI();
            // 记录待重试的操作
            pendingActionAfterLogin = { url, options };
            // 统一通过 handleAuthAction 弹出登录框（和点击登录按钮一致）
            setTimeout(() => handleAuthAction(), 0);
            return Promise.reject(new Error('Authentication required'));
        }
        return response;
    });
};

function showLoginDialog() {
    const overlay = document.getElementById('login-overlay');
    if (!overlay) return;

    overlay.classList.remove('hidden');
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';

    const pwdInput = document.getElementById('login-password');
    if (pwdInput) pwdInput.value = '';
    const errorEl = document.getElementById('login-error');
    if (errorEl) errorEl.classList.add('hidden');

    // 延迟 focus 输入框，确保弹窗完全渲染
    setTimeout(() => {
        if (pwdInput) {
            pwdInput.focus();
        }
    }, 300);
}

function closeLoginDialog(event) {
    if (event && event.target !== event.currentTarget) return;
    const overlay = document.getElementById('login-overlay');
    if (overlay) {
        overlay.style.display = 'none';
        overlay.classList.add('hidden');
    }
    pendingActionAfterLogin = null;
}

function togglePasswordVisibility() {
    const pwdInput = document.getElementById('login-password');
    const icon = document.getElementById('pwd-toggle-icon');
    if (pwdInput && icon) {
        if (pwdInput.type === 'password') {
            pwdInput.type = 'text';
            icon.classList.replace('fa-eye', 'fa-eye-slash');
        } else {
            pwdInput.type = 'password';
            icon.classList.replace('fa-eye-slash', 'fa-eye');
        }
    }
}

function doLogin() {
    const pwdInput = document.getElementById('login-password');
    const errorEl = document.getElementById('login-error');
    const submitBtn = document.getElementById('login-submit-btn');
    const password = pwdInput ? pwdInput.value.trim() : '';

    if (!password) {
        if (errorEl) {
            errorEl.textContent = currentLang === 'zh' ? '请输入密码' : 'Please enter password';
            errorEl.classList.remove('hidden');
        }
        return;
    }

    if (submitBtn) submitBtn.disabled = true;

    fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            isAuthenticated = true;
            updateAuthUI();
            closeLoginDialog();
            // 登录成功后自动重试之前的操作
            if (pendingActionAfterLogin) {
                const action = pendingActionAfterLogin;
                pendingActionAfterLogin = null;
                originalFetch(action.url, action.options);
            }
        } else {
            if (errorEl) {
                errorEl.textContent = currentLang === 'zh' ? '密码错误' : 'Invalid password';
                errorEl.classList.remove('hidden');
            }
            if (pwdInput) { pwdInput.value = ''; pwdInput.focus(); }
        }
    })
    .catch(err => {
        if (errorEl) {
            errorEl.textContent = currentLang === 'zh' ? '登录失败' : 'Login failed';
            errorEl.classList.remove('hidden');
        }
    })
    .finally(() => {
        if (submitBtn) submitBtn.disabled = false;
    });
}

function doLogout() {
    fetch('/api/auth/logout', { method: 'POST' })
    .then(() => {
        isAuthenticated = false;
        updateAuthUI();
    });
}

function handleAuthAction() {
    if (isAuthenticated) {
        doLogout();
    } else {
        showLoginDialog();
    }
}

function updateAuthUI() {
    const icon = document.getElementById('auth-icon');
    const label = document.getElementById('auth-label');
    if (!icon || !label) return;

    if (isAuthenticated) {
        icon.className = 'fas fa-lock-open';
        label.textContent = currentLang === 'zh' ? '退出登录' : 'Logout';
    } else {
        icon.className = 'fas fa-lock';
        label.textContent = currentLang === 'zh' ? '登录' : 'Login';
    }
}

function checkAuthStatus() {
    fetch('/api/auth/status')
    .then(r => r.json())
    .then(data => {
        isAuthenticated = !!data.authenticated;
        updateAuthUI();
    })
    .catch(() => {});
}

// ============================================================
// 语言切换
// ============================================================
function toggleLanguage() {
    const newLang = currentLang === 'zh' ? 'en' : 'zh';
    fetch('/api/language', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lang: newLang }),
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            currentLang = data.lang;
            // 刷新页面以应用新语言
            window.location.reload();
        }
    })
    .catch(err => console.error('Language switch failed:', err));
}

// ============================================================
// 移动端菜单
// ============================================================
function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    menu.classList.toggle('hidden');
}

// ============================================================
// Toast 通知
// ============================================================
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-times-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle',
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="${icons[type] || icons.info}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease-in forwards';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, duration);
}

// ============================================================
// 模态框管理
// ============================================================
function openModal(modalId) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById(modalId);
    if (overlay && modal) {
        overlay.classList.remove('hidden');
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) {
        overlay.classList.add('hidden');
        document.body.style.overflow = '';
    }
    // 隐藏所有模态框内容
    document.querySelectorAll('#modal-overlay > div').forEach(el => {
        el.classList.add('hidden');
    });
}

function closeModalOnOverlay(event) {
    if (event.target === event.currentTarget) {
        closeModal();
    }
}

// ESC 键关闭模态框
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// ============================================================
// 工具函数
// ============================================================
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getSeverityLabel(severity) {
    const labels = {
        zh: { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' },
        en: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' },
    };
    const lang = currentLang || 'zh';
    return (labels[lang] || labels.zh)[severity] || severity;
}

// ============================================================
// 页面初始化
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    // 设置当前语言（从 HTML lang 属性读取）
    const langLabel = document.getElementById('lang-label');
    if (langLabel) {
        currentLang = document.documentElement.lang || 'zh';
        langLabel.textContent = currentLang === 'zh' ? 'EN' : '中文';
    }
    // 检查登录状态
    checkAuthStatus();
});
