/**
 * 安全拦截页面JavaScript
 * 提供现代化交互功能和用户体验增强
 * 支持深色模式、动画效果和高级功能
 */

class SecurityBlockedPage {
    constructor() {
        this.config = {
            enableAnimations: !this.prefersReducedMotion(),
            enableAnalytics: true,
            enableFeedback: true,
            autoHideSensitive: true
        };

        this.state = {
            feedbackSubmitted: false,
            modalOpen: false,
            toastVisible: false
        };

        this.init();
    }

    /**
     * 初始化
     */
    init() {
        this.bindEvents();
        this.setupAccessibility();
        this.autoHideSensitiveInfo();
        this.setupThemeDetection();

        if (this.config.enableAnalytics) {
            this.addAnalytics();
        }

        console.log('🔒 安全拦截页面初始化完成');
    }

    /**
     * 绑定事件处理
     */
    bindEvents() {
        // 返回按钮事件
        this.delegate('.btn-secondary', 'click', (e) => {
            e.preventDefault();
            this.navigateBack();
        });

        // 首页按钮事件
        this.delegate('.btn-primary', 'click', (e) => {
            e.preventDefault();
            this.navigateHome();
        });

        // 反馈按钮事件
        this.delegate('[onclick*="showFeedbackForm"]', 'click', (e) => {
            e.preventDefault();
            this.showFeedbackForm();
        });

        // 复制请求ID事件
        this.delegate('.request-id, .footer-request-id', 'click', (e) => {
            e.preventDefault();
            this.copyRequestId();
        });

        // 键盘快捷键
        document.addEventListener('keydown', (e) => this.handleKeyboard(e));

        // 页面可见性变化
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                this.onPageVisible();
            }
        });

        // 窗口调整大小
        window.addEventListener('resize', this.debounce(() => {
            this.onWindowResize();
        }, 250));
    }

    /**
     * 事件委托
     */
    delegate(selector, event, handler) {
        document.addEventListener(event, (e) => {
            if (e.target.matches(selector) || e.target.closest(selector)) {
                handler(e);
            }
        });
    }

    /**
     * 设置无障碍功能
     */
    setupAccessibility() {
        // 添加跳过链接
        this.addSkipLink();

        // 设置焦点管理
        this.setupFocusManagement();

        // 添加ARIA标签
        this.setupAriaLabels();
    }

    /**
     * 添加跳过链接
     */
    addSkipLink() {
        const skipLink = document.createElement('a');
        skipLink.href = '#main-content';
        skipLink.className = 'skip-link';
        skipLink.textContent = '跳到主要内容';
        skipLink.style.cssText = `
            position: absolute;
            top: -40px;
            left: 6px;
            background: #000;
            color: #fff;
            padding: 8px;
            z-index: 10000;
            text-decoration: none;
            border-radius: 4px;
        `;

        document.body.insertBefore(skipLink, document.body.firstChild);

        // 添加主要内容锚点
        const mainContent = document.querySelector('.security-content');
        if (mainContent) {
            mainContent.id = 'main-content';
            mainContent.setAttribute('tabindex', '-1');
        }
    }

    /**
     * 设置焦点管理
     */
    setupFocusManagement() {
        // 模态框打开时捕获焦点
        this.setupFocusTrap();

        // 设置焦点顺序
        this.setupFocusOrder();
    }

    /**
     * 设置ARIA标签
     */
    setupAriaLabels() {
        const container = document.querySelector('.security-container');
        if (container) {
            container.setAttribute('role', 'alert');
            container.setAttribute('aria-live', 'assertive');
        }

        // 为按钮添加ARIA标签
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(btn => {
            const text = btn.textContent.trim();
            btn.setAttribute('aria-label', text);
        });
    }

    /**
     * 自动隐藏敏感信息
     */
    autoHideSensitiveInfo() {
        if (!this.config.autoHideSensitive || this.isDebugMode()) {
            return;
        }

        const sensitiveElements = document.querySelectorAll('[data-sensitive]');
        sensitiveElements.forEach(el => {
            el.style.display = 'none';
        });

        console.log('🔒 敏感信息已自动隐藏');
    }

    /**
     * 设置主题检测
     */
    setupThemeDetection() {
        // 检测系统主题偏好
        const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        const handleThemeChange = (e) => {
            const isDark = e.matches;
            document.body.classList.toggle('dark-theme', isDark);
            document.body.classList.toggle('light-theme', !isDark);
        };

        // 初始检测
        handleThemeChange(darkModeMediaQuery);

        // 监听主题变化
        darkModeMediaQuery.addEventListener('change', handleThemeChange);
    }

    /**
     * 处理键盘事件
     */
    handleKeyboard(e) {
        switch (e.key) {
            case 'Escape':
                if (this.state.modalOpen) {
                    this.hideFeedbackForm();
                } else {
                    this.navigateBack();
                }
                break;

            case 'Enter':
                if (e.ctrlKey) {
                    this.navigateHome();
                }
                break;

            case 'f':
            case 'F':
                if (e.ctrlKey && this.isDebugMode()) {
                    e.preventDefault();
                    this.showFeedbackForm();
                }
                break;

            case 'c':
            case 'C':
                if (e.ctrlKey) {
                    e.preventDefault();
                    this.copyRequestId();
                }
                break;
        }
    }

    /**
     * 导航返回
     */
    navigateBack() {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            this.navigateHome();
        }
    }

    /**
     * 导航到首页
     */
    navigateHome() {
        window.location.href = '/';
    }

    /**
     * 复制请求ID
     */
    async copyRequestId() {
        const requestId = this.getRequestId();

        try {
            await navigator.clipboard.writeText(requestId);
            this.showToast('✅ 请求ID已复制到剪贴板', 'success');

            // 添加触觉反馈（如果支持）
            if (navigator.vibrate) {
                navigator.vibrate(50);
            }
        } catch (err) {
            console.error('复制失败:', err);
            this.showToast('❌ 复制失败，请手动复制', 'error');
        }
    }

    /**
     * 获取请求ID
     */
    getRequestId() {
        const requestIdElement = document.querySelector('[data-request-id]');
        return requestIdElement ? requestIdElement.textContent.trim() : 'unknown';
    }

    /**
     * 显示反馈表单
     */
    showFeedbackForm() {
        if (this.state.modalOpen || !this.config.enableFeedback) {
            return;
        }

        const modalHtml = `
            <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 id="modal-title">问题反馈</h3>
                        <button type="button" class="modal-close" aria-label="关闭对话框" onclick="securityPage.hideFeedbackForm()">
                            <span aria-hidden="true">×</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <p>如果您认为这是一个错误，请详细描述您遇到的问题：</p>
                        <textarea 
                            id="feedbackText" 
                            placeholder="请详细描述您遇到的情况、操作步骤和期望结果..." 
                            rows="6"
                            aria-describedby="feedback-help"
                        ></textarea>
                        <small id="feedback-help" class="help-text">
                            您的反馈将帮助我们改进安全系统
                        </small>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="securityPage.hideFeedbackForm()">
                            取消
                        </button>
                        <button type="button" class="btn btn-primary" onclick="securityPage.submitFeedback()">
                            📨 提交反馈
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHtml);
        this.state.modalOpen = true;

        // 设置焦点到文本区域
        setTimeout(() => {
            const textarea = document.getElementById('feedbackText');
            if (textarea) {
                textarea.focus();
            }
        }, 100);

        // 设置焦点陷阱
        this.setupModalFocusTrap();
    }

    /**
     * 隐藏反馈表单
     */
    hideFeedbackForm() {
        const modal = document.querySelector('.modal');
        if (modal) {
            modal.remove();
        }
        this.state.modalOpen = false;
    }

    /**
     * 设置模态框焦点陷阱
     */
    setupModalFocusTrap() {
        const modal = document.querySelector('.modal');
        const focusableElements = modal.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        const trapFocus = (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstElement) {
                        e.preventDefault();
                        lastElement.focus();
                    }
                } else {
                    if (document.activeElement === lastElement) {
                        e.preventDefault();
                        firstElement.focus();
                    }
                }
            }
        };

        modal.addEventListener('keydown', trapFocus);
    }

    /**
     * 提交反馈
     */
    async submitFeedback() {
        if (this.state.feedbackSubmitted) {
            this.showToast('⏳ 请勿重复提交反馈', 'warning');
            return;
        }

        const textarea = document.getElementById('feedbackText');
        const feedback = textarea ? textarea.value.trim() : '';

        if (!feedback) {
            this.showToast('📝 请输入反馈内容', 'warning');
            textarea?.focus();
            return;
        }

        if (feedback.length < 10) {
            this.showToast('📝 反馈内容至少需要10个字符', 'warning');
            textarea?.focus();
            return;
        }

        const feedbackData = {
            requestId: this.getRequestId(),
            feedback: feedback,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href,
            viewport: `${window.innerWidth}x${window.innerHeight}`
        };

        try {
            this.state.feedbackSubmitted = true;

            // 显示加载状态
            const submitBtn = document.querySelector('.modal-footer .btn-primary');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '⏳ 提交中...';
                submitBtn.disabled = true;
            }

            await this.sendFeedback(feedbackData);

            this.showToast('✅ 感谢您的反馈！', 'success');
            this.hideFeedbackForm();

            // 重置提交状态
            setTimeout(() => {
                this.state.feedbackSubmitted = false;
            }, 5000);

        } catch (error) {
            console.error('反馈提交失败:', error);
            this.showToast('❌ 提交失败，请稍后重试', 'error');
            this.state.feedbackSubmitted = false;

            // 恢复按钮状态
            const submitBtn = document.querySelector('.modal-footer .btn-primary');
            if (submitBtn) {
                submitBtn.innerHTML = '📨 提交反馈';
                submitBtn.disabled = false;
            }
        }
    }

    /**
     * 发送反馈数据
     */
    async sendFeedback(data) {
        // 这里可以集成到实际的反馈系统
        console.log('📨 发送反馈数据:', data);

        // 模拟网络请求
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                if (Math.random() > 0.1) { // 90% 成功率
                    resolve();
                } else {
                    reject(new Error('模拟网络错误'));
                }
            }, 1000);
        });
    }

    /**
     * 添加分析统计
     */
    addAnalytics() {
        const eventData = {
            type: 'security_block',
            timestamp: new Date().toISOString(),
            requestId: this.getRequestId(),
            path: window.location.pathname,
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };

        this.sendAnalytics(eventData).catch(error => {
            console.warn('分析数据发送失败:', error);
        });
    }

    /**
     * 发送分析数据
     */
    async sendAnalytics(data) {
        try {
            // 使用 Beacon API 如果可用
            if (navigator.sendBeacon) {
                const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
                return navigator.sendBeacon('/api/security/analytics', blob);
            } else {
                // 回退到 fetch API
                return fetch('/api/security/analytics', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data),
                    keepalive: true
                });
            }
        } catch (error) {
            console.warn('分析数据发送失败:', error);
        }
    }

    /**
     * 显示提示消息
     */
    showToast(message, type = 'info') {
        if (this.state.toastVisible) {
            return;
        }

        this.state.toastVisible = true;

        const toast = document.createElement('div');
        toast.className = `security-toast security-toast-${type}`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'polite');
        toast.innerHTML = `
            <div class="toast-content">
                <span class="toast-message">${message}</span>
                <button class="toast-close" aria-label="关闭提示" onclick="this.parentElement.parentElement.remove()">
                    <span aria-hidden="true">×</span>
                </button>
            </div>
        `;

        // 添加样式
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: ${this.getToastColor(type)};
            color: white;
            padding: 0;
            border-radius: 8px;
            z-index: 10000;
            max-width: 400px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            animation: toastSlideIn 0.3s ease;
        `;

        document.body.appendChild(toast);

        // 自动隐藏
        setTimeout(() => {
            if (toast.parentElement) {
                toast.style.animation = 'toastSlideOut 0.3s ease';
                setTimeout(() => {
                    if (toast.parentElement) {
                        toast.remove();
                    }
                    this.state.toastVisible = false;
                }, 300);
            }
        }, 5000);
    }

    /**
     * 获取提示消息颜色
     */
    getToastColor(type) {
        const colors = {
            success: '#28a745',
            error: '#dc3545',
            warning: '#ffc107',
            info: '#17a2b8'
        };
        return colors[type] || colors.info;
    }

    /**
     * 页面可见时回调
     */
    onPageVisible() {
        // 可以在这里添加页面重新激活时的逻辑
        console.log('🔒 安全拦截页面已激活');
    }

    /**
     * 窗口调整大小时回调
     */
    onWindowResize() {
        // 响应式布局调整
        this.adjustLayout();
    }

    /**
     * 调整布局
     */
    adjustLayout() {
        const container = document.querySelector('.security-container');
        if (!container) return;

        const width = window.innerWidth;

        if (width < 480) {
            container.style.padding = '20px 16px';
        } else if (width < 768) {
            container.style.padding = '30px 20px';
        } else {
            container.style.padding = '48px';
        }
    }

    /**
     * 检查是否为调试模式
     */
    isDebugMode() {
        return document.body.getAttribute('data-debug') === 'true' ||
            window.location.search.includes('debug=true') ||
            window.location.hash.includes('debug');
    }

    /**
     * 检查是否偏好减少动画
     */
    prefersReducedMotion() {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    /**
     * 防抖函数
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * 获取页面性能指标
     */
    getPerformanceMetrics() {
        if (!window.performance || !window.performance.timing) {
            return null;
        }

        const timing = window.performance.timing;
        return {
            dns: timing.domainLookupEnd - timing.domainLookupStart,
            tcp: timing.connectEnd - timing.connectStart,
            ttfb: timing.responseStart - timing.requestStart,
            domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
            load: timing.loadEventEnd - timing.navigationStart
        };
    }

    /**
     * 导出页面数据（用于调试）
     */
    exportPageData() {
        return {
            requestId: this.getRequestId(),
            url: window.location.href,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            performance: this.getPerformanceMetrics(),
            config: this.config,
            state: this.state
        };
    }
}

// 添加CSS动画
const injectStyles = () => {
    const styles = `
        @keyframes toastSlideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes toastSlideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        
        .toast-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
        }
        
        .toast-message {
            flex: 1;
            margin-right: 12px;
        }
        
        .toast-close {
            background: none;
            border: none;
            color: inherit;
            font-size: 18px;
            cursor: pointer;
            padding: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0.8;
        }
        
        .toast-close:hover {
            opacity: 1;
        }
        
        .help-text {
            display: block;
            margin-top: 8px;
            color: #6c757d;
            font-size: 0.875rem;
        }
        
        .skip-link:focus {
            top: 6px;
        }
        
        /* 减少动画模式 */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    `;

    const styleSheet = document.createElement('style');
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);
};

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    // 注入样式
    injectStyles();

    // 初始化安全页面
    window.securityPage = new SecurityBlockedPage();

    // 全局错误处理
    window.addEventListener('error', (e) => {
        console.error('安全页面错误:', e.error);
    });

    console.log('🚀 安全拦截页面加载完成');
});

// 导出到模块系统（如果可用）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityBlockedPage;
}