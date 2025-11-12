/**
 * 安全拦截页面JavaScript
 * 提供交互功能和用户体验增强
 */

class SecurityBlockedPage {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
        this.autoHideSensitiveInfo();
        this.addAnalytics();
    }

    /**
     * 绑定事件处理
     */
    bindEvents() {
        // 返回按钮事件
        document.querySelectorAll('.btn-secondary').forEach(btn => {
            btn.addEventListener('click', () => {
                window.history.back();
            });
        });

        // 首页按钮事件
        document.querySelectorAll('.btn-primary').forEach(btn => {
            btn.addEventListener('click', () => {
                window.location.href = '/';
            });
        });

        // 详细信息切换
        const detailsElements = document.querySelectorAll('.security-details');
        detailsElements.forEach(details => {
            const summary = details.querySelector('summary');
            if (summary) {
                summary.addEventListener('click', () => {
                    details.classList.toggle('expanded');
                });
            }
        });

        // 键盘快捷键
        document.addEventListener('keydown', (e) => {
            // ESC键返回上页
            if (e.key === 'Escape') {
                window.history.back();
            }
            // Enter键返回首页
            if (e.key === 'Enter' && e.ctrlKey) {
                window.location.href = '/';
            }
        });
    }

    /**
     * 自动隐藏敏感信息（生产环境）
     */
    autoHideSensitiveInfo() {
        const isDebug = document.body.getAttribute('data-debug') === 'true' ||
            window.location.search.includes('debug=true');

        if (!isDebug) {
            const sensitiveElements = document.querySelectorAll('[data-sensitive]');
            sensitiveElements.forEach(el => {
                el.style.display = 'none';
            });
        }
    }

    /**
     * 添加分析统计
     */
    addAnalytics() {
        // 可以集成到分析平台
        const eventData = {
            type: 'security_block',
            timestamp: new Date().toISOString(),
            requestId: this.getRequestId(),
            path: window.location.pathname,
            userAgent: navigator.userAgent
        };

        // 发送到分析端点（可选）
        this.sendAnalytics(eventData).catch(console.error);
    }

    /**
     * 获取请求ID
     */
    getRequestId() {
        const requestIdElement = document.querySelector('[data-request-id]');
        return requestIdElement ? requestIdElement.textContent : 'unknown';
    }

    /**
     * 发送分析数据
     */
    async sendAnalytics(data) {
        try {
            // 使用navigator.sendBeacon如果可用
            if (navigator.sendBeacon) {
                const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
                return navigator.sendBeacon('/api/security/analytics', blob);
            } else {
                // 回退到fetch API
                return fetch('/api/security/analytics', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
            }
        } catch (error) {
            console.warn('分析数据发送失败:', error);
        }
    }

    /**
     * 显示反馈表单
     */
    showFeedbackForm() {
        const feedbackHtml = `
            <div class="security-feedback">
                <h3>问题反馈</h3>
                <p>如果您认为这是一个错误，请告诉我们：</p>
                <textarea placeholder="请描述您遇到的问题..." rows="4"></textarea>
                <div class="feedback-actions">
                    <button class="btn btn-secondary" onclick="this.closest('.security-feedback').remove()">取消</button>
                    <button class="btn btn-primary" onclick="securityPage.submitFeedback(this)">提交</button>
                </div>
            </div>
        `;

        const container = document.querySelector('.security-container');
        container.insertAdjacentHTML('beforeend', feedbackHtml);
    }

    /**
     * 提交反馈
     */
    submitFeedback(button) {
        const feedbackElement = button.closest('.security-feedback');
        const textarea = feedbackElement.querySelector('textarea');
        const feedback = textarea.value.trim();

        if (!feedback) {
            alert('请输入反馈内容');
            return;
        }

        const feedbackData = {
            requestId: this.getRequestId(),
            feedback: feedback,
            timestamp: new Date().toISOString()
        };

        // 发送反馈
        this.sendFeedback(feedbackData)
            .then(() => {
                alert('感谢您的反馈！');
                feedbackElement.remove();
            })
            .catch(() => {
                alert('反馈提交失败，请稍后重试。');
            });
    }

    /**
     * 发送反馈数据
     */
    async sendFeedback(data) {
        return fetch('/api/security/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
    }

    /**
     * 复制请求ID到剪贴板
     */
    copyRequestId() {
        const requestId = this.getRequestId();
        navigator.clipboard.writeText(requestId)
            .then(() => {
                this.showToast('请求ID已复制到剪贴板');
            })
            .catch(() => {
                this.showToast('复制失败，请手动复制');
            });
    }

    /**
     * 显示提示消息
     */
    showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'security-toast';
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #323232;
            color: white;
            padding: 12px 20px;
            border-radius: 4px;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}

// 添加CSS动画
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .security-details summary::after {
        content: '▶';
        display: inline-block;
        margin-left: 8px;
        transition: transform 0.2s ease;
    }
    .security-details.expanded summary::after {
        transform: rotate(90deg);
    }
`;
document.head.appendChild(style);

// 初始化
const securityPage = new SecurityBlockedPage();

// 导出到全局作用域
window.securityPage = securityPage;

console.log('安全拦截页面脚本加载完成');