<!DOCTYPE html>
<html lang="zh-CN" data-debug="{{ config('app.debug') ? 'true' : 'false' }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>{{ $title ?? '安全拦截' }} - {{ config('app.name', 'Laravel') }}</title>
    <link rel="stylesheet" href="{{ url('/vendor/security/css/security.css') }}">
    <link rel="preload" href="{{ url('/vendor/security/css/security.css') }}" as="style">
    <meta name="description" content="安全拦截页面 - 您的请求被安全系统拦截">
</head>
<body class="security-body">
<div class="security-background"></div>

<div class="security-container">
    <!-- 头部 -->
    <div class="security-header">
        <div class="security-icon">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1Z" fill="currentColor"/>
                <path d="M12 11C13.1046 11 14 10.1046 14 9C14 7.89543 13.1046 7 12 7C10.8954 7 10 7.89543 10 9C10 10.1046 10.8954 11 12 11Z" fill="white"/>
                <path d="M12 13C10.8954 13 10 13.8954 10 15C10 16.1046 10.8954 17 12 17C13.1046 17 14 16.1046 14 15C14 13.8954 13.1046 13 12 13Z" fill="white"/>
            </svg>
        </div>
        <h1 class="security-title">{{ $title ?? '安全拦截' }}</h1>
        <p class="security-subtitle">您的请求被安全系统拦截</p>
    </div>

    <!-- 主要内容 -->
    <div class="security-content">
        <div class="security-message">
            <div class="message-icon">⚠️</div>
            <div class="message-text">
                <strong>拦截原因：</strong>
                {{ $message ?? '检测到潜在的安全威胁' }}
            </div>
        </div>

        <!-- 调试信息 -->
        @if(config('app.debug') && !empty($context))
            <details class="security-details" data-sensitive>
                <summary>调试信息 (仅开发环境显示)</summary>
                <div class="details-content">
                    <div class="detail-item">
                        <strong>拦截类型：</strong>
                        <span class="badge badge-{{ $type ?? 'unknown' }}">{{ $type ?? '未知' }}</span>
                    </div>
                    <div class="detail-item">
                        <strong>请求ID：</strong>
                        <code class="request-id" data-request-id="{{ $request_id ?? '' }}" onclick="securityPage.copyRequestId()" title="点击复制">
                            {{ $request_id ?? '无' }}
                        </code>
                    </div>
                    <div class="detail-item">
                        <strong>时间戳：</strong>
                        <time datetime="{{ $timestamp ?? now()->toISOString() }}">
                            {{ $timestamp ? \Carbon\Carbon::parse($timestamp)->format('Y-m-d H:i:s') : now()->format('Y-m-d H:i:s') }}
                        </time>
                    </div>
                    @if(!empty($context))
                        <div class="detail-item">
                            <strong>上下文信息：</strong>
                            <pre class="context-json"><code>{{ json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) }}</code></pre>
                        </div>
                    @endif
                </div>
            </details>
        @endif

        <!-- 操作按钮 -->
        <div class="security-actions">
            <button type="button" class="btn btn-secondary" onclick="window.history.back()">
                <span class="btn-icon">←</span>
                返回上页
            </button>
            <button type="button" class="btn btn-primary" onclick="window.location.href='/'">
                <span class="btn-icon">🏠</span>
                返回首页
            </button>
            @if(config('app.debug'))
                <button type="button" class="btn btn-outline" onclick="securityPage.showFeedbackForm()">
                    <span class="btn-icon">💬</span>
                    问题反馈
                </button>
            @endif
        </div>
    </div>

    <!-- 页脚 -->
    <div class="security-footer">
        <div class="footer-content">
            <p>如果您认为这是一个错误，请联系网站管理员并提供请求ID</p>
            <p class="request-info">
                <strong>请求ID：</strong>
                <code class="footer-request-id" onclick="securityPage.copyRequestId()" title="点击复制">
                    {{ $request_id ?? '无' }}
                </code>
            </p>
            <p class="copyright">
                &copy; {{ date('Y') }} {{ config('app.name', 'Laravel') }} - 安全防护系统
            </p>
        </div>
    </div>
</div>

<!-- 反馈表单模态框 -->
<div id="feedbackModal" class="modal" style="display: none;">
    <div class="modal-content">
        <div class="modal-header">
            <h3>问题反馈</h3>
            <button type="button" class="modal-close" onclick="securityPage.hideFeedbackForm()">×</button>
        </div>
        <div class="modal-body">
            <p>如果您认为这是一个错误，请描述您遇到的问题：</p>
            <textarea id="feedbackText" placeholder="请详细描述您遇到的情况..." rows="6"></textarea>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="securityPage.hideFeedbackForm()">取消</button>
            <button type="button" class="btn btn-primary" onclick="securityPage.submitFeedback()">提交反馈</button>
        </div>
    </div>
</div>

<!-- 加载JavaScript -->
<script src="{{ url('/vendor/security/js/security.js') }}"></script>

<!-- 内联脚本确保基本功能 -->
<script>
    // 基础功能保障
    if (typeof securityPage === 'undefined') {
        console.warn('安全页面脚本加载失败，使用基础功能');

        // 基础复制功能
        function copyToClipboard(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                showBasicToast('已复制到剪贴板');
            } catch (err) {
                console.error('复制失败:', err);
            }
            document.body.removeChild(textarea);
        }

        function showBasicToast(message) {
            const toast = document.createElement('div');
            toast.textContent = message;
            toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#323232;color:white;padding:12px 20px;border-radius:4px;z-index:1000;';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        // 绑定复制事件
        document.querySelectorAll('.request-id, .footer-request-id').forEach(el => {
            el.style.cursor = 'pointer';
            el.addEventListener('click', function() {
                copyToClipboard(this.textContent.trim());
            });
        });
    }
</script>
</body>
</html>