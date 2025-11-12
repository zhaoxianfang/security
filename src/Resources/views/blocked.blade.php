<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $title ?? '安全拦截' }}</title>
    <link rel="stylesheet" href="{{ asset('vendor/security/css/security.css') }}">
    <style>
        /* 内联基础样式，防止CSS加载失败 */
        .security-container {
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .security-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .security-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
        .security-title {
            font-size: 24px;
            color: #dc3545;
            margin-bottom: 10px;
        }
        .security-message {
            color: #6c757d;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .security-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .security-footer {
            text-align: center;
            margin-top: 30px;
            color: #6c757d;
            font-size: 14px;
        }
    </style>
</head>
<body>
<div class="security-container">
    <div class="security-header">
        <div class="security-icon">🚫</div>
        <h1 class="security-title">{{ $title ?? '安全拦截' }}</h1>
    </div>

    <div class="security-content">
        <p class="security-message">{{ $message ?? '您的请求被安全系统拦截。' }}</p>

        @if(!empty($context) && config('app.debug'))
            <div class="security-details">
                <strong>详细信息：</strong>
                <ul>
                    <li><strong>拦截类型：</strong>{{ $type ?? '未知' }}</li>
                    <li><strong>请求ID：</strong>{{ $request_id ?? '无' }}</li>
                    <li><strong>时间戳：</strong>{{ $timestamp ?? now()->toISOString() }}</li>
                    @foreach($context as $key => $value)
                        <li><strong>{{ $key }}：</strong>{{ is_array($value) ? json_encode($value) : $value }}</li>
                    @endforeach
                </ul>
            </div>
        @endif

        <div class="security-actions">
            <button onclick="window.history.back()" class="btn btn-secondary">返回上页</button>
            <button onclick="window.location.href='/'" class="btn btn-primary">返回首页</button>
        </div>
    </div>

    <div class="security-footer">
        <p>如果您认为这是一个错误，请联系网站管理员。</p>
        <p>请求ID: {{ $request_id ?? '无' }}</p>
    </div>
</div>

<script src="{{ asset('vendor/security/js/security.js') }}"></script>
<script>
    // 内联基础JavaScript
    document.addEventListener('DOMContentLoaded', function() {
        console.log('安全拦截页面加载完成');

        // 自动隐藏调试信息（生产环境）
        if (!{{ config('app.debug') ? 'true' : 'false' }}) {
            const debugElements = document.querySelectorAll('.security-details');
            debugElements.forEach(el => el.style.display = 'none');
        }
    });
</script>
</body>
</html>