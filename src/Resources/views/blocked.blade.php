<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全拦截 - {{ config('app.name', 'Laravel') }}</title>
    <meta name="description" content="zxf/security 安全拦截页面 - 您的请求被安全系统拦截">
    <link rel="stylesheet" href="{{ url('/zxf/security/css/security.css') }}">
</head>
<body>
<div class="bg-animation" id="bgAnimation"></div>
<div class="scan-line"></div>

<div class="container">
    <div class="header">
        <div class="shield-container">
            <svg class="shield" viewBox="0 0 100 100">
                <!-- 盾牌外层光晕 -->
                <defs>
                    <radialGradient id="shieldGlow" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" stop-color="#ff6b6b" stop-opacity="0.8" />
                        <stop offset="100%" stop-color="#e74c3c" stop-opacity="0" />
                    </radialGradient>
                </defs>
                <circle cx="50" cy="50" r="48" fill="url(#shieldGlow)" opacity="0.7" />

                <!-- 盾牌主体 -->
                <path d="M50,10 L10,25 L10,50 C10,70 30,85 50,90 C70,85 90,70 90,50 L90,25 L50,10 Z"
                      fill="#e74c3c" stroke="#fff" stroke-width="2"/>
                <!-- 盾牌内部装饰 -->
                <path d="M50,20 L25,30 L25,50 C25,65 40,75 50,78 C60,75 75,65 75,50 L75,30 L50,20 Z"
                      fill="#c0392b" stroke="#fff" stroke-width="1"/>
                <!-- 盾牌中央图标 -->
                <path d="M50,40 L45,45 L50,50 L55,45 L50,40 Z M50,55 L40,50 L50,60 L60,50 L50,55 Z"
                      fill="#fff"/>
                <!-- 盾牌顶部装饰 -->
                <ellipse cx="50" cy="15" rx="5" ry="3" fill="#fff"/>
                <!-- 盾牌高光 -->
                <path d="M20,30 L35,25 L40,40" fill="none" stroke="#fff" stroke-width="1" opacity="0.5"/>
            </svg>
        </div>
        <h1 class="title">{{ $title ?? '安全拦截' }}</h1>
        <p class="subtitle">系统检测到潜在安全威胁</p>
    </div>

    <div class="content">
        <div class="alert-box">
            <div class="alert-icon">⚠️</div>
            <div class="alert-text">{{ $message ?? '检测到潜在的安全威胁' }}</div>
        </div>

        <div class="details">
            <h2 class="details-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                拦截详情
            </h2>

            <div class="detail-item">
                <div class="detail-label">拦截类型:</div>
                <div class="detail-value">{{ $type ?? '未知' }}</div>
            </div>

            <div class="detail-item">
                <div class="detail-label">请求ID:</div>
                <div class="detail-value">{{ $request_id ?? '-' }}</div>
            </div>

            <div class="detail-item">
                <div class="detail-label">时间戳:</div>
                <div class="detail-value" id="formattedTimestamp">{{ $timestamp ? \Carbon\Carbon::parse($timestamp)->format('Y-m-d H:i:s') : now()->format('Y-m-d H:i:s') }}</div>
            </div>

        </div>
        @if(!empty($context))
        <div class="context-section">
            <h2 class="context-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                上下文信息
            </h2>

            <div class="context-json">
                <code id="jsonContext">{{$context??''}}</code>
            </div>
        </div>
        @endif

        @if(!empty($errors))
            <div class="context-section">
                <h2 class="context-title">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                        <polyline points="10 9 9 9 8 9"></polyline>
                    </svg>
                    异常信息
                </h2>

                <div class="context-json">
                    <code id="jsonErrors">{{$errors??''}}</code>
                </div>
            </div>
        @endif

        <div class="actions">
            <button class="btn btn-secondary" onclick="history.back()">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:8px;">
                    <path d="M19 12H5M12 19l-7-7 7-7"/>
                </svg>
                返回上一页
            </button>
            <button class="btn btn-primary" onclick="location.reload()">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:8px;">
                    <path d="M23 4v6h-6M1 20v-6h6"/>
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                </svg>
                重新加载
            </button>
        </div>
    </div>

    <div class="footer">
        <p>© {{ date('Y') }} {{ config('app.name', 'Laravel') }} 系统安全中心 -by <a href="https://yoc.cn" target="_blank">YOC</a></p>
    </div>
</div>
<script src="{{ url('/zxf/security/js/security.js') }}"></script>
</body>
</html>