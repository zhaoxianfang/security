<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>🔒 安全拦截 - 访问被拒绝</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-danger: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            --radius-xl: 24px; --radius-lg: 16px; --radius-md: 10px;
            --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans SC', sans-serif;
            --font-mono: 'SF Mono', Monaco, monospace;
        }
        body {
            font-family: var(--font-sans); min-height: 100vh; display: flex; align-items: center; justify-content: center;
            padding: 20px; background: var(--gradient-primary); position: relative; overflow-x: hidden;
        }
        .particles { position: fixed; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 0; }
        .particle { position: absolute; border-radius: 50%; background: rgba(255,255,255,0.15); animation: float 15s infinite; }
        @keyframes float { 0%, 100% { transform: translateY(100vh); opacity: 0; } 10% { opacity: 1; } 90% { opacity: 0.5; } 100% { transform: translateY(-100vh); opacity: 0; } }
        .container { position: relative; z-index: 1; width: 100%; max-width: 720px; perspective: 1000px; }
        .card {
            background: rgba(255, 255, 255, 0.97); backdrop-filter: blur(20px); border-radius: var(--radius-xl);
            box-shadow: 0 20px 50px rgba(0,0,0,0.2), 0 0 0 1px rgba(255,255,255,0.5) inset;
            padding: 48px 40px; text-align: center; animation: slideIn 0.7s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        @keyframes slideIn { from { opacity: 0; transform: translateY(40px) rotateX(15deg) scale(0.95); } to { opacity: 1; transform: none; } }
        .shield-wrapper { position: relative; width: 120px; height: 120px; margin: 0 auto 28px; }
        .shield-ring { position: absolute; inset: -10px; border: 2px solid rgba(245, 101, 101, 0.3); border-radius: 50%; animation: ringPulse 2s ease-out infinite; }
        .shield-ring:nth-child(2) { animation-delay: 0.5s; }
        @keyframes ringPulse { 0% { transform: scale(1); opacity: 0.6; } 100% { transform: scale(1.3); opacity: 0; } }
        .shield { position: relative; width: 100%; height: 100%; background: var(--gradient-danger); border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 8px 32px rgba(245, 101, 101, 0.4); animation: floatShield 3s ease-in-out infinite; }
        @keyframes floatShield { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        .shield svg { width: 56px; height: 56px; fill: white; }
        .status-code { position: absolute; bottom: -5px; right: -5px; min-width: 44px; height: 44px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 50%, #f56565 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 900; color: white; border: 3px solid white; box-shadow: 0 4px 15px rgba(238, 90, 111, 0.5), 0 0 0 2px rgba(238, 90, 111, 0.2) inset; text-shadow: 0 1px 2px rgba(0,0,0,0.2); letter-spacing: -0.5px; animation: statusPulse 2s ease-in-out infinite; }
        @keyframes statusPulse { 0%, 100% { box-shadow: 0 4px 15px rgba(238, 90, 111, 0.5), 0 0 0 2px rgba(238, 90, 111, 0.2) inset; } 50% { box-shadow: 0 6px 20px rgba(238, 90, 111, 0.7), 0 0 0 4px rgba(238, 90, 111, 0.3) inset; } }
        h1 { font-size: 32px; font-weight: 800; margin-bottom: 12px; background: linear-gradient(135deg, #1a202c 0%, #4a5568 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #718096; font-size: 16px; line-height: 1.7; max-width: 480px; margin: 0 auto 24px; }
        .badge-group { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; margin-bottom: 24px; }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .badge-danger { background: linear-gradient(135deg, #fed7d7 0%, #feb2b2 100%); color: #c53030; }
        .badge-warning { background: linear-gradient(135deg, #feebc8 0%, #fbd38d 100%); color: #c05621; }
        .badge-info { background: linear-gradient(135deg, #bee3f8 0%, #90cdf4 100%); color: #2b6cb0; }
        .badge-indicator { width: 6px; height: 6px; border-radius: 50%; animation: blink 1.5s infinite; display: inline-block; }
        .badge-danger .badge-indicator { background: #c53030; box-shadow: 0 0 4px #c53030; }
        .badge-warning .badge-indicator { background: #c05621; box-shadow: 0 0 4px #c05621; }
        .badge-info .badge-indicator { background: #2b6cb0; box-shadow: 0 0 4px #2b6cb0; }
        @keyframes blink { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.8); } }
        .threat-card { background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%); border: 1px solid rgba(245, 101, 101, 0.15); border-radius: var(--radius-lg); padding: 24px; margin-bottom: 20px; text-align: left; }
        .threat-header { display: flex; align-items: center; gap: 12px; margin-bottom: 18px; padding-bottom: 16px; border-bottom: 1px solid rgba(245, 101, 101, 0.15); }
        .threat-icon { width: 40px; height: 40px; background: var(--gradient-danger); border-radius: var(--radius-md); display: flex; align-items: center; justify-content: center; }
        .threat-icon svg { width: 22px; height: 22px; fill: white; }
        .threat-title { font-size: 15px; font-weight: 700; color: #1a202c; }
        .threat-subtitle { font-size: 12px; color: #718096; margin-top: 2px; }
        .info-grid { display: grid; gap: 10px; }
        .info-item { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; background: white; border-radius: var(--radius-md); transition: all 0.15s; }
        .info-item:hover { transform: translateX(3px); box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .info-label { display: flex; align-items: center; gap: 8px; color: #4a5568; font-size: 13px; font-weight: 500; }
        .info-label svg { width: 16px; height: 16px; fill: #a0aec0; }
        .info-value { color: #2d3748; font-weight: 600; font-size: 13px; font-family: var(--font-mono); max-width: 50%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .accordion { background: #f7fafc; border-radius: var(--radius-md); margin-bottom: 20px; overflow: hidden; }
        .accordion-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; cursor: pointer; transition: background 0.15s; }
        .accordion-header:hover { background: #edf2f7; }
        .accordion-title { display: flex; align-items: center; gap: 10px; font-size: 14px; font-weight: 600; color: #4a5568; }
        .accordion-title svg { width: 18px; height: 18px; fill: #718096; }
        .accordion-icon { width: 20px; height: 20px; fill: #a0aec0; transition: transform 0.3s; }
        .accordion.expanded .accordion-icon { transform: rotate(180deg); }
        .accordion-content { max-height: 0; overflow: hidden; transition: max-height 0.3s; }
        .accordion.expanded .accordion-content { max-height: 500px; }
        .accordion-body { padding: 0 20px 20px; }
        .request-detail { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px dashed #e2e8f0; font-size: 13px; }
        .request-detail:last-child { border-bottom: none; }
        .request-detail-label { color: #718096; }
        .request-detail-value { color: #4a5568; font-family: var(--font-mono); max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .suggestions { background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%); border: 1px solid rgba(72, 187, 120, 0.15); border-radius: var(--radius-md); padding: 20px; margin-bottom: 24px; text-align: left; }
        .suggestions-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700; color: #22543d; margin-bottom: 12px; }
        .suggestions-title svg { width: 18px; height: 18px; fill: #48bb78; }
        .suggestions-list { list-style: none; font-size: 13px; color: #276749; }
        .suggestions-list li { padding: 6px 0 6px 24px; position: relative; }
        .suggestions-list li::before { content: '✓'; position: absolute; left: 0; color: #48bb78; font-weight: bold; width: 18px; height: 18px; background: rgba(72, 187, 120, 0.15); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; }
        .actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; margin-bottom: 24px; }
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 28px; border-radius: var(--radius-md); font-weight: 600; font-size: 14px; text-decoration: none; transition: all 0.15s; border: none; cursor: pointer; position: relative; overflow: hidden; }
        .btn::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent); transition: left 0.5s; }
        .btn:hover::before { left: 100%; }
        .btn-primary { background: var(--gradient-primary); color: white; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.35); }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102, 126, 234, 0.45); }
        .btn-secondary { background: white; color: #4a5568; border: 2px solid #e2e8f0; }
        .btn-secondary:hover { border-color: #cbd5e0; background: #f7fafc; transform: translateY(-2px); box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .btn svg { width: 16px; height: 16px; fill: currentColor; }
        .footer { padding-top: 24px; border-top: 1px solid #e2e8f0; }
        .request-meta { display: flex; flex-direction: column; gap: 10px; align-items: center; }
        .request-id-box { display: inline-flex; align-items: center; gap: 8px; padding: 10px 16px; background: linear-gradient(135deg, #edf2f7 0%, #e2e8f0 100%); border-radius: var(--radius-md); font-size: 12px; color: #4a5568; font-family: var(--font-mono); border: 1px solid rgba(160, 174, 192, 0.2); }
        .request-id-box svg { width: 14px; height: 14px; fill: #718096; }
        .request-id-box code { color: #2d3748; font-weight: 600; }
        .timestamp { font-size: 12px; color: #a0aec0; }
        .powered-by { margin-top: 8px; font-size: 11px; color: #cbd5e0; }
        .tech-details { background: #f8fafc; border-radius: var(--radius-md); padding: 16px; font-family: var(--font-mono); font-size: 12px; }
        .tech-row { display: flex; margin-bottom: 8px; }
        .tech-row:last-child { margin-bottom: 0; }
        .tech-label { color: #718096; min-width: 100px; flex-shrink: 0; }
        .tech-value { color: #2d3748; word-break: break-all; }
        .matched-content { background: #fff5f5; border: 1px solid #fed7d7; border-radius: var(--radius-md); padding: 10px 12px; color: #c53030; font-family: var(--font-mono); font-size: 11px; word-break: break-all; margin-top: 8px; }
        @media (max-width: 640px) {
            .card { padding: 32px 20px; }
            h1 { font-size: 26px; }
            .shield-wrapper { width: 100px; height: 100px; }
            .shield svg { width: 48px; height: 48px; }
            .info-item { flex-direction: column; align-items: flex-start; gap: 6px; }
            .info-value { max-width: 100%; }
            .request-detail { flex-direction: column; gap: 4px; }
            .request-detail-value { max-width: 100%; }
            .btn { width: 100%; justify-content: center; }
            .actions { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="particles">
        @for($i = 0; $i < 15; $i++)
            <div class="particle" style="left: {{ rand(5, 95) }}%; width: {{ rand(4, 12) }}px; height: {{ rand(4, 12) }}px; animation-delay: {{ $i * 0.8 }}s; animation-duration: {{ 12 + $i * 0.5 }}s;"></div>
        @endfor
    </div>
    <div class="container">
        <div class="card">
            <div class="shield-wrapper">
                <div class="shield-ring"></div>
                <div class="shield-ring"></div>
                <div class="shield">
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
                </div>
                <div class="status-code">{{ $http_status ?? 403 }}</div>
            </div>
            <div class="header">
                <h1>访问被拒绝</h1>
                <p class="subtitle">{{ $message ?? '系统检测到潜在的安全威胁，您的请求已被拦截。这是为了保护我们的系统和您的数据安全。' }}</p>
            </div>
            @if(!empty($threat_type) || !empty($risk_level))
            <div class="badge-group">
                @if(!empty($threat['category']))
                    <span class="badge badge-info"><span class="badge-indicator"></span>{{ $threat['category'] === 'injection' ? '注入攻击' : ($threat['category'] === 'path_attack' ? '路径攻击' : ($threat['category'] === 'client_side' ? '客户端攻击' : ($threat['category'] === 'rate_limit' ? '频率限制' : '安全威胁'))) }}</span>
                @endif
                @if(!empty($risk_level))
                    <span class="badge badge-{{ $risk_level === 'high' ? 'danger' : ($risk_level === 'medium' ? 'warning' : 'info') }}"><span class="badge-indicator"></span>{{ $risk_level === 'high' ? '高危' : ($risk_level === 'medium' ? '中危' : '低危') }}</span>
                @endif
            </div>
            @endif
            @if(!empty($threat) || !empty($threat_type))
            <div class="threat-card">
                <div class="threat-header">
                    <div class="threat-icon"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg></div>
                    <div><div class="threat-title">威胁详情</div>@if(!empty($threat['description']))<div class="threat-subtitle">{{ $threat['description'] }}</div>@endif</div>
                </div>
                <div class="info-grid">
                    @if(!empty($threat_type))<div class="info-item"><span class="info-label"><svg viewBox="0 0 24 24"><path d="M12 2l-5.5 9h11z"/><circle cx="17.5" cy="17.5" r="4.5"/><path d="M3 13.5h8v8H3z"/></svg>威胁类型</span><span class="info-value">{{ $threat_type }}</span></div>@endif
                    @if(!empty($risk_level))<div class="info-item"><span class="info-label"><svg viewBox="0 0 24 24"><path d="M12 2L1 21h22M12 6l7.53 13H4.47M11 10v4h2v-4m-2 6v2h2v-2"/></svg>风险等级</span><span class="info-value"><span class="badge badge-{{ $risk_level === 'high' ? 'danger' : ($risk_level === 'medium' ? 'warning' : 'info') }}"><span class="badge-indicator"></span>{{ $risk_level === 'high' ? '高危' : ($risk_level === 'medium' ? '中危' : '低危') }}</span></span></div>@endif
                    @if(!empty($threats))<div class="info-item"><span class="info-label"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>威胁标识</span><span class="info-value">{{ implode(', ', array_slice($threats, 0, 3)) }}{{ count($threats) > 3 ? ' +' . (count($threats) - 3) : '' }}</span></div>@endif
                    @if(!empty($timestamp))<div class="info-item"><span class="info-label"><svg viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>拦截时间</span><span class="info-value">{{ $timestamp }}</span></div>@endif
                </div>
            </div>
            @endif
            @if(!empty($matched_pattern) || !empty($matched_content) || !empty($request['ip']))
            <div class="accordion" onclick="this.classList.toggle('expanded')">
                <div class="accordion-header"><span class="accordion-title"><svg viewBox="0 0 24 24"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>技术详情</span><svg class="accordion-icon" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5z"/></svg></div>
                <div class="accordion-content"><div class="accordion-body">
                    @if(!empty($request['ip']))<div class="request-detail"><span class="request-detail-label">客户端 IP</span><span class="request-detail-value">{{ $request['ip'] }}</span></div>@endif
                    @if(!empty($request['method']))<div class="request-detail"><span class="request-detail-label">请求方法</span><span class="request-detail-value">{{ $request['method'] }}</span></div>@endif
                    @if(!empty($request['url']))<div class="request-detail"><span class="request-detail-label">请求 URL</span><span class="request-detail-value" title="{{ $request['url'] }}">{{ $request['url'] }}</span></div>@endif
                    @if(!empty($matched_pattern))<div class="request-detail" style="flex-direction: column; align-items: flex-start; gap: 8px;"><span class="request-detail-label">匹配规则</span><code class="matched-content">{{ $matched_pattern }}</code></div>@endif
                    @if(!empty($matched_content))<div class="request-detail" style="flex-direction: column; align-items: flex-start; gap: 8px;"><span class="request-detail-label">匹配内容</span><code class="matched-content">{{ $matched_content }}</code></div>@endif
                </div></div>
            </div>
            @endif
            <div class="suggestions">
                <div class="suggestions-title"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>安全建议</div>
                <ul class="suggestions-list">
                    <li>如果您是正常访问，请检查 URL 是否包含特殊字符</li>
                    <li>避免在 URL 中输入文件路径或系统命令</li>
                    <li>清除浏览器缓存后重试</li>
                    <li>如果问题持续，请联系网站管理员并提供下方请求 ID</li>
                </ul>
            </div>
            <div class="actions">
                <a href="/" class="btn btn-primary"><svg viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>返回首页</a>
                @if(!empty($contact_url))
                <a href="{{ $contact_url }}" class="btn btn-primary"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>联系我们</a>
                @endif
                <a href="javascript:history.back()" class="btn btn-secondary"><svg viewBox="0 0 24 24"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg>返回上页</a>
            </div>
            <div class="footer">
                <div class="request-meta">
                    <div class="request-id-box"><svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>请求ID: <code>{{ $request_id ?? 'SEC_' . date('YmdHis') . '_' . strtoupper(substr(hash('xxh3', random_bytes(8)), 0, 10)) }}</code></div>
                    <div class="timestamp">安全系统于 {{ $timestamp }} 拦截此请求</div>
                    <div class="powered-by">Protected by {{ $app_name ?? 'Security System' }}</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
