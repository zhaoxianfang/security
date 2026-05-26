# 使用示例

本文档提供常见使用场景的完整示例代码。

## 目录

- [基础配置](#基础配置)
- [IP黑白名单](#ip黑白名单)
- [自定义拦截视图](#自定义拦截视图)
- [拦截回调](#拦截回调)
- [动态IP封禁](#动态ip封禁)

---

## 基础配置

### 最小可用配置

```php
// config/security.php
return [
    'enabled' => true,
    'log_enabled' => true,
    'trusted_ips' => ['127.0.0.1', '::1'],
    'rate_limit' => [
        'enabled' => true,
        'max_attempts' => 60,
        'decay_minutes' => 1,
    ],
];
```

---

## IP黑白名单

### 从数据库动态加载黑名单

```php
<?php

namespace App\Security;

use Illuminate\Http\Request;
use zxf\Security\Contracts\IpCheckerInterface;

class DynamicBlacklistChecker implements IpCheckerInterface
{
    public function check(string $ip, Request $request): bool
    {
        return \App\Models\BlockedIp::where('ip', $ip)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }
}
```

配置：

```php
'blacklist' => [
    \App\Security\DynamicBlacklistChecker::class,
],
```

### 基于API密钥的白名单

```php
'whitelist' => [
    function($ip, $request) {
        $apiKey = $request->header('X-API-Key');
        return $apiKey && \App\Models\ApiKey::isValid($apiKey);
    },
],
```

---

## 自定义拦截视图

### 示例1：基础自定义视图

配置文件：

```php
'response' => [
    'view' => 'errors.security',
],
```

视图文件 `resources/views/errors/security.blade.php`：

```blade
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问被拒绝</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            text-align: center;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 15px;
        }
        p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .threat-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: left;
        }
        .threat-info code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>访问被拒绝</h1>
        <p>{{ $message }}</p>

        @if(!empty($threats) && config('security.response.show_threat_details'))
        <div class="threat-info">
            <strong>检测信息：</strong><br>
            威胁类型：
            @foreach($threats as $threat)
                <code>{{ $threat }}</code>
            @endforeach
        </div>
        @endif
    </div>
</body>
</html>
```

### 示例2：使用闭包返回动态内容

```php
'response' => [
    'view' => function($data) {
        // 根据威胁类型选择不同视图
        $view = match(true) {
            in_array('sql', $data['threats']) => 'errors.threats.sql',
            in_array('xss', $data['threats']) => 'errors.threats.xss',
            default => 'errors.generic',
        };

        return view($view, array_merge($data, [
            'client_ip' => request()->ip(),
            'request_id' => uniqid('req_'),
        ]));
    },
],
```

### 示例3：使用类方法

配置文件：

```php
'response' => [
    'view' => ['App\Http\Controllers\SecurityController', 'renderBlockPage'],
],
```

控制器：

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Response;

class SecurityController extends Controller
{
    public function renderBlockPage(array $data): Response
    {
        // 记录到监控
        \Log::channel('security')->warning('Block rendered', $data);

        // 发送告警（仅高危）
        if (in_array('sql', $data['threats']) || in_array('command', $data['threats'])) {
            $this->sendAlert($data);
        }

        return response()->view('errors.security', $data, 403);
    }

    private function sendAlert(array $data): void
    {
        // 发送钉钉/邮件告警
    }
}
```

### 示例4：完整的响应处理器类

```php
<?php

namespace App\Security;

use Illuminate\Http\Response;
use Illuminate\View\View;

class SecurityBlockResponseHandler
{
    private array $threatViews = [
        'sql' => 'errors.threats.sql',
        'command' => 'errors.threats.command',
        'xss_script' => 'errors.threats.xss',
        'default' => 'errors.security',
    ];

    public function __invoke(array $data): Response
    {
        // 记录安全日志
        $this->logBlock($data);

        // 发送告警（高危）
        if ($this->isHighRisk($data['threats'])) {
            $this->sendAlert($data);
        }

        // 选择视图
        $view = $this->selectView($data['threats']);

        return response()->view($view, $data, 403);
    }

    private function logBlock(array $data): void
    {
        \DB::table('security_blocks')->insert([
            'ip' => request()->ip(),
            'url' => request()->fullUrl(),
            'threats' => json_encode($data['threats']),
            'user_agent' => request()->userAgent(),
            'created_at' => now(),
        ]);
    }

    private function sendAlert(array $data): void
    {
        $message = sprintf(
            "🚨 安全告警\n类型: %s\nIP: %s\nURL: %s\n时间: %s",
            implode(', ', $data['threats']),
            request()->ip(),
            $data['url'],
            now()->format('Y-m-d H:i:s')
        );

        // 发送钉钉告警（异步）
        \App\Jobs\SendDingTalkAlert::dispatch($message);
    }

    private function isHighRisk(array $threats): bool
    {
        $highRiskThreats = ['sql', 'command', 'dangerous_upload'];
        return !empty(array_intersect($threats, $highRiskThreats));
    }

    private function selectView(array $threats): string
    {
        foreach ($threats as $threat) {
            if (isset($this->threatViews[$threat])) {
                return $this->threatViews[$threat];
            }
        }
        return $this->threatViews['default'];
    }
}
```

配置：

```php
'response' => [
    'view' => \App\Security\SecurityBlockResponseHandler::class,
],
```

---

## 拦截回调

### 示例1：基础日志记录

```php
'before_block_callback' => function($context) {
    \App\Models\SecurityLog::create([
        'threat_type' => $context->threatType,
        'risk_level' => $context->getRiskLevel(),
        'client_ip' => $context->clientIp,
        'url' => $context->url,
        'user_agent' => $context->request->userAgent(),
    ]);

    return true;
},
```

### 示例2：智能放行策略

```php
'before_block_callback' => function($context) {
    // 1. 内网IP放行
    if (is_intranet_ip($context->clientIp)) {
        return false;
    }

    // 2. 登录用户放行低风险请求
    if (auth()->check() && $context->getRiskLevel() === 'low') {
        return false;
    }

    // 3. 合作伙伴API白名单
    $apiKey = $context->request->header('X-Partner-Key');
    if ($apiKey && \App\Models\Partner::isValidKey($apiKey)) {
        return false;
    }

    // 4. 根据威胁类型决定
    return match($context->threatType) {
        'sql', 'command', 'dangerous_upload' => true,
        'xss_script', 'xss_dom' => true,
        'rate_limit', 'url_too_long' => false,
        default => $context->getRiskLevel() === 'high',
    };
},
```

### 示例3：速率限制 + 自动封禁

```php
'before_block_callback' => function($context) {
    // 记录拦截
    \App\Models\SecurityLog::create($context->toArray());

    // 同IP短时间多次拦截，自动加入黑名单
    $key = 'security:blocks:' . $context->clientIp;
    $count = \Cache::increment($key);
    \Cache::expire($key, 3600); // 1小时过期

    if ($count >= 5) {
        // 自动封禁1小时
        \App\Models\BlockedIp::create([
            'ip' => $context->clientIp,
            'reason' => 'Auto-blocked after 5 violations',
            'expires_at' => now()->addHour(),
        ]);

        // 发送告警
        \Log::channel('security')->alert('IP auto-blocked', [
            'ip' => $context->clientIp,
            'violations' => $count,
        ]);
    }

    return true;
},
```

---

## 动态IP封禁

### 自动封禁暴力破解IP

```php
<?php

namespace App\Listeners;

use Illuminate\Auth\Events\LoginFailed;

class AutoBlockFailedLogins
{
    public function handle(LoginFailed $event): void
    {
        $ip = request()->ip();
        $key = 'login_attempts:' . $ip;

        $attempts = \Cache::increment($key);
        \Cache::put($key, $attempts, now()->addHour());

        if ($attempts >= 10) {
            // 加入黑名单（临时封禁）
            \App\Models\BlockedIp::create([
                'ip' => $ip,
                'reason' => 'Too many failed login attempts',
                'expires_at' => now()->addHours(24),
            ]);

            // 记录日志
            security_log('auto_blacklist', 'IP自动封禁', [
                'ip' => $ip,
                'attempts' => $attempts,
            ]);
        }
    }
}
```

---

## SSRF检测配置

### 基础SSRF防护

SSRF（服务器端请求伪造）检测已内置在 `high_risk_patterns.ssrf` 中，开箱即用：

> **v6.0+ 架构**：所有默认正则模式已迁移至独立数据文件（`src/Security/Patterns/data/`），由 `PatternService` 按需延迟加载。  
> 使用 `intercept_rules` 按风险等级追加自定义规则，`intercept_rules_exclude` 排除特定规则。

```php
// 内置检测覆盖：
// - 内网IP访问（127.0.0.1, 10.x, 172.16-31.x, 192.168.x）
// - 云元数据端点（169.254.169.254, metadata.google.internal）
// - 危险协议（gopher, dict, file, ftp, ldap, tftp）
// - DNS rebinding（nip.io, xip.io）
// - 端口探测

// 自定义SSRF检测规则（按风险等级追加）
'intercept_rules' => [
    'high' => [
        // 添加额外的内网域名
        '/\b(internal|localhost|localdomain)\b/i',
        // 添加更多危险协议
        '/\b(jar|netdoc|mailto|php):\/\//i',
    ],
],
```

### 自定义SSRF回调处理

```php
'before_block_callback' => function($context) {
    // SSRF 尝试记录到专门的安全系统
    if ($context->threatType === 'ssrf') {
        \App\Models\SsrfAttempt::create([
            'ip' => $context->clientIp,
            'url' => $context->url,
            'matched_content' => $context->matchedContent,
            'created_at' => now(),
        ]);
    }

    return true;
},
```

---

## CRLF/HTTP头注入检测

### 基础CRLF防护

CRLF注入检测在两层工作：
1. **配置规则层**：检测请求参数中的CRLF特征
2. **运行时检查层**：扫描所有HTTP头值中的 `\r` `\n` 字符

```php
// 运行时CRLF检测在 headers 配置中控制
'headers' => [
    'enabled' => true,
    'detect_crlf' => true, // 启用头值CRLF扫描
],
```

### 自定义CRLF处理

```php
'before_block_callback' => function($context) {
    if ($context->threatType === 'header_injection') {
        // CRLF注入通常来自恶意扫描器
        \Log::channel('security')->warning('CRLF injection attempt', [
            'ip' => $context->clientIp,
            'matched' => $context->matchedContent,
        ]);

        // 自动加入临时黑名单
        \Cache::put(
            'crlf_blocked:' . $context->clientIp,
            true,
            now()->addHours(24)
        );
    }

    return true;
},
```

---

## 安全响应头配置

### 自定义安全响应头

中间件在拦截响应中自动添加安全HTTP头。如需自定义：

```php
// 扩展中间件覆盖安全响应头方法
namespace App\Http\Middleware;

use zxf\Security\Middleware\SecurityMiddleware as BaseMiddleware;

class CustomSecurityMiddleware extends BaseMiddleware
{
    protected function getSecurityResponseHeaders(): array
    {
        return [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'SAMEORIGIN',  // 允许同源iframe
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Cache-Control' => 'no-store, max-age=0',
            'Pragma' => 'no-cache',
            'X-Permitted-Cross-Domain-Policies' => 'none',
        ];
    }
}
```

---

## 环境配置示例

### 生产环境

```env
SECURITY_ENABLED=true
SECURITY_LOG_ENABLED=true
SECURITY_SHOW_DETAILS=false
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_ATTEMPTS=60
SECURITY_RATE_LIMIT_DECAY=1
SECURITY_RATE_LIMIT_KEY_PREFIX=production

# SSRF 和 CRLF 检测默认始终启用
# 如需关闭特定检测：
# SECURITY_DETECT_HIGH_RISK=true
# SECURITY_DETECT_HEADERS=true
```

### 开发环境

```env
SECURITY_ENABLED=true
SECURITY_LOG_ENABLED=true
SECURITY_SHOW_DETAILS=true
SECURITY_RATE_LIMIT_ENABLED=false
SECURITY_RATE_LIMIT_KEY_PREFIX=development
```
