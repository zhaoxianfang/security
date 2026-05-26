# 配置指南

> 适用于 PHP 8.2 / 8.3 / 8.4 / 8.5 | Laravel 11 / 12 / 13

## 配置文件结构

配置文件位于 `config/security.php`，包含以下主要部分：

```php
return [
    'enabled'                   => true,           // 主开关
    'log_enabled'               => true,           // 日志开关
    'log_level'                 => 'warning',      // 日志级别
    'log_full_request'          => false,          // 完整请求记录
    'detection_layers'          => [...],          // 检测层开关
    'trusted_ips'               => [],             // 信任IP（默认空，需自行配置）
    'rate_limit'                => [...],          // 速率限制
    'blacklist'                 => [...],          // IP黑名单
    'whitelist'                 => [],             // IP白名单（默认空）
    'intercept_rules'           => [...],          // 【追加】自定义拦截规则
    'intercept_rules_exclude'   => [...],          // 【排除】全局拦截规则排除
    'upload'                    => [...],          // 文件上传限制
    'max_url_length'            => [...],          // URL长度限制
    'max_body_size'             => [...],          // 请求体大小限制
    'user_agent_blacklist'      => null,           // UA黑名单（null=使用内置默认）
    'headers'                   => [...],          // HTTP头检查
    'excluded_routes'           => [...],          // 路由排除
    'before_block_callback'     => null,           // 拦截前回调
    'response'                  => [...],          // 响应配置
    'markdown'                  => [...],          // Markdown智能识别
    'encoding_detection'        => [...],          // 编码绕过检测
    'allowed_http_methods'      => null,           // 允许的HTTP方法（null=使用内置默认）
    'input_processing'          => [...],          // 输入处理配置
    'threat_risk_levels'        => [...],          // 威胁风险等级覆盖
];
```

## 基础配置

### enabled

是否启用安全中间件。

```php
'enabled' => env('SECURITY_ENABLED', true),
```

- 设为 `false` 将完全禁用所有安全检查
- 适用于临时维护或调试场景

### log_enabled

是否记录安全威胁日志。

```php
'log_enabled' => env('SECURITY_LOG_ENABLED', true),
```

### log_level

日志级别，控制记录什么级别的安全事件。

```php
'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),
```

可选值：
- `debug` - 记录所有事件（开发环境）
- `info` - 记录信息性事件
- `warning` - 仅记录警告及以上（默认，推荐生产环境）
- `error` - 仅记录错误及以上
- `critical` - 仅记录严重事件

### log_full_request

是否记录完整请求数据（含POST数据）。

```php
'log_full_request' => env('SECURITY_LOG_FULL_REQUEST', false),
```

⚠️ **警告**：生产环境开启可能记录敏感信息（如密码），请谨慎使用！

日志格式示例：

```
[2026-04-08 14:30:00] production.WARNING: [Security] 安全威胁检测 {
  "type": "sql",
  "ip": "192.168.1.100",
  "method": "GET",
  "url": "https://example.com/api?id=1' UNION SELECT...",
  "details": "高危模式匹配: /\\bunion\\s+all\\s+select\\b/i"
}
```

## 检测层开关配置

通过 `detection_layers` 可以单独启用或禁用特定的安全检测层。

```php
'detection_layers' => [
    'url_path'     => env('SECURITY_DETECT_URL_PATH', true),     // URL路径攻击检测
    'encoding'     => env('SECURITY_DETECT_ENCODING', true),     // 多重编码检测
    'user_agent'   => env('SECURITY_DETECT_USER_AGENT', true),   // User-Agent检查
    'headers'      => env('SECURITY_DETECT_HEADERS', true),      // HTTP头检查
    'body_size'    => env('SECURITY_DETECT_BODY_SIZE', true),    // 请求体大小检查
    'rate_limit'   => env('SECURITY_DETECT_RATE_LIMIT', true),   // 速率限制
    'http_method'  => env('SECURITY_DETECT_HTTP_METHOD', true),  // HTTP方法检查
    'url_length'   => env('SECURITY_DETECT_URL_LENGTH', true),   // URL长度检查
    'high_risk'    => env('SECURITY_DETECT_HIGH_RISK', true),    // 高危攻击检测
    'xss'          => env('SECURITY_DETECT_XSS', true),          // XSS攻击检测
    'upload'       => env('SECURITY_DETECT_UPLOAD', true),       // 文件上传检查
],
```

**使用场景**：

1. **减少误报**：如果某类检测产生过多误报，可临时关闭
2. **性能优化**：在高并发场景下关闭非关键检测
3. **调试排查**：逐个关闭检测层定位问题

**注意**：
- IP白名单和黑名单不受这些开关控制（始终启用）
- 建议生产环境保持所有检测启用

## IP配置

### trusted_ips

信任IP列表，这些IP会跳过**所有**安全检查。

```php
'trusted_ips' => [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
],
```

**支持格式**：

- 单个IP：`192.168.1.100`
- CIDR网段：`192.168.0.0/16`

**警告**：谨慎添加公网IP到白名单！

### blacklist

IP黑名单，这些IP会被立即拦截（HTTP 403）。

```php
'blacklist' => [
    '192.168.1.100',      // 单个IP
    '10.0.0.0/24',        // 整个网段
],
```

**适用场景**：

- 封禁已确认的攻击者
- 阻止已知恶意爬虫
- 配合日志自动封禁暴力破解源

### whitelist

IP白名单，语义上用于特定业务场景（如合作伙伴API）。

```php
'whitelist' => [
    '203.0.113.50',       // 合作伙伴服务器
    '198.51.100.0/24',    // 支付网关回调IP段
],
```

**与 trusted_ips 的区别**：

- `trusted_ips`：系统层面的信任（如内网）
- `whitelist`：业务层面的信任（如合作伙伴）

## 速率限制配置

```php
'rate_limit' => [
    'enabled'       => true,
    'max_attempts'  => 60,
    'decay_minutes' => 1,
    'key_prefix'    => 'security',
],
```

### 配置项

| 项 | 说明 | 推荐值 |
|---|------|-------|
| `enabled` | 是否启用 | `true` |
| `max_attempts` | 时间窗口内最大请求数 | 60（网站）、300（API） |
| `decay_minutes` | 时间窗口（分钟） | 1 |
| `key_prefix` | 限流 key 前缀 | `security` |

> **限流 key 说明**：中间件使用 `{key_prefix}:{IP}:{路由路径MD5}` 作为限流 key，避免不同路由间的碰撞。

### 场景建议

**普通网站**：

```php
'max_attempts'  => 60,
'decay_minutes' => 1,    // 60次/分钟
```

**API服务**：

```php
'max_attempts'  => 300,
'decay_minutes' => 1,    // 300次/分钟
```

**后台管理**（更严格）：

```php
'max_attempts'  => 20,
'decay_minutes' => 1,    // 20次/分钟
```

## 拦截回调配置

### before_block_callback

在正式拦截请求前执行的回调函数，允许开发者自定义拦截决策。

```php
'before_block_callback' => null,  // 默认禁用
```

**支持格式**：

| 格式 | 示例 | 说明 |
|------|------|------|
| `null/false` | `null` | 禁用回调，直接拦截 |
| `true` | `true` | 直接拦截（无效果） |
| 闭包 | `function($ctx) { ... }` | 匿名函数 |
| 类名字符串 | `'App\Security\Handler'` | 自动实例化并调用 `__invoke` |
| 可调用数组 | `['App\Security\Handler', 'handle']` | 指定类和方法 |

**返回值说明**：

| 返回值 | 行为 |
|--------|------|
| `false` | **放行** - 请求继续处理 |
| `true` / `null` / 无返回 | **拦截** - 返回拦截响应给用户 |

### 回调示例

**1. 基础日志记录**

```php
'before_block_callback' => function(\zxf\Security\Dto\InterceptionContext $context) {
    // 记录到数据库
    \App\Models\SecurityLog::create([
        'threat_type' => $context->threatType,
        'risk_level' => $context->getRiskLevel(),
        'client_ip' => $context->clientIp,
        'url' => $context->url,
        'details' => $context->toArray(),
    ]);

    return true; // 继续拦截
},
```

**2. 低风险自动放行**

```php
'before_block_callback' => function($context) {
    // 仅拦截高危威胁
    if ($context->getRiskLevel() !== 'high') {
        return false; // 放行低/中风险请求
    }
    return true;
},
```

**3. 特定IP放行**

```php
'before_block_callback' => function($context) {
    // 内网IP放行
    if (str_starts_with($context->clientIp, '192.168.')) {
        \Log::info('内网威胁已放行', ['ip' => $context->clientIp]);
        return false;
    }
    return true;
},
```

**4. 完整业务逻辑**

```php
'before_block_callback' => function($context) {
    $data = $context->toArray();

    // 1. 记录日志（异步）
    \App\Jobs\LogSecurityEvent::dispatch($data);

    // 2. 白名单检查
    $whitelist = ['192.168.1.100', '10.0.0.50'];
    if (in_array($context->clientIp, $whitelist)) {
        return false;
    }

    // 3. 根据威胁类型处理
    return match ($context->threatType) {
        'sql', 'command' => true,           // 高危：拦截
        'xss_script' => true,               // XSS：拦截
        'rate_limit' => false,              // 限流：放行（已有限流提示）
        default => true,                    // 其他：拦截
    };
},
```

### 类方式回调

创建处理类：

```php
<?php

namespace App\Security;

use zxf\Security\Dto\InterceptionContext;

class SecurityInterceptor
{
    public function __invoke(InterceptionContext $context): ?bool
    {
        // 发送告警通知
        if ($context->getRiskLevel() === 'high') {
            $this->sendAlert($context);
        }

        // 允许运营团队IP
        if ($this->isOperationTeam($context->clientIp)) {
            return false;
        }

        return true;
    }

    private function sendAlert(InterceptionContext $context): void
    {
        // 钉钉/企业微信告警
    }

    private function isOperationTeam(string $ip): bool
    {
        return in_array($ip, config('security.operation_ips'));
    }
}
```

配置中使用：

```php
'before_block_callback' => \App\Security\SecurityInterceptor::class,
```

---

## 统一拦截规则管理（v6.0）

v6.0 将原先分散的 `high_risk_patterns`、`xss_patterns`、`url_path_detection.path_patterns` 及各自的 `*_exclude`、`*_add` 配置，合并为两个统一的配置项：

- **`intercept_rules`** — 按风险等级（high / medium / low）追加自定义正则规则
- **`intercept_rules_exclude`** — 全局排除列表（精确字符串匹配正则表达式）

### 规则优先级

1. `intercept_rules_exclude` — 排除列表中的规则**全部忽略**（优先级最高）
2. `intercept_rules` — 用户自定义追加规则（优先级次之）
3. `built-in patterns` — 内置默认规则（数据文件位于 `src/Security/Patterns/data/`）

### intercept_rules

按风险等级分组追加自定义正则，不区分攻击类型。追加的规则将作为独立类型 `_custom_high` / `_custom_medium` / `_custom_low` 参与检测。

```php
'intercept_rules' => [
    'high' => [
        // 业务高危规则
        '/\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i',
    ],
    'medium' => [
        // 业务中危规则
        '/\b(internal_api_secret)\b/i',
    ],
    'low' => [],
],
```

### intercept_rules_exclude

全局排除列表。不管是哪种内置类型（sql、command、xss_script 等），只要添加在此处的正则字符串，就全部排除。

```php
'intercept_rules_exclude' => [
    '/unhex\s*\(/i',           // 业务使用 unhex() 做密码哈希
    '/benchmark\s*\(/i',       // 业务使用 benchmark 做性能测试
    '/\b1\s*=\s*1\b/i',        // 搜索场景常用"1=1"，误报率高
],
```

> ⚠️ **排除规则时务必评估安全风险！**

### 内置检测类别

**高危攻击**（`src/Security/Patterns/data/high_risk_patterns.php`）：

| 类别 | 说明 |
|------|------|
| `sql` | SQL注入（UNION、堆叠查询、危险函数） |
| `command` | 命令注入（system、exec等） |
| `path` | 路径遍历（../../../） |
| `ldap` | LDAP注入 |
| `xml` | XXE/XML注入 |
| `nosql` | NoSQL注入 |
| `ssti` | 服务器端模板注入 |
| `ssrf` | 服务器端请求伪造 |
| `encoding` | 编码绕过攻击 |
| `header_injection` | HTTP头注入 |
| `redirect` | 开放重定向 |
| `file_include` | 文件包含 |

**XSS攻击**（`src/Security/Patterns/data/xss_patterns.php`）：

| 类别 | 说明 |
|------|------|
| `script` | 脚本标签注入 |
| `dom` | DOM型XSS |
| `tag` | 标签属性注入 |
| `encoding` | 编码绕过 |
| `framework` | 框架特定XSS（jQuery/Vue/Angular） |

## 文件上传配置

```php
'upload' => [
    'max_size'             => 50 * 1024 * 1024,  // 单文件最大 50MB
    'check_mime_magic'     => env('SECURITY_UPLOAD_CHECK_MIME', false),
    'mime_magic_map'       => [],                  // 自定义MIME映射

    // 允许上传的文件扩展名（null = 使用内置默认值，数组 = 完全覆盖）
    'allowed_extensions'   => null,

    // 禁止上传的文件扩展名（null = 使用内置默认值，数组 = 完全覆盖）
    'blocked_extensions'   => null,
],
```

支持格式：静态数组、闭包函数、类名字符串、可调用数组。

### check_mime_magic（深度MIME验证）

启用后，中间件会读取文件头部魔数字节，验证扩展名与真实内容是否一致。防止攻击者将 `.php` 文件改名 `.jpg` 上传。

⚠️ **注意**：会轻微增加 CPU 开销，高并发场景建议配合 CDN 使用。

### blocked_extensions 默认列表

```php
'blocked_extensions' => [
    // Web脚本
    'php', 'php3', 'php4', 'php5', 'php7', 'php8', 
    'phtml', 'phar', 'jsp', 'jspx', 'asp', 'aspx',
    
    // 其他脚本
    'pl', 'py', 'rb', 'sh', 'bash', 
    'ps1', 'bat', 'vbs', 'js',
    
    // 可执行文件
    'exe', 'dll', 'bin', 'msi',
],
```

**安全建议**：

1. 上传目录不应有执行权限
2. 建议重命名上传文件
3. 图片文件应二次处理（压缩/转换）
4. 生产环境建议开启 `check_mime_magic`

### user_agent_blacklist

User-Agent 黑名单配置。

```php
// null = 使用内置默认值（常见扫描器特征），数组 = 完全覆盖
'user_agent_blacklist' => null,
```

支持格式：
- 静态字符串：`'sqlmap'`, `'nmap'`
- 正则表达式（以 `/` 开头）：`'/python-requests/i'`
- 闭包函数：`function(string $ua, Request $request): bool { ... }`
- 类名字符串 / 可调用数组（通过 `ConfigResolver` 解析）

### allowed_http_methods

允许的 HTTP 请求方法。

```php
// null = 使用内置默认值（GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS）
'allowed_http_methods' => null,
```

支持格式：静态数组、闭包函数、类名字符串、可调用数组。

### markdown.syntax_patterns

Markdown 语法识别正则。

```php
'markdown' => [
    // ... 其他配置 ...

    // null = 使用内置默认值，数组 = 完全覆盖
    'syntax_patterns' => null,
],
```

支持格式：静态数组、闭包函数、类名字符串、可调用数组。

## 其他配置

### max_url_length

URL最大长度限制，默认2048字符。

```php
'max_url_length' => [
    'limit' => 2048,
],
```

### response

拦截响应配置。

```php
'response' => [
    'blocked_status'      => 403,     // 通用拦截
    'rate_limit_status'   => 429,     // 速率限制
    'message'             => '请求被拒绝：检测到潜在的安全威胁',
    'show_threat_details' => false,   // 显示详细威胁信息
    'view'                => null,    // 自定义视图
],
```

#### view - 自定义拦截视图

支持以下配置格式：

**1. 字符串视图名**

```php
'view' => 'errors.security',
```

创建视图文件 `resources/views/errors/security.blade.php`：

```blade
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <style>
        body { font-family: sans-serif; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        .alert { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }
        .threats { background: #f5f5f5; padding: 15px; margin-top: 20px; }
        code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert">
            <h1>访问被拒绝</h1>
            <p>{{ $message }}</p>
        </div>

        @if(!empty($threats))
        <div class="threats">
            <h3>检测到的威胁：</h3>
            <ul>
                @foreach($threats as $threat)
                    <li><code>{{ $threat }}</code></li>
                @endforeach
            </ul>
        </div>
        @endif
    </div>
</body>
</html>
```

**2. 闭包函数**

```php
'view' => function($data) {
    // $data 包含: message, threats, blocked, matched_pattern, matched_content

    return view('errors.blocked', [
        'message' => $data['message'],
        'threats' => $data['threats'],
        'ip' => request()->ip(),
    ]);
},
```

**3. 类方法数组**

```php
// 配置
'view' => ['App\Http\Controllers\SecurityController', 'renderBlockPage'],

// 控制器
class SecurityController extends Controller
{
    public function renderBlockPage(array $data): \Illuminate\Http\Response
    {
        return response()->view('security.blocked', $data, 403);
    }
}
```

**4. 可调用类**

```php
// 配置
'view' => \App\Security\BlockResponseHandler::class,

// 处理器类
namespace App\Security;

class BlockResponseHandler
{
    public function __invoke(array $data): \Illuminate\Http\Response
    {
        // 记录拦截日志
        Log::warning('Security block', $data);

        // 返回自定义响应
        return response()->view('errors.security', $data, 403);
    }
}
```

**视图接收的数据：**

| 变量 | 类型 | 说明 |
|------|------|------|
| `$message` | string | 拦截提示消息 |
| `$blocked` | bool | 是否被拦截（始终为 true） |
| `$threats` | array | 威胁类型数组 |
| `$matched_pattern` | string | 匹配的正则模式 |
| `$matched_content` | string | 匹配的内容片段（脱敏） |
| `$threat_type` | string | 威胁类型 |
| `$risk_level` | string | 风险等级 (high/medium/low) |
| `$timestamp` | string | 拦截时间戳 |

### 默认错误视图

如果没有配置自定义视图（`view` 为 `null`），系统会使用内置的 `security::error` 视图显示拦截页面。

**视图命名空间**

安全包注册了 `security` 视图命名空间，可通过以下方式访问：

```php
// 访问安全包的错误视图
return view('security::error', $data);

// 如果发布了视图，优先使用应用中的自定义版本
return view('vendor.security.error', $data);
```

### markdown

Markdown智能识别配置。

```php
'markdown' => [
    'smart_detection'       => true,      // 启用智能识别
    'code_block_markers'    => ['```', '~~~'],
    'inline_code_marker'    => '`',
],
```

## 环境变量对照表

| 配置项 | 环境变量 | 默认值 |
|--------|----------|--------|
| enabled | `SECURITY_ENABLED` | `true` |
| log_enabled | `SECURITY_LOG_ENABLED` | `true` |
| rate_limit.enabled | `SECURITY_RATE_LIMIT_ENABLED` | `true` |
| rate_limit.max_attempts | `SECURITY_RATE_LIMIT_ATTEMPTS` | `60` |
| rate_limit.decay_minutes | `SECURITY_RATE_LIMIT_DECAY` | `1` |

## 高级配置

### URL路径攻击检测

URL路径遍历攻击检测已纳入统一规则管理（通过 `PatternService` 按需加载）。

内置检测覆盖：经典路径遍历（`../../`）、Windows 路径遍历、URL 编码绕过、Unicode 绕过、敏感文件访问（`.env`, `.git`, `/etc/passwd` 等）、版本控制文件泄露等。

如需追加自定义路径规则，请使用 `intercept_rules`：

```php
'intercept_rules' => [
    'high' => [
        '/\.(php|jsp|sh)(?:[?#&\/]|$)/i',
    ],
],
```

### encoding_detection

编码绕过攻击检测配置。与内置 `encoding` 类型（内容级检测）互补，本层为请求级结构检测。

```php
'encoding_detection' => [
    // URL编码百分比阈值（0-1）
    // URL中%字符占比超过此值时触发额外检查
    'percent_threshold' => 0.30,

    // 解码后检查的可疑模式（null = 使用内置默认值，数组 = 完全覆盖）
    'suspicious_patterns' => null,
],
```

### allowed_http_methods

允许的HTTP请求方法列表。

```php
'allowed_http_methods' => [
    'GET', 'POST', 'PUT', 'PATCH',
    'DELETE', 'HEAD', 'OPTIONS',
],
```

### input_processing

输入处理配置。

```php
'input_processing' => [
    // 最大输入长度（字节），防止正则回溯
    'max_input_length' => 100 * 1024,

    // 匹配内容最大长度（用于日志）
    'max_match_content_length' => 200,
],
```

### threat_risk_levels

威胁类型到风险等级的映射。

```php
'threat_risk_levels' => [
    // 高危 - 可能导致服务器被接管
    'sql' => 'high',
    'command' => 'high',
    'path' => 'high',
    'xml' => 'high',
    'ssti' => 'high',
    'ssrf' => 'high',
    'blacklist' => 'high',
    'encoding_bypass' => 'high',
    'encoding' => 'high',
    'header_injection' => 'high',
    'dangerous_upload' => 'high',

    // 中危 - 可能造成数据泄露或损坏
    'nosql' => 'medium',
    'xss_script' => 'medium',
    'xss_dom' => 'medium',
    'xss_tag' => 'medium',
    'url_path_attack' => 'medium',
    'bad_user_agent' => 'medium',

    // 低危 - 可能是误报或低风险行为
    'ldap' => 'low',
    'xss_encoding' => 'low',
    'xss_framework' => 'low',
    'rate_limit' => 'low',
    'invalid_method' => 'low',
    'url_too_long' => 'low',
    'body_too_large' => 'low',
    'invalid_headers' => 'low',
],
```

## 环境变量对照表

| 配置项 | 环境变量 | 默认值 |
|--------|----------|--------|
| enabled | `SECURITY_ENABLED` | `true` |
| log_enabled | `SECURITY_LOG_ENABLED` | `true` |
| log_level | `SECURITY_LOG_LEVEL` | `warning` |
| log_full_request | `SECURITY_LOG_FULL_REQUEST` | `false` |
| detection_layers.url_path | `SECURITY_DETECT_URL_PATH` | `true` |
| detection_layers.encoding | `SECURITY_DETECT_ENCODING` | `true` |
| detection_layers.user_agent | `SECURITY_DETECT_USER_AGENT` | `true` |
| detection_layers.headers | `SECURITY_DETECT_HEADERS` | `true` |
| detection_layers.body_size | `SECURITY_DETECT_BODY_SIZE` | `true` |
| detection_layers.rate_limit | `SECURITY_DETECT_RATE_LIMIT` | `true` |
| detection_layers.http_method | `SECURITY_DETECT_HTTP_METHOD` | `true` |
| detection_layers.url_length | `SECURITY_DETECT_URL_LENGTH` | `true` |
| detection_layers.high_risk | `SECURITY_DETECT_HIGH_RISK` | `true` |
| detection_layers.xss | `SECURITY_DETECT_XSS` | `true` |
| detection_layers.upload | `SECURITY_DETECT_UPLOAD` | `true` |
| rate_limit.enabled | `SECURITY_RATE_LIMIT_ENABLED` | `true` |
| rate_limit.max_attempts | `SECURITY_RATE_LIMIT_ATTEMPTS` | `60` |
| rate_limit.decay_minutes | `SECURITY_RATE_LIMIT_DECAY` | `1` |
| rate_limit.key_prefix | `SECURITY_RATE_LIMIT_KEY_PREFIX` | `security` |
| headers.detect_crlf | `SECURITY_DETECT_CRLF` | `true` |
| upload.check_mime_magic | `SECURITY_UPLOAD_CHECK_MIME` | `false` |
| response.show_threat_details | `SECURITY_SHOW_DETAILS` | `false` |

## 完整 .env 示例

```env
# 基础开关
SECURITY_ENABLED=true
SECURITY_LOG_ENABLED=true
SECURITY_LOG_LEVEL=warning
SECURITY_LOG_FULL_REQUEST=false

# 检测层级开关
SECURITY_DETECT_URL_PATH=true
SECURITY_DETECT_ENCODING=true
SECURITY_DETECT_USER_AGENT=true
SECURITY_DETECT_HEADERS=true
SECURITY_DETECT_BODY_SIZE=true
SECURITY_DETECT_RATE_LIMIT=true
SECURITY_DETECT_HTTP_METHOD=true
SECURITY_DETECT_URL_LENGTH=true
SECURITY_DETECT_HIGH_RISK=true
SECURITY_DETECT_XSS=true
SECURITY_DETECT_UPLOAD=true

# 速率限制
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_ATTEMPTS=60
SECURITY_RATE_LIMIT_DECAY=1
SECURITY_RATE_LIMIT_KEY_PREFIX=security

# HTTP头安全检查
SECURITY_DETECT_CRLF=true

# 文件上传
SECURITY_UPLOAD_CHECK_MIME=false

# 响应配置
SECURITY_SHOW_DETAILS=false
```
