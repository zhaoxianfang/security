# API 参考

本文档详细介绍安全中间件提供的所有API接口和数据结构。

## InterceptionContext 类

`InterceptionContext` 是拦截回调中传递的上下文对象，包含拦截时的完整信息。

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `request` | `Request` | HTTP请求对象 |
| `threatType` | `string` | 威胁类型标识 |
| `timestamp` | `DateTimeImmutable` | 拦截时间戳 |
| `matchedPattern` | `string` | 匹配的正则模式 |
| `matchedContent` | `string` | 匹配的内容片段（已脱敏） |
| `clientIp` | `string` | 客户端IP地址 |
| `method` | `string` | HTTP方法（GET/POST等） |
| `url` | `string` | 完整请求URL |
| `allThreats` | `array` | 所有检测到的威胁类型数组 |
| `requestData` | `array` | 请求数据摘要 |

### 方法

#### getThreatTypeDescription()

获取威胁类型的中文描述。

```php
public function getThreatTypeDescription(): string
```

**返回值**：威胁类型中文描述

**示例**：

```php
$callback = function(InterceptionContext $context) {
    $description = $context->getThreatTypeDescription();
    // 返回："SQL注入攻击"、"路径遍历攻击" 等
};
```

**支持的威胁类型**：

| 威胁类型 | 描述 |
|----------|------|
| `sql` | SQL注入攻击 |
| `command` | 命令注入攻击 |
| `path` | 路径遍历攻击 |
| `xml` | XML/XXE注入攻击 |
| `ldap` | LDAP注入攻击 |
| `nosql` | NoSQL注入攻击 |
| `ssti` | 服务器端模板注入(SSTI) |
| `ssrf` | 服务器端请求伪造(SSRF) |
| `header_injection` | HTTP头注入攻击 |
| `xss` | 跨站脚本攻击(XSS) |
| `xss_script` | XSS脚本注入 |
| `xss_dom` | DOM型XSS |
| `xss_tag` | XSS标签注入 |
| `xss_encoding` | XSS编码绕过 |
| `xss_framework` | 框架特定XSS |
| `encoding` | 编码绕过攻击 |
| `encoding_bypass` | 编码绕过尝试 |
| `blacklist` | 黑名单IP访问 |
| `bad_user_agent` | 恶意User-Agent |
| `invalid_headers` | 请求头不合法 |
| `dangerous_upload` | 危险文件上传 |
| `rate_limit` | 请求频率超限 |
| `url_too_long` | URL长度超限 |
| `body_too_large` | 请求体过大 |
| `invalid_method` | 非法HTTP方法 |
| `url_path_attack` | URL路径攻击 |

#### getRiskLevel()

获取威胁的风险等级。

```php
public function getRiskLevel(): string
```

**返回值**：`high`（高危）、`medium`（中危）、`low`（低危）、`unknown`（未知）

**风险等级分类**：

| 等级 | 威胁类型 |
|------|----------|
| high | sql, command, path, blacklist, dangerous_upload, encoding_bypass, encoding, xml, ssti, ssrf, header_injection |
| medium | nosql, xss, xss_script, xss_dom, xss_tag, url_path_attack, bad_user_agent |
| low | xss_encoding, xss_framework, rate_limit, url_too_long, body_too_large, invalid_method, invalid_headers, ldap |

**示例**：

```php
$callback = function(InterceptionContext $context) {
    $risk = $context->getRiskLevel();

    // 根据风险等级采取不同措施
    if ($risk === 'high') {
        // 发送紧急告警
        Alert::sendEmergency($context);
    } elseif ($risk === 'medium') {
        // 记录到数据库
        SecurityLog::create($context->toArray());
    }
};
```

#### toArray()

将上下文转换为数组格式。

```php
public function toArray(): array
```

**返回值结构**：

```php
[
    'threat_type' => 'sql',
    'threat_description' => 'SQL注入攻击',
    'risk_level' => 'high',
    'matched_pattern' => '/\bunion\s+all\s+select\b/i',
    'client_ip' => '192.168.1.100',
    'method' => 'GET',
    'url' => 'https://example.com/api?id=1',
    'all_threats' => ['sql'],
    'timestamp' => '2026-04-09 10:30:00',
]
```

## 拦截响应数据

当请求被拦截时，响应中包含以下数据：

### JSON响应

```json
{
    "message": "检测到SQL注入攻击，请求已被拦截",
    "blocked": true,
    "threats": ["sql"],
    "threat_type": "sql",
    "risk_level": "high"
}
```

当 `show_threat_details` 为 `true` 时，包含更多字段：

```json
{
    "message": "检测到SQL注入攻击，请求已被拦截",
    "blocked": true,
    "threats": ["sql"],
    "threat_type": "sql",
    "risk_level": "high",
    "matched_pattern": "/\\bunion\\s+all\\s+select\\b/i",
    "matched_content": "union all select",
    "timestamp": "2026-04-09T10:30:00+08:00"
}
```

### 视图响应

传递给视图的数据：

| 变量 | 类型 | 说明 |
|------|------|------|
| `$message` | string | 拦截提示消息 |
| `$blocked` | bool | 始终为 true |
| `$threats` | array | 威胁类型数组 |
| `$threat_type` | string | 当前威胁类型 |
| `$risk_level` | string | 风险等级 |
| `$matched_pattern` | string | 匹配的正则模式 |
| `$matched_content` | string | 匹配的内容片段 |
| `$timestamp` | string | ISO 8601格式时间戳 |

**视图使用示例**：

```blade
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
</head>
<body>
    <div class="alert alert-danger">
        <h1>🛡️ {{ $message }}</h1>

        @if($risk_level === 'high')
            <div class="badge badge-danger">高危风险</div>
        @elseif($risk_level === 'medium')
            <div class="badge badge-warning">中危风险</div>
        @else
            <div class="badge badge-info">低危风险</div>
        @endif

        <p>威胁类型：{{ implode(', ', $threats) }}</p>
        <p>拦截时间：{{ $timestamp }}</p>
    </div>
</body>
</html>
```

## IpCheckerInterface 接口

自定义IP检查器需要实现的接口。

### 接口定义

```php
use Illuminate\Http\Request;

interface IpCheckerInterface
{
    /**
     * 检查IP是否匹配
     *
     * @param string $ip 要检查的IP地址
     * @param Request $request HTTP请求对象
     * @return bool true=匹配，false=不匹配
     */
    public function check(string $ip, Request $request): bool;
}
```

### 使用示例

```php
use zxf\Security\Contracts\IpCheckerInterface;
use Illuminate\Http\Request;

class DatabaseIpChecker implements IpCheckerInterface
{
    public function check(string $ip, Request $request): bool
    {
        // 从数据库检查IP是否在黑名单中
        return BlockedIp::where('ip', $ip)
            ->where('expires_at', '>', now())
            ->exists();
    }
}
```

配置使用：

```php
// config/security.php
'blacklist' => [
    \App\Security\DatabaseIpChecker::class,
],
```

## 配置环境变量

所有支持环境变量覆盖的配置项：

| 环境变量 | 配置项 | 默认值 | 说明 |
|----------|--------|--------|------|
| `SECURITY_ENABLED` | `enabled` | `true` | 主开关 |
| `SECURITY_LOG_ENABLED` | `log_enabled` | `true` | 日志开关 |
| `SECURITY_LOG_LEVEL` | `log_level` | `warning` | 日志级别 |
| `SECURITY_LOG_FULL_REQUEST` | `log_full_request` | `false` | 完整请求记录 |
| `SECURITY_RATE_LIMIT_ENABLED` | `rate_limit.enabled` | `true` | 速率限制开关 |
| `SECURITY_RATE_LIMIT_ATTEMPTS` | `rate_limit.max_attempts` | `60` | 速率限制次数 |
| `SECURITY_RATE_LIMIT_DECAY` | `rate_limit.decay_minutes` | `1` | 速率限制时间窗口 |
| `SECURITY_SHOW_DETAILS` | `response.show_threat_details` | `false` | 显示详细威胁信息 |
| `SECURITY_DETECT_URL_PATH` | `detection_layers.url_path` | `true` | URL路径攻击检测 |
| `SECURITY_DETECT_ENCODING` | `detection_layers.encoding` | `true` | 多重编码检测 |
| `SECURITY_DETECT_USER_AGENT` | `detection_layers.user_agent` | `true` | User-Agent检查 |
| `SECURITY_DETECT_HEADERS` | `detection_layers.headers` | `true` | HTTP头检查 |
| `SECURITY_DETECT_BODY_SIZE` | `detection_layers.body_size` | `true` | 请求体大小检查 |
| `SECURITY_DETECT_RATE_LIMIT` | `detection_layers.rate_limit` | `true` | 速率限制 |
| `SECURITY_DETECT_HTTP_METHOD` | `detection_layers.http_method` | `true` | HTTP方法检查 |
| `SECURITY_DETECT_URL_LENGTH` | `detection_layers.url_length` | `true` | URL长度检查 |
| `SECURITY_DETECT_HIGH_RISK` | `detection_layers.high_risk` | `true` | 高危攻击检测 |
| `SECURITY_DETECT_XSS` | `detection_layers.xss` | `true` | XSS攻击检测 |
| `SECURITY_DETECT_UPLOAD` | `detection_layers.upload` | `true` | 文件上传检查 |

## 日志格式

安全中间件产生的日志格式：

### 标准日志

```
[2026-04-09 10:30:00] production.WARNING: [Security] 安全威胁检测 {
    "type": "sql",
    "ip": "192.168.1.100",
    "method": "GET",
    "url": "https://example.com/api?id=1' UNION SELECT...",
    "user_agent": "Mozilla/5.0...",
    "details": "高危模式匹配: /\\bunion\\s+all\\s+select\\b/i",
    "threat_type": "sql",
    "risk_level": "high",
    "timestamp": "2026-04-09T10:30:00.123456+08:00"
}
```

### 完整请求日志（log_full_request=true）

```
[2026-04-09 10:30:00] production.WARNING: [Security] 安全威胁检测 {
    "type": "sql",
    "ip": "192.168.1.100",
    "method": "POST",
    "url": "https://example.com/api/users",
    "user_agent": "Mozilla/5.0...",
    "details": "高危模式匹配...",
    "threat_type": "sql",
    "risk_level": "high",
    "timestamp": "2026-04-09T10:30:00.123456+08:00",
    "headers": {
        "content-type": ["application/json"],
        "user-agent": ["Mozilla/5.0..."]
    },
    "query": {"page": "1"},
    "body": {"name": "test", "email": "test@example.com"},
    "matched_pattern": "/\\bunion\\s+all\\s+select\\b/i",
    "matched_content": "union all select"
}
```

## HTTP状态码

中间件可能返回的HTTP状态码：

| 状态码 | 场景 | 说明 |
|--------|------|------|
| 200 | 请求通过 | 所有安全检查通过 |
| 403 | 通用拦截 | 检测到安全威胁 |
| 429 | 速率限制 | 请求频率超过限制 |

状态码可在配置中自定义：

```php
'response' => [
    'blocked_status' => 403,      // 通用拦截状态码
    'rate_limit_status' => 429,   // 速率限制状态码
],
```

## 响应格式

### JSON 响应

当请求期望 JSON 响应（`Accept: application/json` 头或 AJAX 请求）时，返回 JSON 格式：

```json
{
    "message": "请求被拒绝：检测到潜在的安全威胁",
    "blocked": true,
    "threats": ["sql"],
    "threat_type": "sql",
    "risk_level": "high"
}
```

### HTML 响应

对于普通 Web 请求，返回 HTML 页面：

1. **配置了自定义视图**：使用配置的视图渲染
2. **未配置自定义视图**：使用内置的 `security::error` 视图

内置错误页面包含：
- 拦截提示信息
- 威胁类型详情
- 风险等级标识
- 拦截时间戳
- 返回首页按钮

## 高级配置

> ⚠️ v5.1+ 内存优化：所有内置正则模式已迁移至延迟加载数据文件（`src/Security/Patterns/data/`），  
> 配置文件仅保留轻量参数。完整配置说明请参阅 [配置文档](./configuration.md#攻击检测配置)。

### URL路径攻击检测配置

```php
'url_path_detection' => [
    'enabled' => env('SECURITY_URL_PATH_DETECTION', true),
    'path_patterns' => [],  // v5.1+：默认内置模式自动加载，此处追加自定义模式
],
```

### 编码绕过攻击检测配置

```php
'encoding_detection' => [
    'enabled' => env('SECURITY_ENCODING_DETECTION', true),
    'percent_threshold' => 0.30,
    'suspicious_patterns' => [
        '../', '..\\', '<script', 'javascript:',
        'onerror=', 'onload=',
    ],
    'detect_null_bytes' => true,
    'detect_utf8_overlong' => true,
],
```

### HTTP方法配置

```php
'allowed_http_methods' => [
    'GET', 'POST', 'PUT', 'PATCH',
    'DELETE', 'HEAD', 'OPTIONS',
],
```

### 威胁风险等级映射

```php
'threat_risk_levels' => [
    'sql' => 'high',
    'command' => 'high',
    'path' => 'high',
    'ldap' => 'low',
    'xss_script' => 'medium',
    'rate_limit' => 'low',
    'invalid_method' => 'low',
],
```
