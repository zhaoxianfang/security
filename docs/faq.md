# 常见问题

## 基础问题

### Q: 安装后中间件没有生效？

**检查步骤：**

1. 确认配置文件已发布
   ```bash
   ls -la config/security.php
   ```

2. 检查配置是否启用
   ```bash
   grep SECURITY_ENABLED .env
   # 应显示 SECURITY_ENABLED=true
   ```

3. 清除配置缓存
   ```bash
   php artisan config:clear
   ```

4. 检查中间件注册
   ```bash
   php artisan route:list --middleware | grep security
   ```

### Q: 如何临时关闭安全检测？

**方法1：通过环境变量（推荐）**

```bash
# .env
SECURITY_ENABLED=false
```

然后清除缓存：
```bash
php artisan config:clear
```

**方法2：运行时关闭（仅当前请求）**

```php
config(['security.enabled' => false]);
```

### Q: 日志文件在哪里？

安全日志写入 Laravel 默认日志通道：

```bash
# 查看最新日志
tail -f storage/logs/laravel.log | grep "\[Security\]"

# 统计攻击类型
grep "安全威胁检测" storage/logs/laravel.log | grep -o '"type":"[^"]*"' | sort | uniq -c
```

## 误报问题

### Q: 正常请求被拦截了怎么办？

**步骤1：查看日志确定拦截原因**

```bash
grep "安全威胁检测" storage/logs/laravel.log | tail -1
```

**步骤2：根据类型处理**

| 拦截类型 | 解决方案 |
|---------|----------|
| `sql` | 检查是否包含 `UNION SELECT`、`DROP TABLE` 等关键词，改用参数化查询 |
| `xss` | 如果内容是Markdown文档，确保代码块使用 ``` 包裹 |
| `command` | 检查是否包含 `system(`、`rm -rf` 等危险组合 |
| `path` | 检查是否包含 `../` 路径遍历，使用 basename() 净化路径 |
| `ssrf` | 检查是否请求了内网IP/云元数据/危险协议，改用白名单URL |
| `header_injection` | 检查请求中是否包含 `%0d%0a` 等换行编码 |
| `rate_limit` | 客户端减少请求频率，或调整 `max_attempts` 阈值 |

**步骤3：临时放行（紧急情况）**

将客户端IP加入白名单：

```php
// config/security.php
'whitelist' => [
    '192.168.1.100',  // 被误拦截的IP
],
```

### Q: Markdown文档中的代码被拦截？

**问题示例：**

```markdown
以下是JavaScript示例：

<script>
alert('Hello World');
</script>
```

**解决方案：**

使用代码块包裹：

```markdown
以下是JavaScript示例：

```html
<script>
alert('Hello World');
</script>
```
```

或使用行内代码：

```markdown
`<script>alert(1)</script>`
```

中间件会自动识别 Markdown 代码块内的内容，不进行 XSS 拦截。

### Q: API接口返回 429 Too Many Requests？

**原因：** 客户端请求频率超过 `rate_limit.max_attempts` 限制。

**解决方案：**

1. **增加限流阈值（开发环境）**

```php
// config/security.php
'rate_limit' => [
    'max_attempts' => 300,  // 从60增加到300
],
```

2. **API客户端添加请求间隔**

```javascript
// 添加延迟，避免瞬间大量请求
await sleep(100); // 100ms间隔
```

3. **白名单放行（内部API）**

```php
'trusted_ips' => [
    '192.168.0.0/16',  // 内网IP不限流
],
```

## 配置问题

### Q: 如何封禁特定IP？

**方法1：配置文件（永久封禁）**

```php
// config/security.php
'blacklist' => [
    '192.168.1.100',      // 单个IP
    '10.0.0.0/24',        // 整个网段
],
```

**方法2：动态封禁（运行时）**

```php
// 在控制器或服务中
$blacklist = config('security.blacklist');
$blacklist[] = $request->ip();
config(['security.blacklist' => $blacklist]);
```

### Q: 如何放行内部网络？

```php
// config/security.php
'trusted_ips' => [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',        // A类私网
    '172.16.0.0/12',     // B类私网
    '192.168.0.0/16',    // C类私网
],
```

**注意：** `trusted_ips` 会跳过**所有**检查，包括速率限制。

### Q: 如何自定义拦截响应？

**方法1：自定义中间件**

```php
namespace App\Http\Middleware;

use zxf\Security\Middleware\SecurityMiddleware as BaseMiddleware;

class CustomSecurityMiddleware extends BaseMiddleware
{
    protected function blockRequest($request, $message, $status = 403)
    {
        if ($request->expectsJson()) {
            return response()->json([
                'error' => '请求被拒绝',
                'code' => 'SECURITY_BLOCK',
            ], $status);
        }

        return response()->view('errors.security', compact('message'), $status);
    }
}
```

**方法2：修改配置**

```php
// config/security.php
'response' => [
    'message' => '您的请求存在安全风险，请联系管理员',
],
```

## 性能问题

### Q: 中间件会影响性能吗？

**性能数据：**

| 场景 | 耗时 | 说明 |
|------|------|------|
| 白名单IP | <0.1ms | IP匹配后直接放行 |
| 常规检查 | ~0.5ms | 完整安全检查 |
| 攻击检测 | ~1ms | 触发正则匹配 |

**优化建议：**

1. 将内网IP加入 `trusted_ips`，跳过所有检查
2. 定期清理过长的 `blacklist` 数组
3. 生产环境关闭 `log_enabled`（如使用外部WAF）

### Q: 可以关闭某些检测项吗？

可以，移除对应配置即可：

```php
// 关闭SQL检测
'high_risk_patterns' => [
    // 'sql' => [...],  // 删除或注释此行
    'command' => [...],
    'path' => [...],
],

// 关闭XSS检测
'xss_patterns' => [],
```

## 拦截回调 FAQ

### Q: 如何使用拦截回调实现自定义拦截逻辑？

**场景**：某些业务请求被误拦截，需要动态放行。

**解决方案**：

```php
// config/security.php

'before_block_callback' => function(\zxf\Security\Dto\InterceptionContext $context) {
    // 1. 记录所有拦截事件
    \App\Models\SecurityLog::create($context->toArray());

    // 2. 内网IP放行
    if (str_starts_with($context->clientIp, '192.168.')) {
        return false; // 放行
    }

    // 3. 特定路由放行
    if (str_contains($context->url, '/admin/markdown-editor')) {
        // Markdown编辑器可能有XSS误报
        return $context->getRiskLevel() === 'high' ? true : false;
    }

    // 4. 其他情况按风险等级处理
    return $context->getRiskLevel() === 'low' ? false : true;
},
```

---

### Q: 回调返回 false 后请求会怎样？

返回 `false` 表示**放行**，请求会继续处理：

```php
'before_block_callback' => function($context) {
    // 返回 false → 请求继续执行，不会拦截
    // 返回 true/null → 返回拦截响应给客户端

    if ($context->threatType === 'rate_limit') {
        return false; // 跳过限流检查，继续处理
    }

    return true; // 其他情况拦截
},
```

**注意**：放行后请求进入正常的 Laravel 处理流程，后续可能遇到其他中间件的拦截。

---

### Q: 回调执行失败会怎样？

**默认行为**：回调抛出异常时，系统会**拦截请求**（安全优先）。

```php
'before_block_callback' => function($context) {
    // 如果这里抛出异常
    throw new \Exception('数据库连接失败');
},
```

**结果**：
1. 异常被捕获并记录到日志
2. 请求被拦截（HTTP 403）
3. 客户端看到拦截提示

**建议**：在回调中添加 try-catch：

```php
'before_block_callback' => function($context) {
    try {
        // 业务逻辑...
        return true;
    } catch (\Exception $e) {
        \Log::error('拦截回调异常', ['error' => $e->getMessage()]);
        return true; // 异常时拦截（安全）
    }
},
```

---

### Q: 如何在回调中发送告警通知？

**示例：钉钉告警**

```php
'before_block_callback' => function($context) {
    // 仅高危威胁告警
    if ($context->getRiskLevel() === 'high') {
        $message = sprintf(
            "安全告警\n类型: %s\nIP: %s\nURL: %s\n时间: %s",
            $context->getThreatTypeDescription(),
            $context->clientIp,
            $context->url,
            $context->timestamp->format('Y-m-d H:i:s')
        );

        // 异步发送（不阻塞请求）
        \App\Jobs\SendDingTalkAlert::dispatch($message);
    }

    return true;
},
```

---

### Q: 类方式回调和闭包有什么区别？

| 特性 | 闭包 | 类 |
|------|------|-----|
| 代码组织 | 简单直接 | 可维护性好 |
| 依赖注入 | 手动获取 | 通过构造函数自动注入 |
| 单元测试 | 较难 | 容易测试 |
| 复用性 | 低 | 高 |
| 性能 | 略快 | 略慢（实例化） |

**闭包适合**：简单逻辑、快速原型  
**类适合**：复杂业务、需要依赖注入、需要测试

---

## 高级用法

### Q: 如何记录自定义安全事件？

```php
use function zxf\Security\security_log;

// 记录自定义事件
security_log('brute_force', '多次登录失败', [
    'ip' => $request->ip(),
    'username' => $request->input('username'),
    'attempts' => 5,
]);
```

日志输出：
```
[2026-04-08 14:30:00] production.WARNING: [Security] brute_force: 多次登录失败 {
  "ip": "192.168.1.100",
  "username": "admin",
  "attempts": 5
}
```

### Q: 如何实现自动封禁？

```php
// 在登录失败事件中
public function handle(LoginFailed $event)
{
    $key = 'login_attempts:' . $event->ip;
    $attempts = Cache::increment($key);
    Cache::put($key, $attempts, now()->addHour());

    if ($attempts >= 10) {
        // 加入黑名单
        $blacklist = config('security.blacklist');
        $blacklist[] = $event->ip;
        config(['security.blacklist' => $blacklist]);

        security_log('auto_blacklist', '登录失败过多自动封禁', [
            'ip' => $event->ip,
            'attempts' => $attempts,
        ]);
    }
}
```

### Q: 如何豁免特定路由？

**方法1：路由分组**

```php
// 不使用安全中间件的路由
Route::withoutMiddleware(['security'])->group(function () {
    Route::post('/webhook', [WebhookController::class, 'handle']);
});
```

**方法2：条件豁免**

```php
// 在自定义中间件中
public function handle($request, $next)
{
    // 特定路由跳过检查
    if ($request->is('webhook/*')) {
        config(['security.enabled' => false]);
    }

    return parent::handle($request, $next);
}
```

## 自定义视图 FAQ

### Q: 如何自定义拦截页面？

**方法1：使用 Blade 视图**

```php
// config/security.php
'response' => [
    'view' => 'errors.security',
],
```

创建视图 `resources/views/errors/security.blade.php`：

```blade
@extends('layouts.app')

@section('content')
<div class="container">
    <div class="alert alert-danger">
        <h2>访问被拒绝</h2>
        <p>{{ $message }}</p>

        @if(!empty($threats))
        <hr>
        <p><strong>威胁类型：</strong></p>
        <ul>
            @foreach($threats as $threat)
                <li>{{ $threat }}</li>
            @endforeach
        </ul>
        @endif
    </div>
</div>
@endsection
```

**方法2：使用闭包返回动态内容**

```php
'response' => [
    'view' => function($data) {
        // 根据威胁类型返回不同视图
        if (in_array('sql', $data['threats'])) {
            return view('errors.sql-injection', $data);
        }

        return view('errors.generic', $data);
    },
],
```

---

### Q: 如何在拦截页面显示用户IP和联系信息？

```php
'response' => [
    'view' => function($data) {
        return view('errors.security', array_merge($data, [
            'client_ip' => request()->ip(),
            'support_email' => config('app.support_email'),
            'request_id' => uniqid('req_'),
        ]));
    },
],
```

视图文件：

```blade
<div class="error-page">
    <h1>访问被拒绝</h1>
    <p>{{ $message }}</p>
    <p>您的IP: {{ $client_ip }}</p>
    <p>请求ID: {{ $request_id }}</p>
    <p>如需帮助请联系: {{ $support_email }}</p>
</div>
```

---

### Q: 如何根据威胁类型显示不同页面？

```php
// 创建自定义响应类
namespace App\Security;

class ThreatAwareResponseHandler
{
    private array $threatViews = [
        'sql' => 'errors.threats.sql',
        'xss_script' => 'errors.threats.xss',
        'command' => 'errors.threats.command',
        'default' => 'errors.security',
    ];

    public function __invoke(array $data): \Illuminate\Http\Response
    {
        $view = $this->threatViews['default'];

        // 根据主要威胁类型选择视图
        foreach ($data['threats'] as $threat) {
            if (isset($this->threatViews[$threat])) {
                $view = $this->threatViews[$threat];
                break;
            }
        }

        return response()->view($view, $data, 403);
    }
}
```

配置：

```php
'response' => [
    'view' => \App\Security\ThreatAwareResponseHandler::class,
],
```

---

## 兼容性问题

### Q: 与其他安全包冲突？

通常不会冲突，建议处理顺序：

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    // 1. 先执行其他WAF
    $middleware->append(\Other\Waf\Middleware::class);

    // 2. 再执行本中间件（作为后备防护）
    $middleware->append(\zxf\Security\Middleware\SecurityMiddleware::class);
})
```

### Q: 支持哪些 Laravel 版本？

本包支持 **Laravel 11+、12、13**，使用原生 bootstrap/app.php 中间件注册方式。

如需 Laravel 10 支持，请使用本包的旧版本（v3.x）。

### Q: 支持 PHP 8.1 吗？

本包要求 **PHP 8.2+**。使用了以下 PHP 8.2 特性：

- `readonly` 类属性
- 独立类型声明（null/false/true）
- `\Random\RandomException` 异常处理

如需 PHP 8.1 支持，请使用本包的旧版本（v3.x）。

### Q: SSRF检测会误拦截吗？

SSRF检测规则经过精心设计，仅匹配明确的攻击特征：

- **内网IP**：正则要求严格匹配 RFC1918 格式（如 `10.1.2.3`），不会匹配随机数字
- **云元数据**：只匹配已知端点（`169.254.169.254`、`metadata.google.internal`）
- **危险协议**：仅拦截明确非HTTP协议（`gopher://`、`dict://` 等），不影响正常的 HTTP/HTTPS 请求

如果合法业务需要访问内网地址，可将请求路径加入排除路由：

```php
'excluded_routes' => [
    'api/internal/*',  // 内网API调用豁免SSRF检测
],
```

### Q: CRLF注入检查会误拦截吗？

CRLF检测两层防护都很精确：

1. **请求参数检测**：仅匹配明确的 `%0d%0a` 编码或 `\r\n` 字符
2. **请求头值扫描**：仅在 HTTP 头值中发现换行符时才触发

正常业务请求几乎不会在URL或头值中包含这些字符。如果确实需要（如传输包含换行的Base64编码数据），建议：

```php
// 使用安全的传输方式
$safeData = base64url_encode($data);  // 使用URL安全的Base64
```

### Q: 拦截响应包含哪些安全头？

中间件在拦截响应中自动添加以下安全HTTP头：

| 头名称 | 值 | 作用 |
|-------|-----|------|
| `X-Content-Type-Options` | `nosniff` | 防止MIME类型嗅探 |
| `X-Frame-Options` | `DENY` | 防止点击劫持 |
| `X-XSS-Protection` | `1; mode=block` | 启用浏览器XSS过滤器 |
| `Referrer-Policy` | `no-referrer` | 不发送Referrer信息 |
| `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` | 禁止缓存拦截页面 |
| `Pragma` | `no-cache` | 兼容旧版浏览器缓存控制 |

如需自定义安全头，可扩展中间件覆盖 `getSecurityResponseHeaders()` 方法。

### Q: 速率限制的key是怎么计算的？

速率限制使用 **IP + 路由路径** 的组合作为唯一标识：

```php
$key = 'security:' . $ip . ':' . md5($path);
```

这意味着：
- 同一IP访问不同路由，分别计次
- 不同IP访问同一路由，分别计次
- 路由路径经过MD5哈希，不会暴露具体路径

可通过 `rate_limit.key_prefix` 配置自定义前缀：

```php
'rate_limit' => [
    'key_prefix' => 'my_app',  // 默认 'security'
],
```
