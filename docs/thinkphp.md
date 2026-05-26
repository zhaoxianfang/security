# ThinkPHP 8+ 使用指南

本文档说明如何在 ThinkPHP 8+ 项目中集成 `zxf/security` 安全中间件。

## 目录

- [设计原理](#设计原理)
- [安装](#安装)
- [快速配置](#快速配置)
- [中间件注册](#中间件注册)
- [配置说明](#配置说明)
- [视图定制](#视图定制)
- [速率限制](#速率限制)
- [日志系统](#日志系统)
- [已知差异](#已知差异)
- [常见问题](#常见问题)

---

## 设计原理

`zxf/security` 从 v6.1.0 开始通过 `FrameworkBridge` 桥接层同时支持 Laravel 和 ThinkPHP。

桥接层在运行时自动检测当前框架：

- 检测到 `Illuminate\Foundation\Application` → 使用 Laravel API
- 检测到 `think\App` → 使用 ThinkPHP API

这意味着**同一套中间件代码**在两个框架下行为一致，无需维护两套逻辑。

---

## 安装

```bash
composer require zxf/security
```

本包**零第三方依赖**，仅需 PHP >= 8.2，因此不会与 ThinkPHP 的依赖产生冲突。

---

## 快速配置

### 1. 复制配置文件

将包内默认配置复制到项目 `config/` 目录：

```bash
cp vendor/zxf/security/config/security.php config/security.php
```

> 提示：首次复制后，可根据业务需求编辑 `config/security.php`。

### 2. 合并环境变量（可选）

在 `.env` 中添加：

```env
SECURITY_ENABLED=true
SECURITY_LOG_ENABLED=true
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_ATTEMPTS=60
SECURITY_RATE_LIMIT_DECAY=60
```

ThinkPHP 会自动读取 `.env` 并注入配置系统。如果你的项目已使用 `.env`，安全包的配置项会自动生效。

---

## 中间件注册

### 方式一：全局中间件（推荐）

编辑 `app/middleware.php`，将安全中间件加入全局栈：

```php
<?php

return [
    // ThinkPHP 默认全局中间件
    \think\middleware\AllowCrossDomain::class,
    \think\middleware\LoadLangPack::class,
    \think\middleware\SessionInit::class,

    // zxf/security 安全中间件
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
```

### 方式二：通过服务类注册

在 `app/AppService.php` 的 `init()` 方法中调用：

```php
<?php

namespace app;

use think\Service;
use zxf\Security\Providers\ThinkPHPSecurityServiceProvider;

class AppService extends Service
{
    public function init()
    {
        // 注册安全服务（自动合并配置）
        ThinkPHPSecurityServiceProvider::register($this->app);

        // 可选：自动注册全局中间件
        ThinkPHPSecurityServiceProvider::registerMiddleware($this->app);
    }
}
```

### 方式三：路由中间件（局部生效）

在 `config/route.php` 或具体路由定义中注册：

```php
use think\facade\Route;

Route::group('api', function () {
    // API 路由
})->middleware([\zxf\Security\Middleware\SecurityMiddleware::class]);
```

---

## 配置说明

ThinkPHP 下 `config/security.php` 的写法与 Laravel **完全一致**：

```php
<?php

return [
    // 总开关
    'enabled' => env('SECURITY_ENABLED', true),

    // 日志开关
    'log_enabled' => env('SECURITY_LOG_ENABLED', true),
    'log_level' => 'warning',
    'log_full_request' => false,

    // 响应配置
    'response' => [
        'blocked_status' => 403,
        'rate_limit_status' => 429,
        'show_threat_details' => false,
        // ThinkPHP 下建议使用闭包返回 JSON，因为模板路径与 Laravel Blade 不同
        'view' => function ($data) {
            return json($data, $data['http_status'] ?? 403);
        },
    ],

    // 检测层开关
    'detection_layers' => [
        'url_path' => true,
        'encoding' => true,
        'user_agent' => true,
        'headers' => true,
        'body_size' => true,
        'rate_limit' => true,
        'http_method' => true,
        'url_length' => true,
        'high_risk' => true,
        'xss' => true,
        'upload' => true,
    ],

    // IP 白名单（可信 IP 跳过所有检查）
    'trusted_ips' => [],

    // IP 黑名单（直接拦截）
    'blacklist' => [],

    // 路由排除列表
    'excluded_routes' => [
        'health',
        'api/health',
    ],

    // 速率限制
    'rate_limit' => [
        'max_attempts' => (int) env('SECURITY_RATE_LIMIT_ATTEMPTS', 60),
        'decay_minutes' => (int) env('SECURITY_RATE_LIMIT_DECAY', 1),
        'key_prefix' => env('SECURITY_RATE_LIMIT_KEY_PREFIX', 'security'),
    ],
];
```

> 注意：ThinkPHP 的 `env()` 助手函数返回字符串，对数值型配置建议显式转 `(int)`。

---

## 视图定制

ThinkPHP 使用原生 PHP 模板或 Twig 等引擎，与 Laravel Blade 不同。

### 推荐方式：闭包返回 JSON

由于 ThinkPHP 默认返回 JSON 的 API 场景较多，推荐在配置中使用闭包：

```php
'response' => [
    'view' => function ($data) {
        return json([
            'success' => false,
            'blocked' => true,
            'message' => $data['message'],
            'request_id' => $data['request_id'],
            'timestamp' => $data['timestamp'],
        ], $data['http_status'] ?? 403);
    },
],
```

### 方式二：ThinkPHP 模板

如果使用 ThinkPHP 模板引擎，可创建视图文件 `view/security/error.html`：

```html
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <style>
        body { font-family: sans-serif; padding: 50px; text-align: center; }
        .alert { background: #fee; border: 1px solid #fcc; padding: 30px; border-radius: 5px; max-width: 600px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="alert">
        <h1>访问被拒绝</h1>
        <p><?php echo htmlentities($message); ?></p>
        <?php if (!empty($threats)): ?>
        <div style="background:#f5f5f5;padding:15px;margin-top:20px;text-align:left;">
            <strong>威胁类型：</strong> <?php echo implode(', ', $threats); ?>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>
```

然后在配置中指定视图名（ThinkPHP 下不需要命名空间前缀）：

```php
'response' => [
    'view' => 'security/error',
],
```

---

## 速率限制

ThinkPHP 8 没有内置 `RateLimiter` 门面。安全包在 ThinkPHP 下**自动降级**为使用 `Cache` 门面模拟限流桶：

```php
// 内部实现（FrameworkBridge）
$attempts = Cache::get($key, 0);
if ($attempts >= $maxAttempts) {
    return true; // 触发限流
}
// 使用 set() 保证 TTL 始终生效，避免 inc() 在某些驱动下丢失过期时间
Cache::set($key, $attempts + 1, $decaySeconds);
```

因此，使用速率限制前请确保：

1. 已配置 Cache（默认 File 缓存即可）
2. `config/cache.php` 中设置了有效的缓存驱动

如需关闭速率限制：

```php
'detection_layers' => [
    'rate_limit' => false,
],
```

---

## 日志系统

安全包在 ThinkPHP 下自动使用 `think\facade\Log` 记录日志。

日志默认写入 `runtime/log/` 目录，可在 `config/log.php` 中配置通道。

查看安全事件日志：

```bash
tail -f runtime/log/security/*.log
```

如需自定义日志通道，在 `config/security.php` 中修改：

```php
'log_level' => 'warning', // debug | info | warning | error | critical
```

---

## 已知差异

| 功能 | Laravel | ThinkPHP |
|------|---------|----------|
| 自动服务发现 | ✅ 通过 `extra.laravel.providers` | ❌ 需手动注册 |
| 配置文件发布 | ✅ `php artisan vendor:publish` | ❌ 手动复制 |
| 视图系统 | Blade | PHP 原生 / Twig |
| 速率限制 | `RateLimiter` 门面 | `Cache` 门面模拟 |
| 请求对象 | `Illuminate\Http\Request` | `think\Request` |
| 响应对象 | `Illuminate\Http\Response` | `think\Response` |
| 日志门面 | `Illuminate\Support\Facades\Log` | `think\facade\Log` |
| 文件扩展名 | `getClientOriginalExtension()` | `extension()` |
| 文件 MIME | `getMimeType()` | `getMime()` |

所有差异均由 `FrameworkBridge` 自动处理，业务代码无需关心。

---

## 常见问题

### Q1: 安装后中间件没有生效？

请检查：

1. `app/middleware.php` 中是否正确添加了中间件类
2. `config/security.php` 中 `enabled` 是否为 `true`
3. 是否被 `excluded_routes` 排除

### Q2: ThinkPHP 下拦截页面显示空白？

ThinkPHP 默认可能返回 JSON。检查配置中的 `response.view`：

- 如果是字符串视图名，确保模板文件存在于 `view/` 目录
- 建议优先使用闭包返回 JSON，兼容性最好

### Q3: 速率限制在 ThinkPHP 下不生效？

确保：

1. `config/cache.php` 已配置可用缓存驱动（file/redis 等）
2. Cache 目录可写（`runtime/cache/`）
3. `detection_layers.rate_limit` 为 `true`

### Q4: 能否同时使用 Laravel 和 ThinkPHP？

不能。同一项目只能运行在一个框架下。安全包会自动检测当前框架并适配。

### Q5: ThinkPHP 6 是否支持？

官方仅保证 ThinkPHP **8+** 兼容。ThinkPHP 6 的部分 API 不同，可能存在兼容性问题。

---

## 升级指南

从仅支持 Laravel 的版本升级到跨框架版本：

1. `composer update zxf/security`
2. 对比默认配置 `vendor/zxf/security/config/security.php`，合并新增项到 `config/security.php`
3. 如果使用自定义 `response.view` 且返回 Blade 视图，ThinkPHP 下需改为闭包或 PHP 模板
4. 无需修改任何业务代码，中间件行为保持不变

---

如需更多帮助，请参考 [README.md](../README.md) 或提交 Issue。
