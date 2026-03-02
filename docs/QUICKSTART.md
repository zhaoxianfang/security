# Laravel 安全扩展包 - 快速入门指南

欢迎使用Laravel安全扩展包！本指南将帮助您在5分钟内完成安装和基础配置。

## 📋 前置要求

- PHP >= 8.2
- Laravel >= 11.0
- MySQL/MariaDB/PostgreSQL/SQLite

---

## 🚀 快速安装

### 1. 安装扩展包

```bash
composer require zxf/laravel-security
```

### 2. 发布配置文件

```bash
php artisan vendor:publish --tag=security-config
```

这将在 `config/security.php` 创建配置文件。

### 3. 发布数据库迁移

```bash
php artisan vendor:publish --tag=security-migrations
```

### 4. 运行迁移

```bash
php artisan migrate
```

### 5. 添加中间件

编辑 `app/Http/Kernel.php`：

```php
protected $middleware = [
    // ...
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
```

---

## ⚙️ 基础配置

### 环境变量配置

编辑 `.env` 文件：

```env
# 启用安全扩展
SECURITY_ENABLED=true

# 开发环境建议
SECURITY_DEBUG=true
SECURITY_IGNORE_LOCAL=true

# 生产环境建议
# SECURITY_DEBUG=false
# SECURITY_IGNORE_LOCAL=false
```

### 基础配置文件

编辑 `config/security.php`：

```php
return [
    // 基础设置
    'enabled' => env('SECURITY_ENABLED', true),
    'debug' => env('SECURITY_DEBUG', false),
    'ignore_local' => env('SECURITY_IGNORE_LOCAL', false),

    // 限流配置
    'rate_limiting' => [
        'enabled' => true,
        'limits' => [
            'second' => ['max_requests' => 60],
            'minute' => ['max_requests' => 1000],
            'hour' => ['max_requests' => 10000],
        ],
    ],

    // 威胁检测
    'threat_detection' => [
        'enabled' => true,
        'sql_injection' => ['enabled' => true],
        'xss_attack' => ['enabled' => true],
        'command_injection' => ['enabled' => true],
    ],

    // 内网配置
    'intranet' => [
        'enable_cache' => true,
        'cache_ttl' => 300,
        'skip_rate_limit' => false,
        'skip_blacklist_check' => false,
    ],
];
```

---

## 🎯 5分钟开始使用

### 示例1：保护API路由

```php
// routes/api.php

Route::middleware(['security'])->group(function () {
    Route::apiResource('users', UserController::class);
    Route::post('/login', [AuthController::class, 'login']);
});
```

### 示例2：添加IP到白名单

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 添加管理员IP到白名单
$ipManager->addToWhitelist('192.168.1.100', '管理员PC');

// 添加临时白名单（24小时后过期）
$ipManager->addToWhitelist('192.168.1.101', '临时访问', now()->addHours(24));
```

### 示例3：封禁恶意IP

```php
use zxf\Security\Services\IpManagerService;
use Illuminate\Http\Request;

$ipManager = app(IpManagerService::class);
$request = request();

// 封禁IP（1小时）
$ipManager->banIp($request, 'SQLInjection', 75);

// 封禁IP（24小时）
$ipManager->banIp($request, 'XSSAttack', 90);
```

### 示例4：查看IP统计

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 获取IP统计信息
$stats = $ipManager->getIpStats('192.168.1.100');

echo "威胁评分: {$stats['threat_score']}\n";
echo "请求次数: {$stats['request_count']}\n";
echo "拦截次数: {$stats['blocked_count']}\n";
```

---

## 🔍 验证安装

### 1. 检查中间件是否生效

```bash
# 访问你的应用
curl http://localhost

# 检查日志
tail -f storage/logs/laravel.log | grep "Security"
```

### 2. 测试限流

```bash
# 快速发送多个请求
for i in {1..70}; do curl http://localhost/api/users; done

# 应该看到限流错误
# HTTP 429 Too Many Requests
```

### 3. 测试威胁检测

```bash
# 发送包含SQL注入的请求
curl -X POST http://localhost/api/users \
  -d "name=' OR 1=1 --" \
  -d "email=test@example.com"

# 应该看到拦截错误
# HTTP 403 Forbidden
```

### 4. 检查数据库

```bash
php artisan tinker

>>> \zxf\Security\Models\SecurityIp::count()
=> 0

>>> \zxf\Security\Models\SecurityIp::get()
=> []
```

---

## 🛠️ 常用命令

### 清除安全缓存

```bash
php artisan security:clear-cache
```

或在代码中：

```php
clean_security_cache();
```

### 查看高威胁IP

```bash
php artisan tinker

>>> $ipManager = app(\zxf\Security\Services\IpManagerService::class);
=> zxf\Security\Services\IpManagerService {#1234}

>>> $ips = $ipManager->getHighThreatIps(10);
=> [...]
```

### 清理过期IP

```bash
php artisan security:prune-ips
```

---

## 📊 监控和日志

### 查看安全日志

```bash
# 实时查看日志
tail -f storage/logs/laravel.log | grep -i "security"

# 查看被拦截的请求
tail -f storage/logs/laravel.log | grep -i "blocked"

# 查看高威胁IP
tail -f storage/logs/laravel.log | grep -i "threat"
```

### 配置日志级别

在 `config/logging.php` 中：

```php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => env('SECURITY_LOG_LEVEL', 'warning'),
        'days' => 30,
    ],
],
```

然后在 `config/security.php` 中：

```php
return [
    // ...
    'log_channel' => 'security',
];
```

---

## 🎨 进阶配置

### 自定义白名单处理器

```php
// config/security.php

'whitelist_handler' => function ($request, $ip) {
    // 从数据库查询
    $user = \App\Models\User::where('ip_address', $ip)->first();
    
    return $user && $user->is_admin;
},
```

### 自定义黑名单处理器

```php
// config/security.php

'blacklist_handler' => function ($request, $ip) {
    // 查询威胁情报API
    $response = \Http::get('https://api.threat-intel.com/check', [
        'ip' => $ip,
    ]);
    
    return $response->json('is_malicious', false);
},
```

### 监听安全事件

创建事件监听器：

```bash
php artisan make:listener LogSecurityEvent
```

```php
// app/Listeners/LogSecurityEvent.php

namespace App\Listeners;

use zxf\Security\Events\IpCreated;

class LogSecurityEvent
{
    public function handle(IpCreated $event)
    {
        \Log::info('IP已记录', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
        ]);
    }
}
```

注册监听器：

```php
// app/Providers/EventServiceProvider.php

protected $listen = [
    \zxf\Security\Events\IpCreated::class => [
        \App\Listeners\LogSecurityEvent::class,
    ],
];
```

---

## 🔧 故障排查

### 问题1：中间件未生效

**症状**：安全检查没有执行

**解决方案**：
```bash
# 检查中间件是否注册
php artisan tinker

>>> app(\Illuminate\Contracts\Http\Kernel::class)
    ->getMiddleware()
    ->contains(\zxf\Security\Middleware\SecurityMiddleware::class)
=> true
```

### 问题2：限流不生效

**症状**：请求频率超限但未拦截

**解决方案**：
```php
// 检查配置
config(['security.rate_limiting.enabled' => true]);

// 清除缓存
clean_security_cache();
```

### 问题3：数据库连接错误

**症状**：迁移失败或查询错误

**解决方案**：
```bash
# 检查数据库连接
php artisan tinker

>>> \DB::connection()->getPdo()
=> PDO {#1234}

# 重新运行迁移
php artisan migrate:fresh --seed
```

### 问题4：缓存问题

**症状**：配置更改未生效

**解决方案**：
```bash
# 清除所有缓存
php artisan cache:clear
php artisan config:clear
php artisan route:clear
php artisan view:clear

# 清除安全缓存
clean_security_cache();
```

---

## 📚 下一步

现在您已经完成了基础配置，可以：

1. **阅读完整文档**：[README.md](../README.md)
2. **查看使用示例**：[EXAMPLES.md](./EXAMPLES.md)
3. **了解API文档**：[API.md](./API.md)
4. **配置生产环境**：参考下面的生产环境配置

---

## 🏭 生产环境配置

### 环境变量

```env
# 生产环境配置
SECURITY_ENABLED=true
SECURITY_DEBUG=false
SECURITY_IGNORE_LOCAL=false

# 严格的限流
SECURITY_RATE_LIMIT_PER_SECOND=30
SECURITY_RATE_LIMIT_PER_MINUTE=500
SECURITY_RATE_LIMIT_PER_HOUR=5000

# 日志配置
SECURITY_LOG_LEVEL=warning
```

### 缓存配置

```php
// config/security.php

return [
    // ...
    'enable_ip_cache' => true,
    'enable_debug_logging' => false,
    
    'ip_database' => [
        'cache_ttl' => 600, // 10分钟
    ],
    
    'intranet' => [
        'enable_cache' => true,
        'cache_ttl' => 600,
    ],
];
```

### 定时任务

```php
// app/Console/Kernel.php

protected function schedule(Schedule $schedule)
{
    // 每天凌晨清理过期IP
    $schedule->command('security:prune-ips')->daily();
    
    // 每小时清理缓存
    $schedule->call(function () {
        clean_security_cache();
    })->hourly();
    
    // 每6小时生成报告
    $schedule->command('security:report')->everySixHours();
}
```

---

## 💡 最佳实践

### 1. 分层保护

```php
// 公开API - 基础保护
Route::middleware(['security'])->prefix('api/v1')->group(function () {
    Route::get('/public', [PublicController::class, 'index']);
});

// 私有API - 严格保护
Route::middleware(['security', 'auth'])->prefix('api/v1')->group(function () {
    Route::get('/private', [PrivateController::class, 'index']);
});

// 管理API - 额外保护
Route::middleware(['security', 'auth', 'admin'])->prefix('admin')->group(function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});
```

### 2. 渐进式启用

```php
// 开发环境
if (app()->environment('local', 'testing')) {
    config(['security.ignore_local' => true]);
    config(['security.debug' => true]);
}

// 生产环境
if (app()->environment('production')) {
    config(['security.ignore_local' => false]);
    config(['security.debug' => false]);
}
```

### 3. 监控和告警

```php
// 定期检查高威胁IP
if (app()->runningInConsole()) {
    $ipManager = app(\zxf\Security\Services\IpManagerService::class);
    $highThreatIps = $ipManager->getHighThreatIps(50);
    
    foreach ($highThreatIps as $ip) {
        if ($ip['threat_score'] > 80) {
            // 发送告警
            \Log::alert('高威胁IP检测', $ip);
            // 发送邮件/SMS
        }
    }
}
```

---

## 🆘 获取帮助

- **文档**：[README.md](../README.md)
- **示例**：[EXAMPLES.md](./EXAMPLES.md)
- **问题反馈**：[GitHub Issues](https://github.com/zxf/laravel-security/issues)
- **讨论区**：[GitHub Discussions](https://github.com/zxf/laravel-security/discussions)

---

## 🎉 恭喜！

您已经成功安装并配置了Laravel安全扩展包！

现在您的应用已经具备：
- ✅ IP黑白名单管理
- ✅ 多级限流控制
- ✅ 威胁检测和防护
- ✅ 自动威胁评分
- ✅ 完整的日志记录

继续探索更多功能，打造更安全的Laravel应用！

---

**最后更新**: 2026-03-01
