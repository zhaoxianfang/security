# Laravel 安全扩展包使用示例

本文档提供了Laravel安全扩展包的详细使用示例，帮助您快速上手并在项目中应用各种安全功能。

## 目录

- [快速开始](#快速开始)
- [基础配置](#基础配置)
- [IP管理](#ip管理)
- [限流控制](#限流控制)
- [威胁检测](#威胁检测)
- [白名单配置](#白名单配置)
- [内网配置](#内网配置)
- [高级功能](#高级功能)
- [最佳实践](#最佳实践)

---

## 快速开始

### 1. 安装扩展包

```bash
composer require zxf/laravel-security
```

### 2. 发布配置文件

```bash
php artisan vendor:publish --tag=security-config
```

### 3. 运行数据库迁移

```bash
php artisan migrate
```

### 4. 基础配置

在 `.env` 文件中添加基础配置：

```env
# 基础配置
SECURITY_ENABLED=true
SECURITY_DEBUG=false

# 忽略本地请求（开发环境可设为true）
SECURITY_IGNORE_LOCAL=true
```

---

## 基础配置

### 启用中间件

在 `app/Http/Kernel.php` 中注册中间件：

```php
protected $middleware = [
    // ...
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
```

### 或者在路由中应用

```php
// 应用到所有路由
Route::middleware(['security'])->group(function () {
    Route::get('/api/users', [UserController::class, 'index']);
});

// 应用到特定路由
Route::middleware(['security'])->post('/api/login', [AuthController::class, 'login']);
```

---

## IP管理

### 添加IP到白名单

```php
use zxf\Security\Services\IpManagerService;

// 通过服务
$ipManager = app(IpManagerService::class);

// 添加永久白名单
$ipManager->addToWhitelist('192.168.1.100', '管理员IP');

// 添加临时白名单（24小时后过期）
$ipManager->addToWhitelist('192.168.1.101', '临时访问', now()->addHours(24));
```

### 添加IP到黑名单

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 添加永久黑名单
$ipManager->addToBlacklist('1.2.3.4', '恶意攻击');

// 添加临时黑名单（1小时后过期）
$ipManager->addToBlacklist('5.6.7.8', '频率超限', now()->addHour());

// 自动检测黑名单
$ipManager->addToBlacklist('9.10.11.12', '异常行为', null, true);
```

### 封禁IP（带威胁评分）

```php
use Illuminate\Http\Request;
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);
$request = request();

// 封禁1小时
$ipManager->banIp($request, 'SQLInjection', 75);

// 封禁24小时
$ipManager->banIp($request, 'XSSAttack', 90);

// 自动计算封禁时长
$ipManager->banIp($request, 'RateLimit', 60);
```

### 解除IP封禁

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 解除IP封禁
$ipManager->unbanIp('1.2.3.4');
```

### 获取IP统计信息

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 获取特定IP的统计信息
$stats = $ipManager->getIpStats('192.168.1.100');

print_r($stats);
/*
Array
(
    [ip] => 192.168.1.100
    [exists] => true
    [type] => monitoring
    [threat_score] => 15.5
    [request_count] => 1250
    [blocked_count] => 12
    [success_count] => 1238
    [trigger_count] => 3
    [last_seen] => 2026-03-01 12:30:45
    [first_seen] => 2026-02-28 08:15:20
    [is_range] => false
    [status] => active
    [auto_detected] => false
)
*/
```

### 获取高威胁IP列表

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 获取威胁评分最高的100个IP
$highThreatIps = $ipManager->getHighThreatIps(100);

foreach ($highThreatIps as $ipInfo) {
    echo "IP: {$ipInfo['ip_address']}\n";
    echo "威胁评分: {$ipInfo['threat_score']}\n";
    echo "拦截次数: {$ipInfo['blocked_count']}\n";
    echo "原因: {$ipInfo['reason']}\n";
    echo "\n";
}
```

### 批量添加IP

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 批量添加白名单
$whitelistIps = [
    '192.168.1.100' => '管理员PC',
    '192.168.1.101' => '开发服务器',
    '192.168.1.102' => '测试服务器',
];

foreach ($whitelistIps as $ip => $reason) {
    $ipManager->addToWhitelist($ip, $reason);
}

// 批量添加黑名单
$blacklistIps = [
    '1.2.3.4' => '已知恶意IP',
    '5.6.7.8' => '扫描器',
];

foreach ($blacklistIps as $ip => $reason) {
    $ipManager->addToBlacklist($ip, $reason);
}
```

---

## 限流控制

### 配置限流规则

在 `.env` 文件中配置：

```env
# 限流配置
SECURITY_RATE_LIMIT_ENABLED=true

# 每秒最多60个请求
SECURITY_RATE_LIMIT_PER_SECOND=60

# 每分钟最多1000个请求
SECURITY_RATE_LIMIT_PER_MINUTE=1000

# 每小时最多10000个请求
SECURITY_RATE_LIMIT_PER_HOUR=10000

# 超限后封禁时长（秒）
SECURITY_RATE_LIMIT_BAN_DURATION=3600
```

### 在配置文件中配置

在 `config/security.php` 中：

```php
return [
    // ... 其他配置

    'rate_limiting' => [
        'enabled' => env('SECURITY_RATE_LIMIT_ENABLED', true),

        // 分级限流配置
        'limits' => [
            'second' => [
                'enabled' => true,
                'max_requests' => 60,
                'ban_duration' => 60, // 超限封禁60秒
            ],
            'minute' => [
                'enabled' => true,
                'max_requests' => 1000,
                'ban_duration' => 300, // 超限封禁5分钟
            ],
            'hour' => [
                'enabled' => true,
                'max_requests' => 10000,
                'ban_duration' => 3600, // 超限封禁1小时
            ],
            'day' => [
                'enabled' => false, // 禁用天级限流
                'max_requests' => 100000,
                'ban_duration' => 86400,
            ],
        ],

        // 内网IP是否跳过限流
        'skip_intranet' => env('SECURITY_RATE_LIMIT_SKIP_INTRANET', false),
    ],
];
```

### 自定义限流规则

```php
use zxf\Security\Services\RateLimiterService;

$rateLimiter = app(RateLimiterService::class);

// 检查IP是否超限
if ($rateLimiter->checkRateLimit(request())) {
    // 正常处理请求
    return response()->json(['success' => true]);
} else {
    // 返回限流错误
    return response()->json([
        'error' => '请求过于频繁，请稍后再试',
        'retry_after' => $rateLimiter->getRetryAfter(),
    ], 429);
}
```

### 获取当前限流状态

```php
use zxf\Security\Services\RateLimiterService;

$rateLimiter = app(RateLimiterService::class);

// 获取限流状态
$status = $rateLimiter->getRateLimitStatus(request());

echo "每秒: {$status['second']['current']}/{$status['second']['max']}\n";
echo "每分: {$status['minute']['current']}/{$status['minute']['max']}\n";
echo "每小时: {$status['hour']['current']}/{$status['hour']['max']}\n";
```

---

## 威胁检测

### 配置威胁检测规则

在 `config/security.php` 中：

```php
return [
    // ... 其他配置

    'threat_detection' => [
        'enabled' => true,

        // SQL注入检测
        'sql_injection' => [
            'enabled' => true,
            'patterns' => [
                '/union\s+select/i',
                '/or\s+1\s*=\s*1/i',
                '/drop\s+table/i',
                '/exec\s*\(/i',
            ],
        ],

        // XSS攻击检测
        'xss_attack' => [
            'enabled' => true,
            'patterns' => [
                '/<script[^>]*>.*?<\/script>/i',
                '/javascript:/i',
                '/on\w+\s*=/i',
            ],
        ],

        // 命令注入检测
        'command_injection' => [
            'enabled' => true,
            'patterns' => [
                '/;\s*rm\s+-rf/i',
                '/;\s*cat\s+/i',
                '/\|\s*nc\s+/i',
                '/&&\s*wget\s+/i',
            ],
        ],

        // 路径遍历检测
        'path_traversal' => [
            'enabled' => true,
            'patterns' => [
                '/\.\.[\/\\\\]/',
                '/%2e%2e%2f/i',
                '/\.\.%5c/i',
            ],
        ],
    ],
];
```

### 手动触发威胁检测

```php
use zxf\Security\Services\ThreatDetectionService;

$detector = app(ThreatDetectionService::class);
$request = request();

// 检测请求是否包含威胁
$threats = $detector->detectThreats($request);

if (!empty($threats)) {
    // 发现威胁，记录并处理
    foreach ($threats as $threat) {
        Log::warning('发现安全威胁', [
            'type' => $threat['type'],
            'description' => $threat['description'],
            'severity' => $threat['severity'],
        ]);
    }

    // 返回错误响应
    return response()->json([
        'error' => '请求包含非法内容',
        'threats' => $threats,
    ], 403);
}

// 正常处理请求
```

### 自定义威胁检测规则

```php
use zxf\Security\Services\ThreatDetectionService;

$detector = app(ThreatDetectionService::class);

// 添加自定义检测规则
$detector->addCustomPattern([
    'name' => 'custom_attack',
    'description' => '自定义攻击检测',
    'severity' => 'high',
    'pattern' => '/your-custom-pattern-here/i',
    'fields' => ['query', 'body', 'headers'],
]);

// 检测
$threats = $detector->detectThreats(request());
```

---

## 白名单配置

### 配置路径白名单

在 `config/security.php` 中：

```php
return [
    // ... 其他配置

    'whitelist' => [
        // 公开路径（完全跳过安全检查）
        'public_paths' => [
            '/',
            '/api/health',
            '/api/ping',
            '/login',
            '/register',
        ],

        // 管理员路径（需要额外认证）
        'admin_paths' => [
            '/admin',
            '/admin/*',
            '/api/admin/*',
        ],

        // API路径
        'api_paths' => [
            '/api/v1/public/*',
        ],
    ],
];
```

### 编程方式配置白名单

```php
use zxf\Security\Services\WhitelistSecurityService;

$whitelist = app(WhitelistSecurityService::class);

// 检查路径是否在白名单
$isWhitelisted = $whitelist->checkPath(request());

if ($isWhitelisted) {
    // 跳过安全检查
    return $next($request);
}

// 执行安全检查
```

---

## 内网配置

### 配置内网IP规则

在 `.env` 文件中：

```env
# 内网配置
SECURITY_INTRANET_ENABLE_CACHE=true
SECURITY_INTRANET_CACHE_TTL=300
SECURITY_INTRANET_SKIP_RATE_LIMIT=false
SECURITY_INTRANET_SKIP_BLACKLIST=false
SECURITY_INTRANET_LOG_ACCESS=true
SECURITY_INTRANET_CHECK_LOOPBACK=true
SECURITY_INTRANET_CHECK_LINKLOCAL=true
```

### 配置自定义内网范围

在 `config/security.php` 中：

```php
return [
    // ... 其他配置

    'intranet' => [
        // 启用缓存
        'enable_cache' => env('SECURITY_INTRANET_ENABLE_CACHE', true),

        // 缓存时间（秒）
        'cache_ttl' => env('SECURITY_INTRANET_CACHE_TTL', 300),

        // 跳过限流检查
        'skip_rate_limit' => env('SECURITY_INTRANET_SKIP_RATE_LIMIT', false),

        // 跳过黑名单检查
        'skip_blacklist_check' => env('SECURITY_INTRANET_SKIP_BLACKLIST', false),

        // 记录内网访问
        'log_access' => env('SECURITY_INTRANET_LOG_ACCESS', true),

        // 检查回环地址 (127.0.0.1, ::1)
        'check_loopback' => env('SECURITY_INTRANET_CHECK_LOOPBACK', true),

        // 检查链路本地地址 (169.254.0.0/16, fe80::/10)
        'check_linklocal' => env('SECURITY_INTRANET_CHECK_LINKLOCAL', true),

        // 自定义内网IP范围
        'custom_ranges' => [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ],
    ],
];
```

### 使用内网判断函数

```php
use function zxf\Security\is_intranet_ip;

// 判断IP是否为内网IP
$isIntranet = is_intranet_ip('192.168.1.100'); // true
$isIntranet = is_intranet_ip('8.8.8.8'); // false

// 使用选项控制判断规则
$options = [
    'loopback' => true,      // 检查回环地址
    'linklocal' => true,      // 检查链路本地地址
    'custom' => [            // 自定义范围
        '192.168.0.0/16',
        '10.0.0.0/8',
    ],
];

$isIntranet = is_intranet_ip('172.16.0.1', $options); // true
```

---

## 高级功能

### 自定义黑白名单处理器

在 `config/security.php` 中配置：

```php
return [
    // ... 其他配置

    // 自定义白名单处理器
    'whitelist_handler' => function ($request, $ip) {
        // 从数据库查询
        $user = \App\Models\User::where('ip_address', $ip)->first();
        
        if ($user && $user->is_admin) {
            return true; // 管理员IP在白名单
        }
        
        return false;
    },

    // 自定义黑名单处理器
    'blacklist_handler' => function ($request, $ip) {
        // 从第三方API查询
        $response = \Http::get('https://api.threat-intelligence.com/check', [
            'ip' => $ip,
        ]);
        
        return $response->json('is_malicious', false);
    },
];
```

### 监听安全事件

```php
// 在 EventServiceProvider 中注册
protected $listen = [
    \zxf\Security\Events\IpCreated::class => [
        \App\Listeners\LogIpCreated::class,
    ],
    
    \zxf\Security\Events\IpUpdated::class => [
        \App\Listeners\SendIpAlert::class,
    ],
    
    \zxf\Security\Events\IpDeleted::class => [
        \App\Listeners\ArchiveIpRecord::class,
    ],
];
```

### 创建事件监听器

```php
namespace App\Listeners;

use zxf\Security\Events\IpCreated;
use Illuminate\Support\Facades\Log;

class LogIpCreated
{
    public function handle(IpCreated $event)
    {
        Log::info('IP记录已创建', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
            'threat_score' => $event->ip->threat_score,
        ]);

        // 发送通知
        if ($event->ip->threat_score > 80) {
            // 发送高威胁警报
            // ...
        }
    }
}
```

### 批量导入IP

```php
use zxf\Security\Services\IpManagerService;
use Illuminate\Support\Facades\DB;

$ipManager = app(IpManagerService::class);

// 从CSV文件导入
$csvFile = storage_path('imports/ips.csv');
$handle = fopen($csvFile, 'r');

DB::beginTransaction();
try {
    while (($row = fgetcsv($handle)) !== false) {
        $ip = $row[0];
        $type = $row[1]; // whitelist 或 blacklist
        $reason = $row[2];

        if ($type === 'whitelist') {
            $ipManager->addToWhitelist($ip, $reason);
        } else {
            $ipManager->addToBlacklist($ip, $reason);
        }
    }

    fclose($handle);
    DB::commit();
} catch (\Exception $e) {
    DB::rollBack();
    Log::error('IP导入失败', ['error' => $e->getMessage()]);
}
```

### 定期清理过期IP

创建调度任务：

```php
// 在 app/Console/Kernel.php 中

protected function schedule(Schedule $schedule)
{
    // 每天凌晨清理过期IP
    $schedule->call(function () {
        \zxf\Security\Models\SecurityIp::prune();
    })->daily();
    
    // 每小时清理缓存
    $schedule->call(function () {
        clean_security_cache();
    })->hourly();
}
```

### 获取安全报告

```php
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\RateLimiterService;

$ipManager = app(IpManagerService::class);
$rateLimiter = app(RateLimiterService::class);

// 生成安全报告
$report = [
    'high_threat_ips' => count($ipManager->getHighThreatIps(50)),
    'total_blacklisted' => count($ipManager->getAllBlacklistedIps()),
    'rate_limit_status' => $rateLimiter->getRateLimitStatus(request()),
    'service_stats' => $ipManager->getServiceStats(),
];

// 发送报告邮件
Mail::to('security@example.com')->send(new SecurityReportMail($report));
```

---

## 最佳实践

### 1. 开发环境配置

```env
# .env (开发环境)
SECURITY_ENABLED=true
SECURITY_IGNORE_LOCAL=true      # 忽略本地请求
SECURITY_DEBUG=true             # 启用调试日志
SECURITY_RATE_LIMIT_ENABLED=false  # 开发环境禁用限流
```

### 2. 生产环境配置

```env
# .env (生产环境)
SECURITY_ENABLED=true
SECURITY_IGNORE_LOCAL=false     # 不忽略本地请求
SECURITY_DEBUG=false            # 禁用调试日志
SECURITY_RATE_LIMIT_ENABLED=true  # 启用限流

# 严格的安全策略
SECURITY_RATE_LIMIT_PER_SECOND=30
SECURITY_RATE_LIMIT_PER_MINUTE=500
SECURITY_RATE_LIMIT_BAN_DURATION=7200
```

### 3. 监控和告警

```php
use zxf\Security\Services\IpManagerService;
use Illuminate\Support\Facades\Log;

$ipManager = app(IpManagerService::class);

// 定期检查高威胁IP
if (app()->runningInConsole()) {
    $highThreatIps = $ipManager->getHighThreatIps(100);

    foreach ($highThreatIps as $ip) {
        if ($ip['threat_score'] > 80) {
            Log::alert('发现高威胁IP', [
                'ip' => $ip['ip_address'],
                'score' => $ip['threat_score'],
                'blocked_count' => $ip['blocked_count'],
            ]);

            // 发送告警通知
            // ...
        }
    }
}
```

### 4. 缓存优化

```php
use zxf\Security\Services\IpManagerService;

$ipManager = app(IpManagerService::class);

// 在配置更新后清除缓存
$ipManager->clearCache();

// 批量操作后清除缓存
$ipManager->clearBatchIpCache(['1.2.3.4', '5.6.7.8']);
```

### 5. 错误处理

```php
use zxf\Security\Services\IpManagerService;
use Illuminate\Support\Facades\Log;

try {
    $ipManager = app(IpManagerService::class);
    $ipManager->banIp(request(), 'ManualBan', 90);
} catch (\Exception $e) {
    Log::error('IP封禁失败', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString(),
    ]);

    // 返回用户友好的错误信息
    return response()->json([
        'error' => '操作失败，请稍后重试',
    ], 500);
}
```

### 6. 性能优化

```php
// 1. 使用批量操作
SecurityIp::batchRecordRequests($records);

// 2. 启用缓存
Cache::put('security:ip:whitelist:' . md5($ip), true, 300);

// 3. 使用内网缓存
is_intranet_ip($ip, ['use_cache' => true]);

// 4. 限制查询结果
$ips = SecurityIp::getHighThreatIps(50); // 只查询前50个
```

---

## 常见问题

### Q: 如何临时禁用安全检查？

```php
// 方式1：在配置中禁用
config(['security.enabled' => false]);

// 方式2：在.env中禁用
SECURITY_ENABLED=false

// 方式3：使用中间件排除
Route::withoutMiddleware([\zxf\Security\Middleware\SecurityMiddleware::class])
    ->get('/temp-endpoint', [Controller::class, 'method']);
```

### Q: 如何查看被拦截的请求？

```php
// 查看日志
tail -f storage/logs/laravel.log | grep -i "security"

// 查询数据库
$blockedRequests = \zxf\Security\Models\SecurityIp::where('type', 'blacklist')
    ->orderBy('created_at', 'desc')
    ->limit(100)
    ->get();
```

### Q: 如何测试安全规则？

```php
use zxf\Security\Services\ThreatDetectionService;

$detector = app(ThreatDetectionService::class);

// 创建测试请求
$testRequest = Request::create('/api/test', 'POST', [
    'data' => "' OR 1=1 --", // SQL注入测试
]);

// 检测威胁
$threats = $detector->detectThreats($testRequest);

dump($threats);
```

---

## 总结

本文档提供了Laravel安全扩展包的全面使用示例，涵盖了从基础配置到高级功能的各个方面。通过这些示例，您可以：

- 快速上手使用扩展包
- 配置和定制安全规则
- 集成到现有项目中
- 监控和优化安全性能

如有更多问题，请参考主README文档或联系技术支持。
