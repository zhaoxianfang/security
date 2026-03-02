# Laravel 安全扩展包 - API文档

本文档提供了Laravel安全扩展包的完整API参考。

## 目录

- [服务类](#服务类)
- [辅助函数](#辅助函数)
- [模型](#模型)
- [事件](#事件)
- [中间件](#中间件)

---

## 服务类

### IpManagerService

IP管理服务，提供IP白名单、黑名单、封禁管理等功能。

#### 方法列表

##### `addToWhitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): bool`

添加IP到白名单。

**参数**:
- `$ip` - IP地址
- `$reason` - 原因描述
- `$expiresAt` - 过期时间（可选）

**返回值**: `bool` - 是否成功

**示例**:
```php
$ipManager = app(IpManagerService::class);

// 添加永久白名单
$ipManager->addToWhitelist('192.168.1.100', '管理员IP');

// 添加临时白名单（24小时后过期）
$ipManager->addToWhitelist('192.168.1.101', '临时访问', now()->addHours(24));
```

---

##### `addToBlacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): bool`

添加IP到黑名单。

**参数**:
- `$ip` - IP地址
- `$reason` - 原因描述
- `$expiresAt` - 过期时间（可选）
- `$autoDetected` - 是否自动检测

**返回值**: `bool` - 是否成功

**示例**:
```php
$ipManager = app(IpManagerService::class);

// 添加永久黑名单
$ipManager->addToBlacklist('1.2.3.4', '恶意攻击');

// 添加临时黑名单（1小时后过期）
$ipManager->addToBlacklist('5.6.7.8', '频率超限', now()->addHour());

// 自动检测黑名单
$ipManager->addToBlacklist('9.10.11.12', '异常行为', null, true);
```

---

##### `banIp(Request $request, string $type, float $threatScore = 0): bool`

封禁IP，支持威胁评分和动态封禁时长。

**参数**:
- `$request` - HTTP请求对象
- `$type` - 事件类型
- `$threatScore` - 威胁评分（0-100）

**返回值**: `bool` - 是否成功

**事件类型**:
- `'MaliciousRequest'` - 恶意请求
- `'SQLInjection'` - SQL注入攻击
- `'XSSAttack'` - XSS跨站脚本攻击
- `'CommandInjection'` - 命令注入攻击
- `'RateLimit'` - 频率超限
- `'Blacklist'` - 黑名单

**示例**:
```php
$ipManager = app(IpManagerService::class);
$request = request();

// 封禁1小时
$ipManager->banIp($request, 'SQLInjection', 75);

// 封禁24小时
$ipManager->banIp($request, 'XSSAttack', 90);

// 自动计算封禁时长
$ipManager->banIp($request, 'RateLimit', 60);
```

---

##### `unbanIp(string $ip): bool`

解除IP封禁。

**参数**:
- `$ip` - IP地址

**返回值**: `bool` - 是否成功

**示例**:
```php
$ipManager = app(IpManagerService::class);

// 解除IP封禁
$ipManager->unbanIp('1.2.3.4');
```

---

##### `isWhitelisted(Request $request): bool`

检查IP是否在白名单中。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否在白名单

**示例**:
```php
$ipManager = app(IpManagerService::class);

if ($ipManager->isWhitelisted(request())) {
    // IP在白名单中
}
```

---

##### `isBlacklisted(Request $request): bool`

检查IP是否在黑名单中。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否在黑名单

**示例**:
```php
$ipManager = app(IpManagerService::class);

if ($ipManager->isBlacklisted(request())) {
    // IP在黑名单中
    return response('Access Denied', 403);
}
```

---

##### `getIpStats(string $ip): array`

获取IP统计信息。

**参数**:
- `$ip` - IP地址

**返回值**: `array` - 统计信息数组

**返回字段**:
- `ip` - IP地址
- `exists` - 是否存在
- `type` - 类型
- `threat_score` - 威胁评分
- `request_count` - 请求次数
- `blocked_count` - 拦截次数
- `success_count` - 成功次数
- `trigger_count` - 触发次数
- `last_seen` - 最后访问时间
- `first_seen` - 首次访问时间

**示例**:
```php
$ipManager = app(IpManagerService::class);

$stats = $ipManager->getIpStats('192.168.1.100');

echo "威胁评分: {$stats['threat_score']}\n";
echo "请求次数: {$stats['request_count']}\n";
echo "拦截次数: {$stats['blocked_count']}\n";
```

---

##### `getHighThreatIps(int $limit = 100): array`

获取高威胁IP列表。

**参数**:
- `$limit` - 返回数量限制

**返回值**: `array` - IP信息数组

**示例**:
```php
$ipManager = app(IpManagerService::class);

$highThreatIps = $ipManager->getHighThreatIps(100);

foreach ($highThreatIps as $ipInfo) {
    echo "IP: {$ipInfo['ip_address']}\n";
    echo "威胁评分: {$ipInfo['threat_score']}\n";
    echo "拦截次数: {$ipInfo['blocked_count']}\n";
}
```

---

##### `getAllBlacklistedIps(): array`

获取所有黑名单IP。

**返回值**: `array` - 黑名单IP数组

**示例**:
```php
$ipManager = app(IpManagerService::class);

$blacklistedIps = $ipManager->getAllBlacklistedIps();

foreach ($blacklistedIps as $ipInfo) {
    echo "IP: {$ipInfo['ip_address']}\n";
    echo "原因: {$ipInfo['reason']}\n";
    echo "过期时间: {$ipInfo['expires_at']}\n";
}
```

---

##### `getClientRealIp(Request $request): string`

获取客户端真实IP地址。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `string` - IP地址

**示例**:
```php
$ipManager = app(IpManagerService::class);

$clientIp = $ipManager->getClientRealIp(request());
echo "客户端IP: {$clientIp}\n";
```

---

##### `clearCache(): void`

清除所有缓存。

**示例**:
```php
$ipManager = app(IpManagerService::class);

$ipManager->clearCache();
```

---

##### `getServiceStats(): array`

获取服务统计信息。

**返回值**: `array` - 统计信息

**示例**:
```php
$ipManager = app(IpManagerService::class);

$stats = $ipManager->getServiceStats();

print_r($stats);
/*
Array
(
    [high_threat_ips] => 25
    [cache_enabled] => 1
    [cache_ttl] => 300
    [auto_detection_enabled] => 1
)
*/
```

---

### RateLimiterService

限流服务，提供多窗口限流控制。

#### 方法列表

##### `checkRateLimit(Request $request): bool`

检查IP是否超限。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否未超限

**示例**:
```php
$rateLimiter = app(RateLimiterService::class);

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

---

##### `getRateLimitStatus(Request $request): array`

获取当前限流状态。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `array` - 限流状态

**示例**:
```php
$rateLimiter = app(RateLimiterService::class);

$status = $rateLimiter->getRateLimitStatus(request());

echo "每秒: {$status['second']['current']}/{$status['second']['max']}\n";
echo "每分: {$status['minute']['current']}/{$status['minute']['max']}\n";
echo "每小时: {$status['hour']['current']}/{$status['hour']['max']}\n";
```

---

##### `getRetryAfter(): int`

获取重试等待时间（秒）。

**返回值**: `int` - 等待秒数

**示例**:
```php
$rateLimiter = app(RateLimiterService::class);

if (!$rateLimiter->checkRateLimit(request())) {
    return response()->json([
        'error' => '请求过于频繁',
        'retry_after' => $rateLimiter->getRetryAfter(),
    ], 429);
}
```

---

##### `clearRateLimit(string $ip): void`

清除指定IP的限流记录。

**参数**:
- `$ip` - IP地址

**示例**:
```php
$rateLimiter = app(RateLimiterService::class);

$rateLimiter->clearRateLimit('192.168.1.100');
```

---

### ThreatDetectionService

威胁检测服务，提供多种安全威胁检测功能。

#### 方法列表

##### `detectThreats(Request $request): array`

检测请求是否包含威胁。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `array` - 威胁列表

**示例**:
```php
$detector = app(ThreatDetectionService::class);

$threats = $detector->detectThreats(request());

if (!empty($threats)) {
    return response()->json([
        'error' => '请求包含非法内容',
        'threats' => $threats,
    ], 403);
}
```

---

##### `hasSuspiciousUserAgent(Request $request): bool`

检查是否有可疑User-Agent。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否可疑

**示例**:
```php
$detector = app(ThreatDetectionService::class);

if ($detector->hasSuspiciousUserAgent(request())) {
    Log::warning('检测到可疑User-Agent');
    return response('Forbidden', 403);
}
```

---

##### `hasSuspiciousHeaders(Request $request): bool`

检查是否有可疑HTTP头。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否可疑

**示例**:
```php
$detector = app(ThreatDetectionService::class);

if ($detector->hasSuspiciousHeaders(request())) {
    Log::warning('检测到可疑HTTP头');
    return response('Forbidden', 403);
}
```

---

##### `hasDangerousUploads(Request $request): bool`

检查是否有危险文件上传。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否危险

**示例**:
```php
$detector = app(ThreatDetectionService::class);

if ($detector->hasDangerousUploads(request())) {
    Log::warning('检测到危险文件上传');
    return response('Forbidden', 403);
}
```

---

##### `isSafeUrl(Request $request): bool`

检查URL是否安全。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否安全

**示例**:
```php
$detector = app(ThreatDetectionService::class);

if (!$detector->isSafeUrl(request())) {
    Log::warning('检测到非法URL');
    return response('Forbidden', 403);
}
```

---

##### `isResourcePath(Request $request): bool`

检查是否为资源文件路径。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否为资源路径

**示例**:
```php
$detector = app(ThreatDetectionService::class);

if ($detector->isResourcePath(request())) {
    // 跳过安全检查
    return $next($request);
}
```

---

### WhitelistSecurityService

白名单管理服务。

#### 方法列表

##### `checkPath(Request $request): bool`

检查路径是否在白名单中。

**参数**:
- `$request` - HTTP请求对象

**返回值**: `bool` - 是否在白名单

**示例**:
```php
$whitelist = app(WhitelistSecurityService::class);

if ($whitelist->checkPath(request())) {
    // 跳过安全检查
    return $next($request);
}
```

---

### ConfigHotReloadService

配置热重载服务。

#### 方法列表

##### `reload(): bool`

重新加载配置。

**返回值**: `bool` - 是否成功

**示例**:
```php
$config = app(ConfigHotReloadService::class);

$config->reload();
```

---

##### `getConfigVersion(): string`

获取配置版本。

**返回值**: `string` - 配置版本号

**示例**:
```php
$config = app(ConfigHotReloadService::class);

$version = $config->getConfigVersion();
echo "当前配置版本: {$version}\n";
```

---

##### `checkConfigChanged(): bool`

检查配置是否已更改。

**返回值**: `bool` - 是否已更改

**示例**:
```php
$config = app(ConfigHotReloadService::class);

if ($config->checkConfigChanged()) {
    $config->reload();
}
```

---

## 辅助函数

### `is_intranet_ip(string $ip, array $options = []): bool`

判断IP是否为内网IP。

**参数**:
- `$ip` - IP地址
- `$options` - 选项数组
  - `loopback` (bool) - 检查回环地址，默认true
  - `linklocal` (bool) - 检查链路本地地址，默认true
  - `custom` (array) - 自定义IP范围，默认空数组

**返回值**: `bool` - 是否为内网IP

**示例**:
```php
// 基础用法
$isIntranet = is_intranet_ip('192.168.1.100'); // true

// 使用选项
$options = [
    'loopback' => true,
    'linklocal' => true,
    'custom' => ['10.0.0.0/8', '172.16.0.0/12'],
];
$isIntranet = is_intranet_ip('172.16.0.1', $options); // true
```

---

### `clean_security_cache(): bool`

清除所有安全缓存。

**返回值**: `bool` - 是否成功

**示例**:
```php
clean_security_cache();
```

---

### `security_config(string $key, $default = null): mixed`

获取安全配置项。

**参数**:
- `$key` - 配置键
- `$default` - 默认值

**返回值**: `mixed` - 配置值

**示例**:
```php
$enabled = security_config('enabled', false);
$maxRequests = security_config('rate_limiting.limits.second.max_requests', 60);
```

---

### `is_cidr_match(string $ip, string $cidr): bool`

检查IP是否匹配CIDR范围。

**参数**:
- `$ip` - IP地址
- `$cidr` - CIDR表示法（如192.168.0.0/16）

**返回值**: `bool` - 是否匹配

**示例**:
```php
$isMatch = is_cidr_match('192.168.1.100', '192.168.0.0/16'); // true
$isMatch = is_cidr_match('10.0.1.1', '192.168.0.0/16'); // false
```

---

## 模型

### SecurityIp

IP安全记录模型。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `id` | int | 主键ID |
| `ip_address` | string | IP地址 |
| `ip_range` | string | IP范围（CIDR） |
| `is_range` | bool | 是否为IP范围 |
| `type` | string | 类型（whitelist/blacklist/monitoring/suspicious） |
| `status` | string | 状态（active/inactive） |
| `reason` | string | 原因 |
| `threat_score` | float | 威胁评分（0-100） |
| `request_count` | int | 请求次数 |
| `blocked_count` | int | 拦截次数 |
| `success_count` | int | 成功次数 |
| `trigger_count` | int | 触发次数 |
| `trigger_rules` | array | 触发规则 |
| `auto_detected` | bool | 是否自动检测 |
| `expires_at` | DateTime | 过期时间 |
| `first_seen_at` | DateTime | 首次发现时间 |
| `last_request_at` | DateTime | 最后请求时间 |
| `created_at` | DateTime | 创建时间 |
| `updated_at` | DateTime | 更新时间 |

#### 常量

```php
// 类型常量
TYPE_WHITELIST = 'whitelist';     // 白名单
TYPE_BLACKLIST = 'blacklist';     // 黑名单
TYPE_MONITORING = 'monitoring';   // 监控中
TYPE_SUSPICIOUS = 'suspicious';   // 可疑

// 状态常量
STATUS_ACTIVE = 'active';         // 激活
STATUS_INACTIVE = 'inactive';     // 未激活
```

#### 方法列表

##### `isWhitelisted(string $ip): bool`

静态方法：检查IP是否在白名单。

**参数**:
- `$ip` - IP地址

**返回值**: `bool` - 是否在白名单

**示例**:
```php
if (SecurityIp::isWhitelisted('192.168.1.100')) {
    // IP在白名单中
}
```

---

##### `isBlacklisted(string $ip): bool`

静态方法：检查IP是否在黑名单。

**参数**:
- `$ip` - IP地址

**返回值**: `bool` - 是否在黑名单

**示例**:
```php
if (SecurityIp::isBlacklisted('1.2.3.4')) {
    // IP在黑名单中
}
```

---

##### `addToWhitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): SecurityIp`

静态方法：添加IP到白名单。

**参数**:
- `$ip` - IP地址
- `$reason` - 原因
- `$expiresAt` - 过期时间

**返回值**: `SecurityIp` - 模型实例

**示例**:
```php
SecurityIp::addToWhitelist('192.168.1.100', '管理员IP');
```

---

##### `addToBlacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): SecurityIp`

静态方法：添加IP到黑名单。

**参数**:
- `$ip` - IP地址
- `$reason` - 原因
- `$expiresAt` - 过期时间
- `$autoDetected` - 是否自动检测

**返回值**: `SecurityIp` - 模型实例

**示例**:
```php
SecurityIp::addToBlacklist('1.2.3.4', '恶意攻击');
```

---

##### `recordRequest(string $ip, bool $blocked = false, ?string $rule = null): ?SecurityIp`

静态方法：记录IP请求。

**参数**:
- `$ip` - IP地址
- `$blocked` - 是否被拦截
- `$rule` - 触发规则

**返回值**: `SecurityIp|null` - 模型实例或null

**示例**:
```php
SecurityIp::recordRequest('192.168.1.100', false);
SecurityIp::recordRequest('1.2.3.4', true, 'SQLInjection');
```

---

##### `batchRecordRequests(array $records): int`

静态方法：批量记录IP请求。

**参数**:
- `$records` - 记录数组

**返回值**: `int` - 成功记录数量

**示例**:
```php
$records = [
    ['ip' => '192.168.1.100', 'blocked' => false],
    ['ip' => '1.2.3.4', 'blocked' => true, 'rule' => 'SQLInjection'],
];

$count = SecurityIp::batchRecordRequests($records);
```

---

##### `getIpStats(string $ip): ?array`

静态方法：获取IP统计信息。

**参数**:
- `$ip` - IP地址

**返回值**: `array|null` - 统计信息或null

**示例**:
```php
$stats = SecurityIp::getIpStats('192.168.1.100');
```

---

##### `getHighThreatIps(int $limit = 100): Collection`

静态方法：获取高威胁IP列表。

**参数**:
- `$limit` - 返回数量限制

**返回值**: `Collection` - IP集合

**示例**:
```php
$ips = SecurityIp::getHighThreatIps(100);
```

---

##### `prune(): void`

静态方法：清理过期记录。

**示例**:
```php
SecurityIp::prune();
```

---

## 事件

### IpCreated

IP记录创建事件。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `ip` | SecurityIp | IP记录模型 |

**示例监听器**:
```php
class LogIpCreated
{
    public function handle(IpCreated $event)
    {
        Log::info('IP记录已创建', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
        ]);
    }
}
```

---

### IpUpdated

IP记录更新事件。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `ip` | SecurityIp | IP记录模型 |

**示例监听器**:
```php
class LogIpUpdated
{
    public function handle(IpUpdated $event)
    {
        Log::info('IP记录已更新', [
            'ip' => $event->ip->ip_address,
            'threat_score' => $event->ip->threat_score,
        ]);
    }
}
```

---

### IpDeleted

IP记录删除事件。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `ip` | SecurityIp | IP记录模型 |

**示例监听器**:
```php
class LogIpDeleted
{
    public function handle(IpDeleted $event)
    {
        Log::info('IP记录已删除', [
            'ip' => $event->ip->ip_address,
        ]);
    }
}
```

---

### IpAdded

IP添加事件（添加到白名单或黑名单）。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `ip` | SecurityIp | IP记录模型 |

**示例监听器**:
```php
class LogIpAdded
{
    public function handle(IpAdded $event)
    {
        Log::info('IP已添加', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
            'reason' => $event->ip->reason,
        ]);
    }
}
```

---

### IpTypeChanged

IP类型变更事件。

#### 属性

| 属性 | 类型 | 说明 |
|-----|------|------|
| `ip` | SecurityIp | IP记录模型 |
| `oldType` | string | 旧类型 |

**示例监听器**:
```php
class LogIpTypeChanged
{
    public function handle(IpTypeChanged $event)
    {
        Log::info('IP类型已变更', [
            'ip' => $event->ip->ip_address,
            'old_type' => $event->oldType,
            'new_type' => $event->ip->type,
        ]);
    }
}
```

---

## 中间件

### SecurityMiddleware

安全中间件，提供多层安全检查。

#### 注册中间件

在 `app/Http/Kernel.php` 中：

```php
protected $middleware = [
    // ...
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
```

或在路由中：

```php
Route::middleware(['security'])->group(function () {
    Route::get('/api/users', [UserController::class, 'index']);
});
```

#### 配置选项

通过环境变量配置：

```env
SECURITY_ENABLED=true
SECURITY_DEBUG=false
SECURITY_IGNORE_LOCAL=false
```

或在配置文件中配置 `config/security.php`。

#### 中间件行为

中间件按以下顺序执行安全检查：

1. 资源路径检查
2. 白名单检查
3. 内网IP检查
4. 限流检查
5. 黑名单检查
6. 威胁检测（SQL注入、XSS、命令注入等）
7. 可疑User-Agent检查
8. 可疑HTTP头检查
9. 文件上传检查
10. URL路径检查
11. HTTP方法检查
12. 记录IP访问

---

## 常用配置项

### 全局配置

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `enabled` | bool | true | 是否启用安全检查 |
| `debug` | bool | false | 是否启用调试日志 |
| `ignore_local` | bool | false | 是否忽略本地请求 |

### 限流配置

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `rate_limiting.enabled` | bool | true | 是否启用限流 |
| `rate_limiting.limits.second.max_requests` | int | 60 | 每秒最大请求数 |
| `rate_limiting.limits.minute.max_requests` | int | 1000 | 每分钟最大请求数 |
| `rate_limiting.limits.hour.max_requests` | int | 10000 | 每小时最大请求数 |

### 内网配置

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `intranet.enable_cache` | bool | true | 是否启用内网IP缓存 |
| `intranet.cache_ttl` | int | 300 | 内网IP缓存时间（秒） |
| `intranet.skip_rate_limit` | bool | false | 内网IP是否跳过限流 |
| `intranet.skip_blacklist_check` | bool | false | 内网IP是否跳过黑名单检查 |
| `intranet.log_access` | bool | true | 是否记录内网访问 |
| `intranet.check_loopback` | bool | true | 是否检查回环地址 |
| `intranet.check_linklocal` | bool | true | 是否检查链路本地地址 |

### 威胁检测配置

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `threat_detection.enabled` | bool | true | 是否启用威胁检测 |
| `threat_detection.sql_injection.enabled` | bool | true | 是否启用SQL注入检测 |
| `threat_detection.xss_attack.enabled` | bool | true | 是否启用XSS攻击检测 |
| `threat_detection.command_injection.enabled` | bool | true | 是否启用命令注入检测 |
| `threat_detection.path_traversal.enabled` | bool | true | 是否启用路径遍历检测 |

---

## 示例代码

### 完整的安全检查流程

```php
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\ThreatDetectionService;
use Illuminate\Http\Request;

class SecureController extends Controller
{
    public function handleRequest(Request $request)
    {
        $ipManager = app(IpManagerService::class);
        $rateLimiter = app(RateLimiterService::class);
        $detector = app(ThreatDetectionService::class);

        // 1. 检查白名单
        if ($ipManager->isWhitelisted($request)) {
            return $this->processRequest($request);
        }

        // 2. 检查黑名单
        if ($ipManager->isBlacklisted($request)) {
            return response('Access Denied', 403);
        }

        // 3. 检查限流
        if (!$rateLimiter->checkRateLimit($request)) {
            return response('Too Many Requests', 429);
        }

        // 4. 威胁检测
        $threats = $detector->detectThreats($request);
        if (!empty($threats)) {
            // 封禁IP
            $ipManager->banIp($request, 'ThreatDetected', 80);
            return response('Forbidden', 403);
        }

        // 5. 记录访问
        $ipManager->recordAccess($request);

        // 处理请求
        return $this->processRequest($request);
    }

    private function processRequest(Request $request)
    {
        // 业务逻辑
        return response()->json(['success' => true]);
    }
}
```

---

## 总结

本文档提供了Laravel安全扩展包的完整API参考，包括：

- ✅ 所有服务类的方法和参数
- ✅ 所有辅助函数的用法
- ✅ 模型的属性和方法
- ✅ 所有事件的属性
- ✅ 中间件的配置和使用
- ✅ 常用配置项说明
- ✅ 完整的示例代码

通过本文档，您可以全面了解和使用Laravel安全扩展包的所有功能。

---

**最后更新**: 2026-03-01
