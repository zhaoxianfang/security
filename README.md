# zxf/security - Laravel 11+ & PHP 8.2+ 现代化安全扩展包

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![PHP](https://img.shields.io/badge/php-8.2+-8892bf)
![Laravel](https://img.shields.io/badge/laravel-11+-ff2d20)
![License](https://img.shields.io/badge/license-MIT-green)

**企业级Web安全防护中间件 - 无Redis依赖的现代化解决方案**

</div>

---

## 📖 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
- [API文档](#api文档)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [更新日志](#更新日志)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

---

## 🎯 项目简介

`zxf/security` 是一款基于 Laravel 11+ 和 PHP 8.2+ 开发的企业级Web安全防护中间件。它提供了全方位的Web应用安全防护能力，包括IP黑白名单管理、速率限制、威胁检测、异常行为分析等核心功能。

### 设计理念

- **零依赖Redis**: 采用文件缓存+内存缓存的双重策略，无需Redis即可实现高性能
- **高性能**: 批量操作、采样机制、智能缓存，最小化数据库IO
- **易用性**: 开箱即用，配置简单，丰富的辅助函数
- **可扩展**: 模块化设计，支持自定义检测规则和处理逻辑
- **工业化**: 完善的日志、监控、统计，满足企业级运维需求

---

## ✨ 核心特性

### 🔒 全方位安全防护

| 功能特性 | 说明 | 状态 |
|---------|------|------|
| **IP黑白名单** | 支持IPv4/IPv6及CIDR段 | ✅ |
| **智能速率限制** | 多窗口（秒/分/时/天）限流 | ✅ |
| **SQL注入检测** | 正则表达式深度检测 | ✅ |
| **XSS攻击防护** | 跨站脚本攻击检测 | ✅ |
| **命令注入防护** | 系统命令注入检测 | ✅ |
| **文件上传检查** | 文件类型、大小、内容扫描 | ✅ |
| **异常行为分析** | 参数异常、请求异常检测 | ✅ |
| **威胁评分系统** | 自动IP类型转换 | ✅ |
| **内网IP识别** | 完整的内网IP判断逻辑 | ✅ |

### ⚡ 高性能优化

- **文件缓存系统**: 无需Redis，使用Laravel文件缓存
- **内存缓存预热**: 请求级缓存减少文件IO
- **批量写入**: 支持批量记录IP访问，减少数据库操作
- **采样机制**: 正常请求10%采样，降低数据库压力
- **原子操作**: 文件锁保证并发安全

### 🛠️ 开发友好

- **丰富的辅助函数**: 50+个全局辅助函数
- **详细中文注释**: 所有类和方法都有完整中文说明
- **完善的文档**: README、API文档、配置说明
- **类型安全**: 完整的PHP 8.2+类型提示
- **异常处理**: 优雅的异常处理和降级策略

---

## 📦 系统要求

- **PHP**: 8.2 或更高版本
- **Laravel**: 11.0 或更高版本
- **数据库**: MySQL 5.7+ / PostgreSQL 9.6+ / SQLite 3.8+
- **缓存**: Laravel文件缓存（默认）或支持的其他缓存驱动

---

## 🚀 快速开始

### 1. 安装

```bash
composer require zxf/security
```

### 2. 发布配置文件

```bash
php artisan vendor:publish --provider="zxf\Security\SecurityServiceProvider"
```

### 3. 运行数据库迁移

```bash
php artisan migrate
```

### 4. 配置 `.env` 文件

```env
# 基础配置
SECURITY_MIDDLEWARE_ENABLED=true
SECURITY_MIDDLEWARE_TYPE=global

# 内网配置
SECURITY_INTRANET_ENABLE_CACHE=true
SECURITY_INTRANET_CACHE_TTL=300
SECURITY_INTRANET_SKIP_RATE_LIMIT=false

# 速率限制
SECURITY_RATE_LIMITING_ENABLED=true
SECURITY_MAX_REQUESTS_PER_MINUTE=300
SECURITY_MAX_REQUESTS_PER_HOUR=10000
SECURITY_MAX_REQUESTS_PER_DAY=100000

# 调试日志
SECURITY_DEBUG_LOGGING=false
SECURITY_LOG_DETAILS=false
```

### 5. 注册中间件

在 `app/Http/Kernel.php` 中注册：

```php
protected $middleware = [
    // ...其他中间件
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
```

或者在路由中使用：

```php
Route::middleware(['security'])->group(function () {
    // 你的路由
});
```

### 6. 开始使用

```php
// 检查IP是否在黑名单
if (security_is_blacklisted('192.168.1.1')) {
    // IP在黑名单中
}

// 添加IP到黑名单
security_add_to_blacklist('10.0.0.1', '恶意攻击', now()->addWeek());

// 检查速率限制
$result = security_check_rate_limit($request->ip());
if ($result['blocked']) {
    return response()->json(['error' => '请求过于频繁'], 429);
}
```

---

## ⚙️ 配置说明

### 基础配置

```php
return [
    // 是否启用安全中间件
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),
    
    // 启用方式: global(全局) | route(路由)
    'enabled_type' => env('SECURITY_MIDDLEWARE_TYPE', 'global'),
    
    // 是否忽略本地请求
    'ignore_local' => env('SECURITY_IGNORE_LOCAL', false),
    
    // 日志级别
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),
    
    // 是否启用调试日志
    'enable_debug_logging' => env('SECURITY_DEBUG_LOGGING', false),
];
```

### 内网IP配置

```php
'intranet' => [
    // 是否启用内网IP判断缓存
    'enable_cache' => env('SECURITY_INTRANET_ENABLE_CACHE', true),
    
    // 缓存时间（秒）
    'cache_ttl' => env('SECURITY_INTRANET_CACHE_TTL', 300),
    
    // 内网IP是否跳过速率限制
    'skip_rate_limit' => env('SECURITY_INTRANET_SKIP_RATE_LIMIT', false),
    
    // 内网IP是否跳过黑名单检查
    'skip_blacklist_check' => env('SECURITY_INTRANET_SKIP_BLACKLIST', false),
    
    // 是否检查回环地址（127.0.0.0/8）
    'check_loopback' => env('SECURITY_INTRANET_CHECK_LOOPBACK', true),
    
    // 是否检查链路本地地址（169.254.0.0/16）
    'check_linklocal' => env('SECURITY_INTRANET_CHECK_LINKLOCAL', true),
    
    // 自定义内网IP范围（CIDR格式）
    'custom_ranges' => env('SECURITY_INTRANET_CUSTOM_RANGES', []),
],
```

### 速率限制配置

```php
'rate_limits' => [
    'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 300),
    'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 10000),
    'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 100000),
],

// 指纹策略: ip_only | ip_ua | ip_ua_path | ip_ua_path_method | custom
'rate_limit_strategy' => env('SECURITY_RATE_LIMIT_STRATEGY', 'ip_ua_path'),
```

### IP自动检测配置

```php
'ip_auto_detection' => [
    // 是否启用自动检测
    'enabled' => env('SECURITY_IP_AUTO_DETECTION', true),
    
    // 是否记录正常访客（false=只记录被拦截的）
    'record_normal_visitor' => env('SECURITY_RECORD_NORMAL_VISITOR', false),
    
    // 黑名单转换阈值
    'blacklist_threshold' => env('SECURITY_BLACKLIST_THRESHOLD', 80.0),
    
    // 可疑IP转换阈值
    'suspicious_threshold' => env('SECURITY_SUSPICIOUS_THRESHOLD', 50.0),
    
    // 最大触发规则次数
    'max_triggers' => env('SECURITY_MAX_TRIGGERS', 5),
    
    // 每次拦截增加威胁评分
    'add_threat_score' => env('SECURITY_ADD_THREAT_SCORE', 10.00),
    
    // 每次成功请求降低威胁评分
    'reduce_threat_score' => env('SECURITY_REDUCE_THREAT_SCORE', 1.00),
    
    // 威胁评分自然衰减（每小时）
    'decay_rate_per_hour' => env('SECURITY_DECAY_RATE_PER_HOUR', 0.3),
    
    // 自动清理过期记录
    'auto_cleanup' => env('SECURITY_AUTO_CLEANUP', false),
    
    // 监控IP自动过期时间（天）
    'monitoring_expire_days' => env('SECURITY_MONITORING_EXPIRE_DAYS', 15),
],
```

---

## 📚 使用指南

### IP管理

#### 检查IP状态

```php
use zxf\Security\Models\SecurityIp;
use function zxf\Security\{security_is_whitelisted, security_is_blacklisted};

// 方式1: 使用辅助函数（推荐）
if (security_is_whitelisted('192.168.1.1')) {
    echo 'IP在白名单中';
}

if (security_is_blacklisted('10.0.0.1')) {
    echo 'IP在黑名单中';
}

// 方式2: 使用模型
if (SecurityIp::isWhitelisted('192.168.1.1')) {
    echo 'IP在白名单中';
}

if (SecurityIp::isBlacklisted('10.0.0.1')) {
    echo 'IP在黑名单中';
}
```

#### 添加IP到白名单/黑名单

```php
use function zxf\Security\{security_add_to_whitelist, security_add_to_blacklist};

// 添加到白名单（永久）
security_add_to_whitelist('192.168.1.100', '内部服务器');

// 添加到白名单（临时）
security_add_to_whitelist('192.168.1.101', '临时授权', now()->addHours(2));

// 添加到黑名单
security_add_to_blacklist('10.0.0.100', '恶意攻击', now()->addWeek());

// 添加IP段
security_add_to_blacklist('10.0.0.0/24', '僵尸网络');
```

#### 从黑白名单移除IP

```php
use zxf\Security\Models\SecurityIp;

// 从黑名单移除
SecurityIp::removeFromBlacklist('10.0.0.100');

// 从白名单移除
SecurityIp::removeFromWhitelist('192.168.1.100');
```

#### 获取IP统计信息

```php
use function zxf\Security\security_get_ip_stats;

$stats = security_get_ip_stats('192.168.1.1');
print_r($stats);
// 输出:
// [
//     'ip_address' => '192.168.1.1',
//     'type' => 'monitoring',
//     'threat_score' => 25.50,
//     'request_count' => 1000,
//     'blocked_count' => 5,
//     'success_count' => 995,
//     // ...
// ]
```

#### 获取高威胁IP列表

```php
use function zxf\Security\security_get_high_threat_ips;

// 获取威胁评分最高的100个IP
$threatIps = security_get_high_threat_ips(100);

foreach ($threatIps as $ip) {
    echo "IP: {$ip['ip_address']}, 威胁评分: {$ip['threat_score']}\n";
}
```

### 速率限制

#### 检查速率限制

```php
use function zxf\Security\security_check_rate_limit;

// 检查当前IP速率限制
$result = security_check_rate_limit($request->ip());

if ($result['blocked']) {
    // 被限流
    $window = $result['window']; // 触发的时间窗口
    $retryAfter = $result['retry_after']; // 重试时间（秒）
    
    return response()->json([
        'error' => '请求过于频繁',
        'retry_after' => $retryAfter
    ], 429);
}
```

#### 增加速率限制计数器

```php
use function zxf\Security\security_increment_rate_limit;

// 请求处理成功后增加计数器
security_increment_rate_limit($request->ip());
```

#### 清除速率限制

```php
use function zxf\Security\security_clear_rate_limit;

// 清除IP的速率限制
security_clear_rate_limit($request->ip());
```

### 威胁检测

```php
use Illuminate\Http\Request;
use function zxf\Security\security_detect_threat;

// 检测请求威胁
$threatResult = security_detect_threat($request);

if ($threatResult['has_sql_injection']) {
    Log::warning('检测到SQL注入尝试');
}

if ($threatResult['has_xss_attack']) {
    Log::warning('检测到XSS攻击尝试');
}

if ($threatResult['has_command_injection']) {
    Log::warning('检测到命令注入尝试');
}
```

### 缓存管理

```php
use function zxf\Security\{clean_security_cache, get_all_cache_keys};

// 获取所有security:前缀的缓存键
$keys = get_all_cache_keys('security:');

// 清除所有安全缓存
clean_security_cache();
```

### 安全日志

```php
use function zxf\Security\security_log_event;

// 记录安全事件
security_log_event('检测到异常请求', 'warning', [
    'ip' => $request->ip(),
    'path' => $request->path(),
    'user_agent' => $request->userAgent(),
]);

// 记录安全错误
security_log_event('安全中间件异常', 'error', [
    'exception' => $e->getMessage(),
]);
```

---

## 🔧 API文档

### 辅助函数列表

| 函数名 | 说明 | 返回值 |
|-------|------|--------|
| `security_config(?string $key, mixed $default)` | 获取安全配置 | mixed |
| `security_is_whitelisted(string $ip)` | 检查IP是否在白名单 | bool |
| `security_is_blacklisted(string $ip)` | 检查IP是否在黑名单 | bool |
| `security_record_access(string $ip, bool $blocked, ?string $rule)` | 记录IP访问 | array\|null |
| `security_add_to_whitelist(string $ip, string $reason, ?DateTime $expiresAt)` | 添加IP到白名单 | bool |
| `security_add_to_blacklist(string $ip, string $reason, ?DateTime $expiresAt, bool $autoDetected)` | 添加IP到黑名单 | bool |
| `security_get_ip_stats(string $ip)` | 获取IP统计信息 | array |
| `security_get_high_threat_ips(int $limit)` | 获取高威胁IP列表 | array |
| `security_cleanup_expired()` | 清理过期IP记录 | int |
| `security_log_event(string $message, string $level, array $context, ?Request $request)` | 记录安全事件 | void |
| `security_check_rate_limit(string $identifier, array $limits)` | 检查速率限制 | array |
| `security_increment_rate_limit(string $identifier)` | 增加速率限制计数器 | void |
| `security_clear_rate_limit(string $identifier)` | 清除速率限制计数器 | void |
| `security_detect_threat(Request $request)` | 检测请求威胁 | array |
| `security_response(string $type, string $message, array $context, int $statusCode, array $errors, ?Request $request)` | 创建安全响应 | Response\|JsonResponse |
| `clean_security_cache()` | 清除所有安全缓存 | bool |
| `get_all_cache_keys(string $prefix, ?int $maxSize, bool $removePrefix)` | 获取缓存键列表 | array |
| `is_intranet_ip(string $ip, array $opt)` | 检查IP是否为内网IP | bool |

### SecurityIp 模型方法

```php
// 静态方法
SecurityIp::isWhitelisted(string $ip): bool
SecurityIp::isBlacklisted(string $ip): bool
SecurityIp::removeFromBlacklist(string $ip): bool
SecurityIp::removeFromWhitelist(string $ip): bool
SecurityIp::batchCheck(array $ips): array
SecurityIp::recordRequest(string $ip, bool $blocked, ?string $rule): ?self
SecurityIp::batchRecordRequests(array $records): int
SecurityIp::cleanupExpired(): int
SecurityIp::getHighThreatIps(int $limit): Collection
SecurityIp::getIpStats(string $ip): array
SecurityIp::addToWhitelist(string $ip, string $reason, ?DateTimeInterface $expiresAt): self
SecurityIp::addToBlacklist(string $ip, string $reason, ?DateTimeInterface $expiresAt, bool $autoDetected): self
SecurityIp::addToSuspicious(string $ip, string $reason, ?DateTimeInterface $expiresAt, bool $autoDetected): self

// 实例方法
$ip->checkAndUpdateType(): void
$ip->applyNaturalDecay(): void
```

### RateLimiterService 方法

```php
// 检查速率限制
$rateLimiter->check(Request $request): array

// 批量检查
$rateLimiter->batchCheck(array $fingerprints): array

// 获取客户端速率信息
$rateLimiter->getClientRateInfo(Request $request): array

// 重置客户端速率限制
$rateLimiter->resetClientRateLimit(Request $request): bool

// 获取统计信息
$rateLimiter->getRateLimitStats(): array

// 清除缓存
$rateLimiter->clearCache(): void
$rateLimiter->clearFingerprint(string $fingerprint): void
$rateLimiter->clearIpRateLimit(string $ip): void
```

---

## 🚀 性能优化

### 文件缓存策略

本扩展包采用文件缓存+内存缓存的双重策略，无需Redis即可实现高性能：

1. **内存缓存（请求级）**: 每个请求周期的首次查询结果会被缓存
2. **文件缓存（应用级）**: 使用Laravel文件缓存持久化数据
3. **智能预热**: 常用数据自动预热到内存

### 批量写入优化

```php
// 不推荐：逐条记录
foreach ($requests as $req) {
    SecurityIp::recordRequest($req['ip'], $req['blocked']);
}

// 推荐：批量记录
SecurityIp::batchRecordRequests($requests);
```

### 采样机制

```php
// 配置采样（只记录被拦截的，正常请求10%采样）
'ip_auto_detection' => [
    'record_normal_visitor' => false, // 不记录正常访客
],

// 采样会自动应用，无需额外代码
SecurityIp::recordRequest($ip, false); // 只采样10%
```

### 缓存TTL调优

```php
// 高流量场景：降低TTL，提升实时性
'cache_ttl' => 60, // 1分钟

// 低流量场景：提高TTL，降低数据库压力
'cache_ttl' => 600, // 10分钟
```

### 数据库优化建议

1. **添加索引**：
```sql
CREATE INDEX idx_ip_address ON security_ips(ip_address);
CREATE INDEX idx_type_status ON security_ips(type, status);
CREATE INDEX idx_threat_score ON security_ips(threat_score DESC);
```

2. **定期清理**：
```php
// 在定时任务中执行
$schedule->call(function () {
    security_cleanup_expired();
})->daily();
```

---

## 💡 最佳实践

### 1. 内网IP处理

```php
// 推荐配置：内网IP跳过速率限制，但保留黑名单检查
'intranet' => [
    'skip_rate_limit' => true,
    'skip_blacklist_check' => false,
],
```

### 2. 速率限制策略

```php
// 根据业务类型调整
'rate_limits' => [
    'minute' => 300,  // API接口可以更高
    'hour' => 5000,
    'day' => 50000,
],

// 使用更精确的指纹策略
'rate_limit_strategy' => 'ip_ua_path_method',
```

### 3. 威胁检测阈值

```php
// 生产环境建议：更严格的阈值
'blacklist_threshold' => 70.0, // 降低到70
'suspicious_threshold' => 40.0, // 降低到40
'max_triggers' => 3, // 降低到3
```

### 4. 日志记录

```php
// 生产环境：只记录警告和错误
'log_level' => 'warning',
'enable_debug_logging' => false,
'log_details' => false,

// 开发环境：记录详细信息
'log_level' => 'debug',
'enable_debug_logging' => true,
'log_details' => true,
```

### 5. 缓存清理

```php
// 定时清理缓存
$schedule->call(function () {
    clean_security_cache();
})->daily();

// 定时清理过期IP记录
$schedule->call(function () {
    security_cleanup_expired();
})->weekly();
```

---

## ❓ 常见问题

### 1. 如何禁用某个检查？

```php
// 在配置文件中设置
'defense_layers' => [
    'ip_whitelist' => true,
    'ip_blacklist' => true,
    'method_check' => false, // 禁用HTTP方法检查
    'user_agent_check' => false, // 禁用User-Agent检查
    'header_check' => false, // 禁用请求头检查
    'url_check' => true,
    'upload_check' => false, // 禁用文件上传检查
    'body_check' => true,
    'anomaly_check' => true,
    'rate_limit' => true,
    'sql_check' => true,
    'xss_check' => true,
    'command_check' => true,
    'custom_check' => true,
],
```

### 2. 如何自定义拦截响应？

```php
// 创建自定义响应函数
use function zxf\Security\security_response;

return security_response(
    'CustomRule',
    '自定义规则拦截',
    [
        'details' => '自定义详细信息',
    ],
    403,
    [],
    $request
);
```

### 3. 如何调试限流问题？

```php
// 启用调试日志
'enable_debug_logging' => true,

// 获取客户端速率信息
use zxf\Security\Services\RateLimiterService;

$rateLimiter = app(RateLimiterService::class);
$rateInfo = $rateLimiter->getClientRateInfo($request);

Log::info('速率限制信息', $rateInfo);
```

### 4. 如何处理误判？

```php
// 将误判IP添加到白名单
security_add_to_whitelist($ip, '误判解除');

// 或者降低威胁评分
$ip = SecurityIp::where('ip_address', $ip)->first();
if ($ip) {
    $ip->threat_score = 0;
    $ip->type = 'whitelist';
    $ip->save();
}
```

### 5. 性能调优建议？

- **缓存优先**: 确保`enable_ip_cache`和`enable_pattern_cache`开启
- **合理TTL**: 根据流量调整缓存时间
- **批量操作**: 使用`batchRecordRequests`替代多次`recordRequest`
- **采样启用**: 设置`record_normal_visitor=false`减少数据库写入
- **索引优化**: 为常用查询字段添加数据库索引

---

## 📝 更新日志

### v2.0.0 (2026-03-01)

#### 重大更新
- ✨ **移除Redis依赖**: 改用文件缓存+内存缓存双重策略
- ✨ **移除队列依赖**: 所有事件改为同步触发
- 🚀 **性能优化**: 批量写入和采样机制，降低数据库压力
- 🚀 **速率限制重构**: 使用文件锁保证原子性
- 📝 **完善文档**: 详细的中文注释和使用文档

#### 新增功能
- ✅ 内网IP识别和判断
- ✅ IP批量操作
- ✅ 采样机制（正常请求10%采样）
- ✅ 威胁评分自动衰减
- ✅ 批量清除缓存

#### 优化改进
- 🔄 重构RateLimiterService，移除所有Redis代码
- 🔄 重构Event类，移除队列trait
- 🔄 优化get_all_cache_keys函数，支持文件缓存
- 🔄 优化SecurityIp模型，添加批量写入
- 🔄 完善所有服务类的中文注释

#### Bug修复
- 🐛 修复并发场景下的计数器问题
- 🐛 修复缓存失效时的降级策略
- 🐛 修复IP类型自动转换的bug

---

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

### 贡献流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 遵循 PSR-12 编码规范
- 所有类和方法添加PHPDoc注释
- 使用类型提示（PHP 8.2+）
- 编写单元测试

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 📮 联系我们

- 作者: zxf
- Email: [您的邮箱]
- Issues: [GitHub Issues](https://github.com/yourusername/security/issues)
- 文档: [完整文档](https://github.com/yourusername/security/wiki)

---

## 🙏 致谢

感谢所有为本项目做出贡献的开发者！

---

<div align="center">

**如果觉得这个项目对您有帮助，请给我们一个 ⭐️ Star**

Made with ❤️ by zxf

</div>
