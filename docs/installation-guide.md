# 安装配置指南

本文档详细介绍 `zxf/security` 包的安装和配置步骤，帮助您快速部署安全防护系统。

## 目录

- [环境要求](#环境要求)
- [安装步骤](#安装步骤)
- [基础配置](#基础配置)
- [缓存配置](#缓存配置)
- [性能优化配置](#性能优化配置)
- [验证安装](#验证安装)
- [常见问题](#常见问题)

---

## 环境要求

### 必需环境

- **PHP**: 8.2 或更高版本
- **Laravel**: 11.0 或更高版本
- **数据库**: MySQL 5.7+ / PostgreSQL 9.6+ / SQLite 3.8+
- **文件系统**: 支持读写操作，推荐SSD存储

### PHP扩展要求

```bash
# 必需扩展
- mbstring      # 字符串处理
- filter        # 输入过滤
- json          # JSON处理
- pdo           # 数据库连接

# 推荐扩展
- opcache       # 字节码缓存（大幅提升性能）
- fileinfo      # 文件类型检测
```

### 检查命令

```bash
# 检查PHP版本
php -v

# 检查扩展
php -m | grep -E 'mbstring|filter|json|pdo'

# 检查Laravel版本
cd your-project && php artisan --version
```

---

## 安装步骤

### 1. 通过Composer安装

```bash
# 进入项目目录
cd your-laravel-project

# 安装包
composer require zxf/security

# 或安装特定版本
composer require zxf/security:^3.0
```

### 2. 发布配置文件

```bash
# 发布配置文件
php artisan vendor:publish --provider="zxf\Security\Providers\SecurityServiceProvider"

# 确认输出
# Copied File [/vendor/zxf/security/config/security.php] To [/config/security.php]
```

### 3. 运行数据库迁移

```bash
# 运行迁移
php artisan migrate

# 如果已经有表，可以强制重新创建（会丢失数据）
php artisan migrate:fresh --path=vendor/zxf/security/src/Database/Migrations

# 查看迁移状态
php artisan migrate:status
```

### 4. 创建缓存目录（文件缓存模式）

```bash
# 创建缓存目录
mkdir -p storage/security-cache

# 设置权限
chmod 755 storage/security-cache
chown www-data:www-data storage/security-cache  # 根据实际用户调整

# 测试写入
touch storage/security-cache/.test
cat storage/security-cache/.test
rm storage/security-cache/.test
```

---

## 基础配置

### 环境变量配置

在 `.env` 文件中添加以下配置：

```env
# ==================== 基础配置 ====================

# 是否启用安全中间件
SECURITY_MIDDLEWARE_ENABLED=true

# 启用方式: global(全局) | route(路由)
SECURITY_MIDDLEWARE_TYPE=global

# 是否忽略本地请求（开发环境可设为true）
SECURITY_IGNORE_LOCAL=false

# 日志级别: debug | info | warning | error
SECURITY_LOG_LEVEL=warning

# 是否启用调试日志（生产环境设为false）
SECURITY_DEBUG_LOGGING=false

# 是否记录详细信息
SECURITY_LOG_DETAILS=false
```

### 中间件注册

#### Laravel 11+ (推荐)

编辑 `bootstrap/app.php`：

```php
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // 添加安全中间件（全局）
        $middleware->append(\zxf\Security\Middleware\SecurityMiddleware::class);
        
        // 或者添加到web组
        // $middleware->web(append: [
        //     \zxf\Security\Middleware\SecurityMiddleware::class,
        // ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
```

#### Laravel 10 及以下版本

编辑 `app/Http/Kernel.php`：

```php
protected $middleware = [
    // ...其他中间件
    \Illuminate\Foundation\Http\Middleware\ValidatePostSize::class,
    \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,
    
    // 添加安全中间件
    \zxf\Security\Middleware\SecurityMiddleware::class,
];

// 或者添加到路由中间件组
protected $middlewareGroups = [
    'web' => [
        // ...
        \zxf\Security\Middleware\SecurityMiddleware::class,
    ],
];
```

### 路由配置

如果 `enabled_type` 设置为 `route`，可以在路由中指定：

```php
// routes/web.php

// 应用安全中间件到所有路由
Route::middleware(['security'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
    Route::get('/profile', [ProfileController::class, 'show']);
});

// 只应用到特定路由
Route::get('/admin', [AdminController::class, 'index'])
    ->middleware('security');

// 排除某些路由
Route::withoutMiddleware([\zxf\Security\Middleware\SecurityMiddleware::class])
    ->group(function () {
        Route::get('/webhook', [WebhookController::class, 'handle']);
    });
```

---

## 缓存配置

### 选择缓存驱动

本包提供三种缓存驱动，根据您的需求选择：

#### 1. 文件缓存（推荐，零依赖）

```env
SECURITY_CACHE_DRIVER=file
SECURITY_FILE_CACHE_PATH=/path/to/your/storage/security-cache
SECURITY_FILE_CACHE_AUTO_CLEANUP=true
```

**适用场景：**
- 无Redis环境的项目
- 中小型应用
- 需要简单部署的项目
- 降低运维成本

**优点：**
- 零外部依赖
- 自动目录分片
- LRU内存缓冲
- 原子性写入

#### 2. Laravel缓存

```env
SECURITY_CACHE_DRIVER=laravel
```

使用Laravel配置中的缓存驱动（默认是文件缓存）。

**适用场景：**
- 已经配置了Redis的项目
- 需要分布式缓存的项目

#### 3. 自动选择

```env
SECURITY_CACHE_DRIVER=auto
```

自动检测并使用最佳可用驱动。

### 缓存TTL配置

```env
# 默认缓存时间（秒）
SECURITY_CACHE_TTL=300

# 不同类型数据的TTL
# IP缓存：5分钟
# 速率限制：根据窗口自动设置
# 配置缓存：1小时
```

### 缓存目录权限

```bash
# 确保Web服务器用户有读写权限
sudo chown -R www-data:www-data storage/security-cache
sudo chmod -R 755 storage/security-cache

# SELinux环境（如果需要）
sudo chcon -R -t httpd_sys_rw_content_t storage/security-cache
```

---

## 性能优化配置

### 启用所有优化（生产环境推荐）

```env
# ==================== 性能优化配置 ====================

# 启用延迟写入（减少数据库IO 90%+）
SECURITY_DEFERRED_WRITE=true

# 延迟写入队列阈值
SECURITY_DEFERRED_WRITE_THRESHOLD=50

# 启用滑动窗口算法（平滑流量控制）
SECURITY_SLIDING_WINDOW=true

# 滑动窗口分片数
SECURITY_SLIDING_SUBDIVISIONS=6

# 启用配置预加载（减少80%配置读取开销）
SECURITY_CONFIG_PRELOAD=true

# 启用异步处理（需要配置队列）
SECURITY_ASYNC_PROCESSING=true
```

### 速率限制配置

```env
# ==================== 速率限制配置 ====================

# 是否启用速率限制
SECURITY_RATE_LIMITING_ENABLED=true

# 时间窗口阈值
SECURITY_MAX_REQUESTS_PER_MINUTE=300
SECURITY_MAX_REQUESTS_PER_HOUR=10000
SECURITY_MAX_REQUESTS_PER_DAY=100000

# 指纹策略
# ip_only | ip_ua | ip_ua_path | ip_ua_path_method | custom
SECURITY_RATE_LIMIT_STRATEGY=ip_ua_path
```

### IP自动检测配置

```env
# ==================== IP自动检测配置 ====================

# 是否启用自动检测
SECURITY_IP_AUTO_DETECTION=true

# 是否记录正常访客（false=只记录被拦截的）
SECURITY_RECORD_NORMAL_VISITOR=false

# 黑名单转换阈值（威胁评分>=此值转为黑名单）
SECURITY_BLACKLIST_THRESHOLD=80.0

# 可疑IP转换阈值（威胁评分>=此值转为可疑）
SECURITY_SUSPICIOUS_THRESHOLD=50.0

# 最大触发规则次数
SECURITY_MAX_TRIGGERS=5

# 每次拦截增加威胁评分
SECURITY_ADD_THREAT_SCORE=10.00

# 每次成功请求降低威胁评分
SECURITY_REDUCE_THREAT_SCORE=1.00

# 威胁评分自然衰减（每小时）
SECURITY_DECAY_RATE_PER_HOUR=0.3

# 自动清理过期记录
SECURITY_AUTO_CLEANUP=true

# 监控IP自动过期时间（天）
SECURITY_MONITORING_EXPIRE_DAYS=15
```

### 内网IP配置

```env
# ==================== 内网IP配置 ====================

# 是否启用内网IP判断缓存
SECURITY_INTRANET_ENABLE_CACHE=true

# 缓存时间（秒）
SECURITY_INTRANET_CACHE_TTL=300

# 内网IP是否跳过速率限制
SECURITY_INTRANET_SKIP_RATE_LIMIT=true

# 内网IP是否跳过黑名单检查
SECURITY_INTRANET_SKIP_BLACKLIST=false
```

---

## 验证安装

### 1. 检查配置

```bash
# 查看配置是否加载
php artisan tinker

# 在tinker中执行
>>> security_config('enabled')
=> true

>>> security_config('cache_driver')
=> "file"
```

### 2. 测试IP管理

```php
// 在tinker中测试
use zxf\Security\Models\SecurityIp;

// 添加测试IP到黑名单
SecurityIp::addToBlacklist('10.0.0.1', '测试', null, false);

// 检查IP是否在黑名单
SecurityIp::isBlacklisted('10.0.0.1');

// 查看IP记录
SecurityIp::where('ip_address', '10.0.0.1')->first();

// 清理测试数据
SecurityIp::where('ip_address', '10.0.0.1')->delete();
```

### 3. 测试缓存

```php
// 测试缓存系统
$cache = security_cache();

// 设置缓存
$cache->set('test_key', 'test_value', 60);

// 获取缓存
$value = $cache->get('test_key');
echo $value; // test_value

// 查看缓存统计
$stats = security_cache_stats();
print_r($stats);

// 清理
$cache->delete('test_key');
```

### 4. 测试速率限制

```php
// 创建测试请求
$request = new \Illuminate\Http\Request();
$request->setTrustedProxies([], \Illuminate\Http\Request::HEADER_X_FORWARDED_FOR);
$request->server->set('REMOTE_ADDR', '127.0.0.1');

// 获取速率限制服务
$rateLimiter = app(\zxf\Security\Services\RateLimiterService::class);

// 检查速率限制
$result = $rateLimiter->check($request);
print_r($result);
```

### 5. 查看日志

```bash
# 查看Laravel日志
tail -f storage/logs/laravel.log | grep security

# 查看特定日志
grep "security" storage/logs/laravel.log
```

---

## 常见问题

### Q: 安装后中间件没有生效？

**A:** 请检查以下几点：

```bash
# 1. 清除配置缓存
php artisan config:clear

# 2. 检查中间件是否正确注册
php artisan route:list --middleware

# 3. 检查配置是否加载
grep "SECURITY_MIDDLEWARE_ENABLED" .env

# 4. 检查日志
# 查看是否有安全相关的日志记录
```

### Q: 文件缓存权限错误？

**A:** 检查并修复权限：

```bash
# 1. 创建目录
mkdir -p storage/security-cache

# 2. 设置权限
chmod 755 storage/security-cache

# 3. 设置正确的用户
# 找出Web服务器用户
ps aux | grep nginx  # 或 apache

# 4. 更改所有权
sudo chown -R www-data:www-data storage/security-cache

# 5. 测试写入
sudo -u www-data touch storage/security-cache/test
```

### Q: 数据库迁移失败？

**A:** 常见问题和解决方案：

```bash
# 1. 检查数据库连接
php artisan tinker
>>> DB::connection()->getPdo();

# 2. 如果表已存在，先回滚
php artisan migrate:rollback --path=vendor/zxf/security/src/Database/Migrations

# 3. 手动删除表后重新迁移
# DROP TABLE IF EXISTS security_ips;
php artisan migrate --path=vendor/zxf/security/src/Database/Migrations

# 4. 检查迁移状态
php artisan migrate:status
```

### Q: 如何完全卸载？

**A:** 卸载步骤：

```bash
# 1. 移除中间件注册
# 编辑 bootstrap/app.php 或 app/Http/Kernel.php
# 删除 SecurityMiddleware::class

# 2. 回滚迁移
php artisan migrate:rollback --path=vendor/zxf/security/src/Database/Migrations

# 3. 删除配置文件
rm config/security.php

# 4. 删除包
composer remove zxf/security

# 5. 清理缓存
php artisan config:clear
php artisan cache:clear

# 6. 删除缓存目录
rm -rf storage/security-cache
```

### Q: 如何备份安全数据？

**A:** 备份和恢复：

```bash
# 备份数据库表
mysqldump -u root -p your_database security_ips > security_ips_backup.sql

# 备份缓存文件
tar -czf security-cache-backup.tar.gz storage/security-cache

# 恢复数据库
mysql -u root -p your_database < security_ips_backup.sql

# 恢复缓存
tar -xzf security-cache-backup.tar.gz
```

---

## 下一步

安装完成后，建议：

1. **阅读完整文档**: [README.md](../README.md)
2. **查看API文档**: 了解所有可用的辅助函数和API
3. **配置定时任务**: 设置自动清理和维护
4. **监控性能**: 使用 `SecurityMonitor` 监控安全状态
5. **优化数据库**: 参考 [database-optimization.md](database-optimization.md)

---

## 获取帮助

- **GitHub Issues**: [报告问题](https://github.com/yourusername/security/issues)
- **文档**: [完整文档](../README.md)
- **更新日志**: [CHANGELOG](../CHANGELOG.md)
