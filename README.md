# zxf/security - Laravel 11+ & PHP 8.2+ 现代化安全扩展包

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![PHP](https://img.shields.io/badge/php-8.2+-8892bf)
![Laravel](https://img.shields.io/badge/laravel-11+-ff2d20)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

**企业级Web安全防护中间件 - 零外部依赖的现代化解决方案**

</div>

---

## 📖 目录

- [项目简介](#项目简介)
- [架构设计](#架构设计)
- [核心特性](#核心特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [目录结构](#目录结构)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
- [API文档](#api文档)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)
- [故障排查](#故障排查)
- [常见问题](#常见问题)
- [更新日志](#更新日志)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

---

## 🎯 项目简介

`zxf/security` 是一款基于 Laravel 11+ 和 PHP 8.2+ 开发的企业级Web安全防护中间件。它提供了全方位的Web应用安全防护能力，包括IP黑白名单管理、速率限制、威胁检测、异常行为分析等核心功能。

### 设计理念

- **零外部依赖**: 仅需PHP 8.2+和Laravel 11+，无需Redis、Memcached等外部服务
- **高性能**: 独立文件缓存、批量操作、延迟写入、智能缓存，最小化数据库IO
- **易用性**: 开箱即用，配置简单，丰富的辅助函数，完善的中文文档
- **可扩展**: 模块化设计，支持自定义检测规则和处理逻辑
- **工业化**: 完善的日志、监控、统计，满足企业级运维需求

### 版本 3.0 新特性

- 🚀 **独立文件缓存**: 全新独立的文件缓存驱动，彻底摆脱Redis依赖
- 🚀 **延迟写入**: IP记录批量延迟写入，数据库IO减少90%+
- 🚀 **滑动窗口限流**: 精确控制流量突发，避免临界问题
- 🚀 **配置预加载**: 启动时预加载高频配置，减少运行时开销
- 🚀 **异步处理支持**: 耗时操作支持队列异步处理
- 🚀 **监控仪表板**: 实时监控安全状态和性能指标

---

## 🏗️ 架构设计

### 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层 (Application)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Web路由    │  │   API路由    │  │      自定义控制器        │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
└─────────┼────────────────┼─────────────────────┼───────────────┘
          │                │                     │
          └────────────────┴──────────┬──────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────┐
│                    中间件层 (SecurityMiddleware)                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  1. IP白名单检查 → 2. IP黑名单检查 → 3. 速率限制检查      │  │
│  │  4. SQL注入检测 → 5. XSS检测 → 6. 命令注入检测           │  │
│  │  7. 文件上传检查 → 8. 异常行为分析 → 9. 威胁评分         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    服务层 (Services)                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐    │
│  │ IpManager    │ │ RateLimiter  │ │ ThreatDetection      │    │
│  │ IP管理服务    │ │ 速率限制服务  │ │ 威胁检测服务          │    │
│  └──────────────┘ └──────────────┘ └──────────────────────┘    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐    │
│  │ ConfigManager│ │ SecurityCache│ │ SecurityMonitor      │    │
│  │ 配置管理服务  │ │ 缓存管理服务  │ │ 监控服务              │    │
│  └──────────────┘ └──────────────┘ └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    数据层 (Data Layer)                           │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │  SecurityIp    │  │  CacheAdapter  │  │   AsyncQueue     │   │
│  │   Eloquent模型  │  │   缓存适配器    │  │   异步队列        │   │
│  │   (MySQL/PG)   │  │  File/Redis    │  │   (可选)         │   │
│  └────────────────┘  └────────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 核心组件说明

| 组件 | 职责 | 关键技术 |
|-----|------|---------|
| **SecurityMiddleware** | 统一入口，协调各安全检查 | 责任链模式、异常处理 |
| **IpManagerService** | IP黑白名单管理、威胁评分 | 四级缓存、批量操作 |
| **RateLimiterService** | 滑动窗口速率限制 | 滑动窗口算法、计数器聚合 |
| **ThreatDetectionService** | SQL/XSS/命令注入检测 | 正则表达式、模式匹配 |
| **ConfigManager** | 配置管理和动态加载 | 预加载、缓存策略 |
| **CacheAdapter** | 统一缓存接口 | 适配器模式、文件缓存 |
| **SecurityMonitor** | 监控和统计 | 数据聚合、健康检查 |

### 缓存架构

```
┌─────────────────────────────────────────────────────────────┐
│                      四级缓存策略                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    最快，请求级                        │
│  │  Request Cache  │    零开销，自动清理                     │
│  │  (内存数组)      │                                        │
│  └────────┬────────┘                                        │
│           │                                                 │
│  ┌────────▼────────┐    进程级                              │
│  │  Static Cache   │    单次请求共享                        │
│  │  (静态变量)      │                                        │
│  └────────┬────────┘                                        │
│           │                                                 │
│  ┌────────▼────────┐    应用级                              │
│  │  Memory Buffer  │    LRU淘汰策略                         │
│  │  (文件缓存内存层)│                                        │
│  └────────┬────────┘                                        │
│           │                                                 │
│  ┌────────▼────────┐    持久化                              │
│  │  File Storage   │    原子写入，自动清理                   │
│  │  (文件系统)      │                                        │
│  └─────────────────┘                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ 核心特性

### 🔒 全方位安全防护

| 功能特性 | 说明 | 状态 | 配置键 |
|---------|------|------|--------|
| **IP白名单** | 支持IPv4/IPv6及CIDR段，优先放行 | ✅ | `defense_layers.ip_whitelist` |
| **IP黑名单** | 智能黑名单管理，支持临时封禁 | ✅ | `defense_layers.ip_blacklist` |
| **智能速率限制** | 滑动窗口算法，多时间窗口限流 | ✅ | `defense_layers.rate_limit` |
| **SQL注入检测** | 正则表达式深度检测，覆盖常见攻击 | ✅ | `defense_layers.sql_check` |
| **XSS攻击防护** | 跨站脚本攻击检测，过滤危险字符 | ✅ | `defense_layers.xss_check` |
| **命令注入防护** | 系统命令注入检测，阻止危险命令 | ✅ | `defense_layers.command_check` |
| **文件上传检查** | 文件类型、大小、内容扫描 | ✅ | `defense_layers.upload_check` |
| **异常行为分析** | 参数异常、请求异常检测 | ✅ | `defense_layers.anomaly_check` |
| **威胁评分系统** | 自动IP类型转换和评分，0-100分 | ✅ | `ip_auto_detection.*` |
| **内网IP识别** | 完整的内网IP判断逻辑，支持自定义 | ✅ | `intranet.*` |

### ⚡ 高性能优化

| 优化技术 | 效果 | 适用场景 | 配置方法 |
|---------|------|---------|---------|
| **独立文件缓存** | 无需Redis，自动目录分片 | 所有场景 | `cache_driver=file` |
| **请求级内存缓存** | 零数据库查询 | 高频IP检查 | 自动启用 |
| **延迟写入队列** | IO减少90%+ | 高并发记录 | `enable_deferred_write=true` |
| **滑动窗口算法** | 平滑流量控制 | 速率限制 | `enable_sliding_window=true` |
| **批量操作** | 单次处理多条记录 | 批量导入 | `batchRecordRequests()` |
| **配置预加载** | 减少80%配置读取开销 | 启动优化 | `enable_config_preload=true` |
| **LRU缓存清理** | 防止内存泄漏 | 长期运行 | 自动管理 |
| **缓存预热** | 预加载热点数据 | 启动时 | `warmupCache()` |

### 🛠️ 开发友好

- **丰富的辅助函数**: 60+个全局辅助函数
- **详细中文注释**: 所有类和方法都有完整中文说明
- **完善的文档**: README、API文档、配置说明、使用指南、故障排查
- **类型安全**: 完整的PHP 8.2+类型提示
- **异常处理**: 优雅的异常处理和降级策略
- **事件系统**: 支持监听安全事件进行自定义处理

---

## 📦 系统要求

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

### 可选依赖

以下依赖是可选的，不安装不会影响核心功能：

| 依赖 | 用途 | 是否推荐 |
|-----|------|---------|
| **Redis** | 分布式缓存、高速缓存 | 大型应用推荐 |
| **队列** | 异步处理耗时操作 | 高并发推荐 |
| **定时任务** | 自动清理过期数据 | 生产环境推荐 |

---

## 🚀 快速开始

### 1. 安装

```bash
composer require zxf/security
```

### 2. 发布配置文件

```bash
php artisan vendor:publish --provider="zxf\Security\Providers\SecurityServiceProvider"
```

### 3. 运行数据库迁移

```bash
php artisan migrate
```

### 4. 配置 `.env` 文件

```env
# ==================== 基础配置 ====================
SECURITY_MIDDLEWARE_ENABLED=true
SECURITY_MIDDLEWARE_TYPE=global

# ==================== 缓存配置 ====================
SECURITY_CACHE_DRIVER=file
SECURITY_CACHE_TTL=300
SECURITY_FILE_CACHE_AUTO_CLEANUP=true

# ==================== 性能优化 ====================
SECURITY_DEFERRED_WRITE=true
SECURITY_DEFERRED_WRITE_THRESHOLD=50
SECURITY_SLIDING_WINDOW=true
SECURITY_CONFIG_PRELOAD=true

# ==================== 速率限制 ====================
SECURITY_RATE_LIMITING_ENABLED=true
SECURITY_MAX_REQUESTS_PER_MINUTE=300
SECURITY_MAX_REQUESTS_PER_HOUR=10000
SECURITY_RATE_LIMIT_STRATEGY=ip_ua_path

# ==================== IP检测 ====================
SECURITY_IP_AUTO_DETECTION=true
SECURITY_RECORD_NORMAL_VISITOR=false
SECURITY_BLACKLIST_THRESHOLD=80.0
SECURITY_SUSPICIOUS_THRESHOLD=50.0
```

### 5. 注册中间件

#### Laravel 11+ (推荐)

编辑 `bootstrap/app.php`：

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\zxf\Security\Middleware\SecurityMiddleware::class);
})
```

#### Laravel 10 及以下版本

编辑 `app/Http/Kernel.php`：

```php
protected $middleware = [
    // ...其他中间件
    \zxf\Security\Middleware\SecurityMiddleware::class,
];
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

// 使用新的缓存API
security_cache()->set('key', $value, 300);
$value = security_cache()->get('key', 'default');
```

---

## 📁 目录结构

```
src/
├── Security/
│   ├── Cache/                      # 缓存相关
│   │   ├── CacheAdapter.php        # 缓存适配器
│   │   ├── FileCacheDriver.php     # 文件缓存驱动
│   │   └── SecurityCacheManager.php # 缓存管理器
│   │
│   ├── Console/                    # 命令行工具
│   │   └── Commands/
│   │       └── SecurityCleanupCommand.php  # 清理命令
│   │
│   ├── Constants/                  # 常量定义
│   │   └── SecurityEvent.php       # 安全事件常量
│   │
│   ├── Contracts/                  # 接口契约
│   │   └── CacheManagerInterface.php
│   │
│   ├── Database/                   # 数据库相关
│   │   └── Migrations/
│   │       └── 2025_01_01_000000_create_security_ips_table.php
│   │
│   ├── Exceptions/                 # 异常类
│   │   └── SecurityException.php
│   │
│   ├── Middleware/                 # 中间件
│   │   └── SecurityMiddleware.php  # 安全中间件（核心）
│   │
│   ├── Models/                     # 数据模型
│   │   └── SecurityIp.php          # IP管理模型
│   │
│   ├── Providers/                  # 服务提供者
│   │   └── SecurityServiceProvider.php
│   │
│   ├── Services/                   # 核心服务
│   │   ├── AsyncSecurityProcessor.php  # 异步处理器
│   │   ├── ConfigHotReloadService.php  # 配置热重载
│   │   ├── ConfigManager.php       # 配置管理
│   │   ├── IpManagerService.php    # IP管理服务
│   │   ├── RateLimiterService.php  # 速率限制服务
│   │   ├── RuleEngineService.php   # 规则引擎
│   │   ├── SecurityMonitor.php     # 监控服务
│   │   └── ThreatDetectionService.php  # 威胁检测
│   │
│   └── Utils/                      # 工具类
│       ├── ExceptionHandler.php    # 异常处理
│       └── IpHelper.php            # IP工具
│
├── helpers.php                     # 辅助函数
└── resources/                      # 资源文件
    └── views/                      # 视图模板
        └── security/               # 安全相关视图
            └── blocked.blade.php   # 拦截页面

config/
└── security.php                    # 配置文件

docs/
├── database-optimization.md        # 数据库优化指南
└── installation-guide.md           # 安装配置指南

tests/                              # 测试目录
├── Feature/                        # 功能测试
└── Unit/                           # 单元测试
```

---

## ⚙️ 配置说明

### 完整配置参考表

#### 基础配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `enabled` | `SECURITY_MIDDLEWARE_ENABLED` | bool | `true` | 是否启用安全中间件 |
| `enabled_type` | `SECURITY_MIDDLEWARE_TYPE` | string | `'global'` | 启用方式：global/route |
| `ignore_local` | `SECURITY_IGNORE_LOCAL` | bool | `false` | 是否忽略本地请求 |
| `log_level` | `SECURITY_LOG_LEVEL` | string | `'warning'` | 日志级别 |
| `enable_debug_logging` | `SECURITY_DEBUG_LOGGING` | bool | `false` | 调试日志 |
| `error_view` | - | string | `'security::blocked'` | 拦截页面视图 |

#### 缓存配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `cache_driver` | `SECURITY_CACHE_DRIVER` | string | `'file'` | 驱动：file/laravel/auto |
| `cache_prefix` | `SECURITY_CACHE_PREFIX` | string | `'security:'` | 缓存前缀 |
| `cache_ttl` | `SECURITY_CACHE_TTL` | int | `300` | 默认缓存时间（秒） |
| `file_cache_path` | `SECURITY_FILE_CACHE_PATH` | string | `storage_path('security-cache')` | 文件缓存路径 |
| `file_cache_auto_cleanup` | `SECURITY_FILE_CACHE_AUTO_CLEANUP` | bool | `true` | 自动清理 |

#### 速率限制配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `rate_limits.minute` | `SECURITY_MAX_REQUESTS_PER_MINUTE` | int | `300` | 每分钟最大请求数 |
| `rate_limits.hour` | `SECURITY_MAX_REQUESTS_PER_HOUR` | int | `10000` | 每小时最大请求数 |
| `rate_limits.day` | `SECURITY_MAX_REQUESTS_PER_DAY` | int | `100000` | 每天最大请求数 |
| `rate_limit_strategy` | `SECURITY_RATE_LIMIT_STRATEGY` | string | `'ip_ua_path'` | 指纹策略 |
| `enable_sliding_window` | `SECURITY_SLIDING_WINDOW` | bool | `true` | 启用滑动窗口 |
| `sliding_window_subdivisions` | `SECURITY_SLIDING_SUBDIVISIONS` | int | `6` | 滑动窗口分片数 |

#### IP自动检测配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `ip_auto_detection.enabled` | `SECURITY_IP_AUTO_DETECTION` | bool | `true` | 启用自动检测 |
| `ip_auto_detection.record_normal_visitor` | `SECURITY_RECORD_NORMAL_VISITOR` | bool | `false` | 记录正常访客 |
| `ip_auto_detection.blacklist_threshold` | `SECURITY_BLACKLIST_THRESHOLD` | float | `80.0` | 黑名单阈值 |
| `ip_auto_detection.suspicious_threshold` | `SECURITY_SUSPICIOUS_THRESHOLD` | float | `50.0` | 可疑IP阈值 |
| `ip_auto_detection.max_triggers` | `SECURITY_MAX_TRIGGERS` | int | `5` | 最大触发次数 |
| `ip_auto_detection.add_threat_score` | `SECURITY_ADD_THREAT_SCORE` | float | `10.0` | 拦截增加分数 |
| `ip_auto_detection.reduce_threat_score` | `SECURITY_REDUCE_THREAT_SCORE` | float | `1.0` | 成功减少分数 |
| `ip_auto_detection.decay_rate_per_hour` | `SECURITY_DECAY_RATE_PER_HOUR` | float | `0.3` | 每小时衰减率 |
| `ip_auto_detection.auto_cleanup` | `SECURITY_AUTO_CLEANUP` | bool | `true` | 自动清理 |
| `ip_auto_detection.monitoring_expire_days` | `SECURITY_MONITORING_EXPIRE_DAYS` | int | `15` | 监控IP过期天数 |

#### 内网IP配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `intranet.enable_cache` | `SECURITY_INTRANET_ENABLE_CACHE` | bool | `true` | 启用缓存 |
| `intranet.cache_ttl` | `SECURITY_INTRANET_CACHE_TTL` | int | `300` | 缓存TTL |
| `intranet.skip_rate_limit` | `SECURITY_INTRANET_SKIP_RATE_LIMIT` | bool | `false` | 跳过速率限制 |
| `intranet.skip_blacklist_check` | `SECURITY_INTRANET_SKIP_BLACKLIST` | bool | `false` | 跳过黑名单检查 |
| `intranet.check_loopback` | `SECURITY_INTRANET_CHECK_LOOPBACK` | bool | `true` | 检查回环地址 |
| `intranet.check_linklocal` | `SECURITY_INTRANET_CHECK_LINKLOCAL` | bool | `true` | 检查链路本地地址 |

#### 性能优化配置

| 配置项 | 环境变量 | 类型 | 默认值 | 说明 |
|--------|---------|------|--------|------|
| `enable_deferred_write` | `SECURITY_DEFERRED_WRITE` | bool | `true` | 启用延迟写入 |
| `deferred_write_threshold` | `SECURITY_DEFERRED_WRITE_THRESHOLD` | int | `50` | 延迟写入阈值 |
| `enable_config_preload` | `SECURITY_CONFIG_PRELOAD` | bool | `true` | 启用配置预加载 |
| `enable_async_processing` | `SECURITY_ASYNC_PROCESSING` | bool | `true` | 启用异步处理 |
| `max_recursion_depth` | `SECURITY_MAX_RECURSION_DEPTH` | int | `10` | 最大递归深度 |

#### 防御层配置

```php
'defense_layers' => [
    'ip_whitelist'       => true,   // IP白名单检查
    'ip_blacklist'       => true,   // IP黑名单检查
    'method_check'       => true,   // HTTP方法检查
    'user_agent_check'   => true,   // User-Agent检查
    'header_check'       => true,   // 请求头检查
    'url_check'          => true,   // URL检查
    'upload_check'       => true,   // 文件上传检查
    'body_check'         => true,   // 请求体检查
    'anomaly_check'      => true,   // 异常行为检查
    'rate_limit'         => true,   // 速率限制
    'sql_check'          => true,   // SQL注入检查
    'xss_check'          => true,   // XSS检查
    'command_check'      => true,   // 命令注入检查
    'custom_check'       => true,   // 自定义检查
],
```

### 配置文件示例

```php
<?php
// config/security.php

return [
    // 基础配置
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),
    'enabled_type' => env('SECURITY_MIDDLEWARE_TYPE', 'global'),
    'ignore_local' => env('SECURITY_IGNORE_LOCAL', false),
    
    // 缓存配置
    'cache_driver' => env('SECURITY_CACHE_DRIVER', 'file'),
    'cache_prefix' => env('SECURITY_CACHE_PREFIX', 'security:'),
    'cache_ttl' => env('SECURITY_CACHE_TTL', 300),
    'file_cache_path' => env('SECURITY_FILE_CACHE_PATH', storage_path('security-cache')),
    'file_cache_auto_cleanup' => env('SECURITY_FILE_CACHE_AUTO_CLEANUP', true),
    
    // 速率限制
    'rate_limits' => [
        'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 300),
        'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 10000),
        'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 100000),
    ],
    'rate_limit_strategy' => env('SECURITY_RATE_LIMIT_STRATEGY', 'ip_ua_path'),
    'enable_sliding_window' => env('SECURITY_SLIDING_WINDOW', true),
    'sliding_window_subdivisions' => env('SECURITY_SLIDING_SUBDIVISIONS', 6),
    
    // IP自动检测
    'ip_auto_detection' => [
        'enabled' => env('SECURITY_IP_AUTO_DETECTION', true),
        'record_normal_visitor' => env('SECURITY_RECORD_NORMAL_VISITOR', false),
        'blacklist_threshold' => env('SECURITY_BLACKLIST_THRESHOLD', 80.0),
        'suspicious_threshold' => env('SECURITY_SUSPICIOUS_THRESHOLD', 50.0),
        'max_triggers' => env('SECURITY_MAX_TRIGGERS', 5),
        'add_threat_score' => env('SECURITY_ADD_THREAT_SCORE', 10.0),
        'reduce_threat_score' => env('SECURITY_REDUCE_THREAT_SCORE', 1.0),
        'decay_rate_per_hour' => env('SECURITY_DECAY_RATE_PER_HOUR', 0.3),
        'auto_cleanup' => env('SECURITY_AUTO_CLEANUP', true),
        'monitoring_expire_days' => env('SECURITY_MONITORING_EXPIRE_DAYS', 15),
    ],
    
    // 内网IP
    'intranet' => [
        'enable_cache' => env('SECURITY_INTRANET_ENABLE_CACHE', true),
        'cache_ttl' => env('SECURITY_INTRANET_CACHE_TTL', 300),
        'skip_rate_limit' => env('SECURITY_INTRANET_SKIP_RATE_LIMIT', false),
        'skip_blacklist_check' => env('SECURITY_INTRANET_SKIP_BLACKLIST', false),
        'check_loopback' => env('SECURITY_INTRANET_CHECK_LOOPBACK', true),
        'check_linklocal' => env('SECURITY_INTRANET_CHECK_LINKLOCAL', true),
        'custom_ranges' => [],
    ],
    
    // 性能优化
    'enable_deferred_write' => env('SECURITY_DEFERRED_WRITE', true),
    'deferred_write_threshold' => env('SECURITY_DEFERRED_WRITE_THRESHOLD', 50),
    'enable_config_preload' => env('SECURITY_CONFIG_PRELOAD', true),
    'enable_async_processing' => env('SECURITY_ASYNC_PROCESSING', true),
    'max_recursion_depth' => env('SECURITY_MAX_RECURSION_DEPTH', 10),
    
    // 防御层
    'defense_layers' => [
        'ip_whitelist' => true,
        'ip_blacklist' => true,
        'method_check' => true,
        'user_agent_check' => true,
        'header_check' => true,
        'url_check' => true,
        'upload_check' => true,
        'body_check' => true,
        'anomaly_check' => true,
        'rate_limit' => true,
        'sql_check' => true,
        'xss_check' => true,
        'command_check' => true,
        'custom_check' => true,
    ],
];
```

---

## 📚 使用指南

### IP管理完整指南

#### 检查IP状态

```php
use zxf\Security\Models\SecurityIp;

// ========== 使用辅助函数（推荐）==========

// 检查IP是否在白名单
if (security_is_whitelisted('192.168.1.1')) {
    echo 'IP在白名单中，跳过安全检查';
}

// 检查IP是否在黑名单
if (security_is_blacklisted('10.0.0.1')) {
    echo 'IP在黑名单中，拒绝访问';
}

// ========== 使用模型（更灵活）==========

// 详细状态检查
$status = SecurityIp::batchCheck(['192.168.1.1', '10.0.0.1']);
// 返回: ['192.168.1.1' => 'whitelist', '10.0.0.1' => 'blacklist']

// 四级缓存检查（最高性能）
if (SecurityIp::isWhitelisted('192.168.1.1')) {
    // 使用四级缓存：请求级→静态级→内存级→文件级
}
```

#### 添加IP到白名单/黑名单

```php
// ========== 添加到白名单 ==========

// 永久添加到白名单
security_add_to_whitelist('192.168.1.100', '内部服务器');

// 临时添加到白名单（2小时后过期）
security_add_to_whitelist(
    '192.168.1.101', 
    '临时授权访问',
    now()->addHours(2)
);

// 使用模型（更多选项）
use zxf\Security\Models\SecurityIp;

SecurityIp::addToWhitelist(
    ip: '192.168.1.102',
    reason: 'API合作伙伴',
    expiresAt: now()->addMonth()
);

// ========== 添加到黑名单 ==========

// 简单添加
security_add_to_blacklist('10.0.0.100', '恶意攻击');

// 带过期时间
security_add_to_blacklist(
    '10.0.0.101',
    '暴力破解攻击',
    now()->addWeek()
);

// 添加IP段（CIDR格式）
security_add_to_blacklist('10.0.0.0/24', '僵尸网络IP段');

// 使用模型
SecurityIp::addToBlacklist(
    ip: '10.0.0.102',
    reason: 'SQL注入尝试',
    expiresAt: now()->addDays(7),
    autoDetected: true  // 标记为自动检测
);
```

#### 从黑白名单移除IP

```php
use zxf\Security\Models\SecurityIp;

// 从黑名单移除
SecurityIp::removeFromBlacklist('10.0.0.100');

// 从白名单移除
SecurityIp::removeFromWhitelist('192.168.1.100');

// 同时清理缓存
SecurityIp::clearIpCache('10.0.0.100');

// 清除速率限制
security_clear_rate_limit('10.0.0.100');
```

#### 获取IP统计信息

```php
// ========== 单个IP统计 ==========
$stats = security_get_ip_stats('192.168.1.1');

/*
返回示例:
[
    'ip_address' => '192.168.1.1',
    'type' => 'monitoring',
    'status' => 'active',
    'threat_score' => 25.50,
    'threat_level' => 'medium',  // critical/high/medium/low
    'request_count' => 1000,
    'blocked_count' => 5,
    'success_count' => 995,
    'trigger_count' => 2,
    'trigger_rules' => ['SQL_INJECTION', 'XSS_ATTACK'],
    'last_request_at' => '2026-04-06 12:30:00',
    'first_seen_at' => '2026-03-01 08:00:00',
    'last_activity_minutes' => 5,
]
*/

// ========== 批量获取（高效）==========
$ipManager = app(\zxf\Security\Services\IpManagerService::class);

$ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1'];
$batchStats = $ipManager->getIpStatsBatch($ips);

// ========== 缓存预热 ==========
// 预加载常用IP，后续检查零数据库查询
$commonIps = ['192.168.1.1', '10.0.0.1', '127.0.0.1'];
$ipManager->warmupCache($commonIps);

// ========== 查看缓存统计 ==========
$cacheStats = $ipManager->getCacheStats();
/*
[
    'hits' => 100,
    'misses' => 10,
    'hit_rate' => '90.9%',
    'request_cache_size' => 50
]
*/
```

#### 获取高威胁IP列表

```php
// 获取威胁评分最高的100个IP
$threatIps = security_get_high_threat_ips(100);

foreach ($threatIps as $ip) {
    printf(
        "IP: %s, 威胁评分: %.2f, 拦截次数: %d\n",
        $ip['ip_address'],
        $ip['threat_score'],
        $ip['blocked_count']
    );
}

// 使用模型查询
use zxf\Security\Models\SecurityIp;

// 获取可疑IP列表
$suspiciousIps = SecurityIp::getHighThreatIps(50);

// 自定义查询
$criticalIps = SecurityIp::where('threat_score', '>=', 80)
    ->where('type', 'suspicious')
    ->orderBy('threat_score', 'desc')
    ->get();
```

### 速率限制完整指南

#### 检查速率限制

```php
// 基础检查
$result = security_check_rate_limit($request->ip());

if ($result['blocked']) {
    return response()->json([
        'error' => '请求过于频繁',
        'retry_after' => $result['retry_after'],
        'window' => $result['window']
    ], 429);
}

// 详细检查
$rateLimiter = app(\zxf\Security\Services\RateLimiterService::class);
$checkResult = $rateLimiter->check($request);

/*
返回示例:
[
    'blocked' => true,
    'window' => 'minute',
    'limit' => 300,
    'remaining' => 0,
    'retry_after' => 45,
    'fingerprint' => '192.168.1.1|Mozilla/5.0|/api/users'
]
*/
```

#### 获取客户端速率信息

```php
$rateLimiter = app(\zxf\Security\Services\RateLimiterService::class);
$rateInfo = $rateLimiter->getClientRateInfo($request);

/*
返回示例:
[
    'fingerprint' => '192.168.1.1|Mozilla/5.0|/api/users',
    'limits' => [
        'minute' => ['limit' => 300, 'current' => 250, 'remaining' => 50],
        'hour' => ['limit' => 10000, 'current' => 1500, 'remaining' => 8500],
        'day' => ['limit' => 100000, 'current' => 8000, 'remaining' => 92000],
    ],
    'strategy' => 'ip_ua_path'
]
*/
```

#### 手动管理速率限制

```php
// 增加计数器（通常在请求处理后调用）
security_increment_rate_limit($request->ip());

// 清除速率限制（用于解除封禁）
security_clear_rate_limit($request->ip());

// 重置特定客户端的速率限制
$rateLimiter->resetClientRateLimit($request);

// 清除所有速率限制缓存
$rateLimiter->clearCache();
```

#### 滑动窗口统计

```php
$rateLimiter = app(\zxf\Security\Services\RateLimiterService::class);
$stats = $rateLimiter->getSlidingWindowStats();

/*
[
    'subdivisions' => 6,
    'buffer_size' => 10,
    'cache_size' => 50,
    'windows' => ['second', 'minute', 'hour', 'day']
]
*/
```

### 缓存操作完整指南

#### 使用安全缓存

```php
// 获取缓存实例
$cache = security_cache();

// ========== 基础操作 ==========

// 设置缓存（TTL单位为秒）
$cache->set('user:123:permissions', $permissions, 3600);

// 获取缓存
$permissions = $cache->get('user:123:permissions', []);

// 检查存在
if ($cache->has('user:123:permissions')) {
    // 缓存存在
}

// 删除缓存
$cache->delete('user:123:permissions');

// ========== 高级操作 ==========

// remember模式（原子操作）
$userData = $cache->remember('user:123:data', function () use ($userId) {
    return User::find($userId)->toArray();  //  expensive操作
}, 1800);  // 30分钟缓存

// 计数器操作
$cache->set('page:views:home', 0);
$newCount = $cache->increment('page:views:home');      // 1
$newCount = $cache->increment('page:views:home', 5);   // 6
$newCount = $cache->decrement('page:views:home');      // 5

// ========== 批量操作 ==========

// 批量获取
$keys = ['user:1', 'user:2', 'user:3'];
$values = $cache->many($keys);
// 返回: ['user:1' => {...}, 'user:2' => {...}, 'user:3' => {...}]

// 批量设置
$cache->setMany([
    'config:theme' => 'dark',
    'config:lang' => 'zh-CN',
    'config:timezone' => 'Asia/Shanghai'
], 86400);  // 24小时

// 批量删除
$cache->deleteMany(['cache:key1', 'cache:key2']);

// ========== 管理操作 ==========

// 获取所有缓存键
$keys = $cache->keys('user:');
// 返回: ['user:1', 'user:2', 'user:3', ...]

// 清除所有缓存
$cache->clear();

// 清理过期缓存（返回清理数量）
$cleaned = $cache->cleanupExpired();
echo "清理了 {$cleaned} 个过期缓存文件";
```

#### 缓存统计

```php
$stats = security_cache_stats();

/*
完整返回示例:
[
    'driver' => 'file',
    'prefix' => 'security:',
    'adapter_hits' => 1000,
    'adapter_misses' => 100,
    'adapter_writes' => 200,
    'adapter_deletes' => 50,
    'adapter_hit_rate' => '90.9%',
    'memory_buffer_size' => 500,
    'disk_size_bytes' => 5242880,
    'disk_size_mb' => 5.0,
    'file_count' => 1250,
    'cache_path' => '/var/www/storage/security-cache'
]
*/

// 启用详细统计
$cache->enableStats();

// 重置统计
$cache->resetStats();

// 禁用统计（减少开销）
$cache->disableStats();
```

### 威胁检测完整指南

#### 基础威胁检测

```php
use Illuminate\Http\Request;

// 检测请求威胁
$threatResult = security_detect_threat($request);

/*
返回示例:
[
    'blocked' => false,
    'is_resource_path' => false,
    'has_sql_injection' => false,
    'has_xss_attack' => false,
    'has_command_injection' => false,
    'has_malicious_request' => false,
    'has_anomalous_parameters' => false,
    'has_dangerous_uploads' => false,
    'has_suspicious_user_agent' => false,
    'has_suspicious_headers' => false,
    'is_safe_url' => true,
]
*/

// 根据检测结果处理
if ($threatResult['has_sql_injection']) {
    Log::warning('检测到SQL注入尝试', [
        'ip' => $request->ip(),
        'url' => $request->fullUrl()
    ]);
}

if ($threatResult['has_xss_attack']) {
    // XSS攻击处理
}
```

#### 使用威胁检测服务

```php
use zxf\Security\Services\ThreatDetectionService;

$detector = app(ThreatDetectionService::class);

// 检查SQL注入
if ($detector->hasSQLInjection($request)) {
    // SQL注入检测逻辑
}

// 检查XSS
if ($detector->hasXSSAttack($request)) {
    // XSS检测逻辑
}

// 检查命令注入
if ($detector->hasCommandInjection($request)) {
    // 命令注入检测逻辑
}

// 检查资源路径
if ($detector->isResourcePath($request)) {
    // 静态资源请求，可以跳过某些检查
}

// 检查恶意请求
if ($detector->isMaliciousRequest($request)) {
    // 恶意请求处理
}
```

### 监控仪表板完整指南

#### 获取仪表板数据

```php
use zxf\Security\Services\SecurityMonitor;

$monitor = app(SecurityMonitor::class);

// 获取完整仪表板
$dashboard = $monitor->getDashboard();

/*
返回示例:
[
    'summary' => [
        'total_ips_tracked' => 1500,
        'blacklisted_ips' => 50,
        'whitelisted_ips' => 20,
        'suspicious_ips' => 30,
        'monitoring_ips' => 1400,
    ],
    'recent_events' => [...],  // 最近事件
    'rate_limit_stats' => [...],  // 速率限制统计
    'threat_analysis' => [
        'sql_attacks' => 100,
        'xss_attacks' => 50,
        'command_attacks' => 20,
    ],
    'system_health' => [
        'status' => 'healthy',
        'services' => ['database' => true, 'cache' => true],
    ]
]
*/
```

#### 系统健康检查

```php
// 快速健康检查
if ($monitor->isHealthy()) {
    echo '系统运行正常';
}

// 详细健康状态
$health = $monitor->getSystemHealth();

/*
[
    'status' => 'healthy',  // healthy/degraded/unhealthy
    'services' => [
        'database' => true,
        'cache' => true,
        'rate_limiter' => true,
    ],
    'performance' => [
        'avg_response_time_ms' => 45,
        'requests_per_minute' => 1200,
    ],
    'issues' => []
]
*/

// 检查特定服务
$databaseOk = $monitor->checkService('database');
$cacheOk = $monitor->checkService('cache');
```

#### 性能指标

```php
// 获取性能指标
$metrics = $monitor->getPerformanceMetrics();

// 获取平均响应时间
$avgTime = $monitor->getAverageResponseTime();
echo "平均响应时间: {$avgTime}ms";

// 获取被拦截最多的IP
$topBlocked = $monitor->getTopBlockedIps(10);
```

### 安全日志完整指南

#### 记录安全事件

```php
use function zxf\Security\security_log_event;

// 基础日志
security_log_event('检测到异常请求', 'warning');

// 带上下文的日志
security_log_event('SQL注入尝试', 'warning', [
    'ip' => $request->ip(),
    'path' => $request->path(),
    'method' => $request->method(),
    'user_agent' => $request->userAgent(),
    'payload' => $request->all()
]);

// 错误日志
security_log_event('安全中间件异常', 'error', [
    'exception' => $e->getMessage(),
    'trace' => $e->getTraceAsString()
], $request);

// 信息日志
security_log_event('IP添加到黑名单', 'info', [
    'ip' => $ip,
    'reason' => $reason
]);
```

---

## 🔧 API文档

### 辅助函数完整列表

| 函数名 | 参数 | 返回值 | 说明 |
|--------|------|--------|------|
| `security_config(?string $key, mixed $default)` | `$key`: 配置键, `$default`: 默认值 | `mixed` | 获取安全配置 |
| `security_is_whitelisted(string $ip)` | `$ip`: IP地址 | `bool` | 检查IP是否在白名单 |
| `security_is_blacklisted(string $ip)` | `$ip`: IP地址 | `bool` | 检查IP是否在黑名单 |
| `security_record_access(string $ip, bool $blocked, ?string $rule)` | `$ip`, `$blocked`, `$rule` | `array\|null` | 记录IP访问 |
| `security_add_to_whitelist(string $ip, string $reason, ?DateTime $expiresAt)` | `$ip`, `$reason`, `$expiresAt` | `bool` | 添加IP到白名单 |
| `security_add_to_blacklist(string $ip, string $reason, ?DateTime $expiresAt, bool $autoDetected)` | `$ip`, `$reason`, `$expiresAt`, `$autoDetected` | `bool` | 添加IP到黑名单 |
| `security_get_ip_stats(string $ip)` | `$ip`: IP地址 | `array` | 获取IP统计信息 |
| `security_get_high_threat_ips(int $limit)` | `$limit`: 数量限制 | `array` | 获取高威胁IP列表 |
| `security_cleanup_expired()` | 无 | `int` | 清理过期IP记录 |
| `security_check_rate_limit(string $identifier, array $limits)` | `$identifier`, `$limits` | `array` | 检查速率限制 |
| `security_increment_rate_limit(string $identifier)` | `$identifier` | `void` | 增加速率限制计数器 |
| `security_clear_rate_limit(string $identifier)` | `$identifier` | `void` | 清除速率限制计数器 |
| `security_detect_threat(Request $request)` | `$request` | `array` | 检测请求威胁 |
| `security_response(string $type, string $message, array $context, int $statusCode, array $errors, ?Request $request)` | `$type`, `$message`, `$context`, `$statusCode`, `$errors`, `$request` | `Response\|JsonResponse` | 创建安全响应 |
| `security_cache()` | 无 | `CacheAdapter` | 获取安全缓存实例 |
| `security_cache_stats()` | 无 | `array` | 获取缓存统计 |
| `clean_security_cache()` | 无 | `bool` | 清除所有安全缓存 |
| `get_all_cache_keys(string $prefix, ?int $maxSize, bool $removePrefix)` | `$prefix`, `$maxSize`, `$removePrefix` | `array` | 获取缓存键列表 |
| `is_intranet_ip(string $ip, array $opt)` | `$ip`, `$opt` | `bool` | 检查IP是否为内网IP |
| `security_log_event(string $message, string $level, array $context, ?Request $request)` | `$message`, `$level`, `$context`, `$request` | `void` | 记录安全事件 |

### SecurityIp 模型方法

```php
// ========== 静态方法 - IP状态检查 ==========

/**
 * 检查IP是否在白名单中
 * 使用四级缓存策略，最高性能
 */
SecurityIp::isWhitelisted(string $ip): bool

/**
 * 检查IP是否在黑名单中
 * 使用四级缓存策略，最高性能
 */
SecurityIp::isBlacklisted(string $ip): bool

/**
 * 检查IP是否为可疑IP
 */
SecurityIp::isSuspicious(string $ip): bool

/**
 * 检查IP是否在监控中
 */
SecurityIp::isMonitored(string $ip): bool

/**
 * 批量检查IP状态
 * 单次查询，性能最优
 */
SecurityIp::batchCheck(array $ips): array

/**
 * 批量记录IP请求
 * 使用延迟写入，减少IO 90%+
 */
SecurityIp::batchRecordRequests(array $records): int

/**
 * 记录单个IP请求
 * 支持延迟写入模式
 */
SecurityIp::recordRequest(string $ip, bool $blocked = false, ?string $rule = null): ?self

// ========== 静态方法 - IP管理 ==========

SecurityIp::addToWhitelist(
    string $ip, 
    string $reason, 
    ?DateTimeInterface $expiresAt = null
): self

SecurityIp::addToBlacklist(
    string $ip, 
    string $reason, 
    ?DateTimeInterface $expiresAt = null, 
    bool $autoDetected = false
): self

SecurityIp::addToSuspicious(
    string $ip, 
    string $reason, 
    ?DateTimeInterface $expiresAt = null, 
    bool $autoDetected = false
): self

SecurityIp::removeFromBlacklist(string $ip): bool
SecurityIp::removeFromWhitelist(string $ip): bool

// ========== 静态方法 - 查询和统计 ==========

SecurityIp::getHighThreatIps(int $limit = 100): Collection
SecurityIp::getIpStats(string $ip): array
SecurityIp::cleanupExpired(): int

// ========== 静态方法 - 延迟写入管理 ==========

/**
 * 立即刷新延迟写入队列
 * 将队列中的数据批量写入数据库
 */
SecurityIp::flushDeferredWrites(): void

/**
 * 请求终止时调用
 * 自动刷新延迟写入队列并清理缓存
 */
SecurityIp::onRequestTerminate(): void

/**
 * 获取延迟写入统计信息
 */
SecurityIp::getDeferredWriteStats(): array

// ========== 静态方法 - 缓存管理 ==========

SecurityIp::clearRequestCache(): void
SecurityIp::clearIpCache(string $ip): void

// ========== 实例方法 ==========

$ip->checkAndUpdateType(): void
$ip->applyNaturalDecay(): void
$ip->updateThreatScore(float $delta, ?string $rule = null): void
```

### CacheAdapter 缓存适配器

```php
use zxf\Security\Cache\CacheAdapter;

// 创建实例
$cache = new CacheAdapter('file');  // file | laravel | auto
$cache = security_cache();          // 使用辅助函数（推荐）

// ========== 基础操作 ==========

$cache->get(string $key, mixed $default = null): mixed
$cache->set(string $key, mixed $value, ?int $ttl = null): bool
$cache->delete(string $key): bool
$cache->has(string $key): bool

// ========== 高级操作 ==========

$cache->remember(string $key, callable $callback, ?int $ttl = null): mixed
$cache->increment(string $key, int $value = 1): int|false
$cache->decrement(string $key, int $value = 1): int|false

// ========== 批量操作 ==========

$cache->many(array $keys): array
$cache->setMany(array $values, ?int $ttl = null): bool
$cache->deleteMany(array $keys): bool

// ========== 管理操作 ==========

$cache->clear(): bool
$cache->keys(?string $prefix = null): array
$cache->cleanupExpired(): int

// ========== 统计和配置 ==========

$cache->getStats(): array
$cache->getDriverType(): string
$cache->enableStats(): void
$cache->disableStats(): void
$cache->resetStats(): void
```

### RateLimiterService 速率限制服务

```php
use zxf\Security\Services\RateLimiterService;

$rateLimiter = app(RateLimiterService::class);

// ========== 核心方法 ==========

$rateLimiter->check(Request $request): array
$rateLimiter->batchCheck(array $fingerprints): array

// ========== 客户端管理 ==========

$rateLimiter->getClientRateInfo(Request $request): array
$rateLimiter->resetClientRateLimit(Request $request): bool

// ========== 统计和清理 ==========

$rateLimiter->getRateLimitStats(): array
$rateLimiter->getSlidingWindowStats(): array
$rateLimiter->clearCache(): void
$rateLimiter->onRequestTerminate(): void
```

### SecurityMonitor 监控服务

```php
use zxf\Security\Services\SecurityMonitor;

$monitor = app(SecurityMonitor::class);

// ========== 仪表板 ==========

$monitor->getDashboard(): array          // 获取完整仪表板
$monitor->getSummary(): array            // 获取概览统计
$monitor->getRecentEvents(int $limit = 50): array  // 获取最近事件

// ========== 分析 ==========

$monitor->getThreatAnalysis(): array     // 威胁分析
$monitor->getRateLimitStats(): array     // 速率限制统计
$monitor->getTopBlockedIps(int $limit = 10): array  // 被拦截最多的IP

// ========== 系统健康 ==========

$monitor->getSystemHealth(): array       // 系统健康状态
$monitor->isHealthy(): bool              // 系统是否健康
$monitor->checkService(string $service): bool  // 检查具体服务

// ========== 性能 ==========

$monitor->getPerformanceMetrics(): array // 性能指标
$monitor->getAverageResponseTime(): float // 平均响应时间
```

---

## 🚀 性能优化

### 1. 独立文件缓存策略（推荐）

本扩展包默认使用独立的文件缓存驱动，无需Redis即可实现高性能：

```php
// .env配置
SECURITY_CACHE_DRIVER=file
SECURITY_FILE_CACHE_PATH=/path/to/cache
```

文件缓存特性：
- 自动目录分片（哈希算法分散文件）
- LRU内存缓冲区（减少文件IO）
- 原子性写入（临时文件+重命名）
- 自动过期清理
- 并发安全（文件锁机制）

### 2. 延迟写入优化

```php
// 启用延迟写入
SECURITY_DEFERRED_WRITE=true
SECURITY_DEFERRED_WRITE_THRESHOLD=50

// IP记录会自动进入队列，达到阈值后批量写入
SecurityIp::recordRequest('192.168.1.1', true, 'SQL_INJECTION');

// 手动刷新（通常在请求结束时自动调用）
SecurityIp::flushDeferredWrites();
```

效果对比：
| 场景 | 传统模式 | 延迟写入模式 | 提升 |
|-----|---------|-------------|-----|
| 100个请求 | 100次DB写入 | 1-2次DB写入 | **90%+** |
| 响应时间 | 10-20ms | <1ms | **95%** |

### 3. 滑动窗口限流

```php
// 启用滑动窗口（避免临界突发）
SECURITY_SLIDING_WINDOW=true
SECURITY_SLIDING_SUBDIVISIONS=6
```

滑动窗口 vs 固定窗口：
- 固定窗口：整点重置，可能产生2倍突发
- 滑动窗口：平滑过渡，流量控制更精确

### 4. 批量操作优化

```php
// 不推荐：逐条操作
foreach ($ips as $ip) {
    SecurityIp::recordRequest($ip['ip'], $ip['blocked']);
}

// 推荐：批量操作
SecurityIp::batchRecordRequests($records);

// 批量查询
$ipManager = app(IpManagerService::class);
$stats = $ipManager->getIpStatsBatch($ips);
```

### 5. 缓存预热

```php
// 预加载常用IP数据
$ipManager = app(IpManagerService::class);
$ipManager->warmupCache(['192.168.1.1', '10.0.0.1']);

// 缓存预热后，这些IP的检查将完全在内存中完成
// 无需任何数据库查询
```

### 6. 配置预加载

```php
// 启用配置预加载
SECURITY_CONFIG_PRELOAD=true

// 高频配置项会在启动时预加载到内存
// 后续读取直接从内存获取，零开销
```

### 7. 数据库索引优化

```sql
-- 添加性能索引
ALTER TABLE security_ips ADD INDEX idx_ip_address (ip_address);
ALTER TABLE security_ips ADD INDEX idx_type_status (type, status);
ALTER TABLE security_ips ADD INDEX idx_threat_score (threat_score DESC);
ALTER TABLE security_ips ADD INDEX idx_last_request (last_request_at);
ALTER TABLE security_ips ADD INDEX idx_expires (expires_at);

-- 复合索引（常用查询）
ALTER TABLE security_ips ADD INDEX idx_type_status_ip (type, status, ip_address);
```

### 8. 定期清理

```php
// 在 App\Console\Kernel.php 中配置定时任务
protected function schedule(Schedule $schedule): void
{
    // 每天清理过期IP记录
    $schedule->call(function () {
        $count = security_cleanup_expired();
        Log::info("清理了 {$count} 条过期IP记录");
    })->daily();

    // 每小时清理过期缓存
    $schedule->call(function () {
        $cache = security_cache();
        $count = $cache->cleanupExpired();
        Log::info("清理了 {$count} 个过期缓存文件");
    })->hourly();

    // 每周清理安全缓存
    $schedule->call(function () {
        clean_security_cache();
    })->weekly();
}
```

---

## 💡 最佳实践

### 1. 生产环境配置

```env
# 基础配置
SECURITY_MIDDLEWARE_ENABLED=true
SECURITY_DEBUG_LOGGING=false
SECURITY_LOG_DETAILS=false

# 缓存（推荐文件缓存）
SECURITY_CACHE_DRIVER=file
SECURITY_CACHE_TTL=600

# 性能优化（全部启用）
SECURITY_DEFERRED_WRITE=true
SECURITY_SLIDING_WINDOW=true
SECURITY_CONFIG_PRELOAD=true

# 速率限制（根据业务调整）
SECURITY_RATE_LIMITING_ENABLED=true
SECURITY_MAX_REQUESTS_PER_MINUTE=500
SECURITY_MAX_REQUESTS_PER_HOUR=20000
SECURITY_RATE_LIMIT_STRATEGY=ip_ua_path

# IP检测（严格模式）
SECURITY_IP_AUTO_DETECTION=true
SECURITY_RECORD_NORMAL_VISITOR=false
SECURITY_BLACKLIST_THRESHOLD=70.0
SECURITY_SUSPICIOUS_THRESHOLD=40.0
```

### 2. 内网IP处理

```php
// 推荐配置：内网IP跳过速率限制，但保留黑名单检查
'intranet' => [
    'skip_rate_limit' => true,      // 内网不限速
    'skip_blacklist_check' => false, // 但保留黑名单检查
],
```

### 3. 误判处理流程

```php
// 1. 误判IP处理
Route::post('/security/unblock', function (Request $request) {
    $ip = $request->input('ip');
    
    // 添加到白名单
    security_add_to_whitelist($ip, '误判解除');
    
    // 清除速率限制
    security_clear_rate_limit($ip);
    
    // 清除缓存
    SecurityIp::clearIpCache($ip);
    
    return response()->json(['message' => 'IP已解除限制']);
});
```

### 4. 监控和告警

```php
// 在定时任务中监控
$schedule->call(function () {
    $monitor = app(\zxf\Security\Services\SecurityMonitor::class);
    
    // 检查系统健康
    if (!$monitor->isHealthy()) {
        $health = $monitor->getSystemHealth();
        // 发送告警通知
        Notification::send(new SecurityAlert($health));
    }
    
    // 检查高威胁IP数量
    $summary = $monitor->getSummary();
    if ($summary['suspicious_ips'] > 100) {
        Log::warning('高威胁IP数量异常', $summary);
    }
})->everyFiveMinutes();
```

### 5. 缓存监控

```php
// 定期检查缓存命中率
$schedule->call(function () {
    $stats = security_cache_stats();
    
    if (isset($stats['adapter_hit_rate'])) {
        $hitRate = (float) str_replace('%', '', $stats['adapter_hit_rate']);
        
        if ($hitRate < 80) {
            Log::warning('缓存命中率偏低', $stats);
        }
    }
    
    // 检查磁盘占用
    if (isset($stats['disk_size_mb']) && $stats['disk_size_mb'] > 500) {
        Log::warning('缓存磁盘占用过高', $stats);
    }
})->hourly();
```

---

## 🔧 故障排查

### 1. 中间件未生效

**现象：** 安全防护没有生效，恶意请求未被拦截

**排查步骤：**

```bash
# 1. 检查中间件是否注册
php artisan route:list --middleware | grep security

# 2. 检查配置是否启用
grep "SECURITY_MIDDLEWARE_ENABLED" .env
# 应该显示: SECURITY_MIDDLEWARE_ENABLED=true

# 3. 清除配置缓存
php artisan config:clear

# 4. 检查日志
tail -f storage/logs/laravel.log | grep security
```

**解决方案：**

```php
// 确保在 bootstrap/app.php 中注册
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\zxf\Security\Middleware\SecurityMiddleware::class);
})
```

### 2. 文件缓存权限错误

**现象：** 报错 `Permission denied` 或无法写入缓存文件

**排查步骤：**

```bash
# 1. 检查目录是否存在
ls -la storage/security-cache

# 2. 检查权限
ls -la storage/ | grep security-cache

# 3. 检查Web服务器用户
ps aux | grep nginx
ps aux | grep apache
```

**解决方案：**

```bash
# 创建目录
mkdir -p storage/security-cache

# 设置权限
chmod 755 storage/security-cache

# 设置正确的用户（根据实际用户调整）
chown -R www-data:www-data storage/security-cache

# SELinux环境（如果需要）
chcon -R -t httpd_sys_rw_content_t storage/security-cache
```

### 3. 数据库迁移失败

**现象：** 运行 `php artisan migrate` 时报错

**常见错误及解决方案：**

```bash
# 错误1: 表已存在
# 解决方案：回滚后重新迁移
php artisan migrate:rollback --path=vendor/zxf/security/src/Database/Migrations
php artisan migrate --path=vendor/zxf/security/src/Database/Migrations

# 错误2: 数据库连接失败
# 解决方案：检查数据库配置
grep DB_ .env

# 错误3: 权限不足
# 解决方案：检查数据库用户权限
```

### 4. 缓存命中率低

**现象：** 缓存统计中 `hit_rate` 低于50%

**排查步骤：**

```php
// 1. 检查缓存统计
$stats = security_cache_stats();
print_r($stats);

// 2. 检查缓存驱动
echo $stats['driver'];  // 应该显示 'file' 或 'laravel'

// 3. 检查缓存TTL
$ttl = security_config('cache_ttl');
echo $ttl;  // 不应该太短
```

**解决方案：**

```php
// 1. 增加缓存TTL
SECURITY_CACHE_TTL=600  // 从300增加到600秒

// 2. 启用缓存预热
$ipManager = app(IpManagerService::class);
$ipManager->warmupCache($commonIps);

// 3. 检查是否有频繁清理
grep "clean_security_cache" app/Console/Kernel.php
```

### 5. 延迟写入数据丢失

**现象：** IP记录未及时写入数据库

**排查步骤：**

```php
// 1. 检查延迟写入统计
$stats = SecurityIp::getDeferredWriteStats();
print_r($stats);

// 2. 检查配置
$enabled = security_config('enable_deferred_write');
echo $enabled;  // 应该为true

// 3. 手动刷新
SecurityIp::flushDeferredWrites();
```

**解决方案：**

```php
// 方案1: 降低延迟写入阈值
SECURITY_DEFERRED_WRITE_THRESHOLD=20  // 从50降低到20

// 方案2: 在请求终止时确保刷新
// 这通常在中间件的 terminate 方法中自动处理

// 方案3: 手动刷新关键操作后
SecurityIp::recordRequest($ip, true);
SecurityIp::flushDeferredWrites();  // 立即刷新
```

### 6. 速率限制不生效

**现象：** 请求频率超过限制但未被拦截

**排查步骤：**

```php
// 1. 检查速率限制配置
grep "SECURITY_RATE_LIMITING_ENABLED" .env
grep "SECURITY_RATE_LIMIT_STRATEGY" .env

// 2. 检查当前速率信息
$rateLimiter = app(RateLimiterService::class);
$rateInfo = $rateLimiter->getClientRateInfo($request);
print_r($rateInfo);

// 3. 检查滑动窗口统计
$stats = $rateLimiter->getSlidingWindowStats();
print_r($stats);
```

**解决方案：**

```php
// 确保速率限制已启用
SECURITY_RATE_LIMITING_ENABLED=true

// 调整阈值
SECURITY_MAX_REQUESTS_PER_MINUTE=100  // 适当降低

// 检查指纹策略
SECURITY_RATE_LIMIT_STRATEGY=ip_ua_path  // 使用更精确的策略
```

### 7. 内存占用过高

**现象：** 应用内存占用持续增长

**排查步骤：**

```php
// 1. 检查内存缓存大小
$stats = security_cache_stats();
echo $stats['memory_buffer_size'];

// 2. 检查IP模型缓存
$deferredStats = SecurityIp::getDeferredWriteStats();
echo $deferredStats['queue_size'];

// 3. 检查请求缓存（在请求结束时应该被清理）
```

**解决方案：**

```php
// 1. 定期清理缓存
$schedule->call(function () {
    clean_security_cache();
})->hourly();

// 2. 降低缓存大小限制（修改源码中的常量）
// FileCacheDriver::MAX_BUFFER_SIZE

// 3. 确保请求终止时清理资源
// 中间件会自动调用清理方法
```

### 8. 数据库性能问题

**现象：** 查询缓慢，响应时间长

**排查步骤：**

```sql
-- 1. 检查表大小
SELECT 
    table_name,
    ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb
FROM information_schema.tables
WHERE table_name = 'security_ips';

-- 2. 检查索引
SHOW INDEX FROM security_ips;

-- 3. 检查慢查询
SHOW VARIABLES LIKE 'slow_query%';
```

**解决方案：**

```sql
-- 1. 添加索引
ALTER TABLE security_ips ADD INDEX idx_ip_address (ip_address);
ALTER TABLE security_ips ADD INDEX idx_type_status (type, status);

-- 2. 清理过期数据
DELETE FROM security_ips WHERE expires_at < NOW();

-- 3. 优化表
OPTIMIZE TABLE security_ips;

-- 4. 考虑分区表（大数据量）
-- 参考 docs/database-optimization.md
```

---

## ❓ 常见问题

### 1. 如何禁用某个检查？

```php
'defense_layers' => [
    'ip_whitelist' => true,
    'ip_blacklist' => true,
    'method_check' => false,        // 禁用HTTP方法检查
    'user_agent_check' => false,    // 禁用User-Agent检查
    'header_check' => false,        // 禁用请求头检查
    'url_check' => true,
    'upload_check' => false,        // 禁用文件上传检查
    'body_check' => true,
    'anomaly_check' => true,
    'rate_limit' => true,
    'sql_check' => true,
    'xss_check' => true,
    'command_check' => true,
],
```

### 2. 缓存磁盘占用过高怎么办？

```php
// 1. 定期清理过期缓存
$schedule->call(function () {
    $cache = security_cache();
    $count = $cache->cleanupExpired();
    Log::info("清理了 {$count} 个过期缓存文件");
})->daily();

// 2. 降低缓存TTL
SECURITY_CACHE_TTL=180  // 从300秒降低到180秒

// 3. 完全清除缓存
clean_security_cache();
```

### 3. 如何迁移从Redis到文件缓存？

```php
// 1. 修改配置
SECURITY_CACHE_DRIVER=file

// 2. 清除Redis缓存
clean_security_cache();

// 3. 预热缓存
$ipManager = app(IpManagerService::class);
$commonIps = SecurityIp::pluck('ip_address')->take(100)->toArray();
$ipManager->warmupCache($commonIps);
```

### 4. 延迟写入的数据安全吗？

```php
// 数据是安全的，以下情况会自动刷新：
// 1. 队列达到阈值（默认50条）
// 2. 请求结束时（onRequestTerminate）
// 3. 手动调用 flushDeferredWrites()

// 如需立即确认写入：
SecurityIp::recordRequest($ip, true);
SecurityIp::flushDeferredWrites();  // 立即刷新
```

### 5. 文件缓存的性能如何？

文件缓存性能数据（SSD存储）：
- 读取：~0.1ms（命中内存缓冲区）/ ~1ms（命中文件）
- 写入：~2ms（原子性写入）
- 对比Redis：性能约为Redis的70-80%，但零部署成本

适合场景：
- 中小型应用（<10万IP）
- 无Redis环境
- 需要简单部署的项目

### 6. 如何调试限流问题？

```php
// 启用调试日志
SECURITY_DEBUG_LOGGING=true

// 获取详细速率信息
$rateLimiter = app(RateLimiterService::class);
$rateInfo = $rateLimiter->getClientRateInfo($request);
Log::info('速率限制信息', $rateInfo);

// 获取滑动窗口统计
$stats = $rateLimiter->getSlidingWindowStats();
```

---

## 📝 更新日志

### v3.0.0 (2026-04-06)

#### 重大更新
- ✨ **独立文件缓存**: 全新独立文件缓存驱动，彻底零外部依赖
- ✨ **延迟写入**: IP记录批量延迟写入，数据库IO减少90%+
- ✨ **滑动窗口限流**: 替换固定窗口，避免临界突发问题
- ✨ **配置预加载**: 启动时预加载高频配置，减少运行时开销
- ✨ **监控仪表板**: 全新SecurityMonitor服务，实时监控安全状态
- 🚀 **性能优化**: 四级缓存策略，请求级内存缓存

#### 新增功能
- ✅ CacheAdapter 缓存适配器（支持file/laravel/auto）
- ✅ FileCacheDriver 独立文件缓存驱动
- ✅ AsyncSecurityProcessor 异步处理器
- ✅ SecurityMonitor 监控服务
- ✅ 延迟写入队列管理
- ✅ 滑动窗口算法实现
- ✅ 批量IP查询API
- ✅ 缓存预热功能
- ✅ 缓存统计功能

#### API新增
- `security_cache()` - 获取缓存实例
- `security_cache_stats()` - 获取缓存统计
- `SecurityIp::batchCheck()` - 批量检查IP
- `SecurityIp::flushDeferredWrites()` - 刷新延迟写入
- `SecurityIp::getDeferredWriteStats()` - 延迟写入统计
- `RateLimiterService::getSlidingWindowStats()` - 滑动窗口统计
- `SecurityMonitor::getDashboard()` - 获取监控仪表板

#### 优化改进
- 🔄 重构缓存层，支持多种驱动
- 🔄 优化SecurityIp模型，添加四级缓存
- 🔄 重构RateLimiterService，使用滑动窗口
- 🔄 优化ConfigManager，添加预加载
- 🔄 完善安全中间件，添加资源清理

### v2.0.0 (2026-03-01)

- ✨ 移除Redis依赖，改用文件缓存
- ✨ 批量操作和采样机制
- ✨ 威胁评分系统
- ✨ 内网IP识别

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
- 主页: https://yoc.cn
- Issues: [GitHub Issues](https://github.com/yourusername/security/issues)

---

## 🙏 致谢

感谢所有为本项目做出贡献的开发者！

---

<div align="center">

**如果觉得这个项目对您有帮助，请给我们一个 ⭐️ Star**

Made with ❤️ by zxf

</div>
