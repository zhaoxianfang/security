# Laravel Security 配置指南

> 完整的配置项说明与使用指南

## 配置文件总览表格

| 配置项                                        | 类型                | 默认值               | 说明                         | 相关服务                                            | 是否支持动态配置 |
|--------------------------------------------|-------------------|-------------------|----------------------------|-------------------------------------------------|----------|
| `enabled`                                  | boolean\|callable | true              | 是否启用安全中间件                  | SecurityMiddleware                              | ✓        |
| `enabled_type`                             | string            | global            | 启用方式：global(全局)/route(路由级) | SecurityServiceProvider                         | ✗        |
| `ignore_local`                             | boolean\|callable | false             | 是否忽略本地环境请求                 | SecurityMiddleware                              | ✓        |
| `log_level`                                | string\|callable  | warning           | 日志级别                       | SecurityMiddleware                              | ✓        |
| `enable_debug_logging`                     | boolean\|callable | false             | 是否启用调试日志                   | 全局                                              | ✓        |
| `log_details`                              | boolean\|callable | false             | 是否记录详细日志                   | SecurityMiddleware                              | ✓        |
| `enable_rate_limiting`                     | boolean\|callable | true              | 是否启用速率限制                   | RateLimiterService                              | ✓        |
| `rate_limits`                              | array             | 见配置               | 时间窗口限制                     | RateLimiterService                              | ✓        |
| `rate_limit_strategy`                      | string            | ip_ua_path        | 速率限制策略                     | RateLimiterService                              | ✓        |
| `rate_limit_custom_handler`                | callable          | null              | 自定义指纹处理器                   | RateLimiterService                              | ✓        |
| `ip_auto_detection.enabled`                | boolean           | true              | 是否启用自动检测                   | IpManagerService                                | ✓        |
| `ip_auto_detection.blacklist_threshold`    | float             | 80.0              | 黑名单阈值                      | IpManagerService                                | ✓        |
| `ip_auto_detection.suspicious_threshold`   | float             | 50.0              | 可疑IP阈值                     | IpManagerService                                | ✓        |
| `ip_auto_detection.max_triggers`           | int               | 5                 | 最大触发次数                     | IpManagerService                                | ✓        |
| `ip_auto_detection.add_threat_score`       | float             | 10.00             | 威胁评分增量                     | IpManagerService                                | ✓        |
| `ip_auto_detection.reduce_threat_score`    | float             | 1.00              | 威胁评分减量                     | IpManagerService                                | ✓        |
| `ip_auto_detection.decay_rate_per_hour`    | float             | 0.3               | 每小时衰减率                     | IpManagerService                                | ✓        |
| `ip_auto_detection.auto_cleanup`           | boolean           | false             | 自动清理过期记录                   | 未使用                                             | ✗        |
| `ip_auto_detection.monitoring_expire_days` | int               | 15                | 监控过期天数                     | 未使用                                             | ✗        |
| `ip_database.cache_ttl`                    | int               | 300               | IP缓存时间                     | IpManagerService                                | ✓        |
| `allowed_methods`                          | array             | 见配置               | 允许的HTTP方法                  | SecurityMiddleware                              | ✓        |
| `suspicious_methods`                       | array             | 见配置               | 可疑HTTP方法                   | SecurityMiddleware                              | ✓        |
| `body_patterns`                            | array\|callable   | 见SecurityConfig   | 请求体正则模式                    | ThreatDetectionService                          | ✓        |
| `body_whitelist_paths`                     | array             | 见配置               | 请求体白名单路径                   | ThreatDetectionService                          | ✓        |
| `min_content_length`                       | int               | 3                 | 最小触发内容长度                   | ThreatDetectionService                          | ✓        |
| `url_patterns`                             | array\|callable   | 见SecurityConfig   | URL正则模式                    | ThreatDetectionService                          | ✓        |
| `url_whitelist_paths`                      | array             | 见配置               | URL白名单路径                   | ThreatDetectionService,WhitelistSecurityService | ✓        |
| `whitelist_security_policy`                | array             | 见配置               | 白名单安全策略                    | WhitelistSecurityService                        | ✓        |
| `whitelist_security_policy.always_check`   | array             | 见配置               | 始终检查项                      | WhitelistSecurityService                        | ✓        |
| `whitelist_security_policy.level_checks`   | array             | 见配置               | 级别检查项                      | WhitelistSecurityService                        | ✓        |
| `whitelist_security_policy.require_auth`   | array             | 见配置               | 需认证路径                      | 未使用                                             | ✗        |
| `max_url_length`                           | int               | 2048              | 最大URL长度                    | ThreatDetectionService                          | ✓        |
| `suspicious_user_agents`                   | array\|callable   | 见SecurityConfig   | 可疑UA模式                     | ThreatDetectionService                          | ✓        |
| `whitelist_user_agents`                    | array\|callable   | 见SecurityConfig   | 白名单UA模式                    | ThreatDetectionService                          | ✓        |
| `allow_empty_user_agent`                   | boolean\|callable | false             | 是否允许空UA                    | SecurityMiddleware                              | ✓        |
| `max_user_agent_length`                    | int               | 512               | 最大UA长度                     | SecurityMiddleware                              | ✓        |
| `suspicious_headers`                       | array             | 见配置               | 可疑请求头                      | ThreatDetectionService                          | ✓        |
| `max_header_count`                         | int               | 50                | 最大请求头数量                    | SecurityMiddleware                              | ✓        |
| `enable_file_check`                        | boolean\|callable | true              | 是否启用文件检查                   | ThreatDetectionService                          | ✓        |
| `disallowed_extensions`                    | array\|callable   | 见SecurityConfig   | 禁止扩展名                      | ThreatDetectionService                          | ✓        |
| `disallowed_mime_types`                    | array\|callable   | 见SecurityConfig   | 禁止MIME类型                   | ThreatDetectionService                          | ✓        |
| `max_file_size`                            | int               | 52428800          | 最大文件大小                     | ThreatDetectionService                          | ✓        |
| `enable_file_content_check`                | boolean\|callable | false             | 是否检查文件内容                   | ThreatDetectionService                          | ✓        |
| `allowed_extensions_whitelist`             | array             | 见配置               | 允许扩展名白名单                   | ThreatDetectionService                          | ✓        |
| `enable_anomaly_detection`                 | boolean\|callable | true              | 是否启用异常检测                   | ThreatDetectionService                          | ✓        |
| `anomaly_thresholds`                       | array             | 见配置               | 异常阈值                       | ThreatDetectionService                          | ✓        |
| `enable_sql_injection_detection`           | boolean\|callable | true              | 是否启用SQL注入检测                | ThreatDetectionService                          | ✓        |
| `sql_injection_patterns`                   | array\|callable   | 见SecurityConfig   | SQL注入模式                    | ThreatDetectionService                          | ✓        |
| `enable_xss_detection`                     | boolean\|callable | true              | 是否启用XSS检测                  | ThreatDetectionService                          | ✓        |
| `xss_attack_patterns`                      | array\|callable   | 见SecurityConfig   | XSS攻击模式                    | ThreatDetectionService                          | ✓        |
| `enable_command_injection_detection`       | boolean\|callable | true              | 是否启用命令注入检测                 | ThreatDetectionService                          | ✓        |
| `command_injection_patterns`               | array\|callable   | 见SecurityConfig   | 命令注入模式                     | ThreatDetectionService                          | ✓        |
| `cache_ttl`                                | int               | 3600              | 缓存生存时间                     | ConfigManager                                   | ✓        |
| `ban_duration`                             | int               | 3600              | 默认封禁时长                     | IpManagerService                                | ✓        |
| `max_ban_duration`                         | int               | 7776000           | 最大封禁时长                     | IpManagerService                                | ✓        |
| `ban_duration_map`                         | array\|callable   | 见SecurityConfig   | 封禁时长映射                     | IpManagerService                                | ✓        |
| `adaptive_ban_duration.enabled`            | boolean           | true              | 是否启用自适应封禁                  | IpManagerService                                | ✓        |
| `adaptive_ban_duration.multipliers`        | array             | 见配置               | 自适应倍数                      | IpManagerService                                | ✓        |
| `enable_pattern_cache`                     | boolean\|callable | true              | 是否启用正则缓存                   | ThreatDetectionService                          | ✓        |
| `enable_ip_cache`                          | boolean\|callable | true              | 是否启用IP缓存                   | IpManagerService                                | ✓        |
| `block_on_exception`                       | boolean\|callable | false             | 异常时是否拦截                    | SecurityMiddleware                              | ✓        |
| `ajax_response_format`                     | array             | 见配置               | AJAX响应格式                   | SecurityMiddleware                              | ✓        |
| `error_view`                               | string            | security::blocked | 错误视图                       | SecurityMiddleware                              | ✓        |
| `error_view_data`                          | array             | 见配置               | 错误视图数据                     | SecurityMiddleware                              | ✓        |
| `response_status_codes`                    | array             | 见配置               | 响应状态码映射                    | SecurityMiddleware                              | ✓        |
| `custom_handler`                           | callable          | null              | 自定义处理逻辑                    | SecurityMiddleware                              | ✓        |
| `blacklist_handler`                        | callable          | null              | 黑名单处理逻辑                    | IpManagerService                                | ✓        |
| `whitelist_handler`                        | callable          | null              | 白名单处理逻辑                    | IpManagerService                                | ✓        |
| `alarm_handler`                            | callable          | null              | 安全警报处理                     | SecurityMiddleware                              | ✓        |
| `max_recursion_depth`                      | int               | 10                | 最大递归深度                     | ThreatDetectionService                          | ✓        |
| `defense_layers`                           | array             | 见配置               | 防御层配置                      | SecurityMiddleware                              | ✓        |
| `enable_api_mode`                          | boolean\|callable | true              | 是否启用API模式                  | SecurityMiddleware                              | ✓        |
| `trusted_proxies`                          | array             | 见配置               | 信任的代理IP                    | IpManagerService                                | ✓        |
| `trusted_headers`                          | array             | 见配置               | 信任的代理头                     | IpManagerService                                | ✓        |
| `hot_reload.enabled`                       | boolean           | true              | 是否启用热重载                    | ConfigHotReloadService                          | ✓        |
| `hot_reload.watch_interval`                | int               | 5                 | 监听间隔(秒)                    | 未使用                                             | ✗        |
| `hot_reload.version_key`                   | string            | 见配置               | 版本缓存键                      | ConfigHotReloadService                          | ✓        |
| `hot_reload.realtime_keys`                 | array             | 见配置               | 实时配置项                      | ConfigHotReloadService                          | ✓        |
| `hot_reload.no_cache_keys`                 | array             | 见配置               | 不缓存配置项                     | ConfigManager,ConfigHotReloadService            | ✓        |
| `rule_engine.enabled`                      | boolean           | true              | 是否启用规则引擎                   | 未使用                                             | ✗        |
| `rule_engine.enable_adaptive_learning`     | boolean           | false             | 是否启用自适应学习                  | 未使用                                             | ✗        |
| `rule_engine.adaptive_learning`            | array             | 见配置               | 自适应学习参数                    | 未使用                                             | ✗        |
| `rule_engine.threat_thresholds`            | array             | 见配置               | 威胁阈值                       | ThreatScoringService                            | ✓        |
| `rule_engine.max_threat_score`             | int               | 100               | 最大威胁评分                     | ThreatScoringService                            | ✓        |
| `rule_engine.disabled_rules`               | array             | 见配置               | 禁用的规则ID                    | RuleEngineService                               | ✓        |
| `rule_engine.custom_rules`                 | array             | 见配置               | 自定义规则                      | RuleEngineService                               | ✓        |

## 配置项分类详解

### 1. 基础配置
控制安全中间件的基本行为。

```php
// 是否启用安全中间件
'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),

// 启用方式
'enabled_type' => env('SECURITY_MIDDLEWARE_TYPE', 'global'), // global | route

// 是否忽略本地请求
'ignore_local' => env('SECURITY_IGNORE_LOCAL', false),

// 日志级别
'log_level' => env('SECURITY_LOG_LEVEL', 'warning'), // debug, info, notice, warning, error, critical, alert, emergency

// 调试日志
'enable_debug_logging' => env('SECURITY_DEBUG_LOGGING', false),

// 详细日志
'log_details' => env('SECURITY_LOG_DETAILS', false),
```

### 2. 速率限制配置
防止暴力破解和DDoS攻击。

```php
// 启用速率限制
'enable_rate_limiting' => env('SECURITY_RATE_LIMITING_ENABLED', true),

// 时间窗口限制
'rate_limits' => [
    'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 300),
    'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 10000),
    'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 100000),
],

// 指纹生成策略
'rate_limit_strategy' => env('SECURITY_RATE_LIMIT_STRATEGY', 'ip_ua_path'), // ip_only, ip_ua, ip_ua_path, custom

// 自定义处理器
'rate_limit_custom_handler' => env('SECURITY_RATE_LIMIT_CUSTOM_HANDLER', null),
```

### 3. IP自动检测配置
自动识别和处理威胁IP。

```php
'ip_auto_detection' => [
    'enabled' => env('SECURITY_IP_AUTO_DETECTION', true),
    'blacklist_threshold' => env('SECURITY_BLACKLIST_THRESHOLD', 80.0),
    'suspicious_threshold' => env('SECURITY_SUSPICIOUS_THRESHOLD', 50.0),
    'max_triggers' => env('SECURITY_MAX_TRIGGERS', 5),
    'add_threat_score' => env('SECURITY_ADD_THREAT_SCORE', 10.00),
    'reduce_threat_score' => env('SECURITY_REDUCE_THREAT_SCORE', 1.00),
    'decay_rate_per_hour' => env('SECURITY_DECAY_RATE_PER_HOUR', 0.3),
    'auto_cleanup' => env('SECURITY_AUTO_CLEANUP', false), // ⚠️ 暂未实现
    'monitoring_expire_days' => env('SECURITY_MONITORING_EXPIRE_DAYS', 15), // ⚠️ 暂未实现
],
```

### 4. URL白名单配置
支持多种格式和分级控制。

```php
// 简单格式
'url_whitelist_paths' => [
    'robots.txt',
    'health',
],

// 高级格式（支持级别和方法限制）
'url_whitelist_paths' => [
    ['path' => 'robots.txt', 'level' => 'low'],
    ['path' => 'api/health', 'methods' => ['GET'], 'level' => 'low'],
],

// ⚠️ 危险：避免使用通配符
// 'api/*',  // 危险！建议移除
```

### 5. 防御层配置
控制各个安全检测模块。

```php
'defense_layers' => [
    'ip_whitelist' => env('SECURITY_DEFENSE_IP_WHITELIST', true),
    'ip_blacklist' => env('SECURITY_DEFENSE_IP_BLACKLIST', true),
    'method_check' => env('SECURITY_DEFENSE_METHOD', true),
    'user_agent_check' => env('SECURITY_DEFENSE_USER_AGENT', true),
    'header_check' => env('SECURITY_DEFENSE_HEADER', true),
    'url_check' => env('SECURITY_DEFENSE_URL', true),
    'upload_check' => env('SECURITY_DEFENSE_UPLOAD', true),
    'body_check' => env('SECURITY_DEFENSE_BODY', true),
    'anomaly_check' => env('SECURITY_DEFENSE_ANOMALY', true),
    'rate_limit' => env('SECURITY_DEFENSE_RATE_LIMIT', true),
    'sql_check' => env('SECURITY_DEFENSE_SQL', true),
    'xss_check' => env('SECURITY_DEFENSE_XSS', true),
    'command_check' => env('SECURITY_DEFENSE_COMMON', true),
    'custom_check' => env('SECURITY_DEFENSE_CUSTOM', true),
],
```

### 6. 自适应封禁配置
根据威胁评分动态调整封禁时长。

```php
'adaptive_ban_duration' => [
    'enabled' => true,
    'multipliers' => [
        90 => 10,  // 评分90+，10倍时长
        80 => 5,   // 评分80-90，5倍时长
        70 => 3,   // 评分70-80，3倍时长
        60 => 2,   // 评分60-70，2倍时长
    ],
],
```

### 7. 动态配置支持
支持多种配置源类型。

```php
// 静态数组
'body_patterns' => [...],

// 类方法调用
'body_patterns' => [SecurityConfig::class, 'getMaliciousBodyPatterns'],

// 字符串类方法
'body_patterns' => 'SecurityConfig::getMaliciousBodyPatterns',

// 闭包函数
'body_patterns' => function() {
    return [...];
},
```

## 安全建议

### 1. 白名单配置
- ❌ 避免使用通配符（如 `api/*`）
- ✅ 使用精确路径（如 `api/health`）
- ✅ 使用方法限制（如 `['methods' => ['GET']]`）
- ✅ 设置合适的安全级别（`level: 'low'`）

### 2. 性能优化
- 根据环境调整缓存时间
- 合理设置速率限制阈值
- 适当降低日志详细程度

### 3. 安全防护
- 生产环境启用所有防御层
- 严格限制文件上传类型
- 启用自适应封禁功能

## 配置验证

使用内置方法验证配置完整性：

```php
use zxf\Security\Config\SecurityConfig;

// 验证所有正则表达式
if (!SecurityConfig::validate()) {
    // 配置验证失败
}

// 获取版本信息
$versionInfo = SecurityConfig::getVersionInfo();
```

## 环境变量参考

| 环境变量                             | 配置项                                   | 说明      | 示例值          |
|----------------------------------|---------------------------------------|---------|--------------|
| SECURITY_MIDDLEWARE_ENABLED      | enabled                               | 是否启用中间件 | true/false   |
| SECURITY_MIDDLEWARE_TYPE         | enabled_type                          | 启用方式    | global/route |
| SECURITY_IGNORE_LOCAL            | ignore_local                          | 忽略本地    | true/false   |
| SECURITY_LOG_LEVEL               | log_level                             | 日志级别    | warning      |
| SECURITY_DEBUG_LOGGING           | enable_debug_logging                  | 调试日志    | true/false   |
| SECURITY_LOG_DETAILS             | log_details                           | 详细日志    | true/false   |
| SECURITY_RATE_LIMITING_ENABLED   | enable_rate_limiting                  | 启用速率限制  | true/false   |
| SECURITY_MAX_REQUESTS_PER_MINUTE | rate_limits.minute                    | 每分钟最大请求 | 300          |
| SECURITY_RATE_LIMIT_STRATEGY     | rate_limit_strategy                   | 速率限制策略  | ip_ua_path   |
| SECURITY_IP_AUTO_DETECTION       | ip_auto_detection.enabled             | IP自动检测  | true/false   |
| SECURITY_BLACKLIST_THRESHOLD     | ip_auto_detection.blacklist_threshold | 黑名单阈值   | 80.0         |
| SECURITY_HOT_RELOAD_ENABLED      | hot_reload.enabled                    | 热重载开关   | true/false   |
| SECURITY_BLOCK_ON_EXCEPTION      | block_on_exception                    | 异常时拦截   | true/false   |
| SECURITY_API_MODE                | enable_api_mode                       | API模式   | true/false   |
