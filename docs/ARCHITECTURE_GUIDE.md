# Laravel Security 架构指南

> 系统架构、组件设计和工作流程详解

## 架构总览表格

| 层级   | 组件                        | 职责               | 输入                | 输出            |
|------|---------------------------|------------------|-------------------|---------------|
| 中间件层 | SecurityMiddleware        | 请求拦截、协调各层检测      | HTTP Request      | HTTP Response |
| 服务层  | ThreatDetectionService    | 威胁检测（XSS、SQL注入等） | Request, Config   | bool, array   |
| 服务层  | IpManagerService          | IP管理（黑白名单、评分）    | Request, IP       | IP记录, bool    |
| 服务层  | RateLimiterService        | 速率限制             | Request, Config   | bool, 统计数据    |
| 服务层  | WhitelistSecurityService  | 白名单管理（安全级别）      | Request           | bool, 检查项     |
| 服务层  | ConfigHotReloadService    | 配置热重载            | Config文件          | 无（更新缓存）       |
| 服务层  | RuleEngineService         | 规则引擎             | Request, Patterns | 威胁评分, 拦截决策    |
| 服务层  | ThreatScoringService      | 威胁评分计算           | 事件, IP            | 评分(0-100)     |
| 服务层  | PerformanceMonitorService | 性能监控             | 请求时间, 内存          | 统计数据          |
| 服务层  | SecurityAuditService      | 安全审计             | 事件, IP            | 审计日志, 趋势分析    |
| 服务层  | CacheOptimizerService     | 缓存优化             | 缓存键, 值            | 优化的缓存         |
| 配置层  | ConfigManager             | 配置管理和动态读取        | 配置键               | 配置值           |
| 配置层  | SecurityConfig            | 安全模式定义           | 无                 | 模式数组          |
| 工具层  | ExceptionHandler          | 统一异常处理           | Exception         | 日志, 默认值       |
| 模型层  | SecurityIp                | IP数据模型           | DB, IP            | IP实例          |
| 常量层  | SecurityEvent             | 安全事件常量           | 无                 | 事件类型          |

## 核心架构设计

### 1. 中间件层（Middleware Layer）

#### SecurityMiddleware
**职责**：统一请求入口，协调各个安全检测层

**关键特性**：
- 多层防御检查顺序执行
- 异常保护机制（递归检测、降级放行）
- 性能统计收集
- 配置热重载触发

**工作流程**：
```
1. 请求进入 SecurityMiddleware::handle()
2. 触发配置热重载（如果启用）
3. 检查中间件是否启用
4. 检查是否本地请求（可选）
5. 跳过资源文件
6. 执行防御层检查（按配置顺序）
   - IP白名单检查
   - IP黑名单检查
   - HTTP方法检查
   - User-Agent检查
   - 请求头检查
   - URL检查
   - 文件上传检查
   - 请求体检查
   - 异常参数检查
   - 速率限制检查
   - SQL注入检查
   - XSS攻击检查
   - 命令注入检查
   - 自定义规则检查
7. 如果拦截 → 返回拦截响应
8. 如果通过 → 继续后续中间件
```

**异常处理**：
```php
try {
    // 执行安全检查
    $blockResult = $this->performSecurityChecks($request);
} catch (SecurityException $e) {
    // 安全异常：记录并根据配置决定是否拦截
} catch (Throwable $e) {
    // 其他异常：检测递归，降级放行
    if (ExceptionHandler::isRecursionException($e)) {
        return $next($request); // 递归时放行
    }
}
```

### 2. 服务层（Service Layer）

#### ThreatDetectionService（威胁检测服务）
**职责**：实现各类攻击检测算法

**核心方法**：
```php
// SQL注入检测
public function hasSQLInjection(Request $request): bool

// XSS攻击检测
public function hasXSSAttack(Request $request): bool

// 命令注入检测
public function hasCommandInjection(Request $request): bool

// 恶意请求内容检测
public function isMaliciousRequest(Request $request): bool

// URL安全性检查（含白名单）
public function isSafeUrl(Request $request): bool

// 可疑User-Agent检测
public function hasSuspiciousUserAgent(Request $request): bool

// 可疑请求头检测
public function hasSuspiciousHeaders(Request $request): bool

// 异常参数检测
public function hasAnomalousParameters(Request $request): bool

// 危险文件上传检测
public function hasDangerousUploads(Request $request): bool
```

**关键特性**：
- 正则表达式预编译缓存
- 多层误报过滤机制
- 递归深度控制
- 动态配置源支持（数组、类方法、闭包）

#### IpManagerService（IP管理服务）
**职责**：IP黑白名单管理、威胁评分、封禁逻辑

**核心方法**：
```php
// 检查IP是否在黑名单
public function isBlacklisted(Request $request): bool

// 检查IP是否在白名单
public function isWhitelisted(Request $request): bool

// 记录访问（更新威胁评分）
public function recordAccess(Request $request, bool $blocked, ?string $eventType = null): array

// 封禁IP
public function banIp(Request $request, string $eventType): void

// 获取封禁时长（支持自适应）
protected function getBanDuration(string $type, float $threatScore = 0): int

// 获取威胁评分
public function getThreatScore(string $ip): float
```

**威胁评分系统**：
```
初始评分：0
每次拦截：+threat_score（默认10）
每次成功：-reduce_threat_score（默认1）
每小时衰减：-decay_rate_per_hour（默认0.3）
```

**封禁逻辑**：
```
评分 >= blacklist_threshold（默认80） → 转为黑名单
评分 >= suspicious_threshold（默认50） → 转为可疑
触发次数 >= max_triggers（默认5） → 转为黑名单
```

#### RateLimiterService（速率限制服务）
**职责**：防止暴力破解和DDoS攻击

**指纹策略**：
```php
// 策略1：仅IP
ip_only: md5($request->ip())

// 策略2：IP + User-Agent
ip_ua: md5($request->ip() . $request->userAgent())

// 策略3：IP + User-Agent + 路径
ip_ua_path: md5($request->ip() . $request->userAgent() . $request->path())

// 自定义策略
custom: 调用 rate_limit_custom_handler
```

**滑动窗口算法**：
```
时间窗口：minute（60s）、hour（3600s）、day（86400s）
每个窗口独立计数
超过限制则拦截
```

#### WhitelistSecurityService（白名单安全服务）
**职责**：URL白名单管理和分级安全控制

**白名单格式**：
```php
// 简单格式（字符串）
'robots.txt'

// 高级格式（对象）
['path' => 'api/health', 'methods' => ['GET'], 'level' => 'low']
```

**安全级别**：
```
low（低风险）：
  - 保留检查：method_check, user_agent_check, header_check
  - 跳过检查：url_check

medium（中风险）：
  - 保留检查：method_check
  - 跳过检查：url_check, user_agent_check, header_check

high（高风险）：
  - 最少检查
  - ⚠️ 需谨慎使用
```

**始终保留的检查**：
```php
'always_check' => [
    'ip_blacklist',        // 始终检查IP黑名单
    'rate_limit',          // 始终进行频率限制
    'body_patterns',       // 始终检查请求体恶意内容
    'file_upload',         // 始终检查文件上传
    'sql_injection',       // 始终检测SQL注入
    'xss_attack',          // 始终检测XSS攻击
    'command_injection',    // 始终检测命令注入
],
```

#### ConfigHotReloadService（配置热重载服务）
**职责**：配置修改后立即生效，无需重启应用

**工作机制**：
```php
1. 检查配置文件修改时间
2. 如果有变更，更新版本号
3. 清除相关缓存
4. 重新加载配置
```

**关键配置**：
```php
'hot_reload' => [
    'enabled' => true,                    // 是否启用
    'watch_interval' => 5,                // 监听间隔（秒）
    'version_key' => 'security:config:version', // 版本缓存键
    'realtime_keys' => [                  // 实时配置项
        'url_whitelist_paths',
        'enabled',
        'defense_layers',
    ],
    'no_cache_keys' => [                  // 不缓存的配置项
        'url_whitelist_paths',
        'enabled',
    ],
],
```

#### RuleEngineService（规则引擎服务）
**职责**：高级规则管理和威胁评估

**规则结构**：
```php
$rule = [
    'id' => 'rule_001',
    'name' => 'SQL注入检测规则',
    'enabled' => true,
    'priority' => 100,
    'pattern' => '/UNION\s+SELECT/i',
    'severity' => 'high',  // low, medium, high, critical
    'category' => 'sql_injection',
    'action' => 'block',  // block, log, alert
];
```

**威胁阈值**：
```php
'threat_thresholds' => [
    'critical' => 80,  // 严重威胁
    'high' => 60,      // 高危威胁
    'medium' => 40,    // 中危威胁
    'low' => 20,       // 低危威胁
],
```

#### ThreatScoringService（威胁评分服务）
**职责**：综合评估IP的威胁程度

**评分因子**：
```php
'threat_scoring' => [
    'factor_weights' => [
        'malicious_request' => 0.4,      // 恶意请求权重
        'sql_injection' => 0.5,           // SQL注入权重
        'xss_attack' => 0.4,             // XSS攻击权重
        'command_injection' => 0.5,       // 命令注入权重
        'rate_limit' => 0.3,              // 频率超限权重
        'suspicious_ua' => 0.2,          // 可疑UA权重
        'suspicious_headers' => 0.2,      // 可疑头权重
        'blacklist' => 1.0,               // 黑名单权重
    ],
    'block_threshold' => 60,               // 拦截阈值
    'review_threshold' => 30,              // 审查阈值
],
```

**评分算法**：
```php
threat_score = sum(factor_weight * count) / max_score * 100
```

#### PerformanceMonitorService（性能监控服务）
**职责**：监控系统性能和资源使用

**监控指标**：
```php
// 请求时间
$request_time = end_time - start_time

// 内存使用
$memory_usage = memory_get_usage(true)

// CPU使用（通过进程状态）
$cpu_usage = getrusage()

// 检测层耗时
$layer_time = layer_end_time - layer_start_time
```

**性能瓶颈识别**：
```php
if ($layer_time > threshold) {
    $this->logBottleneck($layer, $layer_time);
}
```

#### SecurityAuditService（安全审计服务）
**职责**：安全事件记录和分析

**审计事件**：
```php
$auditEvent = [
    'timestamp' => now(),
    'event_type' => 'SQL_INJECTION',
    'ip' => '192.168.1.1',
    'threat_score' => 85,
    'details' => [...],
];
```

**威胁趋势分析**：
```php
// 检测攻击激增
if (attack_count > threshold) {
    $this->sendAlert('攻击激增检测');
}

// 检测新的攻击模式
if ($new_pattern_detected) {
    $this->sendAlert('新攻击模式检测');
}
```

### 3. 配置层（Configuration Layer）

#### ConfigManager（配置管理器）
**职责**：统一配置读取和管理

**核心功能**：
```php
// 获取配置（支持动态源）
public function get(string $key, mixed $default = null, mixed $params = null): mixed

// 设置配置
public function set(string $key, mixed $value): void

// 判断是否需要实时读取
protected function shouldReadRealtime(string $key): bool

// 解析可调用对象
protected function resolveCallable(mixed $handler): mixed
```

**动态配置源支持**：
```php
// 1. 静态数组
'key' => ['value1', 'value2']

// 2. 类方法调用
'key' => [SecurityConfig::class, 'getPatterns']

// 3. 字符串类方法
'key' => 'SecurityConfig::getPatterns'

// 4. 闭包函数
'key' => function() { return ['value1', 'value2']; }

// 5. 环境变量
'key' => env('SECURITY_KEY', 'default')
```

#### SecurityConfig（安全配置类）
**职责**：定义所有安全检测模式

**核心方法**：
```php
// 恶意请求体模式（包含所有攻击类型）
public static function getMaliciousBodyPatterns(): array

// SQL注入专项模式
public static function getSQLInjectionPatterns(): array

// XSS攻击专项模式
public static function getXSSAttackPatterns(): array

// 命令注入专项模式
public static function getCommandInjectionPatterns(): array

// 非法URL模式
public static function getIllegalUrlPatterns(): array

// 可疑User-Agent模式
public static function getSuspiciousUserAgents(): array

// 白名单User-Agent模式
public static function getWhitelistUserAgents(): array

// 禁止的文件扩展名
public static function getDisallowedExtensions(): array

// 禁止的MIME类型
public static function getDisallowedMimeTypes(): array

// 事件类型对应的封禁时长
public static function getEventTypeBanDuration(): array
```

**模式分类**：
```php
getMaliciousBodyPatterns() = array_merge(
    getCriticalThreatPatterns(),     // 关键威胁
    getCommonAttackPatterns(),       // 常见攻击
    getAdvancedThreatPatterns(),     // 高级威胁
    getEmergingThreatPatterns(),     // 新兴威胁
    getSQLInjectionPatterns(),       // SQL注入
    getXSSAttackPatterns(),          // XSS攻击
    getCommandInjectionPatterns()    // 命令注入
);
```

### 4. 工具层（Utility Layer）

#### ExceptionHandler（异常处理器）
**职责**：统一异常处理和日志记录

**核心方法**：
```php
// 安全执行（带异常捕获）
public static function safeExecute(callable $callback, mixed $default = null, string $context = ''): mixed

// 处理异常
public static function handle(Throwable $e, array $context = []): void

// 判断是否为递归异常
public static function isRecursionException(Throwable $e): bool
```

**使用场景**：
```php
// 懒加载服务
$this->whitelistService = ExceptionHandler::safeExecute(
    fn() => app(WhitelistSecurityService::class),
    null,
    'WhitelistService initialization'
);

// 安全执行操作
ExceptionHandler::safeExecute(
    fn() => $this->reloadConfig(),
    null,
    'Config hot reload'
);
```

### 5. 数据层（Data Layer）

#### SecurityIp（IP模型）
**职责**：IP数据持久化和管理

**字段定义**：
```php
protected $fillable = [
    'ip',               // IP地址
    'type',             // 类型：blacklist/whitelist/monitoring/suspicious
    'threat_score',      // 威胁评分：0-100
    'request_count',     // 请求次数
    'blocked_count',     // 拦截次数
    'last_seen_at',     // 最后访问时间
    'banned_until',      // 封禁到期时间
    'ban_reason',       // 封禁原因
    'notes',           // 备注
];
```

**查询作用域**：
```php
// 黑名单IP
public function scopeBlacklist($query)

// 白名单IP
public function scopeWhitelist($query)

// 监控中的IP
public function scopeMonitoring($query)

// 封禁中的IP
public function scopeBanned($query)
```

## 工作流程图

### 请求处理流程

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Request                        │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              SecurityMiddleware::handle()                 │
├─────────────────────────────────────────────────────────────┤
│ 1. 检查配置热重载                                    │
│ 2. 检查中间件是否启用                                  │
│ 3. 检查是否本地请求（可选）                             │
│ 4. 跳过资源文件                                         │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              执行防御层检查（按顺序）                       │
├─────────────────────────────────────────────────────────────┤
│ 1. IP白名单检查                                       │
│ 2. IP黑名单检查                                       │
│ 3. HTTP方法检查                                       │
│ 4. User-Agent检查                                     │
│ 5. 请求头检查                                         │
│ 6. URL检查（含白名单）                                │
│ 7. 文件上传检查                                       │
│ 8. 请求体检查                                         │
│ 9. 异常参数检查                                       │
│ 10. 速率限制检查                                       │
│ 11. SQL注入检查                                       │
│ 12. XSS攻击检查                                        │
│ 13. 命令注入检查                                       │
│ 14. 自定义规则检查                                     │
└────────────────────────┬────────────────────────────────┘
                     │
           ┌─────────┴─────────┐
           │                   │
           ▼                   ▼
     [拦截]              [通过]
           │                   │
           ▼                   ▼
┌──────────────┐    ┌──────────────┐
│ 拦截响应     │    │ 继续处理     │
│ (JSON/HTML)  │    │ 下一个中间件  │
└──────────────┘    └──────────────┘
```

### 威胁检测流程

```
┌─────────────────────────────────────────────────────────────┐
│              ThreatDetectionService                       │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. 获取配置（支持动态源）                               │
│    - 数组配置                                           │
│    - 类方法调用                                         │
│    - 闭包函数                                           │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. 预编译正则表达式（如果启用缓存）                        │
│    - 验证正则有效性                                      │
│    - 缓存编译结果                                        │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. 执行检测                                            │
│    - 递归检查输入数据                                    │
│    - 应用正则匹配                                        │
│    - 误报过滤                                           │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. 返回结果                                            │
│    - true: 检测到威胁                                    │
│    - false: 未检测到威胁                                   │
└─────────────────────────────────────────────────────────────┘
```

### IP管理流程

```
┌─────────────────────────────────────────────────────────────┐
│              IpManagerService                            │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. 检查IP类型                                          │
│    - 黑名单IP？                                         │
│    - 白名单IP？                                         │
│    - 监控中IP？                                         │
│    - 可疑IP？                                          │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. 记录访问（更新IP状态）                                │
│    - 增加请求次数                                        │
│    - 更新威胁评分                                        │
│    - 更新最后访问时间                                      │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. 应用自动检测规则（如果启用）                             │
│    - 检查是否达到封禁阈值                                  │
│    - 检查是否达到可疑阈值                                  │
│    - 检查触发次数是否超限                                  │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. 转换IP类型（如需要）                                  │
│    - 监控 → 可疑                                         │
│    - 监控 → 黑名单                                        │
│    - 可疑 → 黑名单                                        │
└────────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. 应用封禁（如果需要）                                   │
│    - 计算封禁时长（基础 + 自适应）                            │
│    - 设置封禁到期时间                                      │
│    - 记录封禁原因                                        │
└─────────────────────────────────────────────────────────────┘
```

## 性能优化策略

### 1. 正则表达式优化
- 预编译缓存，避免重复编译
- 使用原子组减少回溯
- 合并相似模式，减少匹配次数
- 早期返回，快速过滤

### 2. 缓存策略
- IP检查结果缓存
- 配置值缓存
- 正则表达式缓存
- 白名单缓存

### 3. 异常保护
- 懒加载服务，避免循环依赖
- 递归深度控制
- 异常捕获和降级
- 递归异常检测

### 4. 性能监控
- 请求时间统计
- 检测层耗时统计
- 内存使用监控
- 瓶颈识别

## 安全设计原则

### 1. 深度防御
- 多层防护，独立检测
- 不依赖单一防护措施
- 失败时降级放行

### 2. 最小权限
- 白名单路径保留必要检查
- 严格的文件类型限制
- 最低权限原则

### 3. 失败安全
- 异常时默认放行（可选）
- 可配置为严格模式
- 日志记录所有异常

### 4. 误报控制
- 多层误报过滤
- 白名单机制
- 常见合法模式豁免

## 扩展点

### 1. 自定义检测规则
```php
// 在配置中添加自定义规则
'custom_rules' => [
    [
        'id' => 'custom_001',
        'name' => '自定义规则',
        'pattern' => '/custom_pattern/i',
        'severity' => 'high',
        'action' => 'block',
    ],
],
```

### 2. 自定义处理器
```php
// 自定义安全处理逻辑
'custom_handler' => [CustomSecurityHandler::class, 'handle'],

// 自定义黑名单检查
'blacklist_handler' => [CustomBlacklistHandler::class, 'check'],

// 自定义白名单检查
'whitelist_handler' => [CustomWhitelistHandler::class, 'check'],

// 自定义警报处理
'alarm_handler' => [CustomAlarmHandler::class, 'send'],
```

### 3. 自定义指纹策略
```php
// 自定义速率限制指纹
'rate_limit_custom_handler' => function(Request $request) {
    return md5($request->ip() . $request->header('X-Custom-Header'));
},
```

## 故障排查

### 1. 配置问题
- 检查配置文件语法
- 验证正则表达式有效性
- 检查动态配置源返回值

### 2. 性能问题
- 检查缓存是否启用
- 优化正则表达式
- 调整检测层顺序

### 3. 误报问题
- 检查白名单配置
- 调整误报过滤规则
- 降低敏感度阈值
