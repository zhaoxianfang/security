# Laravel Security 安全最佳实践

> 生产环境安全配置与最佳实践指南

## 安全配置建议表格

| 配置项                                  | 生产环境推荐值 | 理由          | 安全级别 |
|--------------------------------------|---------|-------------|------|
| `enabled`                            | true    | 必须启用安全防护    | 高    |
| `enabled_type`                       | global  | 全局防护，无遗漏    | 高    |
| `ignore_local`                       | false   | 生产环境不忽略本地请求 | 中    |
| `log_level`                          | warning | 记录重要事件      | 中    |
| `enable_debug_logging`               | false   | 避免泄露调试信息    | 高    |
| `log_details`                        | true    | 保留详细日志用于审计  | 中    |
| `block_on_exception`                 | true    | 异常时拒绝请求     | 中    |
| `enable_rate_limiting`               | true    | 防止DDoS和暴力破解 | 高    |
| `enable_anomaly_detection`           | true    | 检测异常行为      | 高    |
| `enable_sql_injection_detection`     | true    | 防止SQL注入     | 高    |
| `enable_xss_detection`               | true    | 防止XSS攻击     | 高    |
| `enable_command_injection_detection` | true    | 防止命令注入      | 高    |
| `enable_file_check`                  | true    | 防止恶意文件上传    | 高    |
| `enable_pattern_cache`               | true    | 提升性能        | 低    |
| `enable_ip_cache`                    | true    | 提升性能        | 低    |
| `ip_auto_detection.enabled`          | true    | 自动识别威胁      | 高    |
| `adaptive_ban_duration.enabled`      | true    | 根据威胁程度调整    | 中    |

## 1. 基础安全配置

### 启用全局防护
```php
'enabled' => true,
'enabled_type' => 'global', // 推荐全局模式
```

**理由**：
- 全局防护确保所有请求都经过安全检查
- 避免遗漏任何路由
- 简化配置，减少人为错误

### 日志配置
```php
'log_level' => 'warning', // 记录警告及以上级别
'enable_debug_logging' => false, // 生产环境关闭
'log_details' => true, // 记录详细信息用于审计
```

**理由**：
- 调试日志可能泄露系统信息
- 详细日志有助于事后调查
- 日志级别平衡性能和可追溯性

### 异常处理
```php
'block_on_exception' => true, // 异常时拒绝请求
```

**理由**：
- 系统异常时拒绝请求，避免潜在风险
- 可以配置为false（默认），避免影响业务
- 根据安全需求灵活配置

## 2. 速率限制配置

### 推荐配置
```php
'enable_rate_limiting' => true,
'rate_limits' => [
    'minute' => 300,   // 每分钟300次
    'hour' => 10000,   // 每小时10000次
    'day' => 100000,   // 每天100000次
],
'rate_limit_strategy' => 'ip_ua_path', // 细粒度控制
```

**理由**：
- 防止暴力破解攻击
- 防止DDoS攻击
- 细粒度策略可绕过简单的IP轮换

### 根据业务调整
```php
// API服务：更严格的限制
'rate_limits' => [
    'minute' => 100,
    'hour' => 5000,
    'day' => 50000,
],

// 企业内部应用：宽松限制
'rate_limits' => [
    'minute' => 600,
    'hour' => 20000,
    'day' => 200000,
],
```

## 3. IP安全配置

### 自动威胁检测
```php
'ip_auto_detection' => [
    'enabled' => true,
    'blacklist_threshold' => 80.0,  // 高威胁评分才转黑名单
    'suspicious_threshold' => 50.0,  // 中等威胁转为可疑
    'max_triggers' => 5,            // 5次触发自动封禁
    'add_threat_score' => 10.00,     // 每次拦截加10分
    'reduce_threat_score' => 1.00,  // 每次成功减1分
    'decay_rate_per_hour' => 0.3,    // 每小时衰减0.3分
],
```

**理由**：
- 高阈值避免误封
- 评分机制灵活适应
- 自动衰减允许IP"改过"

### 自适应封禁
```php
'adaptive_ban_duration' => [
    'enabled' => true,
    'multipliers' => [
        90 => 10,  // 极度危险IP，封禁10倍时长
        80 => 5,   // 高危IP，封禁5倍时长
        70 => 3,   // 高风险IP，封禁3倍时长
        60 => 2,   // 中风险IP，封禁2倍时长
    ],
],
```

**理由**：
- 高威胁IP延长封禁时间
- 避免频繁封禁和解除
- 更有效阻挡持续攻击者

## 4. URL白名单最佳实践

### ❌ 错误示例
```php
'url_whitelist_paths' => [
    'api/*',       // 危险！允许所有API路径
    'public/*',     // 危险！公开所有资源
    'static/*',     // 危险！静态文件
],
```

### ✅ 正确示例
```php
'url_whitelist_paths' => [
    // 静态资源（精确路径）
    ['path' => 'robots.txt', 'level' => 'low'],
    ['path' => 'favicon.ico', 'level' => 'low'],
    ['path' => 'sitemap.xml', 'level' => 'low'],

    // 健康检查端点（方法限制）
    ['path' => 'health', 'methods' => ['GET'], 'level' => 'low'],
    ['path' => 'status', 'methods' => ['GET'], 'level' => 'low'],
    ['path' => 'ping', 'methods' => ['GET'], 'level' => 'low'],
],
```

**理由**：
- 精确路径避免安全漏洞
- 方法限制降低攻击面
- 低级别仍保留必要检查

### 白名单安全级别
```php
'whitelist_security_policy' => [
    // 始终检查项（无论什么级别都检查）
    'always_check' => [
        'ip_blacklist',        // IP黑名单必须检查
        'rate_limit',          // 频率限制必须检查
        'body_patterns',       // 恶意内容必须检查
        'file_upload',         // 文件上传必须检查
        'sql_injection',       // SQL注入必须检查
        'xss_attack',          // XSS必须检查
        'command_injection',    // 命令注入必须检查
    ],
],
```

**理由**：
- 关键安全检查不能跳过
- 即便是白名单路径也要防护
- 降低白名单被利用的风险

## 5. 文件上传安全

### 严格限制
```php
'enable_file_check' => true,
'disallowed_extensions' => [SecurityConfig::class, 'getDisallowedExtensions'],
'disallowed_mime_types' => [SecurityConfig::class, 'getDisallowedMimeTypes'],
'allowed_extensions_whitelist' => [
    'jpg', 'jpeg', 'png', 'gif',  // 仅允许图片
    'pdf', 'doc', 'docx',         // 仅允许文档
],
'max_file_size' => 10 * 1024 * 1024,  // 限制10MB
'enable_file_content_check' => true,  // 启用内容检查
```

**理由**：
- 白名单机制更安全
- 限制文件大小防止DoS
- 内容检查防止伪装文件

### 危险文件类型
```php
// 禁止的可执行文件
'exe', 'bat', 'sh', 'php', 'jsp', 'asp',

// 禁止的宏文档
'docm', 'xlsm', 'pptm',

// 禁止的脚本文件
'js', 'vbs', 'wsf', 'ps1',
```

## 6. 防御层配置

### 启用所有防御层
```php
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
```

**理由**：
- 深度防御，多层防护
- 不依赖单一防护措施
- 全面覆盖各种攻击向量

### 根据业务调整
```php
// 内部应用：可以放宽部分检查
'defense_layers' => [
    'ip_whitelist' => false,  // 内部IP不需要
    'ip_blacklist' => true,
    // ... 其他检查
],

// 公网API：需要严格检查
'defense_layers' => [
    'ip_whitelist' => true,
    'ip_blacklist' => true,
    'method_check' => true,   // 严格检查方法
    'user_agent_check' => true, // 严格检查UA
    // ... 其他检查
],
```

## 7. 正则表达式安全

### 使用预定义模式
```php
// ✅ 推荐：使用SecurityConfig预定义模式
'body_patterns' => [SecurityConfig::class, 'getMaliciousBodyPatterns'],
'sql_injection_patterns' => [SecurityConfig::class, 'getSQLInjectionPatterns'],
'xss_attack_patterns' => [SecurityConfig::class, 'getXSSAttackPatterns'],
```

**理由**：
- 预定义模式经过测试
- 覆盖全面的安全威胁
- 持续更新和维护

### 自定义正则注意事项
```php
// ❌ 错误：过于宽松的正则
'custom_patterns' => [
    '/<script>/i',  // 容易绕过
],

// ✅ 正确：严格且精确的正则
'custom_patterns' => [
    '/<script\b[^>]*>.*?<\/script>/is',  // 完整标签匹配
],
```

**理由**：
- 过于宽松容易被绕过
- 完整匹配更安全
- 使用原子组减少回溯

## 8. 性能与安全平衡

### 缓存策略
```php
'enable_pattern_cache' => true,   // 正则缓存
'enable_ip_cache' => true,        // IP缓存
'cache_ttl' => 3600,            // 缓存1小时
'ip_database.cache_ttl' => 300,  // IP缓存5分钟
```

**理由**：
- 缓存提升性能
- 合理的TTL平衡时效性
- IP缓存TTL较短（快速更新）

### 白名单缓存
```php
'hot_reload' => [
    'enabled' => true,
    'realtime_keys' => [
        'url_whitelist_paths',  // 白名单实时生效
        'enabled',
        'defense_layers',
    ],
    'no_cache_keys' => [
        'url_whitelist_paths',
        'enabled',
    ],
],
```

**理由**：
- 白名单变更需要立即生效
- 实时读取避免缓存延迟
- 其他配置可以缓存

## 9. 监控和告警

### 自定义警报
```php
// 创建自定义警报处理器
'alarm_handler' => [App\Services\SecurityAlarmHandler::class, 'send'],

class SecurityAlarmHandler
{
    public static function send(array $alertData): void
    {
        // 发送邮件警报
        Mail::to('security@example.com')->send(new SecurityAlert($alertData));

        // 发送钉钉/企业微信告警
        DingTalk::send($alertData);

        // 发送Slack告警
        Slack::send($alertData);
    }
},
```

### 关键事件告警
```php
// 高危事件立即告警
$highPriorityEvents = [
    'SQL_INJECTION',
    'XSS_ATTACK',
    'COMMAND_INJECTION',
    'MaliciousRequest',
];

if (in_array($alertData['type'], $highPriorityEvents)) {
    // 立即发送高优先级告警
}
```

## 10. 定期维护

### 清理过期记录
```bash
# 创建定时任务清理过期IP
php artisan schedule:run

# 在app/Console/Kernel.php中
$schedule->command('security:cleanup')->daily();
```

### 定期审查日志
```bash
# 检查被拦截的请求
grep "安全拦截" storage/logs/laravel.log

# 检查异常情况
grep "异常" storage/logs/laravel.log

# 分析攻击模式
grep "SQL注入\|XSS攻击\|命令注入" storage/logs/laravel.log | wc -l
```

### 更新威胁情报
```php
// 定期更新安全模式
'body_patterns' => function() {
    // 从外部威胁情报源获取最新模式
    $latestPatterns = ThreatIntelService::getLatestPatterns();
    return array_merge(
        SecurityConfig::getMaliciousBodyPatterns(),
        $latestPatterns
    );
},
```

## 11. 环境差异配置

### 开发环境
```php
'debug' => true,
'enabled' => true,
'enable_debug_logging' => true,
'block_on_exception' => false,  // 开发环境异常时放行
'log_level' => 'debug',
```

### 测试环境
```php
'debug' => true,
'enabled' => true,
'enable_debug_logging' => true,
'block_on_exception' => false,
'log_level' => 'info',
```

### 生产环境
```php
'debug' => false,
'enabled' => true,
'enable_debug_logging' => false,  // 关闭调试日志
'block_on_exception' => true,   // 异常时拒绝请求
'log_level' => 'warning',
```

## 12. 安全审计清单

### 部署前检查
- [ ] 启用所有防御层
- [ ] 配置适当的速率限制
- [ ] 启用IP自动检测
- [ ] 配置自适应封禁
- [ ] 配置安全警报
- [ ] 测试白名单功能
- [ ] 测试黑名单功能
- [ ] 测试速率限制
- [ ] 验证日志输出
- [ ] 检查性能影响

### 定期检查
- [ ] 审查安全日志
- [ ] 分析攻击趋势
- [ ] 检查IP黑名单
- [ ] 更新威胁模式
- [ ] 测试告警机制
- [ ] 清理过期记录
- [ ] 评估配置有效性

### 事件响应
- [ ] 确认安全事件
- [ ] 收集证据信息
- [ ] 评估影响范围
- [ ] 采取缓解措施
- [ ] 更新防护规则
- [ ] 记录事件过程
- [ ] 进行事后分析

## 13. 常见安全场景

### 场景1：遭受SQL注入攻击
```php
// 配置加强检测
'enable_sql_injection_detection' => true,
'sql_injection_patterns' => [SecurityConfig::class, 'getSQLInjectionPatterns'],

// 响应措施
$ip->type = 'blacklist';
$ip->banned_until = now()->addDays(7);  // 封禁7天
$ip->save();
```

### 场景2：遭受XSS攻击
```php
// 配置加强检测
'enable_xss_detection' => true,
'xss_attack_patterns' => [SecurityConfig::class, 'getXSSAttackPatterns'],

// 响应措施
$ip->type = 'blacklist';
$ip->banned_until = now()->addDays(3);  // 封禁3天
$ip->save();
```

### 场景3：遭受DDoS攻击
```php
// 配置严格速率限制
'rate_limits' => [
    'minute' => 60,    // 降低到每分钟60次
    'hour' => 2000,
    'day' => 20000,
],

// 启用IP自动检测
'ip_auto_detection' => [
    'enabled' => true,
    'blacklist_threshold' => 60.0,  // 降低阈值
    'max_triggers' => 3,             // 降低触发次数
],
```

### 场景4：发现0day漏洞
```php
// 立即添加自定义规则
'rule_engine.custom_rules' => [
    [
        'id' => 'zero_day_001',
        'name' => '0day漏洞防护',
        'pattern' => '/vulnerable_pattern/i',
        'severity' => 'critical',
        'action' => 'block',
    ],
],

// 启用警报
'alarm_handler' => function($alertData) {
    if ($alertData['type'] === 'CUSTOM_RULE') {
        // 立即告警
        SecurityAlert::send($alertData);
    }
},
```

## 14. 安全工具集成

### WAF集成
```php
// 与现有WAF协同工作
'defense_layers' => [
    // 基础检查仍保留
    'rate_limit' => true,
    'ip_blacklist' => true,

    // 依赖WAF处理部分检查
    'method_check' => false,   // WAF已处理
    'user_agent_check' => false, // WAF已处理
],
```

### SIEM集成
```php
// 发送安全事件到SIEM系统
'alarm_handler' => function($alertData) {
    // 发送到Splunk
    Splunk::send($alertData);

    // 发送到ELK
    ELK::send($alertData);
},
```

### SOC集成
```php
// 集成安全运营中心
'alarm_handler' => function($alertData) {
    // 自动创建工单
    TicketSystem::create([
        'type' => 'security',
        'priority' => $this->getPriority($alertData['type']),
        'data' => $alertData,
    ]);
},
```

## 15. 合规性要求

### GDPR合规
```php
// 记录数据访问
$logData = [
    'timestamp' => now(),
    'ip' => $request->ip(),
    'action' => 'blocked',
    'reason' => $reason,
    // ⚠️ 不要记录敏感数据
    // 'user_agent' => $request->userAgent(), // 可能包含设备指纹
    // 'referer' => $request->header('referer'), // 可能包含个人信息
],
```

### 等保2.0合规
```php
// 启用完整审计日志
'log_details' => true,
'log_level' => 'info',

// IP记录保留6个月
$ip->retention_days = 180;
```

### PCI DSS合规
```php
// 严格的速率限制
'rate_limits' => [
    'minute' => 50,
    'hour' => 1000,
],

// 记录所有失败尝试
'log_level' => 'info',
```

## 总结

### 必做事项
1. ✅ 启用所有防御层
2. ✅ 配置适当的速率限制
3. ✅ 启用IP自动检测
4. ✅ 严格配置白名单
5. ✅ 启用安全警报
6. ✅ 定期审查日志
7. ✅ 更新威胁模式

### 禁忌事项
1. ❌ 在白名单中使用通配符
2. ❌ 禁用必要的防御层
3. ❌ 在生产环境启用调试日志
4. ❌ 允许上传危险文件类型
5. ❌ 配置过于宽松的速率限制
6. ❌ 忽视安全告警
7. ❌ 不定期更新配置
