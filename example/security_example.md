# security.php 配置文件用法示例

## 配置文件
```php
<?php

use zxf\Security\Config\SecurityConfig;
use App\Services\CustomSecurityService;

/**
 * 安全中间件配置文件 - 完整用法指南
 *
 * 配置特性：
 * 1. 支持动态配置源（类方法、闭包、数组等）
 * 2. 环境变量覆盖支持
 * 3. 性能优化参数
 * 4. 完整的类型提示和默认值
 */

return [

    // ==================== 基础配置 ====================

    /**
     * 是否启用安全中间件
     *
     * 用法示例：
     * - 布尔值：直接启用或禁用
     * - 闭包：根据条件动态启用
     * - 环境变量：通过 .env 文件控制
     *
     * 示例：
     */
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),

    // 动态启用示例
    'enabled' => function() {
        // 只在生产环境启用
        return app()->environment('production');
    },

    // 基于时间启用示例
    'enabled' => function() {
        // 在维护时段禁用
        $hour = now()->hour;
        return $hour >= 8 && $hour <= 22; // 只在 8:00-22:00 启用
    },
    
    // 使用固定值 global|single
    'enabled_type' => 'global',

    /**
     * 日志记录级别
     *
     * 可选值：debug, info, notice, warning, error, critical, alert, emergency
     *
     * 示例：
     */
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),

    // 动态日志级别示例
    'log_level' => function() {
        return app()->isLocal() ? 'debug' : 'warning';
    },

    /**
     * 是否启用调试日志
     *
     * 启用后会记录详细的调试信息，建议在排查问题时开启
     *
     * 示例：
     */
    'enable_debug_logging' => env('SECURITY_DEBUG_LOGGING', false),

    // 开发环境启用调试
    'enable_debug_logging' => app()->isLocal(),

    /**
     * 是否启用性能日志
     *
     * 启用后会记录性能统计信息，用于监控和优化
     *
     * 示例：
     */
    'enable_performance_logging' => env('SECURITY_PERFORMANCE_LOGGING', false),

    // ==================== 速率限制配置 ====================

    /**
     * 是否启用速率限制
     *
     * 防止暴力破解和DDoS攻击
     *
     * 示例：
     */
    'enable_rate_limiting' => env('SECURITY_RATE_LIMITING_ENABLED', true),

    // 对特定路径禁用速率限制
    'enable_rate_limiting' => function() {
        $path = request()->path();
        return !in_array($path, ['api/health', 'status']);
    },

    /**
     * 速率限制配置
     *
     * 定义不同时间窗口的最大请求数
     * 支持分钟、小时、天级别的限制
     *
     * 示例：
     */
    'rate_limits' => [
        'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 60),
        'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 1000),
        'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 10000),
    ],

    // 动态速率限制示例
    'rate_limits' => function() {
        $ip = request()->ip();

        // 对已知爬虫放宽限制
        if ($this->isSearchEngineBot($ip)) {
            return [
                'minute' => 300,  // 搜索引擎：300次/分钟
                'hour' => 5000,   // 搜索引擎：5000次/小时
                'day' => 50000,   // 搜索引擎：50000次/天
            ];
        }

        // 默认限制
        return [
            'minute' => 60,
            'hour' => 1000,
            'day' => 10000,
        ];
    },

    // 基于用户类型的速率限制
    'rate_limits' => [CustomSecurityService::class, 'getRateLimitsByUser'],

    // ==================== HTTP方法配置 ====================

    /**
     * 允许的HTTP方法
     *
     * 只允许列表中的HTTP方法，其他方法将被拒绝
     *
     * 示例：
     */

    // 标准RESTful API方法
    'allowed_methods' => [
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS',
        'HEAD',
    ],

    // 只读API（GET only）
    'allowed_methods' => ['GET', 'HEAD', 'OPTIONS'],

    // 动态方法控制
    'allowed_methods' => function() {
        $path = request()->path();

        // API路径允许所有方法
        if (str_starts_with($path, 'api/')) {
            return ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
        }

        // Web路径只允许GET和POST
        return ['GET', 'POST', 'HEAD', 'OPTIONS'];
    },

    // ==================== 请求体检查配置 ====================

    /**
     * 请求体正则表达式模式
     *
     * 用于检测恶意请求内容的正则表达式模式
     *
     * 示例：
     */

    // 使用默认模式
    'body_patterns' => [SecurityConfig::class, 'getMaliciousBodyPatterns'],

    // 自定义模式
    'body_patterns' => [
        // XSS攻击检测
        '/<script\b[^>]*>([\s\S]*?)<\/script>/i',
        '/javascript:\s*/i',
        '/on\w+\s*=\s*["\']?/i',

        // SQL注入检测
        '/\b(union\s+select|select\s+[\w*]+\s+from|insert\s+into|update\s+\w+\s+set)\b/i',
        '/--\s+/',
        '/\/\*[\s\S]*?\*\//',

        // 自定义业务规则
        '/\b(admin|root|system)\b.*\b(password|passwd|pwd)\b/i',
    ],

    // 动态模式生成
    'body_patterns' => function() {
        $patterns = SecurityConfig::getMaliciousBodyPatterns();

        // 添加自定义业务规则
        $patterns[] = '/\bconfidential\b.*\b(leak|expose|share)\b/i';
        $patterns[] = '/\binternal\b.*\b(document|file|data)\b/i';

        return $patterns;
    },

    /**
     * 不验证请求体的白名单路径
     *
     * 这些路径的请求体将跳过恶意内容检测
     * 常用于API接口、健康检查等
     *
     * 示例：
     */

    // 基础白名单
    'body_whitelist_paths' => [
        'api/health',
        'api/status',
        'health',
        'status',
        'monitoring/ping',
    ],

    // 动态白名单
    'body_whitelist_paths' => function() {
        $paths = [
            'api/health',
            'api/status',
            'webhook/*',  // 通配符支持
        ];

        // 开发环境添加更多白名单
        if (app()->isLocal()) {
            $paths[] = 'tinker';
            $paths[] = 'debugbar/*';
        }

        return $paths;
    },

    // 基于内容类型的白名单
    'body_whitelist_paths' => [CustomSecurityService::class, 'getBodyWhitelistPaths'],

    // ==================== URL检查配置 ====================

    /**
     * URL正则表达式模式
     *
     * 用于检测非法URL路径的正则表达式模式
     *
     * 示例：
     */

    // 使用默认模式
    'url_patterns' => [SecurityConfig::class, 'getIllegalUrlPatterns'],

    // 自定义URL保护规则
    'url_patterns' => [
        // 保护配置文件
        '/\.env$/i',
        '/\.env\./i',
        '/config\.php$/i',
        '/database\.php$/i',

        // 保护日志文件
        '/\.log$/i',
        '/logs\//i',
        '/storage\/logs\//i',

        // 保护备份文件
        '/\.bak$/i',
        '/\.old$/i',
        '/backup\//i',

        // 自定义业务路径
        '/admin\/config\//i',
        '/system\/settings\//i',
    ],

    // ==================== User-Agent检查配置 ====================

    /**
     * 禁止的User-Agent模式
     *
     * 匹配这些模式的User-Agent将被拒绝
     *
     * 示例：
     */

    // 使用默认模式
    'suspicious_user_agents' => [SecurityConfig::class, 'getSuspiciousUserAgents'],

    // 自定义恶意UA模式
    'suspicious_user_agents' => [
        // 安全扫描工具
        '/sqlmap/i',
        '/nikto/i',
        '/nessus/i',
        '/metasploit/i',

        // 恶意爬虫
        '/evil-bot/i',
        '/malicious-crawler/i',
        '/scanner/i',

        // 自定义业务规则
        '/competitor-scraper/i',
        '/price-monitor/i',
    ],

    /**
     * 白名单User-Agent模式
     *
     * 合法的搜索引擎和爬虫User-Agent
     *
     * 示例：
     */

    // 使用默认模式
    'whitelist_user_agents' => [SecurityConfig::class, 'getWhitelistUserAgents'],

    // 自定义白名单
    'whitelist_user_agents' => [
        '/googlebot/i',
        '/bingbot/i',
        '/slurp/i',
        '/duckduckbot/i',
        '/baiduspider/i',
        '/yandexbot/i',

        // 业务合作爬虫
        '/partner-crawler/i',
        '/approved-monitor/i',
    ],

    // ==================== 文件上传检查配置 ====================

    /**
     * 禁止上传的文件扩展名
     *
     * 这些扩展名的文件将被拒绝上传
     *
     * 示例：
     */

    // 使用默认列表
    'disallowed_extensions' => [SecurityConfig::class, 'getDisallowedExtensions'],

    // 自定义禁止列表
    'disallowed_extensions' => [
        // 可执行文件
        'exe', 'bat', 'cmd', 'com', 'msi', 'dll',

        // 脚本文件
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7',
        'jsp', 'asp', 'aspx',

        // 配置文件
        'env', 'config', 'ini', 'conf',

        // 业务相关危险文件
        'sql', 'backup', 'dump',
    ],

    /**
     * 禁止上传的MIME类型
     *
     * 这些MIME类型的文件将被拒绝上传
     *
     * 示例：
     */

    // 使用默认列表
    'disallowed_mime_types' => [SecurityConfig::class, 'getDisallowedMimeTypes'],

    // 自定义MIME类型黑名单
    'disallowed_mime_types' => [
        'application/x-php',
        'text/x-php',
        'application/x-httpd-php',
        'application/x-sh',
        'application/x-bat',
        'application/x-msdownload',
    ],

    /**
     * 最大文件大小（字节）
     *
     * 允许上传的最大文件大小
     *
     * 示例：
     */
    'max_file_size' => env('SECURITY_MAX_FILE_SIZE', 10 * 1024 * 1024), // 10MB

    // 动态文件大小限制
    'max_file_size' => function() {
        $path = request()->path();

        // 头像上传限制较小
        if (str_contains($path, 'avatar')) {
            return 2 * 1024 * 1024; // 2MB
        }

        // 文档上传限制中等
        if (str_contains($path, 'document')) {
            return 20 * 1024 * 1024; // 20MB
        }

        // 默认限制
        return 10 * 1024 * 1024; // 10MB
    },

    /**
     * 是否启用文件内容检查
     *
     * 启用后会对上传文件的内容进行安全扫描
     * 注意：这会增加服务器负载
     *
     * 示例：
     */
    'enable_file_content_check' => env('SECURITY_FILE_CONTENT_CHECK', false),

    // 对大文件禁用内容检查
    'enable_file_content_check' => function() {
        $files = request()->allFiles();
        foreach ($files as $file) {
            // 超过5MB的文件不进行内容检查
            if ($file->getSize() > 5 * 1024 * 1024) {
                return false;
            }
        }
        return true;
    },

    // ==================== 高级检测配置 ====================

    /**
     * 是否启用高级检测
     *
     * 启用更复杂的安全检测逻辑
     *
     * 示例：
     */
    'enable_advanced_detection' => env('SECURITY_ADVANCED_DETECTION', true),

    /**
     * 是否启用指纹识别
     *
     * 通过请求特征识别可疑客户端
     *
     * 示例：
     */
    'enable_fingerprinting' => env('SECURITY_FINGERPRINTING', true),

    // 对API禁用指纹识别
    'enable_fingerprinting' => function() {
        return !request()->is('api/*');
    },

    /**
     * 是否启用异常检测
     *
     * 检测异常的请求参数和行为
     *
     * 示例：
     */
    'enable_anomaly_detection' => env('SECURITY_ANOMALY_DETECTION', true),

    /**
     * 异常检测阈值
     *
     * 异常检测的敏感度阈值
     *
     * 示例：
     */
    'anomaly_thresholds' => [
        'max_parameters' => 100,           // 最大参数数量
        'max_parameter_length' => 255,     // 最大参数值长度
        'max_headers' => 50,               // 最大头部数量
        'max_url_length' => 2048,          // 最大URL长度
    ],

    // 动态阈值配置
    'anomaly_thresholds' => function() {
        $baseThresholds = [
            'max_parameters' => 100,
            'max_parameter_length' => 255,
            'max_headers' => 50,
            'max_url_length' => 2048,
        ];

        // API接口允许更多参数
        if (request()->is('api/*')) {
            $baseThresholds['max_parameters'] = 200;
            $baseThresholds['max_parameter_length'] = 1024;
        }

        return $baseThresholds;
    },

    // ==================== 缓存配置 ====================

    /**
     * 缓存生存时间（秒）
     *
     * 安全相关数据的缓存时间
     *
     * 示例：
     */
    'cache_ttl' => env('SECURITY_CACHE_TTL', 3600), // 1小时

    // 动态缓存时间
    'cache_ttl' => function() {
        // 生产环境缓存时间较长
        if (app()->environment('production')) {
            return 7200; // 2小时
        }

        // 开发环境缓存时间较短
        return 600; // 10分钟
    },

    /**
     * 默认封禁时长（秒）
     *
     * 检测到安全威胁时的默认封禁时间
     *
     * 示例：
     */
    'ban_duration' => env('SECURITY_BAN_DURATION', 3600), // 1小时

    // 基于威胁级别的封禁时间
    'ban_duration' => function() {
        $threatLevel = $this->assessThreatLevel();

        return match($threatLevel) {
            'low' => 1800,      // 30分钟
            'medium' => 3600,   // 1小时
            'high' => 86400,    // 24小时
            'critical' => 604800, // 7天
            default => 3600,
        };
    },

    /**
     * 最大封禁时长（秒）
     *
     * 最大封禁时间，防止设置过长
     *
     * 示例：
     */
    'max_ban_duration' => env('SECURITY_MAX_BAN_DURATION', 86400), // 24小时

    // ==================== 异常处理配置 ====================

    /**
     * 异常时是否阻止请求
     *
     * 安全中间件发生异常时是否拒绝请求
     * 建议在生产环境设置为true，开发环境设置为false
     *
     * 示例：
     */
    'block_on_exception' => env('SECURITY_BLOCK_ON_EXCEPTION', false),

    // 生产环境阻止，开发环境放行
    'block_on_exception' => app()->isProduction(),

    // ==================== 响应格式配置 ====================

    /**
     * AJAX响应格式
     *
     * 拦截请求时返回的JSON响应格式
     *
     * 示例：
     */
    'ajax_response_format' => [
        'code' => 'code',
        'message' => 'message',
        'data' => 'data',
    ],

    // 自定义响应格式
    'ajax_response_format' => [
        'success' => 'success',
        'error' => 'error',
        'message' => 'message',
        'payload' => 'payload',
    ],

    // 动态响应格式
    'ajax_response_format' => function() {
        if (request()->is('api/v1/*')) {
            return [
                'status' => 'status',
                'message' => 'message',
                'code' => 'code',
            ];
        }

        return [
            'code' => 'code',
            'message' => 'message',
            'data' => 'data',
        ];
    },

    /**
     * 自定义错误页面视图
     *
     * 安全拦截时显示的自定义视图
     *
     * 示例：
     */
    'error_view' => 'security::blocked',

    // 自定义视图路径
    'error_view' => 'errors.security',

    // 基于拦截类型使用不同视图
    'error_view' => function() {
        $type = $this->getBlockType(); // 假设这个方法存在

        return match($type) {
            'RateLimit' => 'errors.rate-limit',
            'Blacklist' => 'errors.blacklist',
            'Malicious' => 'errors.malicious',
            default => 'errors.security',
        };
    },

    /**
     * 自定义错误页面数据
     *
     * 传递给错误视图的额外数据
     *
     * 示例：
     */
    'error_view_data' => [],

    // 传递额外数据到视图
    'error_view_data' => [
        'support_email' => 'security@example.com',
        'contact_phone' => '+1-234-567-8900',
        'help_url' => 'https://help.example.com/security',
    ],

    // 动态视图数据
    'error_view_data' => function() {
        return [
            'app_name' => config('app.name'),
            'current_year' => date('Y'),
            'support_contact' => env('SUPPORT_EMAIL', 'support@example.com'),
            'incident_id' => Str::uuid(),
        ];
    },

    // ==================== 自定义处理配置 ====================

    /**
     * 自定义安全处理逻辑
     *
     * 自定义的安全检查逻辑
     * 格式：[Class, method] 或 \Namespace\Class::method
     *
     * 示例：
     */
    'custom_handler' => env('SECURITY_CUSTOM_HANDLE', null),

    // 使用自定义安全检查
    'custom_handler' => [CustomSecurityService::class, 'checkCustomSecurity'],

    // 闭包自定义检查
    'custom_handler' => function($request) {
        // 检查业务逻辑安全
        if ($this->isSuspiciousBusinessOperation($request)) {
            return [
                'blocked' => true,
                'message' => '检测到可疑业务操作',
                'type' => 'BusinessRule',
            ];
        }

        return ['blocked' => false];
    },

    /**
     * 黑名单处理逻辑
     *
     * 自定义的黑名单检查逻辑
     *
     * 示例：
     */
    'blacklist_handler' => env('SECURITY_BLACKLIST_HANDLE', null),

    // 集成第三方黑名单服务
    'blacklist_handler' => [CustomSecurityService::class, 'checkThirdPartyBlacklist'],

    /**
     * 安全警报处理逻辑
     *
     * 发送安全警报的自定义逻辑
     *
     * 示例：
     */
    'alarm_handler' => env('SECURITY_ALARM_HANDLE', null),

    // 发送到多个通知渠道
    'alarm_handler' => [CustomSecurityService::class, 'sendSecurityAlerts'],

    // 闭包警报处理
    'alarm_handler' => function($alertData) {
        // 发送到Slack
        if (config('services.slack.webhook_url')) {
            \Illuminate\Support\Facades\Http::post(config('services.slack.webhook_url'), [
                'text' => "🚨 安全警报: {$alertData['type']}",
                'attachments' => [[
                    'fields' => [
                        ['title' => 'IP', 'value' => $alertData['ip'], 'short' => true],
                        ['title' => '路径', 'value' => $alertData['url'], 'short' => true],
                        ['title' => '时间', 'value' => $alertData['timestamp'], 'short' => true],
                    ]
                ]]
            ]);
        }

        // 发送邮件
        \Illuminate\Support\Facades\Mail::to(config('security.notification_email'))
            ->send(new \App\Mail\SecurityAlert($alertData));
    },

    // ==================== 性能优化配置 ====================

    /**
     * 是否启用正则表达式缓存
     *
     * 启用后正则表达式将被预编译缓存，提升性能
     *
     * 示例：
     */
    'enable_pattern_cache' => env('SECURITY_PATTERN_CACHE', true),

    /**
     * 是否启用指纹缓存
     *
     * 启用后请求指纹将被缓存，避免重复计算
     *
     * 示例：
     */
    'enable_fingerprint_cache' => env('SECURITY_FINGERPRINT_CACHE', true),

    /**
     * 最大递归深度
     *
     * 递归检查输入数据时的最大深度，防止栈溢出
     *
     * 示例：
     */
    'max_recursion_depth' => env('SECURITY_MAX_RECURSION_DEPTH', 10),

    // 动态递归深度
    'max_recursion_depth' => function() {
        // 对复杂API允许更深递归
        if (request()->is('api/*') && request()->isJson()) {
            return 20;
        }

        return 10;
    },

    /**
     * 批量处理大小
     *
     * 批量处理数据时的大小限制，防止内存溢出
     *
     * 示例：
     */
    'batch_size' => env('SECURITY_BATCH_SIZE', 1000),

];
```

## CustomSecurityService

> 说明：CustomSecurityService 中的调用对象支持：
>  - public static function funcName()
>  - public function funcName()

```php
<?php

namespace App\Services;

class CustomSecurityService
{
    public static function getRateLimitsByUser()
    {
        $user = auth()->user();
        
        if (!$user) {
            return ['minute' => 60, 'hour' => 1000, 'day' => 10000];
        }
        
        return match($user->role) {
            'admin' => ['minute' => 1000, 'hour' => 10000, 'day' => 100000],
            'premium' => ['minute' => 500, 'hour' => 5000, 'day' => 50000],
            'basic' => ['minute' => 100, 'hour' => 2000, 'day' => 20000],
            default => ['minute' => 60, 'hour' => 1000, 'day' => 10000],
        };
    }
    
    public static function getWhitelistIps()
    {
        // 从多个源获取白名单IP
        $ips = array_merge(
            config('security.static_whitelist_ips', []),
            self::getDatabaseWhitelistIps(),
            self::getApiWhitelistIps()
        );
        
        return array_unique($ips);
    }
    
    public static function checkCustomSecurity($request)
    {
        // 自定义业务安全检查
        if (self::isSuspiciousGeoLocation($request)) {
            return [
                'blocked' => true,
                'message' => '检测到可疑地理位置访问',
                'type' => 'Geolocation',
            ];
        }
        
        return ['blocked' => false];
    }
}
```