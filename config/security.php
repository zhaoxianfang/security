<?php

use zxf\Security\Config\SecurityConfig;

/**
 * 安全中间件配置文件
 *
 * 配置特性：
 * 1. 所有配置项都有实际代码使用
 * 2. 支持动态配置源（类方法、闭包、数组等）
 * 3. 环境变量覆盖支持
 * 4. 性能优化参数
 * 5. 完整的类型提示和默认值
 * 6. 详细的中文注释和使用示例
 */

return [

    // ==================== 基础配置 ====================

    /**
     * 是否启用安全中间件
     *
     * 在生产环境建议启用，开发环境可以根据需要关闭
     * 支持：boolean | callable
     * 默认值：true
     * 示例：true | false | fn() => app()->environment('production')
     */
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),

    /**
     * 启用安全中间件时的启用方式
     *
     * 在生产环境建议配置为全局使用，开发环境可以根据需要配置
     * 支持：string
     * 可选值：global:全局使用, route:路由使用(在路由、控制器等地方手动使用security中间件)
     * 默认值：global
     *  示例：如果配置全局启用(enabled_type)，则所有路由都将默认使用安全中间件，不需要单独引入
     *       路由分配中间件: Route::middleware(['security'])
     *       控制器中间件: Route::get('profile', [UserController::class, 'show'])->middleware('security');
     *       路由排除中间件: Route::withoutMiddleware(['security'])
     */
    'enabled_type' => env('SECURITY_MIDDLEWARE_TYPE', 'global'),

    /**
     * 安全中间件是否忽略本地环境的请求
     *
     * 在生产环境建议关闭，开发环境可以根据需要开启
     * 支持：boolean | callable
     * 默认值：false
     */
    'ignore_local' => env('SECURITY_IGNORE_LOCAL', false),

    /**
     * 日志记录级别
     *
     * 安全事件的日志记录级别
     * 支持：string | callable
     * 可选值：debug, info, notice, warning, error, critical, alert, emergency
     * 默认值：warning
     */
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),

    /**
     * 是否启用调试日志
     *
     * 启用后会记录详细的调试信息，建议在排查问题时开启
     * 支持：boolean | callable
     * 默认值：false
     */
    'enable_debug_logging' => env('SECURITY_DEBUG_LOGGING', false),

    /**
     * 是否记录详细日志
     *
     * 记录详细的拦截日志，包括请求参数等
     * 支持：boolean | callable
     * 默认值：false
     */
    'log_details' => env('SECURITY_LOG_DETAILS', false),

    // ==================== 速率限制配置 ====================

    /**
     * 是否启用速率限制
     *
     * 防止暴力破解和DDoS攻击
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_rate_limiting' => env('SECURITY_RATE_LIMITING_ENABLED', true),

    /**
     * 速率限制配置
     *
     * 定义不同时间窗口的最大请求数
     * 支持：array | callable
     * 默认值：['minute' => 300, 'hour' => 10000, 'day' => 100000]
     */
    'rate_limits' => [
        'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 300),
        'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 10000),
        'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 100000),
    ],

    /**
     * 速率限制指纹生成策略
     *
     * 定义如何生成请求指纹用于速率限制
     * 支持：string | array | callable
     * 可选值：ip_only, ip_ua, ip_ua_path, custom
     * 默认值：ip_ua_path
     */
    'rate_limit_strategy' => env('SECURITY_RATE_LIMIT_STRATEGY', 'ip_ua_path'),

    /**
     * 自定义速率限制指纹处理器
     *
     * 当 rate_limit_strategy 为 custom 时使用的自定义处理器
     * 支持：string|array|null
     * 默认值：null
     * 示例：'App\Services\SecurityService::generateFingerprint'
     */
    'rate_limit_custom_handler' => env('SECURITY_RATE_LIMIT_CUSTOM_HANDLER', null),

    // ==================== IP自动检测配置 ====================

    /**
     * IP自动检测配置
     *
     * 支持自动检测可疑IP并转为黑名单
     * 类型：array
     */
    'ip_auto_detection' => [
        /**
         * 是否启用自动检测
         *
         * 启用后系统会自动检测可疑IP并处理
         * 类型：boolean
         * 默认值：true
         */
        'enabled' => env('SECURITY_IP_AUTO_DETECTION', true),

        /**
         * 没有被记录过的ip,如果正常访问且不没有被拦截时，是否记录此ip到数据库中(默认不记录)；
         *    false(默认): 没有被拦截时就不记录此ip到数据库中
         *    true: 不管有没有被拦截都会把此ip记录到数据库中
         */
        'record_normal_visitor' => env('SECURITY_RECORD_NORMAL_VISITOR', false),

        /**
         * 黑名单转换阈值
         *
         * 威胁评分达到此值时自动转为黑名单
         * 类型：float
         * 范围：0-100
         * 默认值：80.0
         */
        'blacklist_threshold' => env('SECURITY_BLACKLIST_THRESHOLD', 80.0),

        /**
         * 可疑IP转换阈值
         *
         * 威胁评分达到此值时转为可疑IP
         * 类型：float
         * 范围：0-100
         * 默认值：50.0
         */
        'suspicious_threshold' => env('SECURITY_SUSPICIOUS_THRESHOLD', 50.0),

        /**
         * 最大触发规则次数
         *
         * 触发规则达到此次数时自动转为黑名单
         * 类型：integer
         * 默认值：5
         */
        'max_triggers' => env('SECURITY_MAX_TRIGGERS', 5),

        /**
         * 每次拦截时增加威胁评分
         *
         * 被拦截时增加的威胁评分
         * 类型：float
         * 默认值：10.00
         */
        'add_threat_score' => env('SECURITY_ADD_THREAT_SCORE', 10.00),

        /**
         * 每次成功请求时降低威胁评分
         *
         * 成功请求时降低威胁评分
         * 类型：float
         * 默认值：1.00
         */
        'reduce_threat_score' => env('SECURITY_REDUCE_THREAT_SCORE', 1.00),

        /**
         * 威胁评分自然衰减（每小时）
         *
         * 每小时自动降低威胁评分
         * 类型：float
         * 默认值：0.3
         */
        'decay_rate_per_hour' => env('SECURITY_DECAY_RATE_PER_HOUR', 0.3),

        /**
         * 自动清理过期记录
         *
         * 是否自动清理过期的IP记录, 默认关闭, 清理时会删除此ip的数据库记录
         * 类型：boolean
         * 默认值：true
         */
        'auto_cleanup' => env('SECURITY_AUTO_CLEANUP', false),

        /**
         * 监控IP自动过期时间（天）
         *
         * 监控类型的IP记录自动过期时间【auto_cleanup开启时有效】
         * 类型：integer
         * 默认值：15
         */
        'monitoring_expire_days' => env('SECURITY_MONITORING_EXPIRE_DAYS', 15),
    ],

    // ==================== IP数据库配置 ====================

    /**
     * IP数据库配置
     *
     * 配置IP管理的数据库相关设置
     * 类型：array
     */
    'ip_database' => [
        /**
         * 缓存时间（秒）
         *
         * IP检查结果的缓存时间
         * 类型：integer
         * 默认值：300
         */
        'cache_ttl' => env('SECURITY_IP_CACHE_TTL', 300),

    ],

    // ==================== HTTP方法配置 ====================

    /**
     * 允许的HTTP方法
     *
     * 只允许列表中的HTTP方法，其他方法将被拒绝
     * 支持：array | callable
     * 默认值：['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
     */
    'allowed_methods' => [
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS',
        'HEAD',
    ],

    /**
     * 可疑HTTP方法
     *
     * 这些HTTP方法将被视为可疑请求
     * 支持：array | callable
     * 默认值：['CONNECT', 'TRACE', 'TRACK', 'DEBUG']
     */
    'suspicious_methods' => [
        'CONNECT',
        'TRACE',
        'TRACK',
        'DEBUG',
    ],

    // ==================== 请求体检查配置 ====================

    /**
     * 请求体正则表达式模式
     *
     * 用于检测恶意请求内容的正则表达式模式
     * 支持：array | callable
     * 默认值：SecurityConfig::getMaliciousBodyPatterns()
     */
    'body_patterns' => [SecurityConfig::class, 'getMaliciousBodyPatterns'],

    /**
     * 不验证请求体的白名单路径
     *
     * 这些路径的请求体将跳过恶意内容检测
     * 常用于API接口、健康检查等
     * 支持：array | callable
     * 默认值：['api/health', 'api/status', 'health', 'status']
     */
    'body_whitelist_paths' => [
        'api/health',
        'api/status',
        'health',
        'status',
    ],

    /**
     * 最小触发内容长度
     *
     * 只有内容长度超过此值才进行正则匹配
     * 支持：integer | callable
     * 默认值：3
     */
    'min_content_length' => env('SECURITY_MIN_CONTENT_LENGTH', 3),

    // ==================== URL检查配置 ====================

    /**
     * URL正则表达式模式
     *
     * 用于检测非法URL路径的正则表达式模式
     * 支持：array | callable
     * 默认值：SecurityConfig::getIllegalUrlPatterns()
     */
    'url_patterns' => [SecurityConfig::class, 'getIllegalUrlPatterns'],

    /**
     * 规则引擎配置
     *
     * 启用高级规则引擎，支持：
     * - 规则优先级和权重管理
     * - 动态规则配置和运行时调整
     * - 规则学习和自适应能力
     * - 智能拦截决策机制
     */
    'rule_engine' => [
        // 是否启用规则引擎
        'enabled' => true,

        // 是否启用自适应学习
        'enable_adaptive_learning' => false,

        // 自适应学习参数
        'adaptive_learning' => [
            // 最小学习样本数
            'min_samples' => 100,

            // 学习更新频率（秒）
            'update_interval' => 300,

            // 学习窗口大小
            'window_size' => 1000,
        ],

        // 威胁评分阈值
        'threat_thresholds' => [
            'critical' => 80,  // 严重威胁
            'high' => 60,      // 高危威胁
            'medium' => 40,    // 中危威胁
            'low' => 20,       // 低危威胁
        ],

        // 最大威胁评分
        'max_threat_score' => 100,

        // 禁用的规则ID列表
        'disabled_rules' => [],

        // 自定义规则列表
        'custom_rules' => [],
    ],

    /**
     * 自适应封禁时长配置
     *
     * 根据威胁评分动态调整封禁时长
     */
    'adaptive_ban_duration' => [
        'enabled' => true,

        // 威胁评分与封禁时长倍数映射
        'multipliers' => [
            90 => 10,  // 评分90+，10倍时长
            80 => 5,   // 评分80-90，5倍时长
            70 => 3,   // 评分70-80，3倍时长
            60 => 2,   // 评分60-70，2倍时长
        ],
    ],

    /**
     * URL检测白名单路径 - 安全增强版
     *
     * 这些URL路径将跳过URL安全检测（注意：其他安全检查仍会执行）
     * 支持：array | callable
     *
     * ==================== 安全警告 ====================
     * ⚠️  此白名单仅跳过URL路径检测，不会跳过以下安全检查：
     *    - IP黑名单检查
     *    - 频率限制检查
     *    - 请求体恶意内容检查
     *    - 文件上传检查
     *    - 异常行为检查
     *    - SQL注入/XSS/命令注入检测
     *
     * ⚠️  宽泛的白名单（如 'api/*'）可能导致攻击绕过安全检测
     *    建议使用精确路径而非通配符
     *
     * ⚠️  如需完全跳过某个路径的所有安全检查，
     *    请使用 Route::withoutMiddleware(['security'])
     *
     * ==================== 白名单安全级别 ====================
     * 每个路径可以指定安全级别：
     * - 'low' (低风险): 仅跳过基础URL检查，保留所有安全检测
     * - 'medium' (中风险): 跳过URL检查，但保留关键安全检测
     * - 'high' (高风险): 跳过URL检查，需谨慎使用
     *
     * ==================== 配置示例 ====================
     * 简单格式: 'robots.txt'
     * 带级别: ['path' => 'api/health', 'level' => 'low']
     * 带方法限制: ['path' => 'api/ping', 'methods' => ['GET'], 'level' => 'low']
     */
    'url_whitelist_paths' => [
        // 基础静态文件（低风险）
        ['path' => 'robots.txt', 'level' => 'low'],
        ['path' => 'sitemap.xml', 'level' => 'low'],
        ['path' => 'favicon.ico', 'level' => 'low'],

        // 健康检查端点（低风险，仅限GET方法）
        ['path' => 'health', 'methods' => ['GET'], 'level' => 'low'],
        ['path' => 'status', 'methods' => ['GET'], 'level' => 'low'],
        ['path' => 'ping', 'methods' => ['GET'], 'level' => 'low'],
        ['path' => 'ready', 'methods' => ['GET'], 'level' => 'low'],

        // ⚠️  警告：以下通配符路径可能带来安全风险
        // 建议移除或替换为具体的精确路径
        //
        // 资源文件（中风险 - 仍保留内容安全检查）
        // 'assets/*',    // 建议移除，使用静态资源服务器
        // 'public/*',    // 建议移除，危险
        // 'static/*',    // 建议移除，危险
        // 'css/*',       // 建议移除，使用静态资源服务器
        // 'js/*',        // 建议移除，使用静态资源服务器
        // 'images/*',    // 建议移除，使用静态资源服务器

        // API路径（高风险 - 强烈建议移除通配符）
        // 'api/*',       // 危险！建议移除
        // 'v1/*',        // 危险！建议移除
        // 'v2/*',        // 危险！建议移除
        // 'graphql',     // 需要额外安全措施
        // 'rest/*',      // 危险！建议移除
    ],

    /**
     * 白名单路径安全策略
     *
     * 定义白名单路径的安全检查策略
     */
    'whitelist_security_policy' => [
        // 即使在白名单中，也保留的安全检查
        'always_check' => [
            'ip_blacklist',        // 始终检查IP黑名单
            'rate_limit',          // 始终进行频率限制
            'body_patterns',       // 始终检查请求体恶意内容
            'file_upload',         // 始终检查文件上传
            'sql_injection',       // 始终检测SQL注入
            'xss_attack',          // 始终检测XSS攻击
            'command_injection',    // 始终检测命令注入
        ],

        // 根据级别保留的检查
        'level_checks' => [
            'low' => [
                'method_check',        // HTTP方法检查
                'user_agent_check',    // User-Agent检查
                'header_check',        // 请求头检查
            ],
            'medium' => [
                'method_check',
            ],
            'high' => [
                // 最少检查
            ],
        ],

        // 需要额外认证的白名单路径
        'require_auth' => [
            'graphql',
            'api/*',
        ],
    ],

    /**
     * 配置热重载配置
     *
     * 实现配置修改后立即生效，无需重启应用
     */
    'hot_reload' => [
        // 是否启用热重载
        'enabled' => env('SECURITY_HOT_RELOAD_ENABLED', true),

        // 配置文件监听（秒）
        'watch_interval' => env('SECURITY_CONFIG_WATCH_INTERVAL', 5),

        // 配置版本键（用于检测配置变更）
        'version_key' => 'security:config:version',

        // 需要实时生效的配置项
        'realtime_keys' => [
            'url_whitelist_paths',
            'defense_layers',
            'enabled',
            'ip_auto_detection',
            'rate_limits',
            'ban_duration',
            'rule_engine',
        ],

        // 不应缓存的配置项（实时读取）
        'no_cache_keys' => [
            'url_whitelist_paths',
            'enabled',
            'defense_layers',
        ],
    ],

    /**
     * 最大URL长度
     *
     * 超过此长度的URL将被拒绝
     * 支持：integer | callable
     * 默认值：2048
     */
    'max_url_length' => env('SECURITY_MAX_URL_LENGTH', 2048),

    // ==================== User-Agent检查配置 ====================

    /**
     * 禁止的User-Agent模式
     *
     * 匹配这些模式的User-Agent将被拒绝
     * 支持：array | callable
     * 默认值：SecurityConfig::getSuspiciousUserAgents()
     */
    'suspicious_user_agents' => [SecurityConfig::class, 'getSuspiciousUserAgents'],

    /**
     * 白名单User-Agent模式
     *
     * 合法的搜索引擎和爬虫User-Agent
     * 支持：array | callable
     * 默认值：SecurityConfig::getWhitelistUserAgents()
     */
    'whitelist_user_agents' => [SecurityConfig::class, 'getWhitelistUserAgents'],

    /**
     * 是否允许空User-Agent
     *
     * 是否允许没有User-Agent的请求
     * 支持：boolean | callable
     * 默认值：false
     */
    'allow_empty_user_agent' => env('SECURITY_ALLOW_EMPTY_UA', false),

    /**
     * 最大User-Agent长度
     *
     * 超过此长度的User-Agent将被拒绝
     * 支持：integer | callable
     * 默认值：512
     */
    'max_user_agent_length' => env('SECURITY_MAX_UA_LENGTH', 512),

    // ==================== 请求头检查配置 ====================

    /**
     * 可疑请求头模式
     *
     * 匹配这些模式的请求头将被视为可疑
     * 支持：array | callable
     * 默认值：[
     *     'X-Forwarded-For' => '/,/',  // 包含逗号的X-Forwarded-For
     *     'X-Real-IP' => '/,/',        // 包含逗号的X-Real-IP
     *     'Via' => '/.*\/',            // 任何Via头
     * ]
     */
    'suspicious_headers' => [
        'X-Forwarded-For' => '/,/',
        'X-Real-IP' => '/,/',
        'Via' => '/.*/',
    ],

    /**
     * 最大请求头数量
     *
     * 超过此数量的请求头将被拒绝
     * 支持：integer | callable
     * 默认值：50
     */
    'max_header_count' => env('SECURITY_MAX_HEADER_COUNT', 50),

    // ==================== 文件上传检查配置 ====================

    /**
     * 是否启用文件上传检查
     *
     * 启用后会对上传文件进行安全检查
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_file_check' => env('SECURITY_ENABLE_FILE_CHECK', true),

    /**
     * 禁止上传的文件扩展名
     *
     * 这些扩展名的文件将被拒绝上传
     * 支持：array | callable
     * 默认值：SecurityConfig::getDisallowedExtensions()
     */
    'disallowed_extensions' => [SecurityConfig::class, 'getDisallowedExtensions'],

    /**
     * 禁止上传的MIME类型
     *
     * 这些MIME类型的文件将被拒绝上传
     * 支持：array | callable
     * 默认值：SecurityConfig::getDisallowedMimeTypes()
     */
    'disallowed_mime_types' => [SecurityConfig::class, 'getDisallowedMimeTypes'],

    /**
     * 最大文件大小（字节）
     *
     * 允许上传的最大文件大小
     * 支持：integer | callable
     * 默认值：52,428,800 (50MB)
     */
    'max_file_size' => env('SECURITY_MAX_FILE_SIZE', 50 * 1024 * 1024),

    /**
     * 是否启用文件内容检查
     *
     * 启用后会对上传文件的内容进行安全扫描
     * 注意：这会增加服务器负载
     * 支持：boolean | callable
     * 默认值：false
     */
    'enable_file_content_check' => env('SECURITY_FILE_CONTENT_CHECK', false),

    /**
     * 允许上传的文件扩展名白名单
     *
     * 即使在其他检查中，这些扩展名也被允许
     * 支持：array | callable
     * 默认值：['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx']
     */
    'allowed_extensions_whitelist' => [
        'jpg', 'jpeg', 'png', 'gif', 'pdf',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'zip', 'rar', '7z',
    ],

    // ==================== 高级检测配置 ====================

    /**
     * 是否启用异常检测
     *
     * 检测异常的请求参数和行为
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_anomaly_detection' => env('SECURITY_ANOMALY_DETECTION', true),

    /**
     * 异常检测阈值
     *
     * 异常检测的敏感度阈值
     * 支持：array | callable
     * 默认值：[
     *     'max_parameters' => 100,
     *     'max_parameter_length' => 255,
     *     'max_post_size' => 52428800, // 50MB
     * ]
     */
    'anomaly_thresholds' => [
        'max_parameters' => env('SECURITY_MAX_PARAMETERS', 100),
        'max_parameter_length' => env('SECURITY_MAX_PARAMETER_LENGTH', 255),
        'max_post_size' => env('SECURITY_MAX_POST_SIZE', 50 * 1024 * 1024),
    ],

    /**
     * 是否启用SQL注入专项检测
     *
     * 专门针对SQL注入攻击的深度检测
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_sql_injection_detection' => env('SECURITY_SQL_INJECTION_DETECTION', true),

    /**
     * SQL注入正则表达式
     *
     * 用于检测恶意请求是否包含恶意SQL注入
     * 支持：array | callable
     * 默认值：SecurityConfig::getSQLInjectionPatterns()
     */
    'sql_injection_patterns' => [SecurityConfig::class, 'getSQLInjectionPatterns'],

    /**
     * 是否启用XSS攻击专项检测
     *
     * 专门针对XSS攻击的深度检测
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_xss_detection' => env('SECURITY_XSS_DETECTION', true),

    /**
     * XSS攻击正则表达式
     *
     * 用于检测恶意请求是否包含恶意SQL注入
     * 支持：array | callable
     * 默认值：SecurityConfig::getXSSAttackPatterns()
     */
    'xss_attack_patterns' => [SecurityConfig::class, 'getXSSAttackPatterns'],

    /**
     * 是否启用命令注入专项检测
     *
     * 专门针对命令注入攻击的深度检测
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_command_injection_detection' => env('SECURITY_COMMAND_INJECTION_DETECTION', true),


    /**
     * 命令注入检测正则表达式
     *
     * 用于检测恶意请求是否包含恶意SQL注入
     * 支持：array | callable
     * 默认值：SecurityConfig::getCommandInjectionPatterns()
     */
    'command_injection_patterns' => [SecurityConfig::class, 'getCommandInjectionPatterns'],


    // ==================== 缓存配置 ====================

    /**
     * 缓存生存时间（秒）
     *
     * 安全相关数据的缓存时间
     * 支持：integer | callable
     * 默认值：3600
     */
    'cache_ttl' => env('SECURITY_CACHE_TTL', 3600),

    /**
     * 默认封禁时长（秒）
     *
     * 检测到安全威胁时的默认封禁时间
     * 支持：integer | callable
     * 默认值：3600
     */
    'ban_duration' => env('SECURITY_BAN_DURATION', 3600),

    /**
     * 最大封禁时长（秒）
     *
     * 最大封禁时间，防止设置过长
     * 支持：integer | callable
     * 默认值：7,776,000 （90天）
     */
    'max_ban_duration' => env('SECURITY_MAX_BAN_DURATION', 7776000),

    /**
     * 不同安全事件类型 对应的封禁时长映射
     * 检测到安全威胁时的封禁时间映射
     */
    'ban_duration_map' => [SecurityConfig::class, 'getEventTypeBanDuration'],

    /**
     * 是否启用正则表达式缓存
     *
     * 启用后正则表达式将被预编译缓存，提升性能
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_pattern_cache' => env('SECURITY_PATTERN_CACHE', true),

    /**
     * 是否启用IP检查缓存
     *
     * 启用后IP检查结果将被缓存，提升性能
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_ip_cache' => env('SECURITY_IP_CACHE', true),

    // ==================== 响应配置 ====================

    /**
     * 异常时是否阻止请求
     *
     * 安全中间件发生异常时是否拒绝请求
     * 建议在生产环境设置为true，开发环境设置为false
     * 支持：boolean | callable
     * 默认值：false
     */
    'block_on_exception' => env('SECURITY_BLOCK_ON_EXCEPTION', true),

    /**
     * AJAX响应格式
     *
     * 拦截请求时返回的JSON响应格式
     * 支持：array | callable
     * 默认值：[
     *     'code' => 'code',
     *     'message' => 'message',
     *     'data' => 'data'
     * ]
     */
    'ajax_response_format' => [
        'code' => 'code',
        'message' => 'message',
        'data' => 'data',
    ],

    /**
     * 自定义错误页面视图
     *
     * 安全拦截时显示的自定义视图
     * 支持：string
     * 默认值：'security::blocked'
     */
    'error_view' => 'security::blocked',

    /**
     * 自定义错误页面数据
     *
     * 传递给错误视图的额外数据
     * 支持：array | callable
     * 默认值：[]
     */
    'error_view_data' => [],

    /**
     * 拦截响应HTTP状态码映射
     *
     * 不同类型的拦截返回不同的HTTP状态码
     * 支持：array | callable
     * 默认值：[
     *     'Blacklist' => 403,
     *     'RateLimit' => 429,
     *     'MaliciousRequest' => 403,
     *     'AnomalousParameters' => 422,
     *     'SuspiciousUserAgent' => 400,
     *     'SystemError' => 503,
     * ]
     */
    'response_status_codes' => [
        'Blacklist' => 403,
        'RateLimit' => 429,
        'MaliciousRequest' => 403,
        'AnomalousParameters' => 422,
        'SuspiciousUserAgent' => 400,
        'SystemError' => 503,
        'CustomRule' => 403,
    ],

    // ==================== 自定义处理配置 ====================

    /**
     * 自定义安全处理逻辑
     *
     * 自定义的安全检查逻辑，格式：[Class, method] 或 \Namespace\Class::method
     * 支持：string|array|null
     * 默认值：null
     */
    'custom_handler' => env('SECURITY_CUSTOM_HANDLE', null),

    /**
     * 黑名单处理逻辑
     *
     * 自定义的黑名单检查逻辑，格式同上
     * 支持：string|array|null
     * 默认值：null
     */
    'blacklist_handler' => env('SECURITY_BLACKLIST_HANDLE', null),

    /**
     * 白名单处理逻辑
     *
     * 自定义的白名单检查逻辑，格式同上
     * 支持：string|array|null
     * 默认值：null
     */
    'whitelist_handler' => env('SECURITY_WHITELIST_HANDLE', null),

    /**
     * 安全警报处理逻辑
     *
     * 发送安全警报的自定义逻辑，格式同上
     * 支持：string|array|null, eg. [Class, method] or \Namespace\Class::method
     * 默认值：null
     */
    'alarm_handler' => env('SECURITY_ALARM_HANDLE', null),

    // ==================== 性能优化配置 ====================

    /**
     * 最大递归深度
     *
     * 递归检查输入数据时的最大深度，防止栈溢出
     * 支持：integer | callable
     * 默认值：10
     */
    'max_recursion_depth' => env('SECURITY_MAX_RECURSION_DEPTH', 10),

    // ==================== 防御层配置 ====================

    /**
     * 防御层配置
     *
     * 配置多层防御策略，从上到下依次执行
     * 支持：array | callable
     * 默认值：[
     *     'ip_whitelist' => true,
     *     'ip_blacklist' => true,
     *     'method_check' => true,
     *     'user_agent_check' => true,
     *     'header_check' => true,
     *     'url_check' => true,
     *     'upload_check' => true,
     *     'body_check' => true,
     *     'anomaly_check' => true,
     *     'rate_limit' => true,
     *     'custom_check' => true,
     * ]
     */
    'defense_layers' => [
        'ip_whitelist' => env('SECURITY_DEFENSE_IP_WHITELIST', true),
        'ip_blacklist' => env('SECURITY_DEFENSE_IP_BLACKLIST', true),
        'method_check' => env('SECURITY_DEFENSE_METHOD', true), // 检查请求方法
        'user_agent_check' => env('SECURITY_DEFENSE_USER_AGENT', true), // 检查UA
        'header_check' => env('SECURITY_DEFENSE_HEADER', true),
        'url_check' => env('SECURITY_DEFENSE_URL', true),
        'upload_check' => env('SECURITY_DEFENSE_UPLOAD', true),
        'body_check' => env('SECURITY_DEFENSE_BODY', true),
        'anomaly_check' => env('SECURITY_DEFENSE_ANOMALY', true),
        'rate_limit' => env('SECURITY_DEFENSE_RATE_LIMIT', true),
        'sql_check' => env('SECURITY_DEFENSE_SQL', true), // 检查SQL注入
        'xss_check' => env('SECURITY_DEFENSE_XSS', true), // 检查XSS攻击
        'command_check' => env('SECURITY_DEFENSE_COMMON', true), // 检查命令注入
        'custom_check' => env('SECURITY_DEFENSE_CUSTOM', true),
    ],

    // ==================== 其他配置 ====================

    /**
     * 是否启用API模式
     *
     * 启用后针对API请求优化响应格式
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_api_mode' => env('SECURITY_API_MODE', true),

    /**
     * 信任的代理IP列表
     *
     * 信任的代理服务器IP列表
     * 支持：array | callable
     * 默认值：[]
     */
    'trusted_proxies' => [],

    /**
     * 信任的代理头
     *
     * 信任的代理头名称
     * 支持：array | callable
     * 默认值：['X-Forwarded-For', 'X-Real-IP']
     */
    'trusted_headers' => ['X-Forwarded-For', 'X-Real-IP'],
];
