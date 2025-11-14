<?php

use zxf\Security\Config\SecurityConfig;

/**
 * 安全中间件配置文件
 *
 * 配置特性：
 * 1. 支持动态配置源（类方法、闭包、数组等）
 * 2. 环境变量覆盖支持
 * 3. 性能优化参数
 * 4. 完整的类型提示和默认值
 *
 * 查看支持callable的用法示例：
 * @see  /vendor/zxf/security/example/security_example.md 配置示例
 */

return [

    // ==================== 基础配置 ====================

    /**
     * 是否启用安全中间件
     *
     * 在生产环境建议启用，开发环境可以根据需要关闭
     * 支持：boolean | callable
     * 默认值：true
     */
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),

    /**
     * 启用安全中间件时的启用方式
     *
     * 在生产环境建议配置为全局使用，开发环境可以根据需要配置
     * 支持：string
     * 可选值：global:全局使用, single:单个使用(在路由、控制器等地方手动使用security中间件)
     * 示例：如果配置全局启用(enabled_type)，则所有路由都将默认使用安全中间件，不需要单独引入
     *      路由分配中间件: Route::middleware(['security'])
     *      控制器中间件: Route::get('profile', [UserController::class, 'show'])->middleware('security');
     *      路由排除中间件: Route::withoutMiddleware(['security'])
     * 默认值：global
     */
    'enabled_type' => env('SECURITY_MIDDLEWARE_ENABLED', 'global'),

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
     * 是否启用性能日志
     *
     * 启用后会记录性能统计信息，用于监控和优化
     * 支持：boolean | callable
     * 默认值：false
     */
    'enable_performance_logging' => env('SECURITY_PERFORMANCE_LOGGING', false),

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
     * 默认值：['minute' => 60, 'hour' => 1000, 'day' => 10000]
     */
    'rate_limits' => [
        'minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 60),
        'hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 1000),
        'day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 10000),
    ],

    // ==================== IP管理配置 ====================

    /**
     * 是否启用IP白名单
     *
     * 启用后白名单中的IP将跳过所有安全检查
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_ip_whitelist' => env('SECURITY_IP_WHITELIST_ENABLED', true),

    /**
     * IP白名单列表
     *
     * 允许跳过安全检查的IP地址列表
     * 支持：array | callable | string (类方法)
     * 默认值：['127.0.0.1', '::1', 'localhost']
     */
    'ip_whitelist' => [SecurityConfig::class, 'getWhitelistIps'],

    /**
     * 是否启用IP黑名单
     *
     * 启用后黑名单中的IP将被直接拒绝访问
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_ip_blacklist' => env('SECURITY_IP_BLACKLIST_ENABLED', true),

    /**
     * IP黑名单列表
     *
     * 直接拒绝访问的IP地址列表
     * 支持：array | callable | string (类方法)
     * 默认值：[]
     */
    'ip_blacklist' => [SecurityConfig::class, 'getBlacklistIps'],

    /**
     * 动态IP黑名单缓存时间（秒）
     *
     * 从数据库或其他动态源获取的黑名单缓存时间
     * 支持：integer | callable
     * 默认值：300
     */
    'dynamic_blacklist_cache_ttl' => env('SECURITY_DYNAMIC_BLACKLIST_CACHE_TTL', 300),

    /**
     * 禁封IP操作
     *
     * 禁用某个用户的IP
     * 支持：array | callable
     * 默认值：[]
     */
    'ban_id_handler'=>[SecurityConfig::class, 'banIdHandler'],

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

    // ==================== URL检查配置 ====================

    /**
     * URL正则表达式模式
     *
     * 用于检测非法URL路径的正则表达式模式
     * 支持：array | callable
     * 默认值：SecurityConfig::getIllegalUrlPatterns()
     */
    'url_patterns' => [SecurityConfig::class, 'getIllegalUrlPatterns'],

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

    // ==================== 文件上传检查配置 ====================

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
     * 默认值：10485760 (10MB)
     */
    'max_file_size' => env('SECURITY_MAX_FILE_SIZE', 10 * 1024 * 1024),

    /**
     * 是否启用文件内容检查
     *
     * 启用后会对上传文件的内容进行安全扫描
     * 注意：这会增加服务器负载
     * 支持：boolean | callable
     * 默认值：false
     */
    'enable_file_content_check' => env('SECURITY_FILE_CONTENT_CHECK', false),

    // ==================== 高级检测配置 ====================

    /**
     * 是否启用高级检测
     *
     * 启用更复杂的安全检测逻辑
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_advanced_detection' => env('SECURITY_ADVANCED_DETECTION', true),

    /**
     * 是否启用指纹识别
     *
     * 通过请求特征识别可疑客户端
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_fingerprinting' => env('SECURITY_FINGERPRINTING', true),

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
     * 默认值：['max_parameters' => 100, 'max_parameter_length' => 255]
     */
    'anomaly_thresholds' => [
        'max_parameters' => 100,
        'max_parameter_length' => 255,
        'max_headers' => 50,
    ],

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
     * 默认值：86400
     */
    'max_ban_duration' => env('SECURITY_MAX_BAN_DURATION', 86400),

    // ==================== 异常处理配置 ====================

    /**
     * 异常时是否阻止请求
     *
     * 安全中间件发生异常时是否拒绝请求
     * 建议在生产环境设置为true，开发环境设置为false
     * 支持：boolean | callable
     * 默认值：false
     */
    'block_on_exception' => env('SECURITY_BLOCK_ON_EXCEPTION', false),

    // ==================== 响应格式配置 ====================

    /**
     * AJAX响应格式
     *
     * 拦截请求时返回的JSON响应格式
     * 支持：array | callable
     * 默认值：['code' => 'code', 'message' => 'message', 'data' => 'data']
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
     * 安全警报处理逻辑
     *
     * 发送安全警报的自定义逻辑，格式同上
     * 支持：string|array|null
     * 默认值：null
     */
    'alarm_handler' => env('SECURITY_ALARM_HANDLE', null),

    // ==================== 性能优化配置 ====================

    /**
     * 是否启用正则表达式缓存
     *
     * 启用后正则表达式将被预编译缓存，提升性能
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_pattern_cache' => env('SECURITY_PATTERN_CACHE', true),

    /**
     * 是否启用指纹缓存
     *
     * 启用后请求指纹将被缓存，避免重复计算
     * 支持：boolean | callable
     * 默认值：true
     */
    'enable_fingerprint_cache' => env('SECURITY_FINGERPRINT_CACHE', true),

    /**
     * 最大递归深度
     *
     * 递归检查输入数据时的最大深度，防止栈溢出
     * 支持：integer | callable
     * 默认值：10
     */
    'max_recursion_depth' => env('SECURITY_MAX_RECURSION_DEPTH', 10),

    /**
     * 批量处理大小
     *
     * 批量处理数据时的大小限制，防止内存溢出
     * 支持：integer | callable
     * 默认值：1000
     */
    'batch_size' => env('SECURITY_BATCH_SIZE', 1000),

];