<?php
/**
 * 安全中间件配置文件
 *
 * 配置说明：
 * 1. 所有配置项都有详细的注释说明
 * 2. 提供合理的默认值
 * 3. 支持环境变量覆盖
 * 4. 包含性能和安全相关的调优参数
 */

return [

    // ==================== 基础配置 ====================

    /**
     * 是否启用安全中间件
     *
     * 在生产环境建议启用，开发环境可以根据需要关闭
     * 类型：boolean
     * 默认值：true
     */
    'enabled' => env('SECURITY_MIDDLEWARE_ENABLED', true),

    /**
     * 日志记录级别
     *
     * 安全事件的日志记录级别
     * 可选值：debug, info, notice, warning, error, critical, alert, emergency
     * 类型：string
     * 默认值：warning
     */
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),

    /**
     * 是否启用调试日志
     *
     * 启用后会记录详细的调试信息，建议在排查问题时开启
     * 类型：boolean
     * 默认值：false
     */
    'enable_debug_logging' => env('SECURITY_DEBUG_LOGGING', false),

    /**
     * 是否启用性能日志
     *
     * 启用后会记录性能统计信息，用于监控和优化
     * 类型：boolean
     * 默认值：false
     */
    'enable_performance_logging' => env('SECURITY_PERFORMANCE_LOGGING', false),

    // ==================== 速率限制配置 ====================

    /**
     * 是否启用速率限制
     *
     * 防止暴力破解和DDoS攻击
     * 类型：boolean
     * 默认值：true
     */
    'enable_rate_limiting' => env('SECURITY_RATE_LIMITING_ENABLED', true),

    /**
     * 每分钟最大请求数
     *
     * 单个客户端每分钟允许的最大请求数量
     * 类型：integer
     * 默认值：60
     */
    'max_requests_per_minute' => env('SECURITY_MAX_REQUESTS_PER_MINUTE', 60),

    /**
     * 每小时最大请求数
     *
     * 单个客户端每小时允许的最大请求数量
     * 类型：integer
     * 默认值：1000
     */
    'max_requests_per_hour' => env('SECURITY_MAX_REQUESTS_PER_HOUR', 1000),

    /**
     * 每天最大请求数
     *
     * 单个客户端每天允许的最大请求数量
     * 类型：integer
     * 默认值：10000
     */
    'max_requests_per_day' => env('SECURITY_MAX_REQUESTS_PER_DAY', 10000),

    // ==================== IP管理配置 ====================

    /**
     * 是否启用IP白名单
     *
     * 启用后白名单中的IP将跳过所有安全检查
     * 类型：boolean
     * 默认值：true
     */
    'enable_ip_whitelist' => env('SECURITY_IP_WHITELIST_ENABLED', true),

    /**
     * IP白名单列表
     *
     * 允许跳过安全检查的IP地址列表
     * 类型：array
     * 默认值：['127.0.0.1', '::1', 'localhost']
     */
    'ip_whitelist' => array_filter(explode(',', env('SECURITY_IP_WHITELIST', '127.0.0.1,::1,localhost'))),

    /**
     * 是否启用IP黑名单
     *
     * 启用后黑名单中的IP将被直接拒绝访问
     * 类型：boolean
     * 默认值：true
     */
    'enable_ip_blacklist' => env('SECURITY_IP_BLACKLIST_ENABLED', true),

    /**
     * IP黑名单列表
     *
     * 直接拒绝访问的IP地址列表
     * 类型：array
     * 默认值：[]
     */
    'ip_blacklist' => array_filter(explode(',', env('SECURITY_IP_BLACKLIST', ''))),

    // ==================== HTTP方法配置 ====================

    /**
     * 允许的HTTP方法
     *
     * 只允许列表中的HTTP方法，其他方法将被拒绝
     * 类型：array
     * 默认值：['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
     */
    'allow_methods' => [
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
     * 类型：array
     * 默认值：SecurityMiddleware::MALICIOUS_BODY_PATTERNS
     */
    'reg_exp_body' => [
        // XSS攻击检测
        '/(?:<script[^>]*>.*?<\/script>|javascript:\\s*|on\\w+\\s*=\\s*["\']?)/is',

        // SQL注入检测
        '/(?:\\b(?:union\\s+select|select\\s+[\\w*]+\\s+from|insert\\s+into|update\\s+\\w+\\s+set|drop\\s+table|exec\\s*\\(|xp_cmdshell)\\b|--\\s|\\/\\*[\\s\\S]*?\\*\\/)/is',

        // 命令注入检测
        '/(?:\\b(?:system|exec|shell_exec|passthru)\\s*\\(|`[^`]*`|\\$\\s*\\(|\\|\\s*\\w+|&\\s*\\w+)/i',

        // 目录遍历和文件包含
        '/(?:\\.\\.\\/|\\.\\.\\\\|\\/etc\\/passwd|\\/etc\\/shadow|\\/winnt\\/system32)/i',

        // PHP代码执行
        '/(?:<\\?php|\\b(?:eval|assert|create_function)\\s*\\(|\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\\b(?:include|require)(?:_once)?\\s*\\()/i',
    ],

    /**
     * 不验证请求体的白名单路径
     *
     * 这些路径的请求体将跳过恶意内容检测
     * 常用于API接口、健康检查等
     * 类型：array
     * 默认值：['api/health', 'api/status', 'health', 'status']
     */
    'whitelist_path_of_not_verify_body' => [
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
     * 类型：array
     * 默认值：SecurityMiddleware::ILLEGAL_URL_PATTERNS
     */
    'reg_exp_url' => [
        // 隐藏文件和目录
        '~/(?:\\.(?!well-known)[^/]*)(?=/|$)~i',

        // 配置文件
        '/\\.(?:env|config|settings|configuration)(?:\\.\\w+)?$/i',
        '/(?:composer|package)(?:\\.(?:json|lock))?$/i',

        // 源代码文件
        '/\\.(?:php|phtml|jsp|asp|aspx|pl|py|rb|sh)(?:\\.\\w+)?$/i',

        // 敏感目录
        '/(?:^|\\/)(?:config|setup|install|admin|backup|logs?|temp|node_modules|\\.git)(?:$|\\/)/i',
    ],

    // ==================== User-Agent检查配置 ====================

    /**
     * 禁止的User-Agent模式
     *
     * 匹配这些模式的User-Agent将被拒绝
     * 类型：array
     * 默认值：SecurityMiddleware::SUSPICIOUS_USER_AGENTS
     */
    'forbid_user_agent' => [
        // 安全扫描工具
        '/\\b(?:sqlmap|nikto|metasploit|nessus|wpscan|acunetix|burp|dirbuster|nmap|netsparker)\\b/i',

        // 自动化工具
        '/\\b(?:curl|wget|python-urllib|java|httpclient|guzzle|scrapy|selenium)\\b/i',

        // 恶意软件
        '/\\b(?:masscan|zmeu|blackwidow|hydra|havij|zap|arachni)\\b/i',
    ],

    // ==================== 文件上传检查配置 ====================

    /**
     * 禁止上传的文件扩展名
     *
     * 这些扩展名的文件将被拒绝上传
     * 类型：array
     * 默认值：SecurityMiddleware::DISALLOWED_EXTENSIONS
     */
    'forbid_upload_file_ext' => [
        // 可执行文件
        'exe', 'bat', 'cmd', 'com', 'msi', 'dll', 'so', 'bin', 'run', 'app', 'apk',

        // 脚本文件
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar',
        'jsp', 'jspx', 'asp', 'aspx', 'pl', 'py', 'rb', 'sh', 'bash',
        'js', 'html', 'htm', 'xhtml',

        // 配置文件
        'env', 'config', 'ini', 'conf', 'cfg', 'properties',

        // 数据库文件
        'sql', 'db', 'mdb', 'accdb', 'sqlite',

        // 其他危险文件
        'swf', 'jar', 'war', 'reg', 'vbs', 'wsf', 'ps1',
    ],

    /**
     * 最大文件大小（字节）
     *
     * 允许上传的最大文件大小
     * 类型：integer
     * 默认值：10485760 (10MB)
     */
    'max_file_size' => env('SECURITY_MAX_FILE_SIZE', 10 * 1024 * 1024),

    /**
     * 是否启用文件内容检查
     *
     * 启用后会对上传文件的内容进行安全扫描
     * 注意：这会增加服务器负载
     * 类型：boolean
     * 默认值：false
     */
    'enable_file_content_check' => env('SECURITY_FILE_CONTENT_CHECK', false),

    // ==================== 高级检测配置 ====================

    /**
     * 是否启用高级检测
     *
     * 启用更复杂的安全检测逻辑
     * 类型：boolean
     * 默认值：true
     */
    'enable_advanced_detection' => env('SECURITY_ADVANCED_DETECTION', true),

    /**
     * 是否启用指纹识别
     *
     * 通过请求特征识别可疑客户端
     * 类型：boolean
     * 默认值：true
     */
    'enable_fingerprinting' => env('SECURITY_FINGERPRINTING', true),

    /**
     * 是否启用异常检测
     *
     * 检测异常的请求参数和行为
     * 类型：boolean
     * 默认值：true
     */
    'enable_anomaly_detection' => env('SECURITY_ANOMALY_DETECTION', true),

    // ==================== 缓存配置 ====================

    /**
     * 缓存生存时间（秒）
     *
     * 安全相关数据的缓存时间
     * 类型：integer
     * 默认值：3600
     */
    'cache_ttl' => env('SECURITY_CACHE_TTL', 3600),

    /**
     * 默认封禁时长（秒）
     *
     * 检测到安全威胁时的默认封禁时间
     * 类型：integer
     * 默认值：3600
     */
    'ban_duration' => env('SECURITY_BAN_DURATION', 3600),

    /**
     * 最大封禁时长（秒）
     *
     * 最大封禁时间，防止设置过长
     * 类型：integer
     * 默认值：86400
     */
    'max_ban_duration' => env('SECURITY_MAX_BAN_DURATION', 86400),

    // ==================== 异常处理配置 ====================

    /**
     * 异常时是否阻止请求
     *
     * 安全中间件发生异常时是否拒绝请求
     * 建议在生产环境设置为true，开发环境设置为false
     * 类型：boolean
     * 默认值：false
     */
    'block_on_exception' => env('SECURITY_BLOCK_ON_EXCEPTION', false),

    // ==================== 响应格式配置 ====================

    /**
     * AJAX响应格式
     *
     * 拦截请求时返回的JSON响应格式
     * 类型：array
     * 默认值：['code' => 'code', 'message' => 'message', 'data' => 'data']
     */
    'ajax_resp_format' => [
        'code' => 'code',
        'message' => 'message',
        'data' => 'data',
    ],

    // ==================== 自定义处理配置 ====================

    /**
     * 自定义安全处理逻辑
     *
     * 自定义的安全检查逻辑，格式：[Class, method] 或 \Namespace\Class::method
     * 类型：string|array|null
     * 默认值：null
     */
    'custom_handle' => env('SECURITY_CUSTOM_HANDLE', null),

    /**
     * 黑名单处理逻辑
     *
     * 自定义的黑名单检查逻辑，格式同上
     * 类型：string|array|null
     * 默认值：null
     */
    'blacklist_handle' => env('SECURITY_BLACKLIST_HANDLE', null),

    /**
     * 安全警报处理逻辑
     *
     * 发送安全警报的自定义逻辑，格式同上
     * 类型：string|array|null
     * 默认值：null
     */
    'send_security_alarm_handle' => env('SECURITY_ALARM_HANDLE', null),

];