<?php

return [
    /*
    |--------------------------------------------------------------------------
    | 安全中间件配置
    |--------------------------------------------------------------------------
    |
    | 此配置文件用于配置安全中间件的各种参数，包括检查规则、速率限制、
    | 警报设置、威胁情报等。
    |
    */

    /*
    |--------------------------------------------------------------------------
    | 安全配置档案
    |--------------------------------------------------------------------------
    |
    | 定义不同的安全配置档案，可以根据路由需求应用不同的安全级别。
    | 例如：default（默认）、strict（严格）、api（API专用）、relaxed（宽松）
    |
    */
    'profiles' => [
        'default' => [ // 默认安全配置
            'checks' => [ // 安全检查开关
                'rate_limit' => true, // 速率限制检查
                'time_restriction' => false, // 时间限制检查
                'malicious_user_agent' => true, // 恶意User-Agent检查
                'bot_detection' => true, // 爬虫检测
                'csrf_protection' => true, // CSRF保护
                'xss_protection' => true, // XSS防护
                'sql_injection_protection' => true, // SQL注入防护
                'command_injection_protection' => true, // 命令注入防护
                'path_traversal_protection' => true, // 路径遍历防护
                'malicious_url_protection' => true, // 恶意URL防护
                'file_upload_protection' => true, // 文件上传防护
                'webshell_detection' => true, // WebShell检测
                'xxe_protection' => true, // XXE防护
                'deserialization_protection' => true, // 反序列化防护
                'ssrf_protection' => true, // SSRF防护
                'lfi_protection' => true, // LFI防护
                'rfi_protection' => true, // RFI防护
                'header_injection_protection' => true, // 请求头注入防护
                'suspicious_behavior' => true, // 可疑行为检测
                'custom_rules' => true, // 自定义规则检查
            ],
            'rate_limit' => [ // 速率限制配置
                'max_attempts' => 60, // 最大尝试次数（每分钟）
                'decay_minutes' => 1, // 衰减时间（分钟）
            ],
            'file_upload' => [ // 文件上传配置
                'allowed_mime_types' => [ // 允许的MIME类型
                    'image/jpeg', // JPEG图像
                    'image/png', // PNG图像
                    'image/gif', // GIF图像
                    'image/webp', // WebP图像
                    'application/pdf', // PDF文档
                    'text/plain', // 纯文本
                    'application/msword', // Word文档
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // DOCX文档
                    'application/vnd.ms-excel', // Excel文档
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // XLSX文档
                ],
                'max_size' => 5242880, // 最大文件大小（5MB），单位：字节
                'scan_for_malware' => false, // 恶意软件扫描（需要额外组件）
            ],
            'bot_detection' => [ // 爬虫检测配置
                'block_no_ua' => true, // 拦截无User-Agent的请求
                'allowed_bots' => [ // 允许的爬虫列表
                    'Googlebot', // Google爬虫
                    'Bingbot', // Bing爬虫
                    'Slurp', // Yahoo爬虫
                    'DuckDuckBot', // DuckDuckGo爬虫
                ],
            ],
            'time_restriction' => [ // 时间限制配置
                'enabled' => false, // 是否启用时间限制
                'allowed_hours' => ['08:00', '18:00'], // 允许的时间段 [开始, 结束]
                'timezone' => 'Asia/Shanghai', // 时区设置
            ],
            'suspicious_behavior' => [ // 可疑行为检测配置
                'max_indicators' => 2, // 最大可疑指标数量
            ],
        ],

        'strict' => [ // 严格安全配置
            'rate_limit' => [
                'max_attempts' => 30, // 更严格的速率限制
                'decay_minutes' => 1,
            ],
            'file_upload' => [
                'max_size' => 2097152, // 更小的文件大小限制（2MB）
                'allowed_mime_types' => [ // 更严格的MIME类型
                    'image/jpeg',
                    'image/png',
                    'application/pdf',
                ],
            ],
            'time_restriction' => [
                'enabled' => true, // 启用时间限制
                'allowed_hours' => ['09:00', '17:00'], // 更严格的时间段
            ],
            'suspicious_behavior' => [
                'max_indicators' => 1, // 更严格的可疑行为检测
            ],
        ],

        'api' => [ // API专用配置
            'rate_limit' => [
                'max_attempts' => 1000, // API更高的速率限制
                'decay_minutes' => 1,
            ],
            'file_upload' => [
                'enabled' => false, // API禁用文件上传
            ],
            'csrf_protection' => [
                'enabled' => false, // API通常不需要CSRF保护
            ],
        ],

        'relaxed' => [ // 宽松安全配置
            'checks' => [
                'xss' => false, // 禁用XSS检查
                'suspicious_parameters' => false, // 禁用可疑参数检查
                'webshell_detection' => false, // 禁用WebShell检测
                'xxe_protection' => false, // 禁用XXE防护
            ],
            'rate_limit' => [
                'max_attempts' => 120, // 更宽松的速率限制
                'decay_minutes' => 1,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IP封禁配置
    |--------------------------------------------------------------------------
    |
    | 配置IP自动封禁的相关参数。
    |
    */
    'ban' => [
        'max_violations' => 5, // 最大违规次数（达到此次数后自动封禁）
        'ban_hours' => 24, // 封禁时长（小时）
        'auto_ban' => true, // 是否启用自动封禁
        'permanent_ban_after' => 3, // 3次临时封禁后永久封禁
    ],

    /*
    |--------------------------------------------------------------------------
    | 安全警报配置
    |--------------------------------------------------------------------------
    |
    | 配置安全警报的发送方式和频率。
    |
    */
    'alerts' => [
        'enabled' => env('SECURITY_ALERTS_ENABLED', false), // 是否启用安全警报
        'emails' => array_filter(explode(',', env('SECURITY_ALERT_EMAILS', ''))), // 警报邮箱列表
        'throttle_minutes' => 5, // 警报频率限制（分钟）
        'min_severity' => 'medium', // 最低警报严重程度（low, medium, high）
    ],

    /*
    |--------------------------------------------------------------------------
    | 威胁情报配置
    |--------------------------------------------------------------------------
    |
    | 配置威胁情报服务的相关参数。
    |
    */
    'threat_intelligence' => [
        'enabled' => env('THREAT_INTELLIGENCE_ENABLED', false), // 是否启用威胁情报
        'update_frequency' => 3600, // 威胁情报更新频率（秒）
        'realtime_check' => false, // 是否启用实时检查
        'sources' => [ // 威胁情报源
            'emerging_threats', // Emerging Threats
            'abuse_ch', // Abuse.ch
            'myip_ms', // MyIP.ms
            'blocklist_de', // Blocklist.de
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 行为分析配置
    |--------------------------------------------------------------------------
    |
    | 配置行为分析的相关参数。
    |
    */
    'behavior_analysis' => [
        'enabled' => true, // 是否启用行为分析
        'learning_period' => 604800, // 学习周期（秒），默认7天
        'anomaly_threshold' => 2.0, // 异常阈值
    ],

    /*
    |--------------------------------------------------------------------------
    | 日志记录配置
    |--------------------------------------------------------------------------
    |
    | 配置安全日志记录的相关参数。
    |
    */
    'logging' => [
        'enabled' => true, // 是否启用安全日志记录
        'channel' => 'security', // 日志通道名称
        'retention_days' => 90, // 日志保留天数
    ],

    /*
    |--------------------------------------------------------------------------
    | 性能配置
    |--------------------------------------------------------------------------
    |
    | 配置安全中间件的性能相关参数。
    |
    */
    'performance' => [
        'cache_ttl' => 300, // 缓存TTL（秒）
        'max_processing_time' => 100, // 最大处理时间（毫秒）
        'enable_caching' => true, // 是否启用缓存
        'enable_monitoring' => false, // 是否启用性能监控
    ],
];