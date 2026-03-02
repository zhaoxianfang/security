<?php

namespace zxf\Security\Constants;

/**
 * 安全常量类
 *
 * 集中管理所有安全相关的常量，避免代码中的魔术数字
 * 提高代码可维护性和可读性
 */
class SecurityConstants
{
    // ==================== 缓存相关常量 ====================

    /**
     * 缓存前缀
     */
    public const CACHE_PREFIX = 'security:';

    /**
     * 白名单缓存键
     */
    public const WHITELIST_CACHE_KEY = 'whitelist';

    /**
     * 黑名单缓存键
     */
    public const BLACKLIST_CACHE_KEY = 'blacklist';

    /**
     * 可疑IP缓存键
     */
    public const SUSPICIOUS_CACHE_KEY = 'suspicious';

    /**
     * 监控IP缓存键
     */
    public const MONITORING_CACHE_KEY = 'monitoring';

    /**
     * 内网IP缓存键
     */
    public const INTRANET_CACHE_KEY = 'intranet:';

    /**
     * 模式缓存键
     */
    public const PATTERN_CACHE_KEY = 'patterns:';

    /**
     * 速率限制缓存前缀
     */
    public const RATE_LIMIT_CACHE_PREFIX = 'rate_limit:';

    /**
     * 速率限制锁前缀
     */
    public const RATE_LIMIT_LOCK_PREFIX = 'rate_lock:';

    /**
     * 速率统计前缀
     */
    public const RATE_STATS_PREFIX = 'rate_stats:';

    // ==================== 速率限制常量 ====================

    /**
     * 时间窗口（秒）
     */
    public const TIME_WINDOW_SECOND = 1;
    public const TIME_WINDOW_MINUTE = 60;
    public const TIME_WINDOW_HOUR = 3600;
    public const TIME_WINDOW_DAY = 86400;

    /**
     * 默认速率限制
     */
    public const DEFAULT_RATE_LIMIT_SECOND = 10;
    public const DEFAULT_RATE_LIMIT_MINUTE = 300;
    public const DEFAULT_RATE_LIMIT_HOUR = 5000;
    public const DEFAULT_RATE_LIMIT_DAY = 50000;

    /**
     * 内存缓存最大大小
     */
    public const MAX_MEMORY_CACHE_SIZE = 10000;

    /**
     * 锁等待超时（秒）
     */
    public const LOCK_TIMEOUT = 5;

    /**
     * 锁持有时间（秒）
     */
    public const LOCK_TTL = 10;

    /**
     * 批量操作大小
     */
    public const BATCH_SIZE = 1000;

    // ==================== IP相关常量 ====================

    /**
     * IP类型
     */
    public const IP_TYPE_WHITELIST = 'whitelist';
    public const IP_TYPE_BLACKLIST = 'blacklist';
    public const IP_TYPE_SUSPICIOUS = 'suspicious';
    public const IP_TYPE_MONITORING = 'monitoring';

    /**
     * IP状态
     */
    public const IP_STATUS_ACTIVE = 'active';
    public const IP_STATUS_INACTIVE = 'inactive';
    public const IP_STATUS_EXPIRED = 'expired';

    /**
     * 最大IP段数量
     */
    public const MAX_IP_RANGE_COUNT = 1000;

    /**
     * CIDR掩码最大值（IPv4）
     */
    public const MAX_IPV4_CIDR = 32;

    /**
     * CIDR掩码最大值（IPv6）
     */
    public const MAX_IPV6_CIDR = 128;

    // ==================== 威胁检测常量 ====================

    /**
     * 最大递归深度
     */
    public const MAX_RECURSION_DEPTH = 10;

    /**
     * 最大数据大小（数组元素数量）
     */
    public const MAX_DATA_SIZE = 1000;

    /**
     * 最大字符串长度
     */
    public const MAX_STRING_LENGTH = 10000;

    /**
     * 最大URL长度
     */
    public const MAX_URL_LENGTH = 2048;

    /**
     * 最大User-Agent长度
     */
    public const MAX_USER_AGENT_LENGTH = 512;

    /**
     * 最大Header数量
     */
    public const MAX_HEADER_COUNT = 50;

    /**
     * 最大请求体大小（字节）
     */
    public const MAX_BODY_SIZE = 10485760; // 10MB

    // ==================== 文件上传常量 ====================

    /**
     * 最大文件大小（字节）
     */
    public const MAX_FILE_SIZE = 10485760; // 10MB

    /**
     * 允许的图片扩展名
     */
    public const ALLOWED_IMAGE_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'
    ];

    /**
     * 允许的文档扩展名
     */
    public const ALLOWED_DOCUMENT_EXTENSIONS = [
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'
    ];

    /**
     * 禁止的文件扩展名
     */
    public const FORBIDDEN_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'jsp', 'asp', 'aspx'
    ];

    /**
     * 允许的MIME类型
     */
    public const ALLOWED_MIME_TYPES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/svg+xml',
        'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain', 'text/csv'
    ];

    // ==================== 威胁评分常量 ====================

    /**
     * 黑名单转换阈值
     */
    public const BLACKLIST_THRESHOLD = 80.0;

    /**
     * 可疑IP转换阈值
     */
    public const SUSPICIOUS_THRESHOLD = 50.0;

    /**
     * 最大触发次数
     */
    public const MAX_TRIGGERS = 5;

    /**
     * 威胁评分增加量
     */
    public const THREAT_SCORE_INCREMENT = 10.00;

    /**
     * 威胁评分减少量
     */
    public const THREAT_SCORE_DECREMENT = 1.00;

    /**
     * 威胁评分每小时衰减率
     */
    public const THREAT_SCORE_DECAY_PER_HOUR = 0.3;

    /**
     * 最大威胁评分
     */
    public const MAX_THREAT_SCORE = 100.0;

    /**
     * 最小威胁评分
     */
    public const MIN_THREAT_SCORE = 0.0;

    // ==================== 日志常量 ====================

    /**
     * 日志级别
     */
    public const LOG_LEVEL_DEBUG = 'debug';
    public const LOG_LEVEL_INFO = 'info';
    public const LOG_LEVEL_WARNING = 'warning';
    public const LOG_LEVEL_ERROR = 'error';
    public const LOG_LEVEL_CRITICAL = 'critical';

    /**
     * 日志详情键
     */
    public const LOG_DETAILS_ENABLED = true;
    public const LOG_DETAILS_DISABLED = false;

    // ==================== 性能监控常量 ====================

    /**
     * 性能监控阈值（毫秒）
     */
    public const PERFORMANCE_THRESHOLD_WARNING = 100;  // 100ms
    public const PERFORMANCE_THRESHOLD_CRITICAL = 500;  // 500ms

    /**
     * 采样率（正常请求）
     */
    public const SAMPLING_RATE_NORMAL = 0.1;  // 10%

    /**
     * 采样率（被拦截请求）
     */
    public const SAMPLING_RATE_BLOCKED = 1.0;  // 100%

    // ==================== 配置热重载常量 ====================

    /**
     * 配置重载间隔（秒）
     */
    public const CONFIG_RELOAD_INTERVAL = 5;

    /**
     * 配置文件监控间隔（秒）
     */
    public const CONFIG_FILE_CHECK_INTERVAL = 1;

    // ==================== 内网IP常量 ====================

    /**
     * 内网IP范围（CIDR）
     */
    public const INTRANET_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        'fc00::/7',
        'fe80::/10',
        '::1/128'
    ];

    /**
     * 内网IP缓存TTL（秒）
     */
    public const INTRANET_CACHE_TTL = 300;

    // ==================== 过期时间常量 ====================

    /**
     * 监控IP过期时间（天）
     */
    public const MONITORING_EXPIRE_DAYS = 15;

    /**
     * 过期IP清理批次大小
     */
    public const CLEANUP_BATCH_SIZE = 500;

    // ==================== 正则表达式常量 ====================

    /**
     * 正则表达式超时（毫秒）
     */
    public const REGEX_TIMEOUT = 100;

    /**
     * 最大正则表达式长度
     */
    public const MAX_REGEX_LENGTH = 1000;

    // ==================== 其他常量 ====================

    /**
     * 默认原因
     */
    public const DEFAULT_REASON = '自动添加';

    /**
     * 空字符串
     */
    public const EMPTY_STRING = '';

    /**
     * 包版本
     */
    public const PACKAGE_VERSION = '2.0.0';

    /**
     * 配置版本
     */
    public const CONFIG_VERSION = '2.0.0';

    /**
     * 配置级别
     */
    public const CONFIG_LEVEL = 'commercial_industrial_plus';
}
