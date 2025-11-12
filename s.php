<?php

namespace zxf\Security\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use zxf\Laravel\Trace\Handle;
use zxf\Laravel\Trace\Traits\ExceptionCodeTrait;
use zxf\Laravel\Trace\Traits\ExceptionShowDebugHtmlTrait;

/**
 * 高级安全拦截中间件 - 最终优化版
 *
 * 功能特性：
 * 1. 多层安全检测机制，性能优先
 * 2. 智能误报过滤，减少误拦截
 * 3. 正则表达式优化，提升匹配性能
 * 4. 完整的攻击类型覆盖，深度防御
 * 5. 可扩展的规则引擎，支持自定义
 * 6. 实时威胁情报，动态更新
 * 7. 完善的监控统计，便于运维
 *
 * @package zxf\Security\Middleware
 * @author zxf
 * @version 2.0.0
 */
class SecurityMiddleware
{
    use ExceptionCodeTrait, ExceptionShowDebugHtmlTrait;

    /**
     * 错误信息列表，记录所有检测到的安全威胁
     *
     * @var array
     */
    protected array $errorList = [];

    /**
     * 错误代码，标识具体的错误类型
     *
     * @var string
     */
    protected string $errorCode = '';

    /**
     * 安全配置，存储所有安全相关的配置参数
     *
     * @var array
     */
    protected static array $securityConfig = [];

    /**
     * 预编译的正则表达式缓存，提升匹配性能
     *
     * @var array
     */
    protected static array $compiledPatterns = [];

    /**
     * 请求指纹缓存，避免重复计算
     *
     * @var array
     */
    protected static array $fingerprintCache = [];

    /**
     * 检测统计信息，用于性能监控和分析
     *
     * @var array
     */
    protected array $detectionStats = [
        'checks_performed' => 0,      // 执行的检查次数
        'patterns_matched' => 0,      // 模式匹配次数
        'false_positives' => 0,       // 误报次数
        'execution_time' => 0,        // 执行时间（秒）
        'memory_usage' => 0,          // 内存使用量（字节）
    ];

    /**
     * 性能监控开始时间，用于计算执行时间
     *
     * @var float
     */
    protected float $startTime;

    /**
     * 内存使用基准，用于计算内存消耗
     *
     * @var int
     */
    protected int $startMemory;

    // ==================== 安全模式定义 - 优化正则表达式 ====================

    /**
     * 恶意请求检测模式 - 优化性能版本
     *
     * 优化策略：
     * 1. 使用更精确的模式，减少回溯
     * 2. 分组相似模式，减少匹配次数
     * 3. 使用原子组和 possessive 量词
     * 4. 避免复杂的嵌套和选择分支
     *
     * @var array
     */
    protected const MALICIOUS_BODY_PATTERNS = [
        // XSS攻击检测 - 优化分组
        // 脚本标签和相关事件处理器
        '/(?:<script[^>]*>.*?<\/script>|javascript:\\s*|on\\w+\\s*=\\s*["\']?)/is',

        // SQL注入检测 - 关键操作符和函数
        '/(?:\\b(?:union\\s+select|select\\s+[\\w*]+\\s+from|insert\\s+into|update\\s+\\w+\\s+set|drop\\s+table|exec\\s*\\(|xp_cmdshell)\\b|--\\s|\\/\\*[\\s\\S]*?\\*\\/)/is',

        // 命令注入检测 - 系统命令和特殊字符
        '/(?:\\b(?:system|exec|shell_exec|passthru)\\s*\\(|`[^`]*`|\\$\\s*\\(|\\|\\s*\\w+|&\\s*\\w+)/i',

        // 目录遍历和文件包含
        '/(?:\\.\\.\\/|\\.\\.\\\\|\\/etc\\/passwd|\\/etc\\/shadow|\\/winnt\\/system32)/i',

        // PHP代码执行和危险函数
        '/(?:<\\?php|\\b(?:eval|assert|create_function)\\s*\\(|\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\\b(?:include|require)(?:_once)?\\s*\\()/i',

        // 反序列化攻击特征
        '/(?:O:\\d+:"[^"]*":\\d+:|__destruct|__wakeup|__toString)/i',

        // XXE攻击特征
        '/(?:<!ENTITY|<!DOCTYPE[^>]*SYSTEM|SYSTEM\\s+["\'])/i',

        // 表达式注入
        '/(?:\\$\\{.*\\}|\\(\\{.*\\}\\)|\\{\\{.*\\}\\})/',
    ];

    /**
     * 非法URL路径模式 - 优化性能版本
     *
     * 使用更高效的模式匹配敏感文件和目录
     *
     * @var array
     */
    protected const ILLEGAL_URL_PATTERNS = [
        // 隐藏文件和目录（排除 .well-known）
        '~/(?:\\.(?!well-known)[^/]*)(?=/|$)~i',

        // 配置文件和敏感数据文件
        '/\\.(?:env|config|settings|configuration)(?:\\.\\w+)?$/i',
        '/(?:composer|package)(?:\\.(?:json|lock))?$/i',

        // 源代码和脚本文件
        '/\\.(?:php|phtml|jsp|asp|aspx|pl|py|rb|sh)(?:\\.\\w+)?$/i',

        // 数据库和备份文件
        '/\\.(?:sql|db|mdb|accdb|sqlite|bak|old|backup)$/i',

        // 日志和临时文件
        '/\\.(?:log|trace|debug|temp|tmp)$/i',

        // 敏感目录路径
        '/(?:^|\\/)(?:config|setup|install|backup|logs?|temp|node_modules|\\.git)(?:$|\\/)/i',
    ];

    /**
     * 禁止上传的文件扩展名 - 完整列表
     *
     * @var array
     */
    protected const DISALLOWED_EXTENSIONS = [
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
    ];

    /**
     * 可疑User-Agent模式 - 优化性能版本
     *
     * 使用分组减少正则表达式数量
     *
     * @var array
     */
    protected const SUSPICIOUS_USER_AGENTS = [
        // 安全扫描工具和渗透测试工具
        '/\\b(?:sqlmap|nikto|metasploit|nessus|wpscan|acunetix|burp|dirbuster|nmap|netsparker)\\b/i',

        // 自动化工具和爬虫框架
        '/\\b(?:curl|wget|python-urllib|java|httpclient|guzzle|scrapy|selenium)\\b/i',

        // 恶意软件和攻击工具
        '/\\b(?:masscan|zmeu|blackwidow|hydra|havij|zap|arachni)\\b/i',
    ];

    /**
     * 白名单User-Agent - 合法的搜索引擎和爬虫
     *
     * @var array
     */
    protected const WHITELIST_USER_AGENTS = [
        '/googlebot/i',
        '/bingbot/i',
        '/slurp/i',
        '/duckduckbot/i',
        '/baiduspider/i',
        '/yandexbot/i',
        '/facebookexternalhit/i',
        '/twitterbot/i',
        '/applebot/i',
    ];

    /**
     * 可疑HTTP方法 - 非常规方法可能用于攻击
     *
     * @var array
     */
    protected const SUSPICIOUS_METHODS = [
        'CONNECT', 'TRACE', 'TRACK', 'DEBUG', 'PROPFIND',
    ];

    // ==================== 主处理方法 ====================

    /**
     * 处理传入的HTTP请求 - 主入口方法
     *
     * 执行流程：
     * 1. 初始化配置和性能监控
     * 2. 分层安全检测
     * 3. 速率限制检查
     * 4. 自定义逻辑处理
     * 5. 返回响应或继续处理
     *
     * @param Request $request 当前HTTP请求对象
     * @param Closure $next 下一个中间件闭包
     * @param string|null $encodedConfig 经过base64编码的JSON配置字符串
     * @return mixed HTTP响应或继续处理
     */
    public function handle(Request $request, Closure $next, ?string $encodedConfig = null)
    {
        // 初始化性能监控
        $this->startTime = microtime(true);   // 记录开始时间
        $this->startMemory = memory_get_usage(true);  // 记录开始内存

        try {
            // 1. 配置预处理
            $this->handleSecurityParams($request, $encodedConfig);

            // 2. 检查中间件是否启用
            if (!$this->getMiddlewareConfig($request, 'enabled', true)) {
                return $next($request);  // 中间件禁用，直接放行
            }

            // 3. 快速检查：IP白名单和本地请求
            if ($this->isWhitelistedIp($request) || $this->isLocalRequest($request)) {
                $this->logDebug('IP白名单或本地请求，跳过安全检查');  // 记录调试日志
                return $next($request);  // 白名单IP或本地请求，直接放行
            }

            // 4. 分层安全检测
            $securityResult = $this->performLayeredSecurityCheck($request);
            if ($securityResult['block']) {
                $this->logDetectionStats($request);  // 记录检测统计
                return $securityResult['response'];  // 安全威胁，返回拦截响应
            }

            // 5. 速率限制检查
            $rateLimitResult = $this->checkRateLimit($request);
            if ($rateLimitResult['block']) {
                $this->logDetectionStats($request);  // 记录检测统计
                return $rateLimitResult['response'];  // 速率超限，返回拦截响应
            }

            // 6. 自定义逻辑处理
            $customResult = $this->handleCustomSecurityLogic($request);
            if ($customResult['block']) {
                $this->logDetectionStats($request);  // 记录检测统计
                return $customResult['response'];  // 自定义规则拦截
            }

            // 7. 黑名单检查
            $blacklistResult = $this->checkBlacklist($request);
            if ($blacklistResult['block']) {
                $this->logDetectionStats($request);  // 记录检测统计
                return $blacklistResult['response'];  // 黑名单拦截
            }

            // 8. 请求正常，继续处理
            $this->logDetectionStats($request);  // 记录检测统计
            return $next($request);  // 安全检查通过，继续处理

        } catch (\Exception $e) {
            // 异常处理：记录错误日志并根据配置决定是否阻止请求
            Log::error('安全中间件执行异常: ' . $e->getMessage(), [
                'exception' => $e,
                'request' => $this->getRequestInfo($request)  // 获取请求信息
            ]);

            // 在异常情况下，根据配置决定是否阻止请求
            if ($this->getMiddlewareConfig($request, 'block_on_exception', false)) {
                return $this->createSecurityResponse(
                    $request,
                    'SecurityError',
                    '安全系统异常',
                    '安全检测系统暂时不可用',
                    ['exception' => $e->getMessage()],
                    503  // 服务不可用状态码
                );
            }

            // 默认情况下，异常时放行请求
            return $next($request);
        }
    }

    // ==================== 分层安全检测 ====================

    /**
     * 分层安全检测 - 性能优化版本
     *
     * 检测策略：
     * 1. 超轻量级检查：方法、User-Agent等
     * 2. 轻量级检查：头部、基础特征等
     * 3. 中等重量检查：文件上传、URL路径等
     * 4. 重量级检查：内容扫描、参数分析等
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 检测结果 [block => bool, response => mixed]
     */
    protected function performLayeredSecurityCheck(Request $request): array
    {
        $this->detectionStats['checks_performed']++;  // 增加检查计数

        // 第一层：超轻量级检查（最高性能）
        $ultraLightChecks = [
            'suspicious_method' => fn() => $this->hasSuspiciousMethod($request),  // 可疑HTTP方法
            'empty_user_agent' => fn() => $this->hasEmptyUserAgent($request),     // 空User-Agent
        ];

        foreach ($ultraLightChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResponse($request, $checkType, "{$checkType} detected");  // 创建拦截响应
            }
        }

        // 第二层：轻量级检查（高性能）
        $lightweightChecks = [
            'suspicious_user_agent' => fn() => $this->hasSuspiciousUserAgent($request),  // 可疑User-Agent
            'suspicious_headers' => fn() => $this->hasSuspiciousHeaders($request),       // 可疑HTTP头
        ];

        foreach ($lightweightChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResponse($request, $checkType, "{$checkType} detected");  // 创建拦截响应
            }
        }

        // 第三层：中等重量检查
        $mediumChecks = [
            'dangerous_upload' => fn() => $this->hasDangerousUploads($request),          // 危险文件上传
            'illegal_url' => fn() => !$this->isSafeUrl($request, $request->fullUrl()),   // 非法URL
        ];

        foreach ($mediumChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResponse($request, $checkType, "{$checkType} detected");  // 创建拦截响应
            }
        }

        // 第四层：重量级检查（仅在必要时执行）
        if (!$this->isWhitelistPath($request)) {  // 检查是否为白名单路径
            $heavyChecks = [
                'malicious_request' => fn() => $this->isMaliciousRequest($request),          // 恶意请求内容
                'anomalous_parameters' => fn() => $this->hasAnomalousParameters($request),   // 异常参数
                'suspicious_fingerprint' => fn() => $this->hasSuspiciousFingerprint($request), // 可疑指纹
            ];

            foreach ($heavyChecks as $checkType => $checkFn) {
                if ($checkFn()) {
                    return $this->createBlockResponse($request, $checkType, "{$checkType} detected");  // 创建拦截响应
                }
            }
        }

        return ['block' => false];  // 所有检查通过
    }

    // ==================== 配置管理 ====================

    /**
     * 处理安全参数 - 配置初始化和验证
     *
     * @param Request $request 当前HTTP请求对象
     * @param string|null $encodedConfig 经过base64编码的JSON配置字符串
     * @return void
     */
    protected function handleSecurityParams(Request $request, ?string $encodedConfig = null): void
    {
        if (!empty($encodedConfig)) {
            try {
                // 解码配置字符串
                $config = json_decode(base64_decode($encodedConfig), true, 512, JSON_THROW_ON_ERROR);
                // 合并默认配置和传入配置
                self::$securityConfig = array_merge($this->getDefaultConfig(), (array)$config);

                // 验证配置有效性
                $this->validateSecurityConfig(self::$securityConfig);

            } catch (\Exception $e) {
                // 配置解析失败，使用默认配置并记录警告
                Log::warning('安全配置解析失败，使用默认配置: ' . $e->getMessage());
                self::$securityConfig = $this->getDefaultConfig();
            }
        } else {
            // 没有传入配置，使用默认配置
            self::$securityConfig = $this->getDefaultConfig();
        }

        // 预编译正则表达式，提升性能
        $this->precompilePatterns();
    }

    /**
     * 获取默认配置 - 完整的配置默认值
     *
     * @return array 默认配置数组
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled' => true,                                      // 是否启用安全中间件
            'log_level' => 'warning',                               // 日志级别
            'enable_rate_limiting' => true,                         // 是否启用速率限制
            'max_requests_per_minute' => 60,                        // 每分钟最大请求数
            'max_requests_per_hour' => 1000,                        // 每小时最大请求数
            'max_requests_per_day' => 10000,                        // 每天最大请求数
            'enable_ip_whitelist' => true,                          // 是否启用IP白名单
            'ip_whitelist' => ['127.0.0.1', '::1', 'localhost'],    // IP白名单列表
            'enable_ip_blacklist' => true,                          // 是否启用IP黑名单
            'ip_blacklist' => [],                                   // IP黑名单列表
            'allow_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], // 允许的HTTP方法
            'forbid_user_agent' => self::SUSPICIOUS_USER_AGENTS,    // 禁止的User-Agent模式
            'forbid_upload_file_ext' => self::DISALLOWED_EXTENSIONS, // 禁止上传的文件扩展名
            'reg_exp_body' => self::MALICIOUS_BODY_PATTERNS,        // 请求体正则表达式
            'reg_exp_url' => self::ILLEGAL_URL_PATTERNS,            // URL正则表达式
            'whitelist_path_of_not_verify_body' => ['api/health', 'api/status', 'health', 'status'], // 不验证请求体的白名单路径
            'custom_handle' => null,                                // 自定义处理逻辑
            'blacklist_handle' => null,                             // 黑名单处理逻辑
            'send_security_alarm_handle' => null,                   // 安全警报处理逻辑
            'ajax_resp_format' => [                                 // AJAX响应格式
                'code' => 'code',
                'message' => 'message',
                'data' => 'data',
            ],
            'block_on_exception' => false,                          // 异常时是否阻止请求
            'enable_debug_logging' => false,                        // 是否启用调试日志
            'enable_performance_logging' => false,                  // 是否启用性能日志
            'cache_ttl' => 3600,                                    // 缓存生存时间（秒）
            'ban_duration' => 3600,                                 // 封禁时长（秒）
            'max_ban_duration' => 86400,                            // 最大封禁时长（秒）
            'enable_advanced_detection' => true,                    // 是否启用高级检测
            'enable_fingerprinting' => true,                        // 是否启用指纹识别
            'enable_anomaly_detection' => true,                     // 是否启用异常检测
            'max_file_size' => 10 * 1024 * 1024,                    // 最大文件大小（10MB）
            'enable_file_content_check' => false,                   // 是否启用文件内容检查
        ];
    }

    /**
     * 验证安全配置 - 确保配置参数的有效性
     *
     * @param array $config 待验证的配置数组
     * @return void
     * @throws ValidationException 配置验证失败时抛出异常
     */
    protected function validateSecurityConfig(array $config): void
    {
        $validator = Validator::make($config, [
            'enabled' => 'boolean',                                  // 必须为布尔值
            'log_level' => 'in:debug,info,notice,warning,error,critical,alert,emergency', // 必须为有效的日志级别
            'max_requests_per_minute' => 'integer|min:1',           // 必须为大于0的整数
            'max_requests_per_hour' => 'integer|min:1',             // 必须为大于0的整数
            'max_requests_per_day' => 'integer|min:1',              // 必须为大于0的整数
            'enable_ip_whitelist' => 'boolean',                     // 必须为布尔值
            'ip_whitelist' => 'array',                              // 必须为数组
            'enable_ip_blacklist' => 'boolean',                     // 必须为布尔值
            'ip_blacklist' => 'array',                              // 必须为数组
            'allow_methods' => 'array',                             // 必须为数组
            'forbid_user_agent' => 'array',                         // 必须为数组
            'forbid_upload_file_ext' => 'array',                    // 必须为数组
            'reg_exp_body' => 'array',                              // 必须为数组
            'reg_exp_url' => 'array',                               // 必须为数组
            'whitelist_path_of_not_verify_body' => 'array',         // 必须为数组
            'block_on_exception' => 'boolean',                      // 必须为布尔值
            'enable_debug_logging' => 'boolean',                    // 必须为布尔值
            'enable_performance_logging' => 'boolean',              // 必须为布尔值
            'cache_ttl' => 'integer|min:60',                        // 必须为大于60的整数
            'ban_duration' => 'integer|min:60',                     // 必须为大于60的整数
            'max_ban_duration' => 'integer|min:3600',               // 必须为大于3600的整数
            'enable_advanced_detection' => 'boolean',               // 必须为布尔值
            'enable_fingerprinting' => 'boolean',                   // 必须为布尔值
            'enable_anomaly_detection' => 'boolean',                // 必须为布尔值
            'max_file_size' => 'integer|min:1024',                  // 必须为大于1024的整数
            'enable_file_content_check' => 'boolean',               // 必须为布尔值
        ]);

        if ($validator->fails()) {
            throw new ValidationException($validator);  // 验证失败，抛出异常
        }
    }

    /**
     * 预编译正则表达式 - 提升匹配性能
     *
     * @return void
     */
    protected function precompilePatterns(): void
    {
        $patternTypes = ['reg_exp_body', 'reg_exp_url', 'forbid_user_agent'];  // 需要预编译的正则类型

        foreach ($patternTypes as $type) {
            $patterns = $this->getMiddlewareConfig(null, $type, []);  // 获取配置中的正则表达式
            $this->getCompiledPatterns($patterns);  // 预编译并缓存
        }
    }

    /**
     * 获取中间件配置项
     *
     * @param Request|null $request 当前HTTP请求对象（可选）
     * @param string $name 配置项名称
     * @param mixed $default 默认值
     * @return mixed 配置值
     */
    protected function getMiddlewareConfig(?Request $request, string $name, $default = null): mixed
    {
        return self::$securityConfig[$name] ?? $default;  // 返回配置值或默认值
    }

    // ==================== 安全检测方法 ====================

    /**
     * 检查恶意请求 - 高性能优化版本
     *
     * 优化策略：
     * 1. 使用预编译的正则表达式
     * 2. 递归检查所有输入数据
     * 3. 智能内容预处理
     * 4. 误报过滤机制
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到恶意请求
     */
    protected function isMaliciousRequest(Request $request): bool
    {
        $input = $request->input();  // 获取所有输入数据
        if (empty($input)) {
            return false;  // 没有输入数据，直接返回安全
        }

        $bodyRegExp = $this->getMiddlewareConfig($request, 'reg_exp_body', self::MALICIOUS_BODY_PATTERNS);
        $compiledPatterns = $this->getCompiledPatterns($bodyRegExp);  // 获取预编译的正则表达式

        // 使用递归检查所有输入数据
        return $this->checkInputDataRecursively($request, $input, $compiledPatterns);
    }

    /**
     * 递归检查输入数据 - 深度扫描所有参数
     *
     * @param Request $request 当前HTTP请求对象
     * @param array $data 输入数据数组
     * @param array $patterns 预编译的正则表达式数组
     * @param string $parentKey 父级键名（用于嵌套参数）
     * @return bool 是否检测到恶意内容
     */
    protected function checkInputDataRecursively(Request $request, array $data, array $patterns, string $parentKey = ''): bool
    {
        foreach ($data as $key => $value) {
            $currentKey = $parentKey ? "{$parentKey}.{$key}" : $key;  // 构建当前键名

            if (is_array($value)) {
                // 递归检查数组值
                if ($this->checkInputDataRecursively($request, $value, $patterns, $currentKey)) {
                    return true;  // 子级检测到威胁，直接返回
                }
            } else {
                // 检查单个值
                if ($this->checkInputValue($request, $currentKey, $value, $patterns)) {
                    return true;  // 检测到威胁，直接返回
                }
            }
        }

        return false;  // 所有数据检查通过
    }

    /**
     * 检查单个输入值 - 核心检测逻辑
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $key 参数键名
     * @param mixed $value 参数值
     * @param array $patterns 预编译的正则表达式数组
     * @return bool 是否检测到恶意内容
     */
    protected function checkInputValue(Request $request, string $key, $value, array $patterns): bool
    {
        $this->detectionStats['checks_performed']++;  // 增加检查计数

        if (!is_string($value) || empty(trim($value))) {
            return false;  // 非字符串或空值，跳过检查
        }

        // 预处理内容，提升检测准确性和性能
        $processedValue = $this->preprocessContent($value);
        if (empty($processedValue)) {
            return false;  // 预处理后为空，跳过检查
        }

        // 使用预编译的正则表达式进行模式匹配
        foreach ($patterns as $pattern) {
            $this->detectionStats['patterns_matched']++;  // 增加模式匹配计数

            if (preg_match($pattern, $processedValue)) {
                // 检测到匹配模式，检查是否为误报
                if (!$this->isFalsePositive($request, $key, $processedValue, $pattern)) {
                    // 确认为安全威胁，记录错误信息
                    $this->errorList[] = [
                        'message' => '恶意请求拦截',
                        'key' => $key,
                        'value' => $this->truncateString($processedValue, 100),  // 截断长字符串
                        'pattern' => $pattern,
                        'timestamp' => now()->toISOString(),
                    ];
                    return true;  // 检测到安全威胁
                } else {
                    $this->detectionStats['false_positives']++;  // 增加误报计数
                }
            }
        }

        return false;  // 未检测到安全威胁
    }

    /**
     * 内容预处理 - 提升检测准确性和性能
     *
     * 处理步骤：
     * 1. 移除不可见字符
     * 2. 识别内容类型（Markdown/HTML）
     * 3. 根据类型进行相应清理
     * 4. 标准化空格
     *
     * @param string $content 原始内容
     * @return string 预处理后的内容
     */
    protected function preprocessContent(string $content): string
    {
        $content = trim($content);  // 去除首尾空格

        if (empty($content)) {
            return '';  // 空内容直接返回
        }

        // 移除不可见字符（保留常规空格）
        $content = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $content);

        // 内容类型识别和相应处理
        if ($this->checkIsMarkdown($content)) {
            // Markdown内容：移除代码块和格式标记
            $content = $this->pruneMarkdownCode($content);
        } elseif (!$this->checkIsHtml($content)) {
            // 非HTML内容：移除HTML标签
            $content = strip_tags($content);
        }

        // 标准化空格，减少正则匹配复杂度
        $content = preg_replace('/\s+/', ' ', $content);

        return $content;
    }

    /**
     * 获取预编译的正则表达式 - 带缓存功能
     *
     * @param array $patterns 原始正则表达式数组
     * @return array 预编译后的正则表达式数组
     */
    protected function getCompiledPatterns(array $patterns): array
    {
        $cacheKey = md5(serialize($patterns));  // 生成缓存键

        if (!isset(self::$compiledPatterns[$cacheKey])) {
            $compiled = [];
            foreach ($patterns as $pattern) {
                // 验证正则表达式有效性，避免运行时错误
                if (@preg_match($pattern, '') !== false) {
                    $compiled[] = $pattern;  // 有效的正则表达式
                } else {
                    Log::warning('无效的正则表达式模式: ' . $pattern);  // 记录警告日志
                }
            }
            self::$compiledPatterns[$cacheKey] = $compiled;  // 缓存预编译结果
        }

        return self::$compiledPatterns[$cacheKey];  // 返回缓存结果
    }

    /**
     * 检查可疑User-Agent - 性能优化版本
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到可疑User-Agent
     */
    protected function hasSuspiciousUserAgent(Request $request): bool
    {
        $userAgent = $request->userAgent();  // 获取User-Agent头
        if (empty($userAgent)) {
            $this->errorList[] = ['message' => '空User-Agent'];  // 记录空User-Agent错误
            return true;  // 空User-Agent视为可疑
        }

        // 先检查白名单，减少不必要的黑名单检查
        foreach (self::WHITELIST_USER_AGENTS as $whitelistPattern) {
            if (preg_match($whitelistPattern, $userAgent)) {
                return false;  // 在白名单中，直接返回安全
            }
        }

        // 检查黑名单模式
        $suspiciousPatterns = $this->getMiddlewareConfig($request, 'forbid_user_agent', self::SUSPICIOUS_USER_AGENTS);
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                // 检测到可疑User-Agent，记录错误信息
                $this->errorList[] = [
                    'message' => '可疑User-Agent',
                    'user_agent' => $this->truncateString($userAgent, 200),  // 截断长字符串
                    'pattern' => $pattern,
                    'timestamp' => now()->toISOString(),
                ];
                return true;  // 检测到可疑User-Agent
            }
        }

        return false;  // User-Agent检查通过
    }

    /**
     * 检查空User-Agent - 快速检测
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否为空User-Agent
     */
    protected function hasEmptyUserAgent(Request $request): bool
    {
        $userAgent = $request->userAgent();  // 获取User-Agent头
        if (empty($userAgent)) {
            $this->errorList[] = ['message' => '空User-Agent'];  // 记录空User-Agent错误
            return true;  // 检测到空User-Agent
        }
        return false;  // User-Agent不为空
    }

    /**
     * 检查可疑HTTP方法 - 快速检测
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到可疑HTTP方法
     */
    protected function hasSuspiciousMethod(Request $request): bool
    {
        $method = strtoupper($request->method());  // 获取HTTP方法并转为大写
        $allowedMethods = $this->getMiddlewareConfig($request, 'allow_methods', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

        // 检查是否在允许的方法列表中
        if (!in_array($method, $allowedMethods)) {
            $this->errorList[] = [
                'message' => '可疑HTTP方法',
                'method' => $method,
                'allowed_methods' => $allowedMethods,
            ];
            return true;  // 检测到可疑HTTP方法
        }

        // 检查是否为已知的危险方法
        if (in_array($method, self::SUSPICIOUS_METHODS)) {
            $this->errorList[] = [
                'message' => '危险HTTP方法',
                'method' => $method,
            ];
            return true;  // 检测到危险HTTP方法
        }

        return false;  // HTTP方法检查通过
    }

    /**
     * 检查可疑HTTP头 - 快速检测
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到可疑HTTP头
     */
    protected function hasSuspiciousHeaders(Request $request): bool
    {
        // 检查常见的可疑代理头
        $suspiciousHeaders = ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP'];

        foreach ($suspiciousHeaders as $header) {
            if ($request->headers->has($header)) {
                $value = $request->header($header);
                // 检查头值是否包含多个IP（可能的代理滥用）
                if (str_contains($value, ',')) {
                    $this->errorList[] = [
                        'message' => '可疑HTTP头',
                        'header' => $header,
                        'value' => $value,
                    ];
                    return true;  // 检测到可疑HTTP头
                }
            }
        }
        return false;  // HTTP头检查通过
    }

    // ==================== 文件上传检查 ====================

    /**
     * 检查危险文件上传 - 完整安全检查
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到危险文件上传
     */
    protected function hasDangerousUploads(Request $request): bool
    {
        $files = $request->allFiles();  // 获取所有上传文件
        if (empty($files)) {
            return false;  // 没有文件上传，直接返回安全
        }

        // 检查每个上传文件的安全性
        foreach ($files as $file) {
            if (!$this->isSafeFile($request, $file)) {
                return true;  // 检测到危险文件
            }
        }

        return false;  // 所有文件检查通过
    }

    /**
     * 检查文件安全性 - 多维度检查
     *
     * @param Request $request 当前HTTP请求对象
     * @param mixed $file 文件对象
     * @return bool 文件是否安全
     */
    protected function isSafeFile(Request $request, $file): bool
    {
        if (!$file instanceof UploadedFile) {
            return true;  // 不是上传文件对象，跳过检查
        }

        // 多维度安全检查
        if (!$this->isSafeFileExtension($request, $file)) {
            return false;  // 文件扩展名不安全
        }

        if (!$this->isSafeMimeType($request, $file)) {
            return false;  // MIME类型不安全
        }

        if (!$this->isSafeFileSize($request, $file)) {
            return false;  // 文件大小超限
        }

        // 可选的文件内容检查（性能考虑，默认关闭）
        if ($this->getMiddlewareConfig($request, 'enable_file_content_check', false)) {
            if (!$this->isSafeFileContent($request, $file)) {
                return false;  // 文件内容不安全
            }
        }

        return true;  // 所有安全检查通过
    }

    /**
     * 检查文件扩展名 - 基础安全检查
     *
     * @param Request $request 当前HTTP请求对象
     * @param UploadedFile $file 上传文件对象
     * @return bool 文件扩展名是否安全
     */
    protected function isSafeFileExtension(Request $request, UploadedFile $file): bool
    {
        $extension = strtolower($file->getClientOriginalExtension());  // 获取文件扩展名并转为小写
        $forbiddenExtensions = $this->getMiddlewareConfig($request, 'forbid_upload_file_ext', self::DISALLOWED_EXTENSIONS);

        // 检查扩展名是否在禁止列表中
        if (in_array($extension, $forbiddenExtensions)) {
            $this->errorList[] = [
                'message' => '危险文件扩展名',
                'filename' => $file->getClientOriginalName(),
                'extension' => $extension,
            ];
            return false;  // 扩展名不安全
        }

        return true;  // 扩展名安全
    }

    /**
     * 检查MIME类型 - 防止文件类型欺骗
     *
     * @param Request $request 当前HTTP请求对象
     * @param UploadedFile $file 上传文件对象
     * @return bool MIME类型是否安全
     */
    protected function isSafeMimeType(Request $request, UploadedFile $file): bool
    {
        $mimeType = $file->getMimeType();  // 获取MIME类型
        $forbiddenMimeTypes = [
            'application/x-php',           // PHP文件
            'text/x-php',                  // PHP文件
            'application/x-httpd-php',     // PHP文件
            'application/x-jsp',           // JSP文件
            'application/x-asp',           // ASP文件
            'application/x-sh',            // Shell脚本
            'application/x-bat',           // Batch文件
            'application/x-msdownload',    // Windows可执行文件
        ];

        // 检查MIME类型是否在禁止列表中
        if (in_array($mimeType, $forbiddenMimeTypes)) {
            $this->errorList[] = [
                'message' => '危险MIME类型',
                'filename' => $file->getClientOriginalName(),
                'mime_type' => $mimeType,
            ];
            return false;  // MIME类型不安全
        }

        return true;  // MIME类型安全
    }

    /**
     * 检查文件大小 - 防止资源耗尽攻击
     *
     * @param Request $request 当前HTTP请求对象
     * @param UploadedFile $file 上传文件对象
     * @return bool 文件大小是否安全
     */
    protected function isSafeFileSize(Request $request, UploadedFile $file): bool
    {
        $maxSize = $this->getMiddlewareConfig($request, 'max_file_size', 10 * 1024 * 1024);  // 默认10MB
        $fileSize = $file->getSize();  // 获取文件大小

        // 检查文件大小是否超限
        if ($fileSize > $maxSize) {
            $this->errorList[] = [
                'message' => '文件大小超限',
                'filename' => $file->getClientOriginalName(),
                'file_size' => $fileSize,
                'max_size' => $maxSize,
            ];
            return false;  // 文件大小超限
        }

        return true;  // 文件大小安全
    }

    /**
     * 检查文件内容 - 深度内容扫描（性能敏感）
     *
     * @param Request $request 当前HTTP请求对象
     * @param UploadedFile $file 上传文件对象
     * @return bool 文件内容是否安全
     */
    protected function isSafeFileContent(Request $request, UploadedFile $file): bool
    {
        try {
            $content = file_get_contents($file->getPathname());  // 读取文件内容
            $patterns = $this->getMiddlewareConfig($request, 'reg_exp_body', self::MALICIOUS_BODY_PATTERNS);
            $compiledPatterns = $this->getCompiledPatterns($patterns);  // 获取预编译的正则表达式

            // 检查文件内容是否包含恶意模式
            foreach ($compiledPatterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $this->errorList[] = [
                        'message' => '文件内容包含恶意代码',
                        'filename' => $file->getClientOriginalName(),
                        'pattern' => $pattern,
                    ];
                    return false;  // 文件内容不安全
                }
            }
        } catch (\Exception $e) {
            // 文件读取失败，记录警告但不阻止（可能是权限问题）
            Log::warning('文件内容检查失败: ' . $e->getMessage());
        }

        return true;  // 文件内容安全或检查失败
    }

    // ==================== URL安全检查 ====================

    /**
     * 检查URL安全性 - 路径和参数检查
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $url 完整URL
     * @return bool URL是否安全
     */
    protected function isSafeUrl(Request $request, string $url): bool
    {
        $url = urldecode($url);  // 解码URL编码的字符
        $urlRegExp = $this->getMiddlewareConfig($request, 'reg_exp_url', self::ILLEGAL_URL_PATTERNS);

        $regExp = is_array($urlRegExp) && !empty($urlRegExp) ? $urlRegExp : self::ILLEGAL_URL_PATTERNS;

        if (empty($regExp)) {
            return true;  // 没有URL检查规则，直接返回安全
        }

        // 检查URL是否匹配非法模式
        foreach ($regExp as $pattern) {
            try {
                if (preg_match($pattern, $url)) {
                    $this->errorList['illegal_url'] = [
                        'url' => $this->truncateString($url, 200),  // 截断长URL
                        'pattern' => $pattern,
                    ];
                    return false;  // URL不安全
                }
            } catch (\Exception $e) {
                // 正则匹配失败，记录警告并继续检查其他模式
                Log::warning('URL模式匹配失败: ' . $e->getMessage());
                continue;
            }
        }

        return true;  // URL检查通过
    }

    // ==================== 高级检测功能 ====================

    /**
     * 检查异常参数 - 启发式检测
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到异常参数
     */
    protected function hasAnomalousParameters(Request $request): bool
    {
        if (!$this->getMiddlewareConfig($request, 'enable_anomaly_detection', true)) {
            return false;  // 异常检测未启用
        }

        $parameters = $request->all();  // 获取所有参数

        // 检查参数数量异常（防止参数洪水攻击）
        if (count($parameters) > 100) {
            $this->errorList[] = ['message' => '参数数量异常'];
            return true;  // 参数数量过多
        }

        // 检查参数名和值的异常特征
        foreach ($parameters as $key => $value) {
            // 检查参数名长度异常
            if (strlen($key) > 255) {
                $this->errorList[] = ['message' => '参数名长度异常'];
                return true;  // 参数名过长
            }

            // 检查可疑参数名（常见攻击参数）
            $suspiciousParamNames = ['cmd', 'exec', 'system', 'eval', 'php', 'script', 'javascript'];
            foreach ($suspiciousParamNames as $suspicious) {
                if (stripos($key, $suspicious) !== false) {
                    $this->errorList[] = [
                        'message' => '可疑参数名',
                        'parameter' => $key,
                    ];
                    return true;  // 参数名可疑
                }
            }
        }

        return false;  // 参数检查通过
    }

    /**
     * 检查可疑指纹 - 请求特征分析
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否检测到可疑指纹
     */
    protected function hasSuspiciousFingerprint(Request $request): bool
    {
        if (!$this->getMiddlewareConfig($request, 'enable_fingerprinting', true)) {
            return false;  // 指纹识别未启用
        }

        $fingerprint = $this->getRequestFingerprint($request);  // 获取请求指纹
        $cacheKey = "suspicious_fingerprint:{$fingerprint}";

        // 检查是否已知的可疑指纹
        if (Cache::has($cacheKey)) {
            $this->errorList[] = ['message' => '可疑请求指纹'];
            return true;  // 已知可疑指纹
        }

        // 分析指纹特征，检测新的可疑请求
        $features = $this->analyzeFingerprintFeatures($request);
        if ($this->isSuspiciousFingerprintFeatures($features)) {
            // 缓存新发现的可疑指纹
            Cache::put($cacheKey, true, $this->getMiddlewareConfig($request, 'cache_ttl', 3600));
            $this->errorList[] = ['message' => '可疑指纹特征'];
            return true;  // 指纹特征可疑
        }

        return false;  // 指纹检查通过
    }

    /**
     * 分析指纹特征 - 提取请求特征
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 指纹特征数组
     */
    protected function analyzeFingerprintFeatures(Request $request): array
    {
        return [
            'user_agent_length' => strlen($request->userAgent() ?? ''),  // User-Agent长度
            'header_count' => count($request->headers->all()),           // 头部数量
            'parameter_count' => count($request->all()),                 // 参数数量
            'missing_common_headers' => $this->checkMissingCommonHeaders($request),  // 缺失的常见头部
        ];
    }

    /**
     * 检查缺失的常见头部 - 识别异常请求
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 缺失的头部列表
     */
    protected function checkMissingCommonHeaders(Request $request): array
    {
        $missing = [];
        $commonHeaders = ['User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding'];  // 常见HTTP头部

        foreach ($commonHeaders as $header) {
            if (!$request->headers->has($header)) {
                $missing[] = $header;  // 记录缺失的头部
            }
        }

        return $missing;
    }

    /**
     * 判断指纹特征是否可疑 - 启发式规则
     *
     * @param array $features 指纹特征数组
     * @return bool 是否可疑
     */
    protected function isSuspiciousFingerprintFeatures(array $features): bool
    {
        // 用户代理过短（可能是自动化工具）
        if ($features['user_agent_length'] < 10) {
            return true;
        }

        // 缺失过多常见头部（可能是自定义客户端）
        if (count($features['missing_common_headers']) > 2) {
            return true;
        }

        // 参数过多（可能的参数洪水攻击）
        if ($features['parameter_count'] > 50) {
            return true;
        }

        return false;  // 特征正常
    }

    // ==================== 速率限制 ====================

    /**
     * 检查速率限制 - 多层限制策略
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 限制检查结果
     */
    protected function checkRateLimit(Request $request): array
    {
        if (!$this->getMiddlewareConfig($request, 'enable_rate_limiting', true)) {
            return ['block' => false];  // 速率限制未启用
        }

        $fingerprint = $this->getRequestFingerprint($request);  // 获取请求指纹

        // 多层速率限制：分钟、小时、天
        $minuteKey = "rate_limit:minute:{$fingerprint}";
        $hourKey = "rate_limit:hour:{$fingerprint}";
        $dayKey = "rate_limit:day:{$fingerprint}";

        $maxMinute = $this->getMiddlewareConfig($request, 'max_requests_per_minute', 60);
        $maxHour = $this->getMiddlewareConfig($request, 'max_requests_per_hour', 1000);
        $maxDay = $this->getMiddlewareConfig($request, 'max_requests_per_day', 10000);

        // 获取当前计数
        $minuteCount = Cache::get($minuteKey, 0);
        $hourCount = Cache::get($hourKey, 0);
        $dayCount = Cache::get($dayKey, 0);

        // 检查是否超限
        if ($minuteCount >= $maxMinute || $hourCount >= $maxHour || $dayCount >= $maxDay) {
            $retryAfter = $this->calculateRetryAfter($minuteCount, $hourCount, $dayCount, $maxMinute, $maxHour, $maxDay);

            return [
                'block' => true,
                'response' => $this->handleSecurityViolation(
                    $request,
                    'RateLimit',
                    '访问频率过高',
                    '您的请求过于频繁，请稍后再试',
                    [
                        'retry_after' => $retryAfter,
                        'limits' => [
                            'minute' => $minuteCount . '/' . $maxMinute,
                            'hour' => $hourCount . '/' . $maxHour,
                            'day' => $dayCount . '/' . $maxDay,
                        ],
                    ]
                ),
            ];
        }

        // 更新计数器
        Cache::put($minuteKey, $minuteCount + 1, 60);      // 1分钟过期
        Cache::put($hourKey, $hourCount + 1, 3600);        // 1小时过期
        Cache::put($dayKey, $dayCount + 1, 86400);         // 1天过期

        return ['block' => false];  // 速率检查通过
    }

    /**
     * 计算重试时间 - 智能时间计算
     *
     * @param int $minuteCount 分钟计数
     * @param int $hourCount 小时计数
     * @param int $dayCount 天计数
     * @param int $maxMinute 分钟限制
     * @param int $maxHour 小时限制
     * @param int $maxDay 天限制
     * @return int 重试时间（秒）
     */
    protected function calculateRetryAfter(int $minuteCount, int $hourCount, int $dayCount, int $maxMinute, int $maxHour, int $maxDay): int
    {
        if ($minuteCount >= $maxMinute) {
            return 60;      // 1分钟
        } elseif ($hourCount >= $maxHour) {
            return 3600;    // 1小时
        } elseif ($dayCount >= $maxDay) {
            return 86400;   // 1天
        }

        return 60;  // 默认1分钟
    }

    // ==================== IP管理 ====================

    /**
     * 检查IP白名单 - 快速放行
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否在白名单中
     */
    protected function isWhitelistedIp(Request $request): bool
    {
        if (!$this->getMiddlewareConfig($request, 'enable_ip_whitelist', true)) {
            return false;  // IP白名单未启用
        }

        $clientIp = $this->getClientRealIp($request);  // 获取客户端真实IP
        $whitelist = $this->getMiddlewareConfig($request, 'ip_whitelist', []);

        return in_array($clientIp, $whitelist);  // 检查是否在白名单中
    }

    /**
     * 检查本地请求 - 开发环境放行
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否为本地请求
     */
    protected function isLocalRequest(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);  // 获取客户端真实IP
        return $this->isLocalIp($clientIp);            // 检查是否为本地IP
    }

    /**
     * 检查黑名单 - 静态和动态黑名单
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 黑名单检查结果
     */
    protected function checkBlacklist(Request $request): array
    {
        if (!$this->getMiddlewareConfig($request, 'enable_ip_blacklist', true)) {
            return ['block' => false];  // IP黑名单未启用
        }

        $ip = $this->getClientRealIp($request);  // 获取客户端真实IP

        // 本地IP不检查黑名单
        if ($this->isLocalIp($ip)) {
            return ['block' => false];
        }

        try {
            // 检查静态黑名单
            $staticBlacklist = $this->getMiddlewareConfig($request, 'ip_blacklist', []);
            if (in_array($ip, $staticBlacklist)) {
                return [
                    'block' => true,
                    'response' => $this->handleSecurityViolation(
                        $request,
                        'Blacklist',
                        'IP黑名单拦截',
                        '您的IP地址已被列入黑名单',
                        ['ip' => $ip]
                    ),
                ];
            }

            // 检查动态黑名单（自定义处理逻辑）
            $customBlacklistHandle = $this->getMiddlewareConfig($request, 'blacklist_handle');
            if (!empty($customBlacklistHandle)) {
                $callable = $this->getFuncClass($customBlacklistHandle);
                $result = call_user_func($callable, $ip);

                if (!empty($result) && is_array($result) && $result[0] === true && !empty($result[1])) {
                    return [
                        'block' => true,
                        'response' => $this->handleSecurityViolation(
                            $request,
                            'Blacklist',
                            '黑名单/IP拦截',
                            $result[1],
                            ['ip' => $ip],
                        ),
                    ];
                }
            }
        } catch (\Exception $e) {
            Log::error('黑名单检查失败: ' . $e->getMessage());  // 记录错误日志
        }

        return ['block' => false];  // 黑名单检查通过
    }

    /**
     * 获取客户端真实IP - 代理感知
     *
     * @param Request $request 当前HTTP请求对象
     * @return string 客户端真实IP
     */
    protected function getClientRealIp(Request $request): string
    {
        $ip = $request->ip();  // 获取基础IP

        // 信任的代理头（按可信度排序）
        $trustedHeaders = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];

        foreach ($trustedHeaders as $header) {
            if ($request->headers->has($header)) {
                $ips = explode(',', $request->header($header));  // 解析IP列表
                $candidate = trim($ips[0]);  // 取第一个IP（最接近客户端的）

                // 验证IP有效性（排除私有IP）
                if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $ip = $candidate;  // 使用可信代理头中的IP
                    break;
                }
            }
        }

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';  // 返回验证后的IP
    }

    // ==================== 自定义逻辑处理 ====================

    /**
     * 自定义安全逻辑处理 - 扩展点
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 处理结果
     */
    protected function handleCustomSecurityLogic(Request $request): array
    {
        try {
            $customHandle = $this->getMiddlewareConfig($request, 'custom_handle');
            if (empty($customHandle)) {
                return ['block' => false];  // 没有自定义处理逻辑
            }

            $callable = $this->getFuncClass($customHandle);  // 获取可调用对象
            $result = call_user_func($callable, $request);   // 执行自定义逻辑

            // 检查自定义逻辑返回结果
            if (!empty($result) && is_array($result) && !empty($result['message'])) {
                return [
                    'block' => true,
                    'response' => $this->handleSecurityViolation(
                        $request,
                        $result['type'] ?? 'CustomRule',
                        $result['title'] ?? '自定义规则拦截',
                        $result['message'],
                        $result['context'] ?? []
                    ),
                ];
            }
        } catch (\Exception $e) {
            // 自定义逻辑执行失败，记录错误但不阻止请求
            Log::error('自定义安全逻辑执行失败: ' . $e->getMessage(), [
                'exception' => $e,
                'custom_handle' => $customHandle ?? '未定义'
            ]);
        }

        return ['block' => false];  // 自定义逻辑检查通过
    }

    // ==================== 工具方法 ====================

    /**
     * 是否为白名单路径 - 路径匹配检查
     *
     * @param Request $request 当前HTTP请求对象
     * @return bool 是否为白名单路径
     */
    protected function isWhitelistPath(Request $request): bool
    {
        $path = $request->path();  // 获取请求路径
        $whitelistPath = $this->getMiddlewareConfig($request, 'whitelist_path_of_not_verify_body', []);

        if (is_array($whitelistPath) && !empty($whitelistPath)) {
            foreach ($whitelistPath as $whitelist) {
                // 使用通配符匹配路径
                if (fnmatch($whitelist, $path)) {
                    return true;  // 匹配白名单路径
                }
            }
        }

        return false;  // 不在白名单中
    }

    /**
     * 字符串截断 - 防止日志过大
     *
     * @param string $string 原始字符串
     * @param int $length 最大长度
     * @return string 截断后的字符串
     */
    protected function truncateString(string $string, int $length): string
    {
        if (mb_strlen($string) <= $length) {
            return $string;  // 无需截断
        }

        return mb_substr($string, 0, $length) . '...';  // 截断并添加省略号
    }

    /**
     * 创建阻塞响应 - 统一响应创建
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 拦截类型
     * @param string $message 拦截消息
     * @return array 阻塞响应数组
     */
    protected function createBlockResponse(Request $request, string $type, string $message): array
    {
        return [
            'block' => true,
            'response' => $this->handleSecurityViolation(
                $request,
                $type,
                "安全拦截: {$type}",
                $message,
                ['errors' => $this->errorList]  // 包含详细错误信息
            ),
        ];
    }

    /**
     * 误报检测 - 智能过滤
     *
     * 过滤策略：
     * 1. 白名单参数名
     * 2. 内容类型识别
     * 3. 特定模式白名单
     * 4. 内容长度分析
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $key 参数键名
     * @param string $value 参数值
     * @param string $pattern 匹配的正则模式
     * @return bool 是否为误报
     */
    protected function isFalsePositive(Request $request, string $key, string $value, string $pattern): bool
    {
        // 白名单参数名（常见的内容字段）
        $whitelistKeys = ['content', 'body', 'description', 'markdown', 'html_content', 'code', 'script', 'css', 'style', 'template'];
        if (in_array(strtolower($key), $whitelistKeys)) {
            return true;  // 白名单参数，视为误报
        }

        // 白名单内容类型检测
        if ($this->checkIsMarkdown($value) || $this->checkIsHtml($value)) {
            return true;  // Markdown或HTML内容，视为误报
        }

        // 特定模式的白名单（技术讨论内容）
        $whitelistPatterns = [
            '/test.*script/i' => true,                      // 测试脚本
            '/example.*code/i' => true,                     // 示例代码
            '/demo.*function/i' => true,                    // 演示功能
            '/security.*research/i' => true,                // 安全研究
            '/penetration.*testing/i' => true,              // 渗透测试
        ];

        foreach ($whitelistPatterns as $whitelistPattern => $allowed) {
            if (preg_match($whitelistPattern, $value)) {
                return true;  // 匹配白名单模式，视为误报
            }
        }

        // 检查内容长度（过短的内容可能是误报）
        if (strlen($value) < 10) {
            return true;  // 内容过短，视为误报
        }

        return false;  // 不是误报
    }

    /**
     * 获取请求指纹 - 请求唯一标识
     *
     * @param Request $request 当前HTTP请求对象
     * @return string 请求指纹（MD5哈希）
     */
    protected function getRequestFingerprint(Request $request): string
    {
        $cacheKey = 'fingerprint:' . md5(serialize([
                $request->ip(),
                $request->userAgent(),
                $request->path(),
                $request->method()
            ]));  // 生成缓存键

        if (!isset(self::$fingerprintCache[$cacheKey])) {
            // 构建指纹数据
            $data = [
                'ip' => $request->ip(),
                'ua' => $request->userAgent(),
                'path' => $request->path(),
                'method' => $request->method(),
                'headers' => array_keys($request->headers->all()),  // 只使用头部键名
            ];

            self::$fingerprintCache[$cacheKey] = md5(json_encode($data));  // 计算MD5哈希
        }

        return self::$fingerprintCache[$cacheKey];  // 返回缓存的指纹
    }

    /**
     * 判断是否为本地IP - 开发环境识别
     *
     * @param string $ip IP地址
     * @return bool 是否为本地IP
     */
    protected function isLocalIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false ||  // 私有IP范围
            in_array($ip, ['127.0.0.1', '::1', 'localhost']);  // 本地主机
    }

    // ==================== 内容类型检测 ====================

    /**
     * Markdown检测函数 - 严格条件检测
     *
     * 检测条件：
     * 1. 包含标题（#）
     * 2. 包含代码块（```）或行内代码（`）
     * 3. 包含Markdown链接或格式标记
     *
     * @param string|null $content 待检测内容
     * @return bool 是否为Markdown格式
     */
    public function checkIsMarkdown(?string $content = ''): bool
    {
        $trimmed = trim($content ?? '');
        if (empty($trimmed)) {
            return false;  // 空内容不是Markdown
        }

        // 检测Markdown特征
        $hasHeaders = preg_match('/^#{1,6}\s+\w+/m', $trimmed);                    // 标题
        $hasCodeBlocks = preg_match('/(^```[a-z]*\s*[\s\S]+?^```$|`[^`]+`)/m', $trimmed);  // 代码块
        $hasMarkdownLinks = preg_match('/\[.*?\]\(.*?\)/', $trimmed);              // 链接
        $hasMarkdownFormatting = preg_match('/\*\*.*?\*\*|\*.*?\*|__.*?__|_.*?_/', $trimmed); // 格式标记

        // 必须包含代码块和至少一种其他Markdown特征
        return $hasCodeBlocks && ($hasHeaders || $hasMarkdownLinks || $hasMarkdownFormatting);
    }

    /**
     * 判断字符串是否为HTML格式 - DOM解析验证
     *
     * @param string|null $content 待检测内容
     * @return bool 是否为HTML格式
     */
    private function checkIsHtml(?string $content = ''): bool
    {
        $content = trim($content ?? '');

        // 快速检查：空内容或缺少基本HTML特征
        if (empty($content) ||
            !preg_match('/<[a-z][a-z0-9]*[\/\s>]/i', $content)) {
            return false;  // 不是HTML
        }

        // 检查是否已经是完整HTML文档
        $isFullDocument = preg_match('/^\s*<!DOCTYPE\s+html/i', $content) ||
            preg_match('/^\s*<html[^>]*>/i', $content);

        $doc = new \DOMDocument;
        libxml_use_internal_errors(true);  // 禁止显示HTML解析错误

        // 对于HTML片段，包装成完整文档进行验证
        $htmlToLoad = $isFullDocument ? $content : sprintf(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>%s</body></html>',
            $content
        );

        // 尝试加载HTML
        $loaded = @$doc->loadHTML($htmlToLoad, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        // 检查是否有严重错误（忽略无害警告）
        $hasCriticalErrors = false;
        foreach (libxml_get_errors() as $error) {
            // 忽略HTML5标签在旧规范中的警告（错误码801, 800）
            if ($error->level >= LIBXML_ERR_ERROR && !in_array($error->code, [801, 800])) {
                $hasCriticalErrors = true;
                break;
            }
        }

        libxml_clear_errors();
        libxml_use_internal_errors(false);

        return $loaded && !$hasCriticalErrors;  // 成功加载且无严重错误
    }

    /**
     * 删除Markdown中的代码块和行内代码 - 内容清理
     *
     * @param string $content 原始Markdown内容
     * @return string 清理后的内容
     */
    public function pruneMarkdownCode(string $content): string
    {
        // 移除所有Markdown格式内容
        $content = preg_replace([
            '/```[\s\S]*?```/',       // 代码块
            '/~~~[\s\S]*?~~~/',       // 替代代码块
            '/`[^`]+`/',             // 行内代码
            '/\[.*?\]\(.*?\)/',      // 链接
            '/\*\*.*?\*\*/',         // 加粗
            '/\*.*?\*/',             // 斜体
            '/__.*?__/',             // 加粗
            '/_.*?_/',               // 斜体
            '/<!--[\s\S]*?-->/',     // HTML注释
            '/\/\*[\s\S]*?\*\//',   // CSS/JS注释
            '/\/\/.*?(\n|$)/',        // 单行注释
            '/^#{1,6}\s+.*$/m',      // 标题
            '/^\s*[-*+]\s+.*$/m',    // 列表
            '/^\s*\d+\.\s+.*$/m',    // 数字列表
            '/^\s*>\s+.*$/m',        // 引用
            '/^\s*\|.*\|\s*$/m',     // 表格
            '/^\s*---+\s*$/m',       // 分割线
        ], '', $content);

        // 清理多余空行（保留最多两个连续换行）
        $content = preg_replace("/\n{3,}/", "\n\n", $content);

        return trim($content);
    }

    /**
     * 获取 func 执行类型 的执行对象类 - 灵活调用支持
     *
     * 支持格式：
     * 1. 静态方法：\Namespace\Class::method
     * 2. 数组格式：[\Namespace\Class::class, 'method']
     * 3. 字符串格式：[Class,method]
     *
     * @param string|array $classOrFunc 类或函数定义
     * @return array|string 可调用对象
     */
    private function getFuncClass(string|array $classOrFunc = ''): array|string
    {
        if (is_array($classOrFunc)) {
            if (count($classOrFunc) == 2) {
                return [App::make($classOrFunc[0]), $classOrFunc[1]];  // 数组格式
            }
            return [];  // 无效数组格式
        }

        // 解析字符串格式 [Class,method]
        if (str_contains($classOrFunc, ',') && preg_match('/^\[(.*)\]$/', $classOrFunc, $matches)) {
            $class_or_func = $matches[1];
            [$class, $method] = explode(',', $class_or_func);
            // 清理类和方法的引号和空格
            $class = $this->enhancedTrim($class);
            $method = $this->enhancedTrim($method);

            return [App::make(trim($class)), trim($method)];  // 返回可调用数组
        } else {
            return $this->enhancedTrim($classOrFunc);  // 直接返回字符串
        }
    }

    /**
     * 去除字符串两边的空格、单引号和双引号 - 增强清理
     *
     * @param string $string 原始字符串
     * @return string 清理后的字符串
     */
    private function enhancedTrim(string $string): string
    {
        // 去除字符串两边的空格和引号
        $trimmed = trim($string, " \t\n\r\0\x0B'\"");

        // 使用正则表达式移除开头和结尾的多重引号（嵌套引号情况）
        $trimmed = preg_replace('/^(["\']+)(.*?)(\1)+$/', '$2', $trimmed);

        // 再次清理两边空格（确保清理完正则后的残余空格）
        return trim($trimmed);
    }

    // ==================== 响应处理 ====================

    /**
     * 处理安全违规请求 - 统一处理流程
     *
     * 处理步骤：
     * 1. 记录安全事件
     * 2. 发送安全警报
     * 3. 执行封禁逻辑
     * 4. 返回安全响应
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 违规类型
     * @param string $title 标题
     * @param string $message 消息
     * @param array $context 上下文信息
     * @return mixed HTTP响应
     */
    protected function handleSecurityViolation(
        Request $request,
        string $type,
        string $title,
        string $message,
        array $context = []
    ) {
        // 记录安全事件（异步处理）
        $this->logSecurityEvent($request, $type, $title, $context);

        // 发送安全警报（异步）
        if ($this->shouldSendAlert($type)) {
            $this->sendSecurityAlertAsync($request, $type, $title, $context);
        }

        // 执行封禁逻辑
        if ($this->shouldBan($type)) {
            $this->executeBan($request, $type);
        }

        // 返回适当的响应
        return $this->createSecurityResponse($request, $type, $title, $message, $context);
    }

    /**
     * 记录安全事件 - 详细日志记录
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 事件类型
     * @param string $title 事件标题
     * @param array $context 上下文信息
     * @return void
     */
    protected function logSecurityEvent(
        Request $request,
        string $type,
        string $title,
        array $context = []
    ): void {
        $logData = array_merge([
            'type' => $type,
            'title' => $title,
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'user_agent' => $request->userAgent(),
            'referer' => $request->header('referer'),
            'timestamp' => now()->toISOString(),
            'detection_stats' => $this->detectionStats,
        ], $context);

        // 标记日志已经被记录过了，防止重复记录
        $request->merge(['log_already_recorded' => true]);

        $logLevel = $this->getMiddlewareConfig($request, 'log_level', 'warning');

        // 调试日志（可选）
        if ($this->getMiddlewareConfig($request, 'enable_debug_logging', false)) {
            Log::debug("安全拦截详情: {$title}", $logData);
        }
    }

    /**
     * 判断是否应该发送警报 - 类型过滤
     *
     * @param string $type 违规类型
     * @return bool 是否发送警报
     */
    protected function shouldSendAlert(string $type): bool
    {
        return in_array($type, ['Malicious', 'Anomalous', 'Blacklist', 'RateLimit']);  // 重要安全事件
    }

    /**
     * 异步发送安全警报 - 队列支持
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 警报类型
     * @param string $title 警报标题
     * @param array $context 上下文信息
     * @return void
     */
    protected function sendSecurityAlertAsync(Request $request, string $type, string $title, array $context): void
    {
        try {
            $data = [
                'title' => "安全警报: {$title}",
                'type' => $type,
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'user_agent' => $request->userAgent(),
                'time' => now()->toDateTimeString(),
                'context' => $context,
                'detection_stats' => $this->detectionStats,
            ];

            $securityAlarmHandle = $this->getMiddlewareConfig($request, 'send_security_alarm_handle');
            if ($securityAlarmHandle) {
                $callable = $this->getFuncClass($securityAlarmHandle);

                // 使用队列异步执行（如果可用）
                if (function_exists('dispatch')) {
                    dispatch(function () use ($callable, $data) {
                        call_user_func($callable, $data);
                    })->onQueue('security-alerts');  // 指定队列
                } else {
                    call_user_func($callable, $data);  // 同步执行
                }

                Log::info('安全警报已发送', $data);
            }
        } catch (\Exception $e) {
            // 警报发送失败，记录错误但不影响主要流程
            Log::error("发送安全警报失败: {$e->getMessage()}", [
                'exception' => $e,
                'alert_data' => $data ?? []
            ]);
        }
    }

    /**
     * 判断是否应该封禁 - 严重程度判断
     *
     * @param string $type 违规类型
     * @return bool 是否封禁
     */
    protected function shouldBan(string $type): bool
    {
        return in_array($type, ['Malicious', 'Anomalous', 'RateLimit', 'Blacklist']);  // 严重违规类型
    }

    /**
     * 执行封禁逻辑 - IP封禁
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 封禁类型
     * @return void
     */
    protected function executeBan(Request $request, string $type): void
    {
        try {
            $ip = $this->getClientRealIp($request);  // 获取客户端IP
            $banKey = "ip_banned:{$ip}";             // 封禁缓存键
            $banDuration = $this->getBanDuration($type);  // 获取封禁时长

            // 存储封禁信息
            Cache::put($banKey, [
                'type' => $type,
                'banned_at' => now()->toISOString(),
                'expires_at' => now()->addSeconds($banDuration)->toISOString(),
            ], $banDuration);

            Log::warning("IP封禁: {$ip} 类型: {$type} 时长: {$banDuration}秒");
        } catch (\Exception $e) {
            Log::error("IP封禁失败: {$e->getMessage()}");  // 封禁失败记录错误
        }
    }

    /**
     * 获取封禁时长 - 根据类型确定
     *
     * @param string $type 封禁类型
     * @return int 封禁时长（秒）
     */
    protected function getBanDuration(string $type): int
    {
        $baseDurations = [
            'Malicious' => 24 * 3600,     // 24小时（恶意请求）
            'Anomalous' => 12 * 3600,     // 12小时（异常行为）
            'RateLimit' => 3600,          // 1小时（频率超限）
            'Blacklist' => 30 * 24 * 3600, // 30天（黑名单）
        ];

        return $baseDurations[$type] ?? 3600;  // 默认1小时
    }

    /**
     * 创建安全响应 - 统一响应格式
     *
     * @param Request $request 当前HTTP请求对象
     * @param string $type 响应类型
     * @param string $title 标题
     * @param string $message 消息
     * @param array $context 上下文信息
     * @param int|null $statusCode HTTP状态码
     * @return mixed HTTP响应
     */
    protected function createSecurityResponse(
        Request $request,
        string $type,
        string $title,
        string $message,
        array $context = [],
        int $statusCode = null
    ) {
        $statusCode = $statusCode ?? $this->getStatusCode($type);  // 获取状态码

        $responseData = [
            'title' => $title,
            'message' => $message,
            'type' => $type,
            'status' => $statusCode,
            'timestamp' => now()->toISOString(),
            'request_id' => Str::uuid(),  // 生成唯一请求ID
            'context' => $context,
        ];

        // API请求返回JSON格式
        if ($request->expectsJson() || $request->is('api/*')) {
            $respFormat = $this->getMiddlewareConfig($request, 'ajax_resp_format', [
                'code' => 'code',
                'message' => 'message',
                'data' => 'data',
            ]);

            $response = [
                $respFormat['code'] => $statusCode,
                $respFormat['message'] => $message,
                $respFormat['data'] => [
                    'title' => $title,
                    'type' => $type,
                    'request_id' => $responseData['request_id'],
                    'timestamp' => $responseData['timestamp'],
                ],
            ];

            return response()->json($response, $statusCode);
        }

        // 调试模式返回详细HTML页面
        if (config('app.debug')) {
            return $this->outputDebugHtml($responseData, '操作异常拦截', $statusCode);
        }

        // Web请求返回视图（使用框架的异常处理）
        $resp = $this->respView('[异常拦截]'.$message, $statusCode);

        // 集成Trace调试工具
        /** @var Handle $trace */
        $trace = app('trace');
        return $trace->renderTraceStyleAndScript($request, $resp)->send();
    }

    /**
     * 获取HTTP状态码 - 根据类型映射
     *
     * @param string $type 拦截类型
     * @return int HTTP状态码
     */
    protected function getStatusCode(string $type): int
    {
        return match ($type) {
            'Forbidden' => 403,     // 禁止访问
            'Malicious' => 403,     // 恶意请求
            'Anomalous' => 400,     // 错误请求
            'RateLimit' => 429,     // 请求过多
            'Suspicious' => 422,    // 不可处理的实体
            'Blacklist' => 403,     // 黑名单
            'SecurityError' => 503, // 服务不可用
            default => 403          // 默认禁止访问
        };
    }

    // ==================== 性能监控和统计 ====================

    /**
     * 记录检测统计信息 - 性能分析
     *
     * @param Request $request 当前HTTP请求对象
     * @return void
     */
    protected function logDetectionStats(Request $request): void
    {
        // 计算执行时间和内存使用
        $this->detectionStats['execution_time'] = microtime(true) - $this->startTime;
        $this->detectionStats['memory_usage'] = memory_get_usage(true) - $this->startMemory;

        // 性能日志记录（可选）
        if ($this->getMiddlewareConfig($request, 'enable_performance_logging', false)) {
            Log::debug('安全检测性能统计', [
                'stats' => $this->detectionStats,
                'request' => $this->getRequestInfo($request),
            ]);
        }

        // 记录到监控系统
        $this->recordMetrics($request);
    }

    /**
     * 获取请求信息 - 简化版请求数据
     *
     * @param Request $request 当前HTTP请求对象
     * @return array 请求信息数组
     */
    protected function getRequestInfo(Request $request): array
    {
        return [
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'user_agent' => $this->truncateString($request->userAgent() ?? '', 100),
            'content_type' => $request->header('Content-Type'),
        ];
    }

    /**
     * 记录指标数据 - 监控系统集成
     *
     * @param Request $request 当前HTTP请求对象
     * @return void
     */
    protected function recordMetrics(Request $request): void
    {
        // 可以集成到监控系统如 Prometheus, DataDog 等
        $metrics = [
            'security_checks_total' => $this->detectionStats['checks_performed'],
            'security_patterns_matched' => $this->detectionStats['patterns_matched'],
            'security_false_positives' => $this->detectionStats['false_positives'],
            'security_execution_time' => $this->detectionStats['execution_time'],
            'security_memory_usage' => $this->detectionStats['memory_usage'],
        ];

        // 这里可以添加监控系统集成代码
        // Example:
        // $this->metrics->increment('security.checks', $metrics['security_checks_total']);
        // $this->metrics->gauge('security.execution_time', $metrics['security_execution_time']);
    }

    /**
     * 记录调试信息 - 条件调试输出
     *
     * @param string $message 调试消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logDebug(string $message, array $context = []): void
    {
        if ($this->getMiddlewareConfig(null, 'enable_debug_logging', false)) {
            Log::debug($message, $context);  // 只有启用调试时才记录
        }
    }

    // ==================== 公共方法 ====================

    /**
     * 获取安全统计信息 - 运维监控
     *
     * @return array 统计信息数组
     */
    public function getSecurityStats(): array
    {
        return [
            'detection_stats' => $this->detectionStats,
            'blocked_ips_count' => $this->getBlockedIpsCount(),
            'compiled_patterns_count' => count(self::$compiledPatterns),
            'fingerprint_cache_count' => count(self::$fingerprintCache),
        ];
    }

    /**
     * 获取被封禁的IP数量 - 缓存查询
     *
     * @return int 封禁IP数量
     */
    protected function getBlockedIpsCount(): int
    {
        // 这里需要根据实际存储方式实现
        // 例如从Redis或数据库查询封禁IP数量
        return 0;
    }

    /**
     * 清除缓存 - 维护操作
     *
     * @return void
     */
    public function clearCache(): void
    {
        self::$compiledPatterns = [];    // 清空预编译正则缓存
        self::$fingerprintCache = [];    // 清空指纹缓存
        self::$securityConfig = [];      // 清空配置缓存

        Log::info('安全中间件缓存已清除');  // 记录维护日志
    }

    /**
     * 重新加载配置 - 动态配置更新
     *
     * @param array $newConfig 新配置数组
     * @return void
     */
    public function reloadConfig(array $newConfig = []): void
    {
        self::$securityConfig = array_merge($this->getDefaultConfig(), $newConfig);  // 合并配置
        $this->precompilePatterns();  // 重新预编译正则表达式

        Log::info('安全中间件配置已重新加载');  // 记录配置更新日志
    }
}