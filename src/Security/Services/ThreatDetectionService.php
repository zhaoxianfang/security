<?php

namespace zxf\Security\Services;

use Exception;
use Throwable;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use zxf\Security\Config\SecurityConfig;
use zxf\Security\Utils\ExceptionHandler;

/**
 * 威胁检测服务
 *
 * 提供多层安全检测功能，包括：
 * 1. 请求内容检测
 * 2. URL路径检测
 * 3. User-Agent检测
 * 4. 文件上传检测
 * 5. 异常行为检测
 * 6. 专项攻击检测
 */
class ThreatDetectionService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 白名单安全服务实例
     */
    protected ?WhitelistSecurityService $whitelistService = null;

    /**
     * 配置热重载服务实例
     */
    protected ?ConfigHotReloadService $hotReloadService = null;

    /**
     * 预编译的正则表达式缓存
     */
    protected static array $compiledPatterns = [];

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;

        // 懒加载白名单服务（使用异常处理工具）
        $this->whitelistService = ExceptionHandler::safeExecute(
            fn() => app(WhitelistSecurityService::class),
            null,
            'WhitelistService initialization in ThreatDetectionService'
        );

        // 懒加载热重载服务（使用异常处理工具）
        $this->hotReloadService = ExceptionHandler::safeExecute(
            fn() => app(ConfigHotReloadService::class),
            null,
            'ConfigHotReloadService initialization in ThreatDetectionService'
        );

        // 预编译正则表达式（带异常保护）
        ExceptionHandler::safeExecute(
            fn() => $this->precompilePatterns(),
            null,
            'Pattern precompilation'
        );
    }

    /**
     * 检查是否为资源文件路径
     */
    public function isResourcePath(Request $request): bool
    {
        $path = $request->path();

        // 安全包资源文件路径
        if (str_starts_with($path, 'zxf/security/')) {
            return true;
        }

        // 静态文件扩展名检查
        return $this->isStaticFile($path);
    }

    /**
     * 检查是否为静态文件
     */
    private function isStaticFile(string $path): bool
    {
        $staticExtensions = [
            // 图片文件
            'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'bmp', 'webp', 'tiff',
            // 样式文件
            'css', 'scss', 'sass', 'less',
            // 脚本文件
            'js', 'mjs', 'cjs',
            // 字体文件
            'woff', 'woff2', 'ttf', 'eot', 'otf',
            // 文档文件
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
            // 媒体文件
            'mp3', 'mp4', 'mpeg', 'mpg', 'm4a', 'm4v', 'wmv', 'avi', 'mov', 'flv', 'webm', 'ogg', 'ogv', '3gp', '3g2', 'mkv', 'wav', 'aac',
            // 压缩文件
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
            // 其他静态文件
            'txt', 'xml', 'json', 'csv', 'yml', 'yaml', 'md', 'log',
        ];

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return in_array($extension, $staticExtensions);
    }

    /**
     * 检查可疑User-Agent
     *
     * 支持动态配置源（类方法、闭包、数组）
     * 增强异常处理，避免配置错误导致系统异常
     */
    public function hasSuspiciousUserAgent(Request $request): bool
    {
        $userAgent = $request->userAgent();

        if (empty($userAgent)) {
            return false;
        }

        // 获取白名单模式（支持动态配置）
        $whitelistPatternsConfig = $this->config->get('whitelist_user_agents', []);
        $whitelistPatterns = $this->resolvePatterns($whitelistPatternsConfig, 'whitelist_user_agents');

        // 先检查白名单
        if (!empty($whitelistPatterns)) {
            foreach ($whitelistPatterns as $pattern) {
                if (@preg_match($pattern, $userAgent)) {
                    return false;
                }
            }
        }

        // 获取可疑模式（支持动态配置）
        $suspiciousPatternsConfig = $this->config->get('suspicious_user_agents', []);
        $suspiciousPatterns = $this->resolvePatterns($suspiciousPatternsConfig, 'suspicious_user_agents');

        // 检查黑名单
        if (!empty($suspiciousPatterns)) {
            foreach ($suspiciousPatterns as $pattern) {
                if (@preg_match($pattern, $userAgent)) {
                    $this->logDetection('可疑User-Agent', [
                        'user_agent' => Str::limit($userAgent, 100),
                        'pattern' => $pattern
                    ]);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查可疑HTTP头
     *
     * 支持动态配置源，增强异常处理
     * 支持配置项为数组或可调用对象
     */
    public function hasSuspiciousHeaders(Request $request): bool
    {
        $suspiciousHeadersConfig = $this->config->get('suspicious_headers', []);
        $suspiciousHeaders = [];

        // 处理动态配置源
        if (is_callable($suspiciousHeadersConfig)) {
            try {
                $suspiciousHeaders = call_user_func($suspiciousHeadersConfig);
            } catch (\Exception $e) {
                $this->logDetection('可疑HTTP头配置读取失败', [
                    'error' => $e->getMessage()
                ]);
                $suspiciousHeaders = [];
            }
        } elseif (is_array($suspiciousHeadersConfig)) {
            $suspiciousHeaders = $suspiciousHeadersConfig;
        }

        if (empty($suspiciousHeaders)) {
            return false;
        }

        // 遍历检查每个可疑头
        foreach ($suspiciousHeaders as $header => $pattern) {
            // 跳过非关联数组的键
            if (!is_string($header) || !is_string($pattern)) {
                continue;
            }

            if ($request->headers->has($header)) {
                $value = $request->header($header);
                if (@preg_match($pattern, $value)) {
                    $this->logDetection('可疑HTTP头', [
                        'header' => $header,
                        'value' => Str::limit($value, 100),
                        'pattern' => $pattern
                    ]);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查危险文件上传
     */
    public function hasDangerousUploads(Request $request): bool
    {
        if (!$this->config->get('enable_file_check', true)) {
            return false;
        }

        $files = $request->allFiles();
        if (empty($files)) {
            return false;
        }

        foreach ($files as $file) {
            if (!$this->isSafeFile($file)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查URL安全性
     *
     * 1. 先检查白名单，提高效率
     * 2. 再进行安全检测
     * 3. 最后进行误报过滤
     *
     * @param Request $request HTTP请求对象
     * @return bool URL是否安全
     */
    public function isSafeUrl(Request $request): bool
    {
        $path = $request->path();
        $fullUrl = $request->fullUrl();

        // 1. 检查URL路径白名单（优先级最高）
        // 安全处理：配置项可能为数组或可调用对象
        $urlWhitelistConfig = $this->config->get('url_whitelist_paths', []);
        $urlWhitelist = [];

        // 处理配置项为可调用对象的情况
        if (is_callable($urlWhitelistConfig)) {
            try {
                $urlWhitelist = call_user_func($urlWhitelistConfig);
            } catch (\Exception $e) {
                $this->logDetection('URL白名单配置读取失败', [
                    'error' => $e->getMessage()
                ]);
                $urlWhitelist = [];
            }
        } elseif (is_array($urlWhitelistConfig)) {
            $urlWhitelist = $urlWhitelistConfig;
        }

        // 遍历白名单配置（支持简单字符串和复杂对象格式）
        foreach ($urlWhitelist as $item) {
            if (is_string($item)) {
                // 简单字符串格式：直接匹配路径
                if (fnmatch($item, $path)) {
                    return true;
                }
            } elseif (is_array($item) && isset($item['path'])) {
                // 复杂对象格式：支持路径、方法、级别等配置
                $whitelistPath = $item['path'];
                // 检查路径匹配
                if (fnmatch($whitelistPath, $path)) {
                    // 检查方法限制
                    if (isset($item['methods']) && is_array($item['methods'])) {
                        $currentMethod = $request->method();
                        if (!in_array($currentMethod, $item['methods'], true)) {
                            // 方法不匹配，继续检查其他白名单项
                            continue;
                        }
                    }
                    return true;
                }
            }
        }

        // 2. 检查是否为常见的安全路径（避免误报）
        if ($this->isCommonSafePath($path)) {
            return true;
        }

        // 3. 检查URL长度（防止缓冲区溢出攻击）
        $maxUrlLength = $this->config->get('max_url_length', 2048);
        if (strlen($fullUrl) > $maxUrlLength) {
            $this->logDetection('URL过长', [
                'url' => Str::limit($fullUrl, 200),
                'length' => strlen($fullUrl),
                'max_length' => $maxUrlLength
            ]);
            return false;
        }

        // 4. 进行正则表达式安全检测
        $patterns = $this->getCompiledPatterns('url_patterns');
        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $fullUrl)) {
                // 5. 检查是否为误报
                if ($this->isUrlFalsePositive($fullUrl, $path, $pattern)) {
                    $this->logDebug('URL命中规则但通过误报过滤', [
                        'url' => Str::limit($fullUrl, 200),
                        'pattern' => $pattern
                    ]);
                    return true;
                }

                $this->logDetection('非法URL访问', [
                    'url' => Str::limit($fullUrl, 200),
                    'pattern' => $pattern
                ]);
                return false;
            }
        }

        return true;
    }

    /**
     * 检查是否为常见的安全路径
     *
     * 用于快速识别常见的合法路径，减少不必要的检测
     *
     * @param string $path URL路径
     * @return bool 是否为安全路径
     */
    protected function isCommonSafePath(string $path): bool
    {
        // 常见的API路径前缀
        $apiPrefixes = [
            '/api/',
            '/v1/',
            '/v2/',
            '/graphql',
            '/rest/',
            '/rpc/',
        ];

        foreach ($apiPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        // 常见的资源路径
        $resourcePaths = [
            '/public/',
            '/static/',
            '/assets/',
            '/uploads/',
            '/images/',
            '/css/',
            '/js/',
        ];

        foreach ($resourcePaths as $resourcePath) {
            if (str_starts_with($path, $resourcePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查URL是否为误报
     *
     * 基于多层过滤机制，识别合法的URL
     *
     * @param string $fullUrl 完整URL
     * @param string $path URL路径
     * @param string $pattern 匹配的正则表达式
     * @return bool 是否为误报
     */
    protected function isUrlFalsePositive(string $fullUrl, string $path, string $pattern): bool
    {
        // 1. 检查是否包含合法的查询参数
        $queryParams = parse_url($fullUrl, PHP_URL_QUERY);
        if ($queryParams) {
            parse_str($queryParams, $params);

            // 检查常见的安全查询参数
            $safeParams = [
                'id', 'page', 'limit', 'offset', 'sort', 'order', 'q', 'query',
                'keyword', 'search', 'category', 'type', 'status', 'mode',
                'start', 'end', 'from', 'to', 'begin', 'date', 'time',
                'user_id', 'product_id', 'order_id', 'article_id', 'post_id',
                'token', 'code', 'session', 'lang', 'locale', 'format',
                'callback', 'jsonp', 'callback_json', 'json_callback',
                'fields', 'include', 'exclude', 'expand', 'embed',
                'lat', 'lng', 'longitude', 'latitude', 'radius', 'distance',
                'filter', 'filters', 'filter[]', 'tags', 'tag',
                'count', 'per_page', 'per-page', 'page_size',
                'sort_by', 'sort_order', 'direction', 'asc', 'desc',
            ];

            foreach ($params as $key => $value) {
                if (in_array(strtolower($key), $safeParams)) {
                    return true;
                }

                // 检查常见的安全值模式
                if ($this->isSafeQueryValue($value)) {
                    return true;
                }
            }
        }

        // 2. 检查路径中的合法关键词
        $safePathKeywords = [
            'mode', 'view', 'edit', 'delete', 'create', 'update', 'list', 'show',
            'detail', 'details', 'profile', 'settings', 'config', 'configuration',
            'search', 'query', 'find', 'filter', 'sort', 'order', 'page',
            'category', 'type', 'status', 'state', 'action', 'method',
            'upload', 'download', 'export', 'import', 'sync', 'refresh',
            'login', 'logout', 'register', 'signup', 'signin', 'auth',
            'user', 'users', 'admin', 'manager', 'dashboard', 'console',
            'api', 'v1', 'v2', 'rest', 'graphql', 'rpc',
        ];

        foreach ($safePathKeywords as $keyword) {
            if (str_contains(strtolower($path), $keyword)) {
                return true;
            }
        }

        // 3. 检查是否为常见的合法URL模式
        $safeUrlPatterns = [
            // RESTful API模式
            '/^\/api\/[a-z0-9_\-]+\/[a-z0-9_\-]+\/\d+$/i',
            '/^\/v[1-9]\/[a-z0-9_\-]+\/[a-z0-9_\-]+$/i',

            // 带ID的路径
            '/^\/[a-z0-9_\-]+\/\d+$/i',
            '/^\/[a-z0-9_\-]+\/[a-z0-9_\-]+\/\d+$/i',

            // 简单的单层或多层路径
            '/^\/[a-z0-9_\-]+\/[a-z0-9_\-]+$/i',
            '/^\/[a-z0-9_\-]+\/[a-z0-9_\-]+\/[a-z0-9_\-]+$/i',
        ];

        foreach ($safeUrlPatterns as $safePattern) {
            if (@preg_match($safePattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查查询参数值是否安全
     *
     * @param mixed $value 查询参数值
     * @return bool 是否安全
     */
    protected function isSafeQueryValue($value): bool
    {
        if (!is_string($value)) {
            return true; // 非字符串值通常是安全的（数字、数组等）
        }

        // 检查常见的安全值模式
        $safePatterns = [
            '/^\d+$/', // 纯数字
            '/^[a-z0-9_\-]+$/i', // 字母数字+下划线+连字符
            '/^[a-z0-9_\-,\s]+$/i', // 字母数字+下划线+连字符+逗号+空格
            '/^\d{4}-\d{2}-\d{2}$/', // 日期
            '/^\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}$/', // 日期时间
            '/^(true|false)$/i', // 布尔值
            '/^(asc|desc)$/i', // 排序方向
            '/^(asc|desc|up|down|yes|no|on|off|enabled|disabled|active|inactive)$/i', // 常见选项
        ];

        foreach ($safePatterns as $pattern) {
            if (@preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查恶意请求内容
     *
     * 【优化】根据检测敏感度级别调整检测策略
     */
    public function isMaliciousRequest(Request $request): bool
    {
        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        // 【新增】根据敏感度级别调整检测策略
        $sensitivity = $this->config->get('detection_sensitivity', 'normal');

        // 宽松/最小模式下，大幅降低检测强度
        if (in_array($sensitivity, ['loose', 'minimal'])) {
            // 仅对明显的恶意内容进行粗略检查
            return $this->isHighRiskMaliciousRequest($input);
        }

        $patterns = $this->getCompiledPatterns('body_patterns');

        return $this->checkInputDataRecursively($input, $patterns);
    }

    /**
     * 【新增】仅检测高危恶意请求 - 用于宽松模式
     *
     * 只拦截明显的、高危的恶意请求
     */
    protected function isHighRiskMaliciousRequest(array $input): bool
    {
        // 高危模式 - 仅检测最危险的攻击
        $highRiskPatterns = [
            // 明显的XSS攻击
            '/<script\b[^>]*>\s*(?:alert|confirm|prompt|eval|document\.cookie)\s*\(/i',
            '/javascript:\s*(?:alert|confirm|prompt|eval)\s*\(/i',
            '/on\w+\s*=\s*["\']?\s*(?:alert|confirm|prompt|eval)\s*\(/i',
            '/<iframe\b[^>]*src\s*=\s*["\']?\s*javascript:/i',
            '/<object\b[^>]*data\s*=\s*["\']?\s*javascript:/i',

            // 明显的SQL注入
            '/\bunion\s+all\s+select\b/i',
            '/\bunion\s+select\s+null\b/i',
            '/;\s*drop\s+table\b/i',
            '/;\s*delete\s+from\b/i',
            '/xp_cmdshell\s*\(/i',

            // 明显的命令注入
            '/\b(?:system|exec|shell_exec|passthru)\s*\(\s*["\']\s*(?:rm|del|wget|curl)\b/i',
            '/`\s*(?:rm|del|wget|curl|nc|netcat)\b/i',
        ];

        foreach ($input as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            // 对内容进行URL解码和HTML实体解码
            $decodedValue = urldecode(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'));

            foreach ($highRiskPatterns as $pattern) {
                if (@preg_match($pattern, $decodedValue)) {
                    $this->logDetection('宽松模式下检测到高危恶意内容', [
                        'parameter' => $key,
                        'pattern' => $pattern
                    ]);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查SQL注入
     */
    public function hasSQLInjection(Request $request): bool
    {
        if (!$this->config->get('enable_sql_injection_detection', true)) {
            return false;
        }

        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        $patterns = $this->getCompiledPatterns('sql_injection_patterns');

        return $this->checkInputDataRecursively($input, $patterns);
    }

    /**
     * 检查XSS攻击
     */
    public function hasXSSAttack(Request $request): bool
    {
        if (!$this->config->get('enable_xss_detection', true)) {
            return false;
        }

        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        $patterns = $this->getCompiledPatterns('xss_attack_patterns');

        return $this->checkInputDataRecursively($input, $patterns);
    }

    /**
     * 检查命令注入
     */
    public function hasCommandInjection(Request $request): bool
    {
        if (!$this->config->get('enable_command_injection_detection', true)) {
            return false;
        }

        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        $patterns = $this->getCompiledPatterns('command_injection_patterns');

        return $this->checkInputDataRecursively($input, $patterns);
    }

    /**
     * 检查异常参数
     */
    public function hasAnomalousParameters(Request $request): bool
    {
        if (!$this->config->get('enable_anomaly_detection', true)) {
            return false;
        }

        $parameters = $request->all();
        $thresholds = $this->config->get('anomaly_thresholds', []);

        // 检查参数数量
        if (count($parameters) > ($thresholds['max_parameters'] ?? 100)) {
            $this->logDetection('参数数量异常', [
                'count' => count($parameters),
                'max' => $thresholds['max_parameters'] ?? 100
            ]);
            return true;
        }

        // 检查POST数据大小
        $postSize = strlen(serialize($request->post()));
        if ($postSize > ($thresholds['max_post_size'] ?? 52428800)) {
            $this->logDetection('POST数据过大', [
                'size' => $postSize,
                'max_size' => $thresholds['max_post_size'] ?? 52428800
            ]);
            return true;
        }

        // 检查参数名和值
        foreach ($parameters as $key => $value) {
            // 检查参数名长度
            if (strlen($key) > ($thresholds['max_parameter_length'] ?? 255)) {
                $this->logDetection('参数名长度异常', [
                    'key' => $key,
                    'length' => strlen($key),
                    'max_length' => $thresholds['max_parameter_length'] ?? 255
                ]);
                return true;
            }

            // 检查可疑参数名
            $suspiciousNames = ['cmd', 'exec', 'system', 'eval', 'php', 'script', 'shell', 'bash', 'sh'];
            foreach ($suspiciousNames as $suspicious) {
                if (stripos($key, $suspicious) !== false) {
                    $this->logDetection('可疑参数名', ['key' => $key]);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查文件安全性
     */
    protected function isSafeFile($file): bool
    {
        try {
            if (!$file instanceof UploadedFile) {
                return true;
            }

            // 检查文件上传是否有错误
            if ($file->getError() !== UPLOAD_ERR_OK) {
                $this->logDetection('文件上传错误', [
                    'filename' => $file->getClientOriginalName(),
                    'error_code' => $file->getError(),
                ]);
                return false;
            }

            // 检查文件是否存在
            if (!$file->isValid()) {
                $this->logDetection('文件无效', [
                    'filename' => $file->getClientOriginalName(),
                ]);
                return false;
            }

            // 检查文件扩展名
            if (!$this->isSafeFileExtension($file)) {
                return false;
            }

            // 检查文件大小
            if (!$this->isSafeFileSize($file)) {
                return false;
            }

            // 检查MIME类型
            if (!$this->isSafeMimeType($file)) {
                return false;
            }

            // 可选的文件内容检查
            if ($this->config->get('enable_file_content_check', false)) {
                return $this->isSafeFileContent($file);
            }

            return true;
        } catch (Throwable $e) {
            $this->logDetection('文件安全检查异常', [
                'filename' => $file instanceof UploadedFile ? $file->getClientOriginalName() : 'unknown',
                'error' => $e->getMessage(),
            ]);
            // 异常时放行，避免影响正常文件上传
            return true;
        }
    }

    /**
     * 检查文件扩展名
     *
     * 支持动态配置源（类方法、闭包、数组）
     * 增强异常处理
     */
    protected function isSafeFileExtension(UploadedFile $file): bool
    {
        $extension = strtolower($file->getClientOriginalExtension());

        // 获取白名单（支持动态配置）
        $whitelistConfig = $this->config->get('allowed_extensions_whitelist', []);
        $whitelist = $this->resolvePatterns($whitelistConfig, 'allowed_extensions_whitelist');

        // 检查白名单
        if (in_array($extension, $whitelist, true)) {
            return true;
        }

        // 获取黑名单（支持动态配置）
        $disallowedConfig = $this->config->get('disallowed_extensions', []);
        $disallowed = $this->resolvePatterns($disallowedConfig, 'disallowed_extensions');

        // 检查黑名单
        if (in_array($extension, $disallowed, true)) {
            $this->logDetection('危险文件扩展名', [
                'extension' => $extension,
                'filename' => $file->getClientOriginalName()
            ]);
            return false;
        }

        return true;
    }

    /**
     * 检查文件大小
     */
    protected function isSafeFileSize(UploadedFile $file): bool
    {
        try {
            $maxSize = $this->config->get('max_file_size', 50 * 1024 * 1024);
            $fileSize = $file->getSize();

            // 检查文件大小是否有效
            if ($fileSize < 0) {
                $this->logDetection('文件大小无效', [
                    'size' => $fileSize,
                    'filename' => $file->getClientOriginalName()
                ]);
                return false;
            }

            if ($fileSize > $maxSize) {
                $this->logDetection('文件大小超限', [
                    'size' => $fileSize,
                    'max_size' => $maxSize,
                    'filename' => $file->getClientOriginalName()
                ]);
                return false;
            }

            return true;
        } catch (Throwable $e) {
            $this->logDetection('文件大小检查异常', [
                'filename' => $file->getClientOriginalName(),
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * 检查MIME类型
     *
     * 支持动态配置源（类方法、闭包、数组）
     * 增强异常处理
     */
    protected function isSafeMimeType(UploadedFile $file): bool
    {
        try {
            $mimeType = $file->getMimeType();

            // 检查MIME类型是否有效
            if (empty($mimeType) || !is_string($mimeType)) {
                $this->logDetection('MIME类型无效', [
                    'mime_type' => $mimeType,
                    'filename' => $file->getClientOriginalName()
                ]);
                return false;
            }

            // 获取禁止的MIME类型（支持动态配置）
            $disallowedConfig = $this->config->get('disallowed_mime_types', []);
            $disallowed = $this->resolvePatterns($disallowedConfig, 'disallowed_mime_types');

            if (in_array($mimeType, $disallowed, true)) {
                $this->logDetection('危险MIME类型', [
                    'mime_type' => $mimeType,
                    'filename' => $file->getClientOriginalName()
                ]);
                return false;
            }

            return true;
        } catch (Throwable $e) {
            $this->logDetection('MIME类型检查异常', [
                'filename' => $file->getClientOriginalName(),
                'error' => $e->getMessage(),
            ]);
            // 异常时放行，避免影响正常文件上传
            return true;
        }
    }

    /**
     * 检查文件内容
     */
    protected function isSafeFileContent(UploadedFile $file): bool
    {
        try {
            $filePath = $file->getPathname();

            // 检查文件是否存在
            if (!file_exists($filePath) || !is_readable($filePath)) {
                $this->logDetection('文件不存在或不可读', [
                    'filename' => $file->getClientOriginalName(),
                    'path' => $filePath
                ]);
                return false;
            }

            $content = file_get_contents($filePath);

            // 检查内容是否为空
            if ($content === false || empty($content)) {
                // 空文件不一定是危险的，跳过检查
                return true;
            }

            // 限制内容检查大小，避免内存问题
            $maxContentCheckSize = 10 * 1024 * 1024; // 10MB
            $contentLength = strlen($content);
            if ($contentLength > $maxContentCheckSize) {
                $this->logDetection('文件过大，跳过内容检查', [
                    'filename' => $file->getClientOriginalName(),
                    'size' => $contentLength,
                    'max_size' => $maxContentCheckSize
                ]);
                return true;
            }

            $patterns = $this->getCompiledPatterns('body_patterns');

            foreach ($patterns as $pattern) {
                if (@preg_match($pattern, $content)) {
                    $this->logDetection('文件内容包含恶意代码', [
                        'filename' => $file->getClientOriginalName(),
                        'pattern' => $pattern
                    ]);
                    return false;
                }
            }
        } catch (Throwable $e) {
            $this->logDetection('文件内容检查失败', [
                'filename' => $file->getClientOriginalName(),
                'error' => $e->getMessage(),
            ]);
        }

        return true;
    }

    /**
     * 递归检查输入数据（增强版）
     *
     * 优化点：
     * 1. 超过深度限制时记录警告日志
     * 2. 添加性能监控，记录耗时过长的检测
     * 3. 防止恶意构造深层数据导致DoS
     * 4. 数据大小限制，防止超大数组攻击
     */
    protected function checkInputDataRecursively(array $data, array $patterns, string $parentKey = '', int $depth = 0): bool
    {
        $maxDepth = $this->config->get('max_recursion_depth', 10);
        $maxDataSize = $this->config->get('max_data_size', 1000); // 最大数组元素数量

        // 超过深度限制
        if ($depth > $maxDepth) {
            Log::warning('递归检测超过最大深度', [
                'depth' => $depth,
                'max_depth' => $maxDepth,
                'parent_key' => $parentKey,
                'data_size' => count($data),
            ]);
            return false;
        }

        // 数据大小限制检查
        if (count($data) > $maxDataSize) {
            Log::warning('递归检测数据过大', [
                'data_size' => count($data),
                'max_size' => $maxDataSize,
                'depth' => $depth,
            ]);
            return false;
        }

        // 性能监控开始
        $startTime = microtime(true);
        $result = false;

        try {
            foreach ($data as $key => $value) {
                $currentKey = $parentKey ? "{$parentKey}.{$key}" : $key;

                if (is_array($value)) {
                    if ($this->checkInputDataRecursively($value, $patterns, $currentKey, $depth + 1)) {
                        $result = true;
                        break;
                    }
                } else {
                    if ($this->checkInputValue($currentKey, $value, $patterns)) {
                        $result = true;
                        break;
                    }
                }
            }
        } finally {
            // 性能监控结束
            $elapsed = microtime(true) - $startTime;

            // 超过100ms记录警告
            if ($elapsed > 0.1) {
                Log::warning('递归检测耗时过长', [
                    'elapsed' => round($elapsed * 1000, 2) . 'ms',
                    'depth' => $depth,
                    'data_size' => count($data),
                    'parent_key' => $parentKey,
                ]);
            }
        }

        return $result;
    }

    /**
     * 检查单个输入值
     *
     * 【优化策略】大幅降低检测敏感度，优先保证业务正常
     * 1. 超宽阈值范围，减少拦截
     * 2. 强化误报检测，智能识别合法内容
     * 3. Markdown/富文本内容专项保护
     * 4. 正则表达式匹配后置，降低误报
     *
     * @param string $key 参数键名
     * @param mixed $value 参数值
     * @param array $patterns 正则表达式数组
     * @return bool 是否检测到恶意内容
     */
    protected function checkInputValue(string $key, $value, array $patterns): bool
    {
        // 1. 快速类型检查 - 早期返回
        if (!is_string($value) || empty(trim($value))) {
            return false;
        }

        // 2. 【放宽】长度检查阈值 - 大幅放宽限制
        $minLength = $this->config->get('min_content_length', 3);
        $maxLength = 100000; // 放宽到100KB，支持大段Markdown内容
        $valueLength = strlen($value);

        if ($valueLength < $minLength || $valueLength > $maxLength) {
            return false;
        }

        // 3. 【强化】快速检查常见安全值 - 扩大安全值识别范围
        if ($this->isLikelySafeValue($value)) {
            return false;
        }

        // 4. 【弱化】检查键名白名单 - 降低白名单依赖，转为辅助判断
        $isWhitelistKey = $this->isWhitelistParameterName($key);

        // 5. 【新增】Markdown/富文本内容智能识别 - 非白名单键也能识别
        if ($this->isMarkdownOrRichContent($value, $key)) {
            return false;
        }

        // 6. 内容预处理
        $processedValue = $this->preprocessContent($value);
        if (empty($processedValue)) {
            return false;
        }

        // 7. 【新增】二次内容安全预检 - 降低正则匹配频率
        if ($this->isContentLikelySafe($processedValue, $isWhitelistKey)) {
            return false;
        }

        // 8. 【后置】正则表达式匹配 - 仅在前面检查都通过后执行
        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $processedValue)) {
                // 9. 【强化】误报检查 - 大幅提高误报判断权重
                if ($this->isFalsePositive($key, $processedValue, $pattern) || $isWhitelistKey) {
                    $this->logDebug('内容命中规则但判定为误报', [
                        'parameter' => $key,
                        'pattern' => $pattern
                    ]);
                    return false;
                }
                // 【放宽】仅对明确的高危模式进行拦截
                if (!$this->isHighRiskPattern($pattern)) {
                    $this->logDebug('内容命中非高危规则，予以放行', [
                        'parameter' => $key,
                        'pattern' => $pattern
                    ]);
                    return false;
                }
                $this->logDetection('检测到高危恶意内容', [
                    'parameter' => $key,
                    'value' => Str::limit($processedValue, 100),
                    'pattern' => $pattern
                ]);
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否为 Markdown 或富文本内容
     *
     * 智能识别文档类内容，避免误拦截
     */
    protected function isMarkdownOrRichContent(string $value, string $key): bool
    {
        // 检查键名是否暗示内容类型
        $contentIndicators = [
            'content', 'body', 'description', 'markdown', 'html',
            'text', 'message', 'comment', 'article', 'post',
            'doc', 'document', 'readme', 'note', 'remark',
            'about', 'intro', 'introduction', 'summary', 'detail',
            'bio', 'profile', 'signature'
        ];
        foreach ($contentIndicators as $indicator) {
            if (str_contains(strtolower($key), $indicator)) {
                return true;
            }
        }

        // 检测 Markdown 特征
        $markdownPatterns = [
            '/^#{1,6}\s+/m',                    // 标题
            '/\*\*.*?\*\*/s',                  // 粗体
            '/\*.*?\*/s',                      // 斜体
            '/`{3}[\s\S]*?`{3}/m',             // 代码块
            '/`[^`]+`/',                        // 行内代码
            '/\[.*?\]\(.*?\)/',               // 链接
            '/!\[.*?\]\(.*?\)/',              // 图片
            '/^[-*+]\s+/m',                    // 列表
            '/^\d+\.\s+/m',                   // 有序列表
            '/^>\s+/m',                        // 引用
            '/^---$/m',                        // 分隔线
            '/\|.*?\|/',                       // 表格
        ];

        $markdownScore = 0;
        foreach ($markdownPatterns as $pattern) {
            if (@preg_match($pattern, $value)) {
                $markdownScore++;
            }
        }

        // 命中3个以上Markdown特征，判定为Markdown内容
        if ($markdownScore >= 3) {
            return true;
        }

        // 检测技术文档特征（如JSON配置、代码示例等）
        if ($this->isTechnicalDocumentation($value)) {
            return true;
        }

        return false;
    }

    /**
     * 判断是否为技术文档内容
     */
    protected function isTechnicalDocumentation(string $value): bool
    {
        // API Key 示例模式（带省略号或占位符）
        if (preg_match('/["\']apiKey["\']\s*:\s*["\']sk-[a-z]*\.\.\.["\']/i', $value)) {
            return true;
        }

        // JSON 配置示例
        if (preg_match('/\{\s*["\']\w+["\']\s*:\s*["\'][^"\']*["\']/', $value) &&
            preg_match('/["\']\w+["\']\s*:\s*["\']sk-|apiKey|config|setting/', $value)) {
            return true;
        }

        // Shell 命令示例（带说明性注释）
        if (preg_match('/^\s*\$\s+\w+.*#/', $value) ||
            preg_match('/```(?:bash|shell|sh)\s*\n/', $value)) {
            return true;
        }

        // URL 示例
        if (preg_match('/https?:\/\/api\./', $value) ||
            preg_match('/https?:\/\/[^\s]+\.com\/docs?/', $value)) {
            return true;
        }

        return false;
    }

    /**
     * 内容安全预检 - 快速判断内容是否明显安全
     */
    protected function isContentLikelySafe(string $value, bool $isWhitelistKey): bool
    {
        // 1. 白名单键名的内容，默认安全
        if ($isWhitelistKey) {
            // 即使是白名单键，也要检查明显的恶意脚本
            $obviousMalicious = [
                '/<script\b[^>]*>.*?<\/script>/is',
                '/javascript:\s*alert\s*\(/i',
                '/on\w+\s*=\s*["\']?\s*alert\s*\(/i',
            ];
            foreach ($obviousMalicious as $pattern) {
                if (@preg_match($pattern, $value)) {
                    return false; // 发现明显恶意代码
                }
            }
            return true;
        }

        // 2. 纯文本内容（中英文、数字、常见标点）
        if (preg_match('/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\s\.,!?;:"\'\-()【】（）。，！？；：""\'\-_\/\\\[\]{}|<>]+$/u', $value)) {
            return true;
        }

        // 3. 技术教程/文档常见特征
        if (preg_match('/步骤|Step|教程|Guide|安装|Install|配置|Config/', $value) &&
            substr_count($value, '\n') > 3) {
            return true;
        }

        return false;
    }

    /**
     * 判断是否为高危模式
     *
     * 仅对明确的高危攻击模式进行拦截
     */
    protected function isHighRiskPattern(string $pattern): bool
    {
        // 高危模式特征
        $highRiskIndicators = [
            'script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
            'union.*select', 'exec\s*\(', 'xp_cmdshell', '<iframe',
            'system\s*\(', 'shell_exec', 'passthru', 'eval\s*\(',
            'base64_decode.*eval', 'gzinflate.*base64',
        ];

        foreach ($highRiskIndicators as $indicator) {
            if (str_contains(strtolower($pattern), strtolower($indicator))) {
                return true;
            }
        }

        return false;
    }

    /**
     * 快速检查是否为可能的安全值
     *
     * 使用快速字符串操作而非正则表达式，提高性能
     *
     * @param string $value 值
     * @return bool 是否安全
     */
    protected function isLikelySafeValue(string $value): bool
    {
        // 检查常见的安全值特征
        $valueTrimmed = trim($value);

        // 纯数字（10-20位）
        if (preg_match('/^\d{10,20}$/', $valueTrimmed)) {
            return true;
        }

        // 简单的ID格式
        if (preg_match('/^[\dA-Za-z\-_]{10,50}$/', $valueTrimmed)) {
            return true;
        }

        // URL格式
        if (str_starts_with($valueTrimmed, 'http://') ||
            str_starts_with($valueTrimmed, 'https://') ||
            str_starts_with($valueTrimmed, '/')) {
            return true;
        }

        // 邮箱格式
        if (str_contains($valueTrimmed, '@') &&
            filter_var($valueTrimmed, FILTER_VALIDATE_EMAIL)) {
            return true;
        }

        // 日期时间格式
        if (preg_match('/^\d{4}-\d{2}-\d{2}/', $valueTrimmed)) {
            return true;
        }

        // 简单的枚举值
        $enumValues = ['true', 'false', 'yes', 'no', 'on', 'off', 'enabled', 'disabled',
                       'active', 'inactive', 'asc', 'desc', 'up', 'down', 'male', 'female',
                       '0', '1', 'all', 'none', 'pending', 'success', 'error', 'warning'];
        if (in_array(strtolower($valueTrimmed), $enumValues)) {
            return true;
        }

        return false;
    }

    /**
     * 检查参数键名是否在白名单中
     *
     * 使用快速字符串检查而非正则表达式，提高性能
     *
     * @param string $key 参数键名
     * @return bool 是否在白名单中
     */
    protected function isWhitelistParameterName(string $key): bool
    {
        // 常见的白名单参数名
        $whitelistParams = [
            'id', 'name', 'title', 'content', 'body', 'description', 'summary',
            'category', 'type', 'status', 'state', 'mode', 'action', 'method',
            'page', 'size', 'limit', 'offset', 'sort', 'order', 'dir', 'direction',
            'start', 'end', 'from', 'to', 'begin', 'date', 'time', 'datetime',
            'q', 'query', 'search', 'keyword', 'filter', 'filters', 'tag', 'tags',
            'user_id', 'product_id', 'order_id', 'article_id', 'post_id', 'comment_id',
            'lat', 'lng', 'longitude', 'latitude', 'radius', 'distance', 'location',
            'token', 'code', 'session', 'cookie', 'lang', 'locale', 'language',
            'format', 'output', 'callback', 'callback_url', 'redirect_url',
            'created_at', 'updated_at', 'deleted_at', 'published_at',
            'is_active', 'is_enabled', 'is_deleted', 'is_public', 'is_visible',
        ];

        return in_array(strtolower($key), $whitelistParams);
    }

    /**
     * 内容预处理
     */
    protected function preprocessContent(string $content): string
    {
        $content = trim($content);
        if (empty($content)) {
            return '';
        }

        // 移除不可见字符
        $content = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $content);

        // 标准化空格
        $content = preg_replace('/\s+/', ' ', $content);

        // 解码常见编码
        $content = urldecode($content);
        return html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * 误报检测 - 【大幅放宽】
     *
     * 【优化策略】大幅降低误报检测门槛，优先保证业务正常
     * 1. 扩大白名单键名范围
     * 2. 增加技术内容识别
     * 3. 放宽合法模式匹配
     *
     * @param string $key 参数键名
     * @param string $value 参数值
     * @param string $pattern 匹配的正则表达式
     * @return bool 是否为误报
     */
    protected function isFalsePositive(string $key, string $value, string $pattern): bool
    {
        // 1. 【扩大】白名单键名检查 - 大幅增加内容相关键名
        $whitelistKeys = [
            // 基础内容字段
            'content', 'body', 'description', 'markdown', 'html_content', 'html',
            'message', 'comment', 'text', 'remark', 'note', 'summary',
            'introduction', 'about', 'details', 'information', 'content_text',
            'post_content', 'article_content', 'page_content', 'bio', 'profile',
            // 技术文档字段
            'code', 'code_block', 'snippet', 'example', 'demo', 'sample',
            'config', 'configuration', 'setting', 'settings', 'options',
            'readme', 'documentation', 'docs', 'guide', 'tutorial',
            'instruction', 'steps', 'procedure',
            // 富文本字段
            'editor', 'rich_text', 'formatted_text', 'wysiwyg',
            'draft', 'preview', 'template', 'layout',
            // API/数据字段
            'data', 'payload', 'response', 'request', 'json', 'xml',
            'params', 'parameters', 'arguments', 'args',
            // 其他常见内容字段
            'value', 'values', 'input', 'output', 'result', 'results',
            'query', 'search', 'filter', 'criteria',
        ];

        $keyLower = strtolower($key);
        foreach ($whitelistKeys as $whitelistKey) {
            if (str_contains($keyLower, $whitelistKey)) {
                return true;
            }
        }

        // 2. 【放宽】内容长度检查 - 允许更多内容通过
        if (strlen($value) < 50) {
            return true;
        }

        // 3. 【新增】技术内容快速识别
        if ($this->isTechnicalContent($value)) {
            return true;
        }

        // 4. 【扩大】常见合法内容模式检测
        $legitimatePatterns = [
            // URL模式
            '/https?:\/\/[a-zA-Z0-9\-._~:\/?#[\]@!$&\'()*+,;=%]+/i',

            // 邮箱模式
            '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/',

            // 手机号模式
            '/\+?\d{10,15}/',

            // 纯数字
            '/^\d+$/',

            // 日期时间格式
            '/\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}/',
            '/\d{4}-\d{2}-\d{2}/',

            // 纯文本（扩展字符集）
            '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\s\.,!?;:"\'\-()【】（）。，！？；：""\'\-_\/\\\[\]{}|<>*#`@$%^&+=~]+$/u',

            // 代码相关
            '/^[`\[\]{}()<>.\/\\:=;,"\'\-+*/%!&|^~]+$/',  // 纯符号（可能是代码）
            '/[{}\[\];,].*[{}\[\];,]/s',  // 包含代码结构

            // JSON特征
            '/"\w+"\s*:\s*"[^"]*"/',
            '/"\w+"\s*:\s*\{/', '/"\w+"\s*:\s*\[/',

            // Markdown特征
            '/^#{1,6}\s+/m', '/\*\*.*?\*\*/s', '/`[^`]+`/',
        ];

        // 特殊检查：JSON字符串
        if ($this->isLikelyJson($value)) {
            return true; // JSON内容默认放行
        }

        // 特殊检查：HTML/XML
        if ($this->containsHtmlTags($value)) {
            // 【放宽】只要不是明显恶意脚本，都放行
            if (!$this->containsObviousMaliciousScript($value)) {
                return true;
            }
        }

        foreach ($legitimatePatterns as $legitPattern) {
            if (@preg_match($legitPattern, $value)) {
                return true;
            }
        }

        // 5. 【放宽】常见合法参数模式 - 模糊匹配
        $safeParameterPatterns = [
            '/id$/i', '/_id$/i',
            '/page|size|limit|offset/i',
            '/sort|order|dir/i',
            '/start|end|from|to/i',
            '/key|value|name|title/i',
            '/type|category|status|state/i',
            '/token|code|session/i',
            '/content|text|body|desc/i',
            '/config|setting|option/i',
            '/data|info|detail/i',
        ];

        foreach ($safeParameterPatterns as $paramPattern) {
            if (@preg_match($paramPattern, $key)) {
                return true;
            }
        }

        // 6. 【新增】内容语义分析 - 判断是否为用户输入的自然内容
        if ($this->isNaturalUserContent($value)) {
            return true;
        }

        return false;
    }

    /**
     * 判断是否为技术内容
     */
    protected function isTechnicalContent(string $value): bool
    {
        // API 相关
        if (preg_match('/api|endpoint|request|response|header|token|key/i', $value) &&
            (str_contains($value, '{') || str_contains($value, '[') || str_contains($value, '"'))) {
            return true;
        }

        // 代码示例
        if (preg_match('/```|function|class|const|let|var|def|import|from|require/', $value)) {
            return true;
        }

        // 配置文件示例
        if (preg_match('/sk-|apiKey|secret|token|config|setting/i', $value) &&
            (str_contains($value, '...') || str_contains($value, 'xxx') || str_contains($value, 'your-'))) {
            return true;
        }

        // 命令行示例
        if (preg_match('/^\s*(\$|#|>|npm|yarn|composer|pip|docker|kubectl|git|vim|cd|ls|cat)\s/', $value)) {
            return true;
        }

        return false;
    }

    /**
     * 判断是否包含明显的恶意脚本
     */
    protected function containsObviousMaliciousScript(string $value): bool
    {
        $obviousMalicious = [
            '/<script\b[^>]*>\s*(alert|confirm|prompt|eval|document\.write)\s*\(/i',
            '/javascript:\s*(alert|confirm|prompt|eval)\s*\(/i',
            '/on\w+\s*=\s*["\']?\s*(alert|confirm|prompt|eval)\s*\(/i',
            '/<iframe\b[^>]*src\s*=\s*["\']?\s*javascript:/i',
            '/<object\b[^>]*data\s*=\s*["\']?\s*javascript:/i',
            '/<embed\b[^>]*src\s*=\s*["\']?\s*javascript:/i',
        ];

        foreach ($obviousMalicious as $pattern) {
            if (@preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否为自然的用户输入内容
     */
    protected function isNaturalUserContent(string $value): bool
    {
        // 长文本（可能是文章、说明等）
        if (strlen($value) > 200 && substr_count($value, ' ') > 20) {
            return true;
        }

        // 包含多语言文本
        if (preg_match('/[\x{4e00}-\x{9fa5}]/u', $value) && strlen($value) > 50) {
            return true;
        }

        // 段落结构（换行符分割）
        $paragraphs = explode("\n\n", $value);
        if (count($paragraphs) >= 2) {
            return true;
        }

        // 列表结构
        if (preg_match('/^\s*[-*+\d]\.\s/m', $value)) {
            return true;
        }

        return false;
    }

    /**
     * 检查是否可能是JSON字符串
     */
    protected function isLikelyJson(string $value): bool
    {
        $trimmed = trim($value);
        return (str_starts_with($trimmed, '{') && str_ends_with($trimmed, '}')) ||
               (str_starts_with($trimmed, '[') && str_ends_with($trimmed, ']'));
    }

    /**
     * 检查是否包含HTML标签
     */
    protected function containsHtmlTags(string $value): bool
    {
        return preg_match('/<[^>]+>/i', $value) === 1;
    }

    /**
     * 检查是否为合法的HTML内容
     */
    protected function isLegitimateHtml(string $value): bool
    {
        // 排除包含恶意脚本的HTML
        $maliciousPatterns = [
            '/<script\b[^>]*>/i',
            '/<iframe\b[^>]*>/i',
            '/javascript:/i',
            '/on\w+\s*=\s*["\']?\s*(?:alert|confirm|prompt)\s*\(/i',
            '/vbscript:/i',
            '/data:\s*text\/javascript/i',
        ];

        foreach ($maliciousPatterns as $pattern) {
            if (@preg_match($pattern, $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 检查是否为部分匹配（可能是误报）
     */
    protected function isPartialMatch(string $value): bool
    {
        // 如果内容太短，可能是部分匹配
        if (strlen($value) < 15) {
            return true;
        }

        // 检查是否只包含一个关键字（没有上下文）
        $keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION'];
        $valueUpper = strtoupper(trim($value));
        return in_array($valueUpper, $keywords);
    }

    /**
     * 检查是否为白名单路径
     */
    public function isWhitelistPath(Request $request): bool
    {
        $path = $request->path();
        $whitelistPaths = $this->config->get('body_whitelist_paths', []);

        foreach ($whitelistPaths as $pattern) {
            if (fnmatch($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 预编译正则表达式
     */
    protected function precompilePatterns(): void
    {
        if (!$this->config->get('enable_pattern_cache', true)) {
            return;
        }

        $patternTypes = [
            'body_patterns',
            'url_patterns',
            'suspicious_user_agents',
            'whitelist_user_agents',
        ];

        foreach ($patternTypes as $type) {
            $this->getCompiledPatterns($type);
        }
    }

    /**
     * 获取预编译的正则表达式
     *
     * 支持动态配置源（类方法、闭包、数组）
     * 增强异常处理
     */
    protected function getCompiledPatterns(string $type): array
    {
        $cacheKey = "compiled_patterns:{$type}";

        if (isset(self::$compiledPatterns[$cacheKey])) {
            return self::$compiledPatterns[$cacheKey];
        }

        // 获取配置（支持动态配置）
        $patternsConfig = $this->config->get($type, []);
        $patterns = $this->resolvePatterns($patternsConfig, $type);

        $compiled = [];

        foreach ($patterns as $pattern) {
            // 验证正则表达式有效性
            if ($this->isValidPattern($pattern)) {
                $compiled[] = $pattern;
            }
        }

        self::$compiledPatterns[$cacheKey] = $compiled;
        return $compiled;
    }

    /**
     * 解析模式配置
     *
     * 支持多种配置源：
     * - 静态数组
     * - 类方法调用 [ClassName, method]
     * - 字符串类方法 "ClassName::method"
     * - 闭包函数
     *
     * @param mixed $config 配置值
     * @param string $configKey 配置键名（用于日志）
     * @return array 解析后的模式数组
     */
    protected function resolvePatterns(mixed $config, string $configKey): array
    {
        try {
            // 如果是数组，直接返回
            if (is_array($config)) {
                return $config;
            }

            // 如果是可调用对象，执行调用
            if (is_callable($config)) {
                $result = call_user_func($config);
                return is_array($result) ? $result : [];
            }

            // 如果是字符串，尝试解析类方法
            if (is_string($config) && str_contains($config, '::')) {
                try {
                    [$className, $methodName] = explode('::', $config, 2);
                    if (class_exists($className) && method_exists($className, $methodName)) {
                        $result = call_user_func([$className, $methodName]);
                        return is_array($result) ? $result : [];
                    }
                } catch (Throwable $e) {
                    $this->logDetection("配置项 {$configKey} 解析失败", [
                        'error' => $e->getMessage(),
                        'config_value' => $config,
                    ]);
                    return [];
                }
            }

            // 无法解析，返回空数组
            $this->logDetection("配置项 {$configKey} 格式不支持", [
                'config_type' => gettype($config),
            ]);
            return [];
        } catch (Throwable $e) {
            $this->logDetection("配置项 {$configKey} 处理异常", [
                'error' => $e->getMessage(),
                'config_type' => gettype($config ?? 'null'),
            ]);
            return [];
        }
    }

    /**
     * 验证正则表达式有效性
     */
    protected function isValidPattern(string $pattern): bool
    {
        // 简单的有效性检查
        if (@preg_match($pattern, '') !== false) {
            return true;
        }

        $error = error_get_last();
        if ($error && str_contains($error['message'], 'preg_match')) {
            $this->logDetection('无效的正则表达式', [
                'pattern' => $pattern,
                'error' => $error['message']
            ]);
        }

        return false;
    }

    /**
     * 获取配置值
     */
    public function getConfig(string $key, mixed $default = null, mixed $params = null)
    {
        return $this->config->get($key, $default, $params);
    }

    /**
     * 记录检测日志
     */
    protected function logDetection(string $message, array $context = []): void
    {
        if ($this->config->get('enable_debug_logging', false)) {
            Log::debug("安全检测: {$message}", $context);
        }
    }

    /**
     * 记录调试日志
     */
    protected function logDebug(string $message, array $context = []): void
    {
        if ($this->config->get('enable_debug_logging', false)) {
            Log::debug("安全调试: {$message}", $context);
        }
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        self::$compiledPatterns = [];
    }
}
