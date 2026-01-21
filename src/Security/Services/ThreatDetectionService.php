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
 * 威胁检测服务 - 优化增强版
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
     */
    public function hasSuspiciousUserAgent(Request $request): bool
    {
        $userAgent = $request->userAgent();

        if (empty($userAgent)) {
            return false;
        }

        // 先检查白名单
        $whitelistPatterns = $this->config->get('whitelist_user_agents', []);
        foreach ($whitelistPatterns as $pattern) {
            if (@preg_match($pattern, $userAgent)) {
                return false;
            }
        }

        // 检查黑名单
        $suspiciousPatterns = $this->config->get('suspicious_user_agents', []);
        foreach ($suspiciousPatterns as $pattern) {
            if (@preg_match($pattern, $userAgent)) {
                $this->logDetection('可疑User-Agent', [
                    'user_agent' => Str::limit($userAgent, 100),
                    'pattern' => $pattern
                ]);
                return true;
            }
        }

        return false;
    }

    /**
     * 检查可疑HTTP头
     */
    public function hasSuspiciousHeaders(Request $request): bool
    {
        $suspiciousHeaders = $this->config->get('suspicious_headers', []);

        foreach ($suspiciousHeaders as $header => $pattern) {
            if ($request->headers->has($header)) {
                $value = $request->header($header);
                if (@preg_match($pattern, $value)) {
                    $this->logDetection('可疑HTTP头', [
                        'header' => $header,
                        'value' => $value
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
     * 检查URL安全性 - 优化增强版
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
        $urlWhitelist = $this->config->get('url_whitelist_paths', []);
        foreach ($urlWhitelist as $pattern) {
            if (fnmatch($pattern, $path)) {
                return true;
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
     */
    public function isMaliciousRequest(Request $request): bool
    {
        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        $patterns = $this->getCompiledPatterns('body_patterns');

        return $this->checkInputDataRecursively($input, $patterns);
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
        if (!$file instanceof UploadedFile) {
            return true;
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
    }

    /**
     * 检查文件扩展名
     */
    protected function isSafeFileExtension(UploadedFile $file): bool
    {
        $extension = strtolower($file->getClientOriginalExtension());

        // 检查白名单
        $whitelist = $this->config->get('allowed_extensions_whitelist', []);
        if (in_array($extension, $whitelist)) {
            return true;
        }

        // 检查黑名单
        $disallowed = $this->config->get('disallowed_extensions', []);
        if (in_array($extension, $disallowed)) {
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
        $maxSize = $this->config->get('max_file_size', 50 * 1024 * 1024);
        $fileSize = $file->getSize();

        if ($fileSize > $maxSize) {
            $this->logDetection('文件大小超限', [
                'size' => $fileSize,
                'max_size' => $maxSize,
                'filename' => $file->getClientOriginalName()
            ]);
            return false;
        }

        return true;
    }

    /**
     * 检查MIME类型
     */
    protected function isSafeMimeType(UploadedFile $file): bool
    {
        $mimeType = $file->getMimeType();
        $disallowed = $this->config->get('disallowed_mime_types', []);

        if (in_array($mimeType, $disallowed)) {
            $this->logDetection('危险MIME类型', [
                'mime_type' => $mimeType,
                'filename' => $file->getClientOriginalName()
            ]);
            return false;
        }

        return true;
    }

    /**
     * 检查文件内容
     */
    protected function isSafeFileContent(UploadedFile $file): bool
    {
        try {
            $content = file_get_contents($file->getPathname());
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
        } catch (Exception $e) {
            $this->logDetection('文件内容检查失败', [
                'filename' => $file->getClientOriginalName(),
                'error' => $e->getMessage()
            ]);
        }

        return true;
    }

    /**
     * 递归检查输入数据
     */
    protected function checkInputDataRecursively(array $data, array $patterns, string $parentKey = '', int $depth = 0): bool
    {
        $maxDepth = $this->config->get('max_recursion_depth', 10);
        if ($depth > $maxDepth) {
            return false;
        }

        foreach ($data as $key => $value) {
            $currentKey = $parentKey ? "{$parentKey}.{$key}" : $key;

            if (is_array($value)) {
                if ($this->checkInputDataRecursively($value, $patterns, $currentKey, $depth + 1)) {
                    return true;
                }
            } else {
                if ($this->checkInputValue($currentKey, $value, $patterns)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查单个输入值 - 性能优化版
     *
     * 优化点：
     * 1. 早期返回，减少不必要的处理
     * 2. 快速检查常见合法值
     * 3. 延迟正则匹配，优先使用快速检查
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

        // 2. 快速长度检查
        $minLength = $this->config->get('min_content_length', 3);
        $maxLength = 5000; // 避免过长的内容影响性能
        $valueLength = strlen($value);

        if ($valueLength < $minLength || $valueLength > $maxLength) {
            return false;
        }

        // 3. 快速检查常见安全值 - 早期返回
        if ($this->isLikelySafeValue($value)) {
            return false;
        }

        // 4. 检查键名白名单 - 早期返回
        if ($this->isWhitelistParameterName($key)) {
            return false;
        }

        // 5. 内容预处理
        $processedValue = $this->preprocessContent($value);
        if (empty($processedValue)) {
            return false;
        }

        // 6. 正则表达式匹配（只在前面的快速检查都通过后执行）
        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $processedValue)) {
                // 7. 误报检查
                if (!$this->isFalsePositive($key, $processedValue, $pattern)) {
                    $this->logDetection('恶意请求内容', [
                        'parameter' => $key,
                        'value' => Str::limit($processedValue, 100),
                        'pattern' => $pattern
                    ]);
                    return true;
                }
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
     * 误报检测 - 全面优化版
     *
     * 智能识别合法内容，减少误报率
     * 基于多层过滤机制，提高检测准确性
     *
     * @param string $key 参数键名
     * @param string $value 参数值
     * @param string $pattern 匹配的正则表达式
     * @return bool 是否为误报
     */
    protected function isFalsePositive(string $key, string $value, string $pattern): bool
    {
        // 1. 白名单键名检查 - 首层过滤
        $whitelistKeys = [
            'content', 'body', 'description', 'markdown', 'html_content',
            'message', 'comment', 'text', 'remark', 'note', 'summary',
            'introduction', 'about', 'details', 'information', 'content_text',
            'post_content', 'article_content', 'page_content', 'bio', 'profile'
        ];
        if (in_array(strtolower($key), $whitelistKeys)) {
            return true;
        }

        // 2. 内容长度检查 - 避免过短内容的误判
        if (strlen($value) < 10) {
            return true;
        }

        // 3. 常见合法内容模式检测
        $legitimatePatterns = [
            // URL模式 - 各种合法的URL格式
            '/^https?:\/\/[a-zA-Z0-9\-._~:\/?#[\]@!$&\'()*+,;=%]+$/i',

            // 邮箱模式
            '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',

            // 手机号模式（国际和国内）
            '/^\+?\d{10,15}$/',

            // 长数字ID（订单号、用户ID等）
            '/^\d{8,20}$/',

            // MD5哈希
            '/^[a-f0-9]{32}$/i',

            // SHA256哈希
            '/^[a-f0-9]{64}$/i',

            // UUID
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',

            // 日期时间格式
            '/^\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}/',

            // 纯文本（仅包含中英文、数字、基本标点）
            '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\s\.,!?;:"\'\-()【】（）。，！？；：""\'\-_]+$/u',

            // 简单的JSON字符串
            '/^[\s\S]*$/', // 占位符，实际检查在下面

            // 十六进制字符串（常见于ID转换）
            '/^(0x)?[0-9a-f]+$/i',

            // Base64字符串（排除太短的）
            '/^[A-Za-z0-9+\/]{20,}={0,2}$/',
        ];

        // 特殊检查：JSON字符串（需要更精确的检测）
        if ($this->isLikelyJson($value)) {
            try {
                json_decode($value, true, 512, JSON_THROW_ON_ERROR);
                return true;
            } catch (\JsonException $e) {
                // 不是有效的JSON，继续其他检查
            }
        }

        // 特殊检查：HTML/XML（富文本内容）
        if ($this->containsHtmlTags($value)) {
            // 如果是合法的HTML内容（不是恶意脚本），可能是误报
            if ($this->isLegitimateHtml($value)) {
                return true;
            }
        }

        foreach ($legitimatePatterns as $legitPattern) {
            if (@preg_match($legitPattern, $value)) {
                return true;
            }
        }

        // 4. 检查是否为常见的合法参数模式
        // API常见的参数名模式
        $safeParameterPatterns = [
            '/^id$/i',
            '/^(user|product|order|article|post)_id$/i',
            '/^(page|size|limit|offset)$/i',
            '/^(sort|order|dir|asc|desc)$/i',
            '/^(start|end|from|to|begin)$/i',
            '/^(key|value|name|title|type|category)$/i',
            '/^(lat|lng|longitude|latitude)$/i',
            '/^(q|query|search|keyword)$/i',
            '/^(token|code|session|cookie)$/i',
            '/^(status|state|enabled|disabled|active)$/i',
            '/^(mode|method|action|operation)$/i',
        ];

        foreach ($safeParameterPatterns as $paramPattern) {
            if (@preg_match($paramPattern, $key)) {
                return true;
            }
        }

        // 5. 检查常见的安全误报模式
        $falsePositivePatterns = [
            // 包含"SELECT"、"INSERT"等SQL关键字的普通文本（不是完整的SQL语句）
            '/^(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER BY)$/',
            // 包含常见HTML标签的普通文本
            '/^(<div|<span|<p|<a|<img|<ul|<li|<table|<tr|<td|<h[1-6]>\s*\/?>)/i',
        ];

        foreach ($falsePositivePatterns as $fpPattern) {
            if (@preg_match($fpPattern, $value)) {
                // 需要进一步检查，可能只是部分匹配
                if ($this->isPartialMatch($value)) {
                    return true;
                }
            }
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
     */
    protected function getCompiledPatterns(string $type): array
    {
        $cacheKey = "compiled_patterns:{$type}";

        if (isset(self::$compiledPatterns[$cacheKey])) {
            return self::$compiledPatterns[$cacheKey];
        }

        $patterns = $this->config->get($type, []);
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
