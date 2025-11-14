<?php

namespace zxf\Security\Services;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * 威胁检测服务
 *
 * 提供多层安全检测功能，包括：
 * 1. 请求内容检测
 * 2. URL路径检测
 * 3. User-Agent检测
 * 4. 文件上传检测
 * 5. 异常行为检测
 */
class ThreatDetectionService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

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
        $this->precompilePatterns();
    }

    /**
     * 检查是否为资源文件路径：跳过资源文件的安全检查
     */
    public function isResourcePath(Request $request): bool
    {
        $path = $request->path();

        return match(true) {
            str_starts_with($path, 'zxf/security/css/'),
            str_starts_with($path, 'zxf/security/js/'),
            str_starts_with($path, 'zxf/security/images/'),
            str_starts_with($path, 'zxf/security/fonts/') => true,
            default => false
        };
    }

    /**
     * 执行分层安全检测
     */
    public function performLayeredSecurityCheck(Request $request): array
    {

        // 第一层：超轻量级检查
        $ultraLightChecks = [
            'suspicious_method' => fn() => $this->hasSuspiciousMethod($request),
            'empty_user_agent' => fn() => $this->hasEmptyUserAgent($request),
        ];

        foreach ($ultraLightChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResult($checkType, "检测到{$checkType}");
            }
        }

        // 第二层：轻量级检查
        $lightweightChecks = [
            'suspicious_user_agent' => fn() => $this->hasSuspiciousUserAgent($request),
            'suspicious_headers' => fn() => $this->hasSuspiciousHeaders($request),
        ];

        foreach ($lightweightChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResult($checkType, "检测到{$checkType}");
            }
        }

        // 第三层：中等重量检查
        $mediumChecks = [
            'dangerous_upload' => fn() => $this->hasDangerousUploads($request),
            'illegal_url' => fn() => !$this->isSafeUrl($request),
        ];

        foreach ($mediumChecks as $checkType => $checkFn) {
            if ($checkFn()) {
                return $this->createBlockResult($checkType, "检测到{$checkType}");
            }
        }

        // 第四层：重量级检查（白名单路径跳过）
        if (!$this->isWhitelistPath($request)) {
            $heavyChecks = [
                'malicious_request' => fn() => $this->isMaliciousRequest($request),
                'anomalous_parameters' => fn() => $this->hasAnomalousParameters($request),
            ];

            foreach ($heavyChecks as $checkType => $checkFn) {
                if ($checkFn()) {
                    return $this->createBlockResult($checkType, "检测到{$checkType}");
                }
            }
        }

        return ['blocked' => false];
    }

    /**
     * 检查可疑HTTP方法
     */
    protected function hasSuspiciousMethod(Request $request): bool
    {
        $method = strtoupper($request->method());
        $allowedMethods = $this->config->get('allowed_methods', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

        if (!in_array($method, $allowedMethods)) {
            Log::warning("可疑HTTP方法: {$method}");
            return true;
        }

        $suspiciousMethods = ['CONNECT', 'TRACE', 'TRACK', 'DEBUG'];
        return in_array($method, $suspiciousMethods);
    }

    /**
     * 检查空User-Agent
     */
    protected function hasEmptyUserAgent(Request $request): bool
    {
        return empty($request->userAgent());
    }

    /**
     * 检查可疑User-Agent
     */
    protected function hasSuspiciousUserAgent(Request $request): bool
    {
        $userAgent = $request->userAgent();
        if (empty($userAgent)) {
            return true;
        }

        // 先检查白名单
        $whitelistPatterns = $this->config->get('whitelist_user_agents', []);
        foreach ($whitelistPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return false;
            }
        }

        // 检查黑名单
        $suspiciousPatterns = $this->config->get('suspicious_user_agents', []);
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                Log::warning("可疑User-Agent: " . Str::limit($userAgent, 100));
                return true;
            }
        }

        return false;
    }

    /**
     * 检查可疑HTTP头
     */
    protected function hasSuspiciousHeaders(Request $request): bool
    {
        $suspiciousHeaders = ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP'];

        foreach ($suspiciousHeaders as $header) {
            if ($request->headers->has($header)) {
                $value = $request->header($header);
                if (str_contains($value, ',')) {
                    Log::warning("可疑HTTP头: {$header} = {$value}");
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查危险文件上传
     */
    protected function hasDangerousUploads(Request $request): bool
    {
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
     */
    protected function isSafeUrl(Request $request): bool
    {
        $url = $request->fullUrl();
        $patterns = $this->config->get('url_patterns', []);

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $url)) {
                Log::warning("非法URL访问: " . Str::limit($url, 200));
                return false;
            }
        }

        return true;
    }

    /**
     * 检查恶意请求内容
     */
    protected function isMaliciousRequest(Request $request): bool
    {
        $input = $request->input();
        if (empty($input)) {
            return false;
        }

        $patterns = $this->getCompiledPatterns('body_patterns');
        return $this->checkInputDataRecursively($input, $patterns);
    }

    /**
     * 检查异常参数
     */
    protected function hasAnomalousParameters(Request $request): bool
    {
        if (!$this->config->get('enable_anomaly_detection', true)) {
            return false;
        }

        $parameters = $request->all();
        $thresholds = $this->config->get('anomaly_thresholds', [
            'max_parameters' => 100,
            'max_parameter_length' => 255,
        ]);

        // 检查参数数量
        if (count($parameters) > $thresholds['max_parameters']) {
            Log::warning("参数数量异常: " . count($parameters));
            return true;
        }

        // 检查参数名和值
        foreach ($parameters as $key => $value) {
            if (strlen($key) > $thresholds['max_parameter_length']) {
                Log::warning("参数名长度异常: {$key}");
                return true;
            }

            // 检查可疑参数名
            $suspiciousNames = ['cmd', 'exec', 'system', 'eval', 'php', 'script'];
            foreach ($suspiciousNames as $suspicious) {
                if (stripos($key, $suspicious) !== false) {
                    Log::warning("可疑参数名: {$key}");
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
        $disallowed = $this->config->get('disallowed_extensions', []);

        if (in_array($extension, $disallowed)) {
            Log::warning("危险文件扩展名: {$extension} - " . $file->getClientOriginalName());
            return false;
        }

        return true;
    }

    /**
     * 检查文件大小
     */
    protected function isSafeFileSize(UploadedFile $file): bool
    {
        $maxSize = $this->config->get('max_file_size', 10 * 1024 * 1024);
        $fileSize = $file->getSize();

        if ($fileSize > $maxSize) {
            Log::warning("文件大小超限: {$fileSize} - " . $file->getClientOriginalName());
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
            Log::warning("危险MIME类型: {$mimeType} - " . $file->getClientOriginalName());
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
                if (preg_match($pattern, $content)) {
                    Log::warning("文件内容包含恶意代码: " . $file->getClientOriginalName());
                    return false;
                }
            }
        } catch (\Exception $e) {
            Log::warning("文件内容检查失败: " . $e->getMessage());
        }

        return true;
    }

    /**
     * 递归检查输入数据
     */
    protected function checkInputDataRecursively(array $data, array $patterns, string $parentKey = '', int $depth = 0): bool
    {
        if ($depth > $this->config->get('max_recursion_depth', 10)) {
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
     * 检查单个输入值
     */
    protected function checkInputValue(string $key, $value, array $patterns): bool
    {
        if (!is_string($value) || empty(trim($value))) {
            return false;
        }

        $processedValue = $this->preprocessContent($value);
        if (empty($processedValue)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $processedValue)) {
                if (!$this->isFalsePositive($key, $processedValue, $pattern)) {
                    Log::warning("恶意请求内容 - 参数: {$key}, 模式: {$pattern}");
                    return true;
                }
            }
        }

        return false;
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

        return $content;
    }

    /**
     * 误报检测
     */
    protected function isFalsePositive(string $key, string $value, string $pattern): bool
    {
        $whitelistKeys = ['content', 'body', 'description', 'markdown', 'html_content'];
        if (in_array(strtolower($key), $whitelistKeys)) {
            return true;
        }

        if (strlen($value) < 10) {
            return true;
        }

        return false;
    }

    /**
     * 检查是否为白名单路径
     */
    protected function isWhitelistPath(Request $request): bool
    {
        $path = $request->path();
        $whitelistPaths = $this->config->get('body_whitelist_paths', []);

        foreach ($whitelistPaths as $whitelist) {
            if (fnmatch($whitelist, $path)) {
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

        $patternTypes = ['body_patterns', 'url_patterns', 'suspicious_user_agents'];

        foreach ($patternTypes as $type) {
            $this->getCompiledPatterns($type);
        }
    }

    /**
     * 获取预编译的正则表达式
     */
    protected function getCompiledPatterns(string $type): array
    {
        $cacheKey = $type;

        if (!isset(self::$compiledPatterns[$cacheKey])) {
            $patterns = $this->config->get($type, []);
            $compiled = [];

            foreach ($patterns as $pattern) {
                if (@preg_match($pattern, '') !== false) {
                    $compiled[] = $pattern;
                } else {
                    Log::warning("无效的正则表达式: {$pattern}");
                }
            }

            self::$compiledPatterns[$cacheKey] = $compiled;
        }

        return self::$compiledPatterns[$cacheKey];
    }

    /**
     * 创建拦截结果
     */
    protected function createBlockResult(string $type, string $message): array
    {
        return [
            'blocked' => true,
            'type' => $type,
            'reason' => $message,
            'message' => $this->getBlockMessage($type),
        ];
    }

    /**
     * 获取拦截消息
     */
    protected function getBlockMessage(string $type): string
    {
        $messages = [
            'suspicious_method' => '请求方法不被允许',
            'empty_user_agent' => 'User-Agent不能为空',
            'suspicious_user_agent' => '可疑的User-Agent',
            'suspicious_headers' => '可疑的请求头',
            'dangerous_upload' => '危险的文件上传',
            'illegal_url' => '非法的URL访问',
            'malicious_request' => '恶意请求内容',
            'anomalous_parameters' => '异常请求参数',
        ];

        return $messages[$type] ?? '安全规则拦截';
    }

    /**
     * 获取配置值
     */
    public function getConfig(string $key, mixed $default = null, mixed $params = null)
    {
        return $this->config->get($key, $default, $params);
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        self::$compiledPatterns = [];
    }
}