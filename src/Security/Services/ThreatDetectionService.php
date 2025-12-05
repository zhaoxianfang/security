<?php

namespace zxf\Security\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use zxf\Security\Config\SecurityConfig;

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
     * 检查URL安全性
     */
    public function isSafeUrl(Request $request): bool
    {
        $url = $request->fullUrl();
        $patterns = $this->getCompiledPatterns('url_patterns');

        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $url)) {
                $this->logDetection('非法URL访问', [
                    'url' => Str::limit($url, 200),
                    'pattern' => $pattern
                ]);
                return false;
            }
        }

        // 检查URL白名单
        $urlWhitelist = $this->config->get('url_whitelist_paths', []);
        $path = $request->path();

        foreach ($urlWhitelist as $pattern) {
            if (fnmatch($pattern, $path)) {
                return true;
            }
        }

        return true;
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
     * 检查单个输入值
     */
    protected function checkInputValue(string $key, $value, array $patterns): bool
    {
        if (!is_string($value) || empty(trim($value))) {
            return false;
        }

        // 检查最小内容长度
        $minLength = $this->config->get('min_content_length', 3);
        if (strlen($value) < $minLength) {
            return false;
        }

        $processedValue = $this->preprocessContent($value);
        if (empty($processedValue)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $processedValue)) {
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
     * 误报检测
     */
    protected function isFalsePositive(string $key, string $value, string $pattern): bool
    {
        // 白名单键名
        $whitelistKeys = ['content', 'body', 'description', 'markdown', 'html_content', 'message', 'comment'];
        if (in_array(strtolower($key), $whitelistKeys)) {
            return true;
        }

        // 过短的内容
        if (strlen($value) < 10) {
            return true;
        }

        // 常见合法内容模式
        $legitimatePatterns = [
            '/^https?:\/\/[^\s]+$/i', // URL
            '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', // 邮箱
            '/^\d{10,15}$/', // 长数字
            '/^[a-f0-9]{32}$/i', // MD5
            '/^[a-f0-9]{64}$/i', // SHA256
        ];
        $legitimatePatterns[] = $pattern;

        foreach ($legitimatePatterns as $legitPattern) {
            if (@preg_match($legitPattern, $value)) {
                return true;
            }
        }

        return false;
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
     * 清除缓存
     */
    public function clearCache(): void
    {
        self::$compiledPatterns = [];
    }
}
