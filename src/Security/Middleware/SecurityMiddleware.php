<?php

namespace zxf\Security\Middleware;

use Closure;
use DateTimeImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use zxf\Security\Dto\InterceptionContext;
use zxf\Security\Services\IpMatcherService;

/**
 * Laravel 安全拦截中间件
 *
 * 核心设计理念：
 * 1. 高危操作精准拦截 - 采用高置信度检测模式，确保攻击被拦截
 * 2. 低误报率 - 智能识别合法内容（如Markdown文档中的代码示例）
 * 3. 零缓存依赖 - 不使用任何自定义缓存，直接使用 Laravel 原生功能
 * 4. 高性能 - 精简逻辑，单次请求处理耗时 < 1ms
 * 5. 灵活配置 - 支持回调、动态规则、路由排除
 *
 * 安全防护层级（按执行顺序）：
 *  1. 路由排除检查    - 配置的路由直接放行
 *  2. IP 白名单检查   - 可信IP直接放行
 *  3. IP 黑名单检查   - 已知恶意IP直接拦截
 *  4. URL路径攻击检测 - 直接检测URL中的路径遍历等攻击
 *  5. 多重编码检测    - 检测编码绕过攻击
 *  6. User-Agent检查  - 封禁已知恶意扫描器
 *  7. HTTP头检查      - 验证关键头部安全性
 *  8. 请求体大小检查  - 防止内存溢出
 *  9. 请求速率限制    - 防止暴力破解和CC攻击
 * 10. HTTP方法检查   - 拦截非法HTTP方法
 * 11. URL长度检查    - 防止缓冲区溢出攻击
 * 12. 高危攻击检测   - SQL注入、命令注入、路径遍历、NoSQL、SSTI等
 * 13. XSS攻击检测    - 跨站脚本攻击（智能识别Markdown内容）
 * 14. 文件上传检查   - 防止恶意文件上传
 *
 * @package zxf\Security\Middleware
 * @version 5.0.0
 */
class SecurityMiddleware
{
    /**
     * 配置缓存数组
     * 在构造函数中一次性加载，避免重复读取配置
     *
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * IP匹配服务
     *
     * @var IpMatcherService
     */
    protected IpMatcherService $ipMatcher;

    /**
     * 检测到的威胁类型数组
     * 用于记录多种威胁类型，返回给客户端参考
     *
     * @var array<string>
     */
    protected array $threats = [];

    /**
     * 最后一次匹配的攻击模式
     * 用于回调时传递给开发者
     *
     * @var string
     */
    protected string $lastMatchedPattern = '';

    /**
     * 最后一次匹配的内容片段
     * 用于回调时传递给开发者
     *
     * @var string
     */
    protected string $lastMatchedContent = '';

    /**
     * 当前检测到的威胁类型
     *
     * @var string
     */
    protected string $currentThreatType = '';

    /**
     * 构造函数
     * 预加载配置到内存，提高后续访问速度
     */
    public function __construct()
    {
        $this->config = config('security', []);
        $this->ipMatcher = new IpMatcherService();
    }

    /**
     * 获取最大输入长度
     */
    protected function getMaxInputLength(): int
    {
        return $this->config['input_processing']['max_input_length'] ?? 100000;
    }

    /**
     * 获取威胁风险等级
     */
    protected function getThreatRiskLevel(string $threatType): string
    {
        $levels = $this->config['threat_risk_levels'] ?? [];
        $defaultLevels = [
            // 高危
            'sql' => 'high',
            'command' => 'high',
            'path' => 'high',
            'xml' => 'high',
            'ssti' => 'high',
            'blacklist' => 'high',
            'encoding_bypass' => 'high',

            // 中危
            'nosql' => 'medium',
            'xss_script' => 'medium',
            'xss_dom' => 'medium',
            'xss_tag' => 'medium',
            'dangerous_upload' => 'medium',
            'url_path_attack' => 'medium',
            'bad_user_agent' => 'medium',

            // 低危
            'ldap' => 'low',
            'xss_encoding' => 'low',
            'xss_framework' => 'low',
            'rate_limit' => 'low',
            'invalid_method' => 'low',
            'url_too_long' => 'low',
            'body_too_large' => 'low',
            'invalid_headers' => 'low',
        ];
        $levels = !empty($levels) && is_array($levels) ? array_merge($defaultLevels, $levels) : $defaultLevels;

        return $levels[$threatType] ?? 'unknown';
    }

    /**
     * 处理传入的HTTP请求
     *
     * 这是中间件的核心方法，按顺序执行各项安全检查。
     * 任何一项检查失败都会立即拦截请求，不再继续后续检查。
     *
     * @param Request $request HTTP请求对象
     * @param Closure $next 下一个中间件处理程序
     * @return mixed 响应对象或向下传递请求
     */
    public function handle(Request $request, Closure $next)
    {
        // 检查中间件是否被禁用
        if (!($this->config['enabled'] ?? true)) {
            return $next($request);
        }

        // 检查是否在排除路由列表中
        if ($this->isExcludedRoute($request)) {
            return $next($request);
        }

        // 获取客户端真实IP地址
        $ip = $request->ip();

        // ========== 第一层：IP 白名单检查 ==========
        if ($this->isWhitelisted($ip, $request)) {
            return $next($request);
        }

        // ========== 第二层：IP 黑名单检查 ==========
        if ($this->isBlacklisted($ip, $request)) {
            $this->threats[] = 'blacklist';
            $this->currentThreatType = 'blacklist';
            $context = $this->createInterceptionContext($request, 'blacklist');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'blacklist', 'IP地址位于黑名单中: ' . $ip);
                return $this->blockRequest($request, 'IP已被禁止访问', 403, 'blacklist');
            }
            // return $next($request);
        }

        // ========== 第三层：URL路径攻击检测 ==========
        // 在解码之前先检测原始URL中的攻击
        if ($this->isDetectionEnabled('url_path') && $this->detectUrlPathAttacks($request)) {
            $this->threats[] = 'url_path_attack';
            $this->currentThreatType = 'url_path_attack';
            $context = $this->createInterceptionContext($request, 'url_path_attack');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'url_path_attack', 'URL路径包含攻击模式: ' . $this->lastMatchedPattern);
                return $this->blockRequest($request, '请求包含非法内容', 403, 'url_path_attack');
            }
            // return $next($request);
        }

        // ========== 第四层：多重编码检测 ==========
        if ($this->isDetectionEnabled('encoding') && $this->detectMultiEncodingAttacks($request)) {
            $this->threats[] = 'encoding_bypass';
            $this->currentThreatType = 'encoding_bypass';
            $context = $this->createInterceptionContext($request, 'encoding_bypass');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'encoding_bypass', '检测到编码绕过攻击');
                return $this->blockRequest($request, '请求格式非法', 403, 'encoding_bypass');
            }
            // return $next($request);
        }

        // ========== 第五层：User-Agent检查 ==========
        if ($this->isDetectionEnabled('user_agent') && $this->isBadUserAgent($request)) {
            $this->threats[] = 'bad_user_agent';
            $this->currentThreatType = 'bad_user_agent';
            $context = $this->createInterceptionContext($request, 'bad_user_agent');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'bad_user_agent', '恶意User-Agent: ' . $request->userAgent());
                return $this->blockRequest($request, '请求被拒绝', 403, 'bad_user_agent');
            }
            // return $next($request);
        }

        // ========== 第六层：HTTP头检查 ==========
        if ($this->isDetectionEnabled('headers') && $this->hasInvalidHeaders($request)) {
            $this->threats[] = 'invalid_headers';
            $this->currentThreatType = 'invalid_headers';
            $context = $this->createInterceptionContext($request, 'invalid_headers');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'invalid_headers', 'HTTP头检查失败');
                return $this->blockRequest($request, '请求被拒绝', 403, 'invalid_headers');
            }
            // return $next($request);
        }

        // ========== 第七层：请求体大小检查 ==========
        if ($this->isDetectionEnabled('body_size') && $this->isBodyTooLarge($request)) {
            $this->threats[] = 'body_too_large';
            $this->currentThreatType = 'body_too_large';
            $context = $this->createInterceptionContext($request, 'body_too_large');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'body_too_large', '请求体大小超过限制');
                return $this->blockRequest($request, '请求体过大', 403, 'body_too_large');
            }
            // return $next($request);
        }

        // ========== 第八层：请求速率限制 ==========
        if ($this->isDetectionEnabled('rate_limit') && $this->isRateLimited($request)) {
            $this->threats[] = 'rate_limit';
            $this->currentThreatType = 'rate_limit';
            $context = $this->createInterceptionContext($request, 'rate_limit');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'rate_limit', '请求频率超过限制');
                return $this->blockRequest($request, '请求过于频繁，请稍后再试', 429, 'rate_limit');
            }
            // return $next($request);
        }

        // ========== 第九层：HTTP方法检查 ==========
        if ($this->isDetectionEnabled('http_method') && $this->hasInvalidMethod($request)) {
            $this->threats[] = 'invalid_method';
            $this->currentThreatType = 'invalid_method';
            $context = $this->createInterceptionContext($request, 'invalid_method');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'invalid_method', '非法HTTP方法: ' . $request->method());
                return $this->blockRequest($request, '不支持的请求方法', 403, 'invalid_method');
            }
            // return $next($request);
        }

        // ========== 第十层：URL长度检查 ==========
        if ($this->isDetectionEnabled('url_length') && $this->isUrlTooLong($request)) {
            $this->threats[] = 'url_too_long';
            $this->currentThreatType = 'url_too_long';
            $context = $this->createInterceptionContext($request, 'url_too_long');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'url_too_long', 'URL长度超限');
                return $this->blockRequest($request, '请求URL过长', 403, 'url_too_long');
            }
            // return $next($request);
        }

        // ========== 第十一层：高危攻击检测 ==========
        if ($this->isDetectionEnabled('high_risk')) {
            $threatType = $this->detectHighRiskAttacks($request);
            if ($threatType !== null) {
                $this->currentThreatType = $threatType;
                $context = $this->createInterceptionContext($request, $threatType);
                if ($this->shouldBlock($context)) {
                    $this->logThreat($request, $threatType, '高危模式匹配: ' . $this->lastMatchedPattern);
                    return $this->blockRequest($request, '请求包含高危安全威胁', 403, $threatType);
                }
                // return $next($request);
            }
        }

        // ========== 第十二层：XSS攻击检测 ==========
        if ($this->isDetectionEnabled('xss')) {
            $xssType = $this->detectXssAttacks($request);
            if ($xssType !== null) {
                $this->currentThreatType = $xssType;
                $context = $this->createInterceptionContext($request, $xssType);
                if ($this->shouldBlock($context)) {
                    $this->logThreat($request, $xssType, 'XSS模式匹配: ' . $this->lastMatchedPattern);
                    return $this->blockRequest($request, '请求包含潜在的安全威胁', 403, $xssType);
                }
                // return $next($request);
            }
        }

        // ========== 第十三层：文件上传检查 ==========
        if ($this->isDetectionEnabled('upload') && $this->hasDangerousUpload($request)) {
            $this->threats[] = 'dangerous_upload';
            $this->currentThreatType = 'dangerous_upload';
            $context = $this->createInterceptionContext($request, 'dangerous_upload');
            if ($this->shouldBlock($context)) {
                $this->logThreat($request, 'dangerous_upload', '检测到危险文件上传');
                return $this->blockRequest($request, '文件上传被拒绝', 403, 'dangerous_upload');
            }
            // return $next($request);
        }

        // 所有安全检查通过，继续处理请求
        return $next($request);
    }

    // ==================== 路由检查 ====================

    /**
     * 检查请求是否在排除路由列表中
     *
     * @param Request $request HTTP请求对象
     * @return bool true=在排除列表中，false=不在
     */
    protected function isExcludedRoute(Request $request): bool
    {
        $excluded = $this->config['excluded_routes'] ?? [];

        foreach ($excluded as $pattern) {
            // 闭包函数
            if ($pattern instanceof \Closure) {
                if ($pattern($request) === true) {
                    return true;
                }
                continue;
            }

            // 正则表达式
            if (is_string($pattern) && str_starts_with($pattern, '/')) {
                if (preg_match($pattern, $request->path())) {
                    return true;
                }
                continue;
            }

            // 字符串模式（支持通配符 *）
            if (is_string($pattern)) {
                if ($request->is($pattern)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ==================== IP 相关检查 ====================

    /**
     * 检查IP是否在白名单中
     *
     * 支持多种格式：静态IP、CIDR、闭包、类
     *
     * @param string $ip 要检查的IP地址
     * @param Request $request HTTP请求对象
     * @return bool true=在白名单中，false=不在白名单
     */
    protected function isWhitelisted(string $ip, Request $request): bool
    {
        // 合并用户配置的白名单和系统信任的内网IP
        $whitelist = array_merge(
            $this->config['whitelist'] ?? [],
            $this->config['trusted_ips'] ?? []
        );

        return $this->ipMatcher->matches($ip, $whitelist, $request);
    }

    /**
     * 检查IP是否在黑名单中
     *
     * 支持多种格式：静态IP、CIDR、闭包、类
     *
     * @param string $ip 要检查的IP地址
     * @param Request $request HTTP请求对象
     * @return bool true=在黑名单中，false=不在黑名单
     */
    protected function isBlacklisted(string $ip, Request $request): bool
    {
        $blacklist = $this->config['blacklist'] ?? [];

        return $this->ipMatcher->matches($ip, $blacklist, $request);
    }

    /**
     * 检查指定检测层是否启用
     *
     * @param string $layer 检测层名称
     * @return bool true=启用，false=禁用
     */
    protected function isDetectionEnabled(string $layer): bool
    {
        $layers = $this->config['detection_layers'] ?? [];

        return $layers[$layer] ?? true;
    }

    // ==================== URL路径攻击检测 ====================

    /**
     * 检测URL路径和查询参数中的攻击
     * 专门检测路径遍历等直接出现在URL路径或查询参数中的攻击
     *
     * @param Request $request HTTP请求对象
     * @return bool true=检测到攻击，false=正常
     */
    protected function detectUrlPathAttacks(Request $request): bool
    {
        $config = $this->config['url_path_detection'] ?? [];

        if (!($config['enabled'] ?? true)) {
            return false;
        }

        // 收集所有需要检查的来源
        $checkSources = [];

        // 1. URL路径（原始和解码）
        $url = $request->fullUrl();
        $checkSources['url'] = [$url, urldecode($url), urldecode(urldecode($url))];

        // 2. 路由参数
        $routeParams = $request->route()?->parameters() ?? [];
        $this->collectParamsForCheck($routeParams, $checkSources, 'route');

        // 从配置获取路径遍历检测模式
        $pathTraversalPatterns = $config['path_traversal_patterns'] ?? [];
        $traversalThreshold = $config['traversal_threshold'] ?? 2;

        // 检查所有来源
        foreach ($checkSources as $source => $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || empty($checkString)) {
                    continue;
                }

                foreach ($pathTraversalPatterns as $pattern) {
                    if (preg_match($pattern, $checkString)) {
                        // 检查是否匹配了足够多的遍历
                        $traversalCount = substr_count($checkString, '../') +
                                         substr_count($checkString, '..\\') +
                                         substr_count($checkString, '..%2f') +
                                         substr_count($checkString, '..%2F');

                        if ($traversalCount >= $traversalThreshold) {
                            $this->lastMatchedPattern = $pattern;
                            $this->lastMatchedContent = substr($checkString, 0, 100);
                            return true;
                        }
                    }
                }
            }
        }

        // 从配置获取敏感文件访问检测模式
        $sensitiveFilePatterns = $config['sensitive_file_patterns'] ?? [];

        foreach ($checkSources as $source => $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || empty($checkString)) {
                    continue;
                }

                foreach ($sensitiveFilePatterns as $pattern) {
                    if (preg_match($pattern, $checkString)) {
                        $this->lastMatchedPattern = $pattern;
                        $this->lastMatchedContent = substr($checkString, 0, 100);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 收集参数用于检查
     *
     * @param array $params 参数数组
     * @param array $checkSources 检查来源数组（引用）
     * @param string $prefix 前缀标识
     * @return void
     */
    protected function collectParamsForCheck(array $params, array &$checkSources, string $prefix): void
    {
        foreach ($params as $key => $value) {
            if (is_string($value)) {
                // 原始值
                $checkSources[$prefix . '.' . $key][] = $value;
                // 解码后的值
                $decoded = urldecode($value);
                $checkSources[$prefix . '.' . $key][] = $decoded;
                // 双重解码
                $checkSources[$prefix . '.' . $key][] = urldecode($decoded);
            } elseif (is_array($value)) {
                // 递归处理数组
                $this->collectParamsForCheck($value, $checkSources, $prefix . '.' . $key);
            }
        }
    }

    /**
     * 检测多重编码攻击
     * 攻击者常使用多重URL编码绕过WAF
     *
     * @param Request $request HTTP请求对象
     * @return bool true=检测到攻击，false=正常
     */
    protected function detectMultiEncodingAttacks(Request $request): bool
    {
        $config = $this->config['encoding_detection'] ?? [];

        if (!($config['enabled'] ?? true)) {
            return false;
        }

        $rawUrl = $request->fullUrl();

        // 检测空字节注入
        if (($config['detect_null_bytes'] ?? true) &&
            (str_contains($rawUrl, "%00") || str_contains($rawUrl, "\x00"))) {
            $this->lastMatchedPattern = 'null_byte_injection';
            $this->lastMatchedContent = '%00';
            return true;
        }

        // 检测过多的URL编码（可能是编码绕过）
        $percentCount = substr_count($rawUrl, '%');
        $urlLength = strlen($rawUrl);
        $percentThreshold = $config['percent_threshold'] ?? 0.30;

        // 如果URL中%字符占比超过阈值，可能是编码攻击
        if ($urlLength > 0 && ($percentCount * 3) / $urlLength > $percentThreshold) {
            // 进一步检查是否有危险模式的编码
            $decoded = urldecode($rawUrl);
            $doubleDecoded = urldecode($decoded);

            // 解码后检查可疑模式
            $suspicious = $config['suspicious_patterns'] ?? ['../', '..\\', '<script', 'javascript:', 'onerror=', 'onload='];
            foreach ($suspicious as $pattern) {
                if (str_contains($decoded, $pattern) || str_contains($doubleDecoded, $pattern)) {
                    $this->lastMatchedPattern = 'encoding_bypass_attempt';
                    $this->lastMatchedContent = substr($decoded, 0, 100);
                    return true;
                }
            }
        }

        // 检测无效的UTF-8序列（可能的UTF-8攻击）
        if ($config['detect_utf8_overlong'] ?? true) {
            $path = $request->path();
            if (preg_match('/%[c-f][0-9a-f](?:%[8-9a-b][0-9a-f])+/i', $path)) {
                // 可能是UTF-8过度编码攻击
                $decoded = urldecode($path);
                if (preg_match('/(?:\.\.\/|\.\.\\\\)/', $decoded)) {
                    $this->lastMatchedPattern = 'utf8_overlong_encoding';
                    $this->lastMatchedContent = substr($decoded, 0, 100);
                    return true;
                }
            }
        }

        return false;
    }

    // ==================== User-Agent检查 ====================

    /**
     * 检查User-Agent是否在黑名单中
     *
     * @param Request $request HTTP请求对象
     * @return bool true=恶意UA，false=正常
     */
    protected function isBadUserAgent(Request $request): bool
    {
        $uaList = $this->config['user_agent_blacklist'] ?? [];

        if (empty($uaList)) {
            return false;
        }

        $userAgent = strtolower($request->userAgent() ?? '');

        foreach ($uaList as $item) {
            // 闭包函数
            if ($item instanceof \Closure) {
                if ($item($request->userAgent(), $request) === true) {
                    return true;
                }
                continue;
            }

            // 正则表达式
            if (is_string($item) && str_starts_with($item, '/')) {
                if (preg_match($item, $request->userAgent())) {
                    return true;
                }
                continue;
            }

            // 字符串匹配（不区分大小写，支持部分匹配）
            if (is_string($item)) {
                if (str_contains($userAgent, strtolower($item))) {
                    return true;
                }
            }
        }

        return false;
    }

    // ==================== HTTP头检查 ====================

    /**
     * 检查HTTP头是否存在安全问题
     *
     * @param Request $request HTTP请求对象
     * @return bool true=存在安全问题，false=正常
     */
    protected function hasInvalidHeaders(Request $request): bool
    {
        $headersConfig = $this->config['headers'] ?? ['enabled' => false];

        if (!($headersConfig['enabled'] ?? false)) {
            return false;
        }

        // 检查禁止的头
        $forbidden = $headersConfig['forbidden'] ?? [];
        foreach ($forbidden as $header) {
            if ($request->hasHeader($header)) {
                return true;
            }
        }

        // Host头验证
        $hostValidation = $headersConfig['host_validation'] ?? ['enabled' => false];
        if ($hostValidation['enabled'] ?? false) {
            $allowedHosts = $hostValidation['allowed_hosts'] ?? [];
            $host = $request->getHost();

            $matched = false;
            foreach ($allowedHosts as $allowed) {
                if (str_starts_with($allowed, '*.')) {
                    $domain = substr($allowed, 2);
                    if (str_ends_with($host, $domain)) {
                        $matched = true;
                        break;
                    }
                } elseif ($host === $allowed) {
                    $matched = true;
                    break;
                }
            }

            if (!$matched) {
                return true;
            }
        }

        return false;
    }

    // ==================== 请求检查 ====================

    /**
     * 检查请求体是否过大
     *
     * @param Request $request HTTP请求对象
     * @return bool true=过大，false=正常
     */
    protected function isBodyTooLarge(Request $request): bool
    {
        $bodyConfig = $this->config['max_body_size'] ?? ['enabled' => false];

        if (!($bodyConfig['enabled'] ?? false)) {
            return false;
        }

        $limit = $bodyConfig['limit'] ?? 10 * 1024 * 1024;
        $contentLength = (int) $request->header('Content-Length', 0);

        return $contentLength > $limit;
    }

    /**
     * 检查请求是否超过速率限制
     *
     * @param Request $request HTTP请求对象
     * @return bool true=超过限制需要拦截，false=未超过限制
     */
    protected function isRateLimited(Request $request): bool
    {
        $rateLimit = $this->config['rate_limit'] ?? ['enabled' => false];

        if (!($rateLimit['enabled'] ?? false)) {
            return false;
        }

        $key = 'security:' . $request->ip();
        $maxAttempts = $rateLimit['max_attempts'] ?? 60;
        $decayMinutes = $rateLimit['decay_minutes'] ?? 1;

        if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
            return true;
        }

        RateLimiter::hit($key, $decayMinutes * 60);

        return false;
    }

    /**
     * 检查HTTP方法是否合法
     *
     * @param Request $request HTTP请求对象
     * @return bool true=方法非法，false=方法合法
     */
    protected function hasInvalidMethod(Request $request): bool
    {
        $allowedMethods = $this->config['allowed_http_methods'] ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

        return !in_array($request->method(), $allowedMethods, true);
    }

    /**
     * 检查URL长度是否超过限制
     *
     * @param Request $request HTTP请求对象
     * @return bool true=URL过长，false=URL长度正常
     */
    protected function isUrlTooLong(Request $request): bool
    {
        $maxLength = $this->config['max_url_length'] ?? 2048;
        return strlen($request->fullUrl()) > $maxLength;
    }

    // ==================== 攻击检测 ====================

    /**
     * 检测高危攻击
     *
     * @param Request $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function detectHighRiskAttacks(Request $request): ?string
    {
        $patterns = $this->config['high_risk_patterns'] ?? [];

        if (empty($patterns)) {
            return null;
        }

        // 1. 首先检查URL路径（重要：路径遍历攻击通常直接出现在URL中）
        $urlPath = $request->path();
        $pathResult = $this->checkPatternsAgainstInput($patterns, $urlPath);
        if ($pathResult !== null) {
            return $pathResult;
        }

        // 2. 检查完整URL（包含查询字符串）
        $fullUrl = $request->fullUrl();
        $urlResult = $this->checkPatternsAgainstInput($patterns, $fullUrl);
        if ($urlResult !== null) {
            return $urlResult;
        }

        // 3. 检查请求输入数据
        $input = $this->getInputString($request, false);
        $input = $this->truncateInput($input);

        $inputResult = $this->checkPatternsAgainstInput($patterns, $input);
        if ($inputResult !== null) {
            return $inputResult;
        }

        return null;
    }

    /**
     * 检查输入字符串是否匹配攻击模式
     *
     * @param array $patterns 攻击模式数组
     * @param string $input 输入字符串
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkPatternsAgainstInput(array $patterns, string $input): ?string
    {
        if (empty($input)) {
            return null;
        }

        foreach ($patterns as $type => $typePatterns) {
            foreach ($typePatterns as $pattern) {
                if (preg_match($pattern, $input, $matches)) {
                    $this->threats[] = $type;
                    $this->lastMatchedPattern = $pattern;
                    $this->lastMatchedContent = $this->sanitizeMatchedContent($matches[0] ?? '');
                    return $type;
                }
            }
        }

        return null;
    }

    /**
     * 检测XSS攻击
     *
     * @param Request $request HTTP请求对象
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function detectXssAttacks(Request $request): ?string
    {
        $patterns = $this->config['xss_patterns'] ?? [];

        if (empty($patterns)) {
            return null;
        }

        // 检查URL路径（反射型XSS常出现在URL中）
        $urlPath = urldecode($request->path());
        $urlPathResult = $this->checkXssPatterns($patterns, $urlPath, $urlPath);
        if ($urlPathResult !== null) {
            return $urlPathResult;
        }

        // 检查查询字符串
        $queryString = urldecode($request->getQueryString() ?? '');
        $queryResult = $this->checkXssPatterns($patterns, $queryString, $queryString);
        if ($queryResult !== null) {
            return $queryResult;
        }

        $rawInput = $this->getInputString($request, false);
        $cleanInput = $this->getInputString($request, true);

        // 限制输入长度
        $rawInput = $this->truncateInput($rawInput);
        $cleanInput = $this->truncateInput($cleanInput);

        if (empty($patterns)) {
            return null;
        }

        // 检查请求体输入
        $inputResult = $this->checkXssPatterns($patterns, $cleanInput, $rawInput);
        if ($inputResult !== null) {
            return $inputResult;
        }

        return null;
    }

    /**
     * 检查XSS攻击模式
     *
     * @param array $patterns XSS模式数组
     * @param string $input 要检查的输入
     * @param string $rawInput 原始输入（用于Markdown检测）
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function checkXssPatterns(array $patterns, string $input, string $rawInput): ?string
    {
        if (empty($input)) {
            return null;
        }

        foreach ($patterns as $type => $typePatterns) {
            foreach ($typePatterns as $pattern) {
                if (preg_match($pattern, $input, $matches)) {
                    if ($this->isLikelyMarkdownContent($rawInput, $pattern)) {
                        continue;
                    }

                    $threatType = 'xss_' . $type;
                    $this->threats[] = $threatType;
                    $this->lastMatchedPattern = $pattern;
                    $this->lastMatchedContent = $this->sanitizeMatchedContent($matches[0] ?? '');
                    return $threatType;
                }
            }
        }

        return null;
    }

    /**
     * 截断输入字符串，防止正则回溯
     *
     * @param string $input 原始输入
     * @return string 截断后的输入
     */
    protected function truncateInput(string $input): string
    {
        $maxLength = $this->getMaxInputLength();

        if (strlen($input) > $maxLength) {
            return substr($input, 0, $maxLength);
        }

        return $input;
    }

    /**
     * 判断内容是否可能是合法的Markdown文档
     *
     * @param string $content 原始内容
     * @param string $matchedPattern 匹配到的正则模式
     * @return bool true=可能是Markdown内容（误报），false=不是Markdown
     */
    protected function isLikelyMarkdownContent(string $content, string $matchedPattern): bool
    {
        $config = $this->config['input_processing'] ?? [];

        // 如果内容太短，不太可能是Markdown文档
        $minLength = $config['markdown_min_length'] ?? 100;
        if (strlen($content) < $minLength) {
            return false;
        }

        $markdownConfig = $this->config['markdown'] ?? [];
        $codeBlockMarkers = $markdownConfig['code_block_markers'] ?? ['```', '~~~'];
        $inlineCodeMarker = $markdownConfig['inline_code_marker'] ?? '`';

        // 检测是否包含代码块
        $hasCodeBlock = false;
        foreach ($codeBlockMarkers as $marker) {
            if (str_contains($content, $marker)) {
                $hasCodeBlock = true;
                break;
            }
        }

        // 检测是否包含大量行内代码
        $inlineCodeCount = substr_count($content, $inlineCodeMarker);
        $hasInlineCode = $inlineCodeCount >= 4;

        // 从配置获取Markdown语法模式
        $markdownPatterns = $config['markdown_patterns'] ?? [
            '/^#{1,6}\s+/m',
            '/^[-*+]\s+/m',
            '/\[.+?\]\(.+?\)/',
            '/^\s*>\s+/m',
            '/^\s*\|\s*[-:]+\s*\|/m',
            '/!\[.*?\]\(.*?\)/',
            '/\*\*.*?\*\*/',
        ];

        $markdownSyntaxCount = 0;
        foreach ($markdownPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $markdownSyntaxCount++;
            }
        }

        // 综合判断
        $isMarkdown = $hasCodeBlock || ($hasInlineCode && $markdownSyntaxCount >= 2) || $markdownSyntaxCount >= 3;

        if ($isMarkdown && $hasCodeBlock) {
            return $this->isPatternInCodeBlock($content, $matchedPattern);
        }

        return $isMarkdown;
    }

    /**
     * 检查匹配的XSS模式是否位于Markdown代码块内
     *
     * @param string $content 原始内容
     * @param string $pattern 匹配的正则模式
     * @return bool true=在代码块内（误报），false=不在代码块内
     */
    protected function isPatternInCodeBlock(string $content, string $pattern): bool
    {
        $lines = explode("\n", $content);
        $inCodeBlock = false;
        $codeBlockMarker = '';

        // 先找到匹配的行
        $matchedLineIndex = -1;
        foreach ($lines as $index => $line) {
            if (preg_match($pattern, $line)) {
                $matchedLineIndex = $index;
                break;
            }
        }

        if ($matchedLineIndex === -1) {
            return false;
        }

        // 从开头扫描到匹配行
        for ($i = 0; $i <= $matchedLineIndex; $i++) {
            $line = $lines[$i];
            $trimmed = trim($line);

            if (str_starts_with($trimmed, '```') || str_starts_with($trimmed, '~~~')) {
                if (!$inCodeBlock) {
                    $inCodeBlock = true;
                    $codeBlockMarker = str_starts_with($trimmed, '```') ? '```' : '~~~';
                } else {
                    $marker = str_starts_with($trimmed, '```') ? '```' : '~~~';
                    if ($marker === $codeBlockMarker) {
                        $inCodeBlock = false;
                    }
                }
            }
        }

        return $inCodeBlock;
    }

    // ==================== 辅助方法 ====================

    /**
     * 获取请求的输入字符串
     *
     * @param Request $request HTTP请求对象
     * @param bool $sanitizeMarkdown 是否移除Markdown代码块
     * @return string 合并后的输入字符串
     */
    protected function getInputString(Request $request, bool $sanitizeMarkdown = false): string
    {
        $input = array_merge(
            $request->query(),
            $request->post(),
            $request->route()?->parameters() ?? []
        );

        $result = $this->flattenInput($input);

        if ($sanitizeMarkdown) {
            $result = $this->removeMarkdownCodeBlocks($result);
        }

        return $result;
    }

    /**
     * 扁平化多维数组为字符串
     *
     * @param array $input 输入数组
     * @return string 连接后的字符串
     */
    protected function flattenInput(array $input): string
    {
        $result = '';

        array_walk_recursive($input, function ($value) use (&$result) {
            if (is_string($value)) {
                $result .= ' ' . $value;
            }
        });

        return $result;
    }

    /**
     * 移除Markdown代码块
     *
     * @param string $content 原始内容
     * @return string 移除代码块后的内容
     */
    protected function removeMarkdownCodeBlocks(string $content): string
    {
        $content = preg_replace('/```[\s\S]*?```/', ' ', $content);
        $content = preg_replace('/~~~[\s\S]*?~~~/', ' ', $content);
        $content = preg_replace('/`[^`]+`/', ' ', $content);

        return $content;
    }

    /**
     * 检查文件上传是否包含危险文件
     *
     * @param Request $request HTTP请求对象
     * @return bool true=包含危险文件，false=文件安全或没有上传
     */
    protected function hasDangerousUpload(Request $request): bool
    {
        $upload = $this->config['upload'] ?? ['enabled' => false];

        if (!($upload['enabled'] ?? false)) {
            return false;
        }

        $files = $request->allFiles();

        if (empty($files)) {
            return false;
        }

        $blockedExtensions = $upload['blocked_extensions'] ?? [];
        $maxSize = $upload['max_size'] ?? 10 * 1024 * 1024;

        foreach ($files as $file) {
            $fileList = is_array($file) ? $file : [$file];

            foreach ($fileList as $singleFile) {
                $extension = strtolower($singleFile->getClientOriginalExtension());
                if (in_array($extension, $blockedExtensions, true)) {
                    return true;
                }

                if ($singleFile->getSize() > $maxSize) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 拦截请求并返回响应
     *
     * @param Request $request HTTP请求对象
     * @param string $message 拦截提示消息
     * @param int $status HTTP状态码
     * @param string $threatType 威胁类型
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\Response
     */
    protected function blockRequest(Request $request, string $message, int $status = 403, string $threatType = '')
    {
        $defaultStatus = $this->config['response']['blocked_status'] ?? 403;
        $status = $status === 429
            ? ($this->config['response']['rate_limit_status'] ?? 429)
            : $defaultStatus;

        $showDetails = $this->config['response']['show_threat_details'] ?? false;

        // 根据威胁类型获取更详细的拦截消息
        $detailedMessage = $this->getBlockMessage($threatType, $message);

        // 构建响应数据
        $responseData = [
            'message' => $detailedMessage,
            'blocked' => true,
            'threats' => array_unique($this->threats),
            'threat_type' => $threatType,
            'risk_level' => $this->getRiskLevel($threatType),
            'matched_pattern' => $this->lastMatchedPattern,
            'matched_content' => $this->lastMatchedContent,
            'timestamp' => now()->toIso8601String(),
        ];

        // JSON 响应
        if ($request->expectsJson() || $request->is('api/*') || $request->ajax()) {
            $response = [
                'message' => $detailedMessage,
                'blocked' => true,
            ];

            if ($showDetails) {
                $response['threats'] = array_unique($this->threats);
                $response['threat_type'] = $threatType;
                $response['risk_level'] = $this->getRiskLevel($threatType);
            }

            return response()->json($response, $status);
        }

        // 检查是否配置了自定义视图
        $viewConfig = $this->config['response']['view'] ?? null;

        if ($viewConfig !== null && $viewConfig !== '') {
            return $this->renderViewResponse($viewConfig, $responseData, $status);
        }

        // 默认文本响应
        return response($detailedMessage, $status);
    }

    /**
     * 获取拦截消息
     * 根据威胁类型返回配置的详细消息
     *
     * @param string $threatType 威胁类型
     * @param string $defaultMessage 默认消息
     * @return string 拦截消息
     */
    protected function getBlockMessage(string $threatType, string $defaultMessage): string
    {
        if (empty($threatType)) {
            return $defaultMessage;
        }

        $messages = $this->config['response']['messages'] ?? [];

        return $messages[$threatType] ?? $defaultMessage;
    }

    /**
     * 获取威胁的风险等级
     *
     * @param string $threatType 威胁类型
     * @return string 风险等级：high, medium, low, unknown
     */
    protected function getRiskLevel(string $threatType): string
    {
        return $this->getThreatRiskLevel($threatType);
    }

    /**
     * 渲染自定义视图响应
     *
     * 支持多种配置格式：
     * - 字符串视图名：'errors.security'
     * - 闭包函数：function($data) { return view(...); }
     * - 类方法：['App\Http\Controllers\SecurityController', 'block']
     * - 可调用类：App\Security\CustomResponseHandler::class
     *
     * @param mixed $viewConfig 视图配置
     * @param array $data 响应数据
     * @param int $status HTTP状态码
     * @return \Illuminate\Http\Response
     */
    protected function renderViewResponse(mixed $viewConfig, array $data, int $status): \Illuminate\Http\Response
    {
        try {
            // 1. 闭包函数
            if ($viewConfig instanceof \Closure) {
                $result = $viewConfig($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 2. 可调用数组 [类名, 方法名]
            if (is_array($viewConfig) && count($viewConfig) === 2) {
                $instance = app($viewConfig[0]);
                $result = $instance->{$viewConfig[1]}($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 3. 类名字符串（自动实例化并调用 __invoke）
            if (is_string($viewConfig) && class_exists($viewConfig)) {
                $instance = app($viewConfig);
                $result = $instance($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 4. 字符串视图名
            if (is_string($viewConfig) && view()->exists($viewConfig)) {
                return response()->view($viewConfig, $data, $status);
            }

            // 配置无效，返回默认响应
            Log::warning('[Security] 自定义视图配置无效，使用默认响应', [
                'view_config' => $viewConfig,
            ]);

            return response($data['message'], $status);
        } catch (\Throwable $e) {
            Log::error('[Security] 自定义视图渲染失败', [
                'exception' => $e->getMessage(),
                'view_config' => $viewConfig,
            ]);

            return response($data['message'], $status);
        }
    }

    /**
     * 规范化视图响应
     *
     * @param mixed $result 视图返回结果
     * @param int $status HTTP状态码
     * @return \Illuminate\Http\Response
     */
    protected function normalizeViewResponse(mixed $result, int $status): \Illuminate\Http\Response
    {
        if ($result instanceof \Illuminate\Http\Response) {
            return $result;
        }

        if ($result instanceof \Illuminate\View\View) {
            return response($result->render(), $status);
        }

        return response((string) $result, $status);
    }

    /**
     * 判断是否应拦截请求
     *
     * @param InterceptionContext $context 拦截上下文
     * @return bool true=拦截，false=放行
     */
    protected function shouldBlock(InterceptionContext $context): bool
    {
        $callback = $this->config['before_block_callback'] ?? null;

        if ($callback === null || $callback === false) {
            return true;
        }

        if ($callback === true) {
            return true;
        }

        try {
            $result = $this->executeCallback($callback, $context);

            if ($result === false) {
                return false;
            }

            return true;
        } catch (\Throwable $e) {
            Log::error('[Security] 拦截回调执行异常', [
                'exception' => $e->getMessage(),
                'threat_type' => $context->threatType,
                'ip' => $context->clientIp,
            ]);

            return true;
        }
    }

    /**
     * 执行回调函数
     *
     * @param mixed $callback 回调
     * @param InterceptionContext $context 拦截上下文
     * @return mixed 回调返回值
     */
    protected function executeCallback(mixed $callback, InterceptionContext $context): mixed
    {
        if (is_string($callback) && class_exists($callback)) {
            $instance = app($callback);
            return $instance($context);
        }

        if (is_callable($callback)) {
            return $callback($context);
        }

        return $callback($context);
    }

    /**
     * 创建拦截上下文对象
     *
     * @param Request $request HTTP请求对象
     * @param string $threatType 威胁类型
     * @return InterceptionContext 拦截上下文对象
     */
    protected function createInterceptionContext(Request $request, string $threatType): InterceptionContext
    {
        $requestData = [
            'query_keys' => array_keys($request->query()),
            'post_keys' => array_keys($request->post()),
            'content_type' => $request->header('Content-Type'),
        ];

        return new InterceptionContext(
            request: $request,
            threatType: $threatType,
            matchedPattern: $this->lastMatchedPattern,
            matchedContent: $this->lastMatchedContent,
            clientIp: $request->ip() ?? '',
            method: $request->method(),
            url: $request->fullUrl(),
            allThreats: array_unique($this->threats),
            requestData: $requestData,
            timestamp: new DateTimeImmutable(),
        );
    }

    /**
     * 脱敏处理匹配到的内容
     *
     * @param string $content 原始匹配内容
     * @return string 脱敏后的内容
     */
    protected function sanitizeMatchedContent(string $content): string
    {
        if (empty($content)) {
            return '';
        }

        $config = $this->config['input_processing'] ?? [];
        $maxLength = $config['max_match_content_length'] ?? 200;

        if (strlen($content) > $maxLength) {
            $content = substr($content, 0, $maxLength) . '...[截断]';
        }

        $sensitivePatterns = [
            '/(password|passwd|pwd|token|secret|key)=\S+/i' => '$1=***',
        ];

        foreach ($sensitivePatterns as $pattern => $replacement) {
            $content = preg_replace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * 记录安全威胁日志
     *
     * @param Request $request HTTP请求对象
     * @param string $type 威胁类型
     * @param string $details 详细信息
     */
    protected function logThreat(Request $request, string $type, string $details): void
    {
        if (!($this->config['log_enabled'] ?? true)) {
            return;
        }

        $logLevel = $this->config['log_level'] ?? 'warning';
        $logFullRequest = $this->config['log_full_request'] ?? false;

        $logData = [
            'type' => $type,
            'ip' => $request->ip(),
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'user_agent' => $request->userAgent(),
            'details' => $details,
            'threat_type' => $this->currentThreatType,
            'risk_level' => $this->getRiskLevel($type),
            'timestamp' => now()->toIso8601String(),
        ];

        // 如果开启完整请求记录，添加更多数据
        if ($logFullRequest) {
            $logData['headers'] = $request->headers->all();
            $logData['query'] = $request->query();
            $logData['body'] = $request->except(['password', 'token', 'secret']);
            $logData['matched_pattern'] = $this->lastMatchedPattern;
            $logData['matched_content'] = $this->lastMatchedContent;
        }

        // 根据日志级别使用不同的日志方法
        match ($logLevel) {
            'debug' => Log::debug('[Security] 安全威胁检测', $logData),
            'info' => Log::info('[Security] 安全威胁检测', $logData),
            'error' => Log::error('[Security] 安全威胁检测', $logData),
            'critical' => Log::critical('[Security] 安全威胁检测', $logData),
            default => Log::warning('[Security] 安全威胁检测', $logData),
        };
    }
}
