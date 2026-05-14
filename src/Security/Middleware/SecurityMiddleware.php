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
     * 当前请求ID
     * 用于日志记录等处理
     *
     * @var string
     */
    protected string $requestId = '';

    /**
     * @var InterceptionContext 拦截上下文信息
     */
    protected InterceptionContext $context;

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
            // 高危 - 可能导致服务器被接管
            'sql' => 'high',
            'command' => 'high',
            'path' => 'high',
            'xml' => 'high',
            'ssti' => 'high',
            'blacklist' => 'high',
            'encoding_bypass' => 'high',
            'dangerous_upload' => 'high',

            // 中危 - 可能造成数据泄露或损坏
            'nosql' => 'medium',
            'xss_script' => 'medium',
            'xss_dom' => 'medium',
            'xss_tag' => 'medium',
            'url_path_attack' => 'medium',
            'bad_user_agent' => 'medium',

            // 低危 - 可能是误报或低风险行为
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

        // 生成唯一请求ID
        try {
            $randomBytes = random_bytes(8);
        } catch (\Random\RandomException) {
            $randomBytes = (string) random_int(10000000, 99999999);
        }
        $this->requestId = 'SEC_' . strtoupper(uniqid()) . '_' . substr(md5($randomBytes), 0, 8);

        // ========== 第二层：IP 黑名单检查 ==========
        if ($this->isBlacklisted($ip, $request)) {
            $this->threats[] = 'blacklist';
            $this->currentThreatType = 'blacklist';
            $this->context = $this->createInterceptionContext($request, 'blacklist');
            if ($this->shouldBlock($this->context)) {
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
            $this->context = $this->createInterceptionContext($request, 'url_path_attack');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'url_path_attack', 'URL路径包含攻击模式: ' . $this->lastMatchedPattern);
                return $this->blockRequest($request, '请求包含非法内容', 403, 'url_path_attack');
            }
            // return $next($request);
        }

        // ========== 第四层：多重编码检测 ==========
        if ($this->isDetectionEnabled('encoding') && $this->detectMultiEncodingAttacks($request)) {
            $this->threats[] = 'encoding_bypass';
            $this->currentThreatType = 'encoding_bypass';
            $this->context = $this->createInterceptionContext($request, 'encoding_bypass');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'encoding_bypass', '检测到编码绕过攻击');
                return $this->blockRequest($request, '请求格式非法', 403, 'encoding_bypass');
            }
            // return $next($request);
        }

        // ========== 第五层：User-Agent检查 ==========
        if ($this->isDetectionEnabled('user_agent') && $this->isBadUserAgent($request)) {
            $this->threats[] = 'bad_user_agent';
            $this->currentThreatType = 'bad_user_agent';
            $this->context = $this->createInterceptionContext($request, 'bad_user_agent');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'bad_user_agent', '恶意User-Agent: ' . $request->userAgent());
                return $this->blockRequest($request, '请求被拒绝', 403, 'bad_user_agent');
            }
            // return $next($request);
        }

        // ========== 第六层：HTTP头检查 ==========
        if ($this->isDetectionEnabled('headers') && $this->hasInvalidHeaders($request)) {
            $this->threats[] = 'invalid_headers';
            $this->currentThreatType = 'invalid_headers';
            $this->context = $this->createInterceptionContext($request, 'invalid_headers');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'invalid_headers', 'HTTP头检查失败');
                return $this->blockRequest($request, '请求被拒绝', 403, 'invalid_headers');
            }
            // return $next($request);
        }

        // ========== 第七层：请求体大小检查 ==========
        if ($this->isDetectionEnabled('body_size') && $this->isBodyTooLarge($request)) {
            $this->threats[] = 'body_too_large';
            $this->currentThreatType = 'body_too_large';
            $this->context = $this->createInterceptionContext($request, 'body_too_large');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'body_too_large', '请求体大小超过限制');
                return $this->blockRequest($request, '请求体过大', 403, 'body_too_large');
            }
            // return $next($request);
        }

        // ========== 第八层：请求速率限制 ==========
        if ($this->isDetectionEnabled('rate_limit') && $this->isRateLimited($request)) {
            $this->threats[] = 'rate_limit';
            $this->currentThreatType = 'rate_limit';
            $this->context = $this->createInterceptionContext($request, 'rate_limit');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'rate_limit', '请求频率超过限制');
                return $this->blockRequest($request, '请求过于频繁，请稍后再试', 429, 'rate_limit');
            }
            // return $next($request);
        }

        // ========== 第九层：HTTP方法检查 ==========
        if ($this->isDetectionEnabled('http_method') && $this->hasInvalidMethod($request)) {
            $this->threats[] = 'invalid_method';
            $this->currentThreatType = 'invalid_method';
            $this->context = $this->createInterceptionContext($request, 'invalid_method');
            if ($this->shouldBlock($this->context)) {
                $this->logThreat($request, 'invalid_method', '非法HTTP方法: ' . $request->method());
                return $this->blockRequest($request, '不支持的请求方法', 403, 'invalid_method');
            }
            // return $next($request);
        }

        // ========== 第十层：URL长度检查 ==========
        if ($this->isDetectionEnabled('url_length') && $this->isUrlTooLong($request)) {
            $this->threats[] = 'url_too_long';
            $this->currentThreatType = 'url_too_long';
            $this->context = $this->createInterceptionContext($request, 'url_too_long');
            if ($this->shouldBlock($this->context)) {
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
                $this->context = $this->createInterceptionContext($request, $threatType);
                if ($this->shouldBlock($this->context)) {
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
                $this->context = $this->createInterceptionContext($request, $xssType);
                if ($this->shouldBlock($this->context)) {
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
            $this->context = $this->createInterceptionContext($request, 'dangerous_upload');
            if ($this->shouldBlock($this->context)) {
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
                if ($this->safePregMatch($pattern, $request->path())) {
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
        // $checkSources['url'] = [$url, urldecode($url), urldecode(urldecode($url))];
        $checkSources['url'] = [$url, urldecode($url)];

        // 2. 路由参数
        $routeParams = $request->route()?->parameters() ?? [];
        $this->collectParamsForCheck($routeParams, $checkSources, 'route');

        // 从配置获取遍历检测模式
        $pathPatterns = $config['path_patterns'] ?? [];

        // 检查所有来源
        foreach ($checkSources as $_source => $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || empty($checkString)) {
                    continue;
                }

                foreach ($pathPatterns as $pattern) {
                    if ($this->safePregMatch($pattern, $checkString)) {
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
            if ($this->safePregMatch('/%[c-f][0-9a-f](?:%[8-9a-b][0-9a-f])+/i', $path)) {
                // 可能是UTF-8过度编码攻击
                $decoded = urldecode($path);
                if ($this->safePregMatch('/(?:\.\.\/|\.\.\\\\)/', $decoded)) {
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
                if ($this->safePregMatch($item, $request->userAgent())) {
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

        // CRLF/Header注入检测 - 检查头部值中是否包含换行符
        if ($headersConfig['detect_crlf'] ?? true) {
            $allHeaders = $request->headers->all();
            foreach ($allHeaders as $name => $values) {
                foreach ((array) $values as $value) {
                    if (str_contains($value, "\r") || str_contains($value, "\n")) {
                        $this->lastMatchedPattern = 'crlf_injection_in_header:' . $name;
                        $this->lastMatchedContent = substr($value, 0, 100);
                        return true;
                    }
                }
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

        // 使用 IP + 路由路径组合作为限流 key，避免不同路由间的碰撞
        // 同时支持配置自定义 key 前缀
        $prefix = $rateLimit['key_prefix'] ?? 'security';
        $key = $prefix . ':' . $request->ip() . ':' . md5($request->path());
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
                if ($this->safePregMatch($pattern, $input, $matches)) {
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
                if ($this->safePregMatch($pattern, $input, $matches)) {
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
            if ($this->safePregMatch($pattern, $content)) {
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
            if ($this->safePregMatch($pattern, $line)) {
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
     * 安全执行 preg_match，捕获并处理 PCRE 编译错误
     *
     * PCRE2（PHP 7.3+）不支持 \F, \L, \l, \N{name}, \U, \u 等转义序列。
     * 如果用户配置的正则模式包含这些不支持的特性，preg_match 会返回 false 并产生警告。
     * 本方法封装了错误处理，防止正则编译失败导致运行时崩溃。
     *
     * @param string $pattern 正则表达式模式
     * @param string $subject 要匹配的字符串
     * @param array|null $matches 匹配结果数组（引用）
     * @return bool true=匹配成功，false=未匹配或正则错误
     */
    protected function safePregMatch(string $pattern, string $subject, ?array &$matches = null): bool
    {
        if (empty($pattern) || empty($subject)) {
            return false;
        }

        // 使用 @ 抑制 PHP 警告，通过 preg_last_error 判断是否出错
        $result = @preg_match($pattern, $subject, $matches);

        if ($result === false) {
            $errorMsg = preg_last_error_msg();
            Log::warning('[Security] 正则表达式编译失败，已跳过该规则', [
                'pattern' => substr($pattern, 0, 100),
                'error' => $errorMsg,
                'request_id' => $this->requestId,
            ]);
            return false;
        }

        return $result === 1;
    }

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
     * 安全执行 preg_replace，捕获并处理 PCRE 编译错误
     *
     * @param string $pattern 正则表达式模式
     * @param string $replacement 替换字符串
     * @param string $subject 要处理的字符串
     * @return string 处理后的字符串，出错时返回原始字符串
     */
    protected function safePregReplace(string $pattern, string $replacement, string $subject): string
    {
        if (empty($pattern) || $subject === '') {
            return $subject;
        }

        $result = @preg_replace($pattern, $replacement, $subject);

        if ($result === null) {
            $errorMsg = preg_last_error_msg();
            Log::warning('[Security] 正则替换失败，保留原内容', [
                'pattern' => substr($pattern, 0, 100),
                'error' => $errorMsg,
                'request_id' => $this->requestId,
            ]);
            return $subject;
        }

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
        $content = $this->safePregReplace('/```[\s\S]*?```/', ' ', $content);
        $content = $this->safePregReplace('/~~~[\s\S]*?~~~/', ' ', $content);
        $content = $this->safePregReplace('/`[^`]+`/', ' ', $content);

        return $content;
    }

    /**
     * 检查文件上传是否包含危险文件
     *
     * 检查维度：
     * 1. 文件扩展名黑名单
     * 2. 文件大小限制
     * 3. MIME magic bytes 深度验证（防止扩展名伪装）
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
        $checkMimeMagic = $upload['check_mime_magic'] ?? false;

        foreach ($files as $file) {
            $fileList = is_array($file) ? $file : [$file];

            foreach ($fileList as $singleFile) {
                // 1. 扩展名检查
                $extension = strtolower($singleFile->getClientOriginalExtension());
                if (in_array($extension, $blockedExtensions, true)) {
                    return true;
                }

                // 2. 文件大小检查
                if ($singleFile->getSize() > $maxSize) {
                    return true;
                }

                // 3. MIME magic bytes 深度验证（防止扩展名伪装）
                if ($checkMimeMagic && $singleFile->isValid()) {
                    if ($this->detectMimeTypeMismatch($singleFile)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 检测文件MIME类型与实际内容不匹配（Magic Bytes检测）
     *
     * 通过读取文件头部魔数字节，验证文件扩展名是否与真实内容一致。
     * 防止攻击者将 .php 文件改名为 .jpg 上传。
     *
     * @param \Illuminate\Http\UploadedFile $file 上传文件
     * @return bool true=类型不匹配（危险），false=类型匹配或无法判断
     */
    protected function detectMimeTypeMismatch(\Illuminate\Http\UploadedFile $file): bool
    {
        $claimExt = strtolower($file->getClientOriginalExtension());

        if (empty($claimExt)) {
            return true; // 无扩展名，视为危险
        }

        // 从配置获取允许的MIME类型映射
        $allowedExtensions = $this->config['upload']['allowed_extensions'] ?? [];
        $mimeMap = $this->config['upload']['mime_magic_map'] ?? $this->getDefaultMimeMagicMap();

        // 如果扩展名不在允许列表中，跳过 magic bytes 检查（扩展名检查会处理）
        if (!in_array($claimExt, $allowedExtensions, true)) {
            return false;
        }

        // 获取预期MIME类型
        $expectedMime = $mimeMap[$claimExt] ?? null;

        if ($expectedMime === null) {
            return false; // 无预期映射，不做判断
        }

        $detectedMime = $file->getMimeType();

        // 如果声明的扩展名对应的MIME不匹配实际MIME，可能被伪装
        $expectedList = is_array($expectedMime) ? $expectedMime : [$expectedMime];

        if (!in_array($detectedMime, $expectedList, true)) {
            $this->lastMatchedPattern = 'mime_mismatch:' . $claimExt;
            $this->lastMatchedContent = sprintf(
                'Extension: %s → Expected: %s → Got: %s',
                $claimExt,
                implode('|', $expectedList),
                $detectedMime ?? 'unknown'
            );
            return true;
        }

        return false;
    }

    /**
     * 获取默认的 MIME magic bytes 映射表
     *
     * @return array<string, string|array<string>>
     */
    protected function getDefaultMimeMagicMap(): array
    {
        return [
            // 图片类
            'jpg' => ['image/jpeg', 'image/jpg'],
            'jpeg' => ['image/jpeg', 'image/jpg'],
            'png' => 'image/png',
            'gif' => 'image/gif',
            'webp' => 'image/webp',
            'bmp' => 'image/bmp',

            // 文档类
            'pdf' => 'application/pdf',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls' => 'application/vnd.ms-excel',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'csv' => ['text/csv', 'text/plain'],
            'txt' => 'text/plain',
            'md' => ['text/markdown', 'text/plain'],

            // 压缩包
            'zip' => ['application/zip', 'application/x-zip-compressed'],
            'rar' => 'application/vnd.rar',
            'gz' => ['application/gzip', 'application/x-gzip'],

            // 音视频
            'mp3' => ['audio/mpeg', 'audio/mp3'],
            'mp4' => 'video/mp4',
        ];
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

        // 构建标准化的拦截响应数据
        $interceptionData = $this->buildInterceptionData(
            $request,
            $detailedMessage,
            $threatType,
            $status,
            $showDetails
        );

        // 安全响应头
        $securityHeaders = $this->getSecurityResponseHeaders();

        // JSON 响应
        if ($request->expectsJson() || $request->is('api/*') || $request->ajax()) {
            return response()->json($interceptionData, $status)
                ->withHeaders($securityHeaders);
        }

        // 检查是否配置了自定义视图
        $viewConfig = $this->config['response']['view'] ?? null;

        if ($viewConfig !== null && $viewConfig !== '') {
            return $this->renderViewResponse($viewConfig, $interceptionData, $status)
                ->withHeaders($securityHeaders);
        }

        // 使用默认的安全拦截视图 security::error
        return response()->view('security::error', $interceptionData, $status)
            ->withHeaders($securityHeaders);
    }

    /**
     * 获取安全响应头
     *
     * 在拦截响应中添加安全相关的HTTP头，增强整体安全性。
     *
     * @return array<string, string>
     */
    protected function getSecurityResponseHeaders(): array
    {
        return [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'no-referrer',
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
        ];
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
     * 构建标准化的拦截响应数据
     *
     * 统一 JSON 和 Blade 响应的数据结构，确保一致性
     *
     * @param Request $request 请求对象
     * @param string $message 拦截消息
     * @param string $threatType 威胁类型
     * @param int $status HTTP状态码
     * @param bool $showDetails 是否显示详细信息
     * @return array 标准化的响应数据
     */
    protected function buildInterceptionData(
        Request $request,
        string $message,
        string $threatType,
        int $status,
        bool $showDetails
    ): array {
        $riskLevel = $this->getRiskLevel($threatType);
        $threats = array_values(array_unique($this->threats));

        // 基础数据结构
        $data = [
            'success' => false,
            'blocked' => true,
            'message' => $message,
            'request_id' => $this->requestId,
            'timestamp' => now()->toIso8601String(),
            'http_status' => $status,
        ];

        // 请求元数据
        $data['request'] = [
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ];

        // 威胁信息（始终包含基础信息）
        $data['threat'] = [
            'type' => $threatType,
            'risk_level' => $riskLevel,
            'category' => $this->getThreatCategory($threatType),
        ];

        // 详细信息（根据配置决定是否包含）
        if ($showDetails) {
            $data['threat']['identifiers'] = $threats;
            $data['threat']['matched_pattern'] = $this->lastMatchedPattern;
            $data['threat']['matched_content'] = $this->lastMatchedContent;
            $data['threat']['description'] = $this->getThreatDescription($threatType);
        }

        // 兼容性字段（用于 Blade 视图）
        $data['threat_type'] = $threatType;
        $data['risk_level'] = $riskLevel;
        $data['threats'] = $threats;
        $data['matched_pattern'] = $this->lastMatchedPattern;
        $data['matched_content'] = $this->lastMatchedContent;

        return $data;
    }

    /**
     * 获取威胁分类
     *
     * @param string $threatType 威胁类型
     * @return string 威胁分类
     */
    protected function getThreatCategory(string $threatType): string
    {
        $categories = [
            'sql' => 'injection',
            'command' => 'injection',
            'path' => 'path_attack',
            'lfi' => 'path_attack',
            'rfi' => 'path_attack',
            'xss' => 'client_side',
            'xss_script' => 'client_side',
            'xss_dom' => 'client_side',
            'xss_tag' => 'client_side',
            'xss_encoding' => 'client_side',
            'xss_framework' => 'client_side',
            'xxe' => 'xml_attack',
            'ldap' => 'injection',
            'xpath' => 'injection',
            'nosql' => 'injection',
            'ssti' => 'template_attack',
            'ssrf' => 'ssrf',
            'encoding' => 'evasion',
            'encoding_bypass' => 'evasion',
            'null_byte' => 'evasion',
            'header_injection' => 'header_attack',
            'high_risk_pattern' => 'pattern_match',
            'blacklist' => 'access_control',
            'bad_user_agent' => 'reconnaissance',
            'invalid_headers' => 'reconnaissance',
            'dangerous_upload' => 'upload',
            'rate_limit' => 'rate_limit',
            'invalid_method' => 'protocol_violation',
            'url_too_long' => 'protocol_violation',
            'body_too_large' => 'protocol_violation',
            'url_path_attack' => 'path_attack',
        ];

        return $categories[$threatType] ?? 'unknown';
    }

    /**
     * 获取威胁描述
     *
     * @param string $threatType 威胁类型
     * @return string 威胁描述
     */
    protected function getThreatDescription(string $threatType): string
    {
        $descriptions = [
            // 高危攻击
            'sql' => '检测到SQL注入攻击，试图通过输入字段操纵数据库查询',
            'command' => '检测到命令注入攻击，试图执行系统命令',
            'path' => '检测到路径遍历攻击，试图访问受限文件系统路径',
            'lfi' => '检测到本地文件包含攻击',
            'rfi' => '检测到远程文件包含攻击',
            'xml' => '检测到XML/XXE外部实体攻击',
            'ldap' => '检测到LDAP注入攻击',
            'nosql' => '检测到NoSQL注入攻击',
            'ssti' => '检测到服务器端模板注入攻击',
            'ssrf' => '检测到服务器端请求伪造(SSRF)攻击',
            'encoding' => '检测到编码绕过攻击',
            'encoding_bypass' => '检测到编码绕过攻击',
            'null_byte' => '检测到空字节注入',
            'header_injection' => '检测到HTTP头注入攻击',
            'high_risk_pattern' => '检测到高风险攻击模式',

            // XSS攻击
            'xss' => '检测到跨站脚本攻击(XSS)，试图注入恶意脚本',
            'xss_script' => '检测到XSS脚本注入攻击',
            'xss_dom' => '检测到DOM型XSS攻击',
            'xss_tag' => '检测到XSS标签注入攻击',
            'xss_encoding' => '检测到XSS编码绕过攻击',
            'xss_framework' => '检测到框架特定XSS攻击',

            // IP/访问控制
            'blacklist' => 'IP地址在黑名单中，已被禁止访问',
            'bad_user_agent' => '检测到恶意用户代理(User-Agent)',
            'invalid_headers' => '检测到可疑的HTTP请求头',
            'dangerous_upload' => '检测到危险文件上传',

            // 请求限制
            'rate_limit' => '请求频率超过限制',
            'invalid_method' => '使用了不允许的HTTP方法',
            'url_too_long' => 'URL长度超过限制',
            'body_too_large' => '请求体大小超过限制',
            'url_path_attack' => 'URL路径包含攻击特征',
        ];

        return $descriptions[$threatType] ?? '检测到未知的安全威胁';
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
                'request_id' => $this->requestId,
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
            timestamp: new DateTimeImmutable(),
            matchedPattern: $this->lastMatchedPattern,
            matchedContent: $this->lastMatchedContent,
            clientIp: $request->ip() ?? '',
            method: $request->method(),
            url: $request->fullUrl(),
            allThreats: array_unique($this->threats),
            requestData: $requestData,
            request_id: $this->requestId,
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
            '/(authorization|bearer)\s+\S+/i' => '$1 ***',
        ];

        foreach ($sensitivePatterns as $pattern => $replacement) {
            $content = $this->safePregReplace($pattern, $replacement, $content);
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
            'threat_type_text' => isset($this->context) ? $this->context->getThreatTypeDescription() : '未知威胁',
            'risk_level' => $this->getRiskLevel($type),
            'request_id' => $this->requestId,
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
