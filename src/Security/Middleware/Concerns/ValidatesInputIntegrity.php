<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;

/**
 * 请求输入完整性验证 — 第七至第十一层安全防护
 *
 * 检查 HTTP 请求的各个维度是否符合安全标准：
 *   - User-Agent 黑名单检测（已知攻击工具识别）
 *   - HTTP 头安全检查（禁止头、CRLF 注入、Host 头验证）
 *   - 请求体大小限制（防止 DoS 大载荷攻击）
 *   - 请求速率限制（基于 IP+路由的漏/令牌桶）
 *   - HTTP 方法白名单（仅允许 GET/POST/PUT/DELETE 等）
 *   - URL 长度限制（防止缓冲区溢出/长 URL 绕过）
 *   - 多重编码攻击检测（null 字节、% 占比、UTF-8 过度编码）
 *
 * 这些检查关注请求本身的形式合法性，不涉及内容模式匹配。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - safePregMatch(): bool     — 安全正则匹配
 *   - $this->config[][]: mixed  — 安全配置数组
 *   - $this->requestId: string  — 唯一请求 ID
 *   - $this->lastMatchedPattern: string — 最后匹配的模式
 *   - $this->lastMatchedContent: string — 最后匹配的内容
 *
 * 跨框架兼容：所有方法接受 object 类型请求对象，内部通过 FrameworkBridge 统一访问。
 * ThinkPHP 8+ 下速率限制使用 Cache 门面模拟（原子 inc() 减少高并发计数丢失）。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 * @version 6.2.0
 */
trait ValidatesInputIntegrity
{
    // ==================== User-Agent 检查 ====================

    /**
     * 检查User-Agent是否在黑名单中
     *
     * @param object $request HTTP请求对象
     * @return bool true=恶意UA，false=正常
     */
    protected function isBadUserAgent(object $request): bool
    {
        $uaList = \zxf\Security\Config\DefaultConfig::getUserAgentBlacklist($this->config);

        if (empty($uaList)) {
            return false;
        }

        $rawUserAgent = FrameworkBridge::requestUserAgent($request) ?? '';
        $userAgent = strtolower($rawUserAgent);

        foreach ($uaList as $item) {
            // 闭包函数
            if ($item instanceof \Closure) {
                try {
                    if ($item($rawUserAgent, $request) === true) {
                        return true;
                    }
                } catch (\Throwable $e) {
                    // 用户自定义闭包异常不应阻断请求流程，记录日志后继续
                    if ($this->config['log_enabled'] ?? true) {
                        FrameworkBridge::logWarning('[Security] UA黑名单闭包执行异常', [
                            'error' => $e->getMessage(),
                            'request_id' => $this->requestId ?? '',
                        ]);
                    }
                }
                continue;
            }

            // 正则表达式
            if (is_string($item) && str_starts_with($item, '/')) {
                if ($this->safePregMatch($item, $rawUserAgent)) {
                    return true;
                }
                continue;
            }

            // 字符串匹配（不区分大小写，支持部分匹配）
            // 防御：空字符串会导致所有 UA 被匹配，必须过滤
            if (is_string($item) && $item !== '' && str_contains($userAgent, strtolower($item))) {
                return true;
            }
        }

        return false;
    }

    // ==================== HTTP 头检查 ====================

    /**
     * 检查HTTP头是否存在安全问题
     *
     * @param object $request HTTP请求对象
     * @return bool true=存在安全问题，false=正常
     */
    protected function hasInvalidHeaders(object $request): bool
    {
        $headersConfig = $this->config['headers'] ?? [];

        // 检查禁止的头
        $forbidden = $headersConfig['forbidden'] ?? [];
        foreach ($forbidden as $header) {
            if (FrameworkBridge::requestHasHeader($request, $header)) {
                return true;
            }
        }

        // CRLF/Header注入检测 - 检查头部值中是否包含换行符
        if ($headersConfig['detect_crlf'] ?? true) {
            $allHeaders = FrameworkBridge::requestHeaders($request);
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
            $host = FrameworkBridge::requestGetHost($request) ?? '';

            // 防御：无法获取 Host 时视为非法（防止 Host 头缺失绕过）
            if ($host === '') {
                return true;
            }

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

    // ==================== 请求大小/频率/方法检查 ====================

    /**
     * 检查请求体是否过大
     *
     * @param object $request HTTP请求对象
     * @return bool true=过大，false=正常
     */
    protected function isBodyTooLarge(object $request): bool
    {
        $bodyConfig = $this->config['max_body_size'] ?? [];
        $limit = $bodyConfig['limit'] ?? 10 * 1024 * 1024;
        $contentLength = (int) FrameworkBridge::requestGetHeader($request, 'Content-Length', 0);

        return $contentLength > $limit;
    }

    /**
     * 检查请求是否超过速率限制
     *
     * ThinkPHP 8+ 下使用 Cache 门面模拟限流桶行为。
     *
     * @param object $request HTTP请求对象
     * @return bool true=超过限制需要拦截，false=未超过限制
     */
    protected function isRateLimited(object $request): bool
    {
        $rateLimit = $this->config['rate_limit'] ?? [];

        // 使用 IP + 路由路径组合作为限流 key，避免不同路由间的碰撞
        $prefix = $rateLimit['key_prefix'] ?? 'security';
        $key = $prefix . ':' . (FrameworkBridge::requestIp($request) ?? 'unknown') . ':' . hash('xxh3', FrameworkBridge::requestPath($request));
        $maxAttempts = $rateLimit['max_attempts'] ?? 60;
        $decayMinutes = $rateLimit['decay_minutes'] ?? 1;

        try {
            if (FrameworkBridge::rateLimitTooManyAttempts($key, $maxAttempts)) {
                return true;
            }

            FrameworkBridge::rateLimitHit($key, $decayMinutes * 60);
        } catch (\Throwable $e) {
            // 限流服务（如 Redis）异常时不应阻断正常请求，记录日志后降级放行
            if ($this->config['log_enabled'] ?? true) {
                FrameworkBridge::logWarning('[Security] 速率限制服务异常，已降级放行', [
                    'error' => $e->getMessage(),
                    'request_id' => $this->requestId ?? '',
                ]);
            }
        }

        return false;
    }

    /**
     * 检查HTTP方法是否合法
     *
     * @param object $request HTTP请求对象
     * @return bool true=方法非法，false=方法合法
     */
    protected function hasInvalidMethod(object $request): bool
    {
        $allowedMethods = \zxf\Security\Config\DefaultConfig::getAllowedHttpMethods($this->config);

        return !in_array(FrameworkBridge::requestMethod($request), $allowedMethods, true);
    }

    /**
     * 检查URL长度是否超过限制
     *
     * @param object $request HTTP请求对象
     * @return bool true=URL过长，false=URL长度正常
     */
    protected function isUrlTooLong(object $request): bool
    {
        $urlConfig = $this->config['max_url_length'] ?? 2048;

        // 数组格式：['limit' => 2048]，标量格式：向后兼容旧版
        $maxLength = is_array($urlConfig) ? ($urlConfig['limit'] ?? 2048) : (int) $urlConfig;

        return strlen(FrameworkBridge::requestFullUrl($request)) > $maxLength;
    }

    // ==================== 编码绕过检测 ====================

    /**
     * 检测多重编码攻击
     * 攻击者常使用多重URL编码绕过WAF
     *
     * 支持通过 encoding_detection.encoding_patterns_exclude 排除特定检测模式
     * （如第三方回调需要 %25 双重编码）
     *
     * @param object $request HTTP请求对象
     * @return bool true=检测到攻击，false=正常
     */
    protected function detectMultiEncodingAttacks(object $request): bool
    {
        $config = $this->config['encoding_detection'] ?? [];
        $rawUrl = FrameworkBridge::requestFullUrl($request);

        // 获取排除的编码绕过检测维度列表（统一由 encoding_patterns_exclude 控制）
        $excludePatterns = $config['encoding_patterns_exclude'] ?? [];

        // 向后兼容：旧版单独布尔开关 detect_null_bytes / detect_utf8_overlong（v5.x → v6 迁移后移除）
        if (!in_array('null_byte', $excludePatterns, true) && isset($config['detect_null_bytes']) && $config['detect_null_bytes'] === false) {
            $excludePatterns[] = 'null_byte';
        }
        if (!in_array('utf8_overlong', $excludePatterns, true) && isset($config['detect_utf8_overlong']) && $config['detect_utf8_overlong'] === false) {
            $excludePatterns[] = 'utf8_overlong';
        }

        // 检测空字节注入
        if (!in_array('null_byte', $excludePatterns, true) &&
            (str_contains($rawUrl, "%00") || str_contains($rawUrl, "\x00"))) {
            $this->lastMatchedPattern = 'null_byte_injection';
            $this->lastMatchedContent = '%00';
            return true;
        }

        // 检测过多的URL编码（可能是编码绕过）
        if (!in_array('percent_threshold', $excludePatterns, true)) {
            $percentCount = substr_count($rawUrl, '%');
            $urlLength = strlen($rawUrl);
            $percentThreshold = $config['percent_threshold'] ?? 0.30;

            // 如果URL中%字符占比超过阈值，可能是编码攻击
            // 注意：percent_threshold 默认为 0.30（即 30%），该值为直接百分比，不含倍数因子
            // 实际经验：正常 URL 中 % 编码占比通常低于 5%，超过 30% 则极大概率为编码攻击
            if ($urlLength > 0 && $percentCount / $urlLength > $percentThreshold) {
                // 进一步检查是否有危险模式的编码
                $decoded = urldecode($rawUrl);
                $doubleDecoded = urldecode($decoded);

                // 解码后检查可疑模式
                $suspicious = \zxf\Security\Config\DefaultConfig::getEncodingSuspiciousPatterns($this->config);
                foreach ($suspicious as $pattern) {
                    if (str_contains($decoded, $pattern) || str_contains($doubleDecoded, $pattern)) {
                        $this->lastMatchedPattern = 'encoding_bypass_attempt';
                        $this->lastMatchedContent = substr($decoded, 0, 100);
                        return true;
                    }
                }
            }
        }

        // 检测无效的UTF-8序列（可能的UTF-8攻击）
        if (!in_array('utf8_overlong', $excludePatterns, true)) {
            $path = FrameworkBridge::requestPath($request);
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
}
