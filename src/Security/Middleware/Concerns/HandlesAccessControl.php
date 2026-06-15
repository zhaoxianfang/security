<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;
use zxf\Security\Services\IpMatcherService;
use zxf\Security\Services\ConfigResolver;

/**
 * 访问控制检查 — 第一至第三层安全防护
 *
 * 处理路由排除、IP 白名单/黑名单、检测层级开关等门控逻辑。
 * 这些检查是安全防护的第一道防线，发生在攻击检测之前。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - isCliMode(): bool             — 判断当前是否 CLI 模式
 *   - safePregMatch(): bool         — 安全正则匹配
 *   - $this->config[][]: mixed      — 安全配置数组
 *   - $this->ipMatcher: IpMatcherService — IP 匹配服务实例
 *   - $this->requestId: string      — 唯一请求 ID
 *
 * 跨框架兼容：所有方法接受 object 类型请求对象，内部通过 FrameworkBridge 统一访问。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.0.0
 */
trait HandlesAccessControl
{
    /**
     * IP匹配服务
     *
     * @var IpMatcherService
     */
    protected readonly IpMatcherService $ipMatcher;

    /**
     * 检查请求是否在排除路由列表中
     *
     * @param object $request HTTP请求对象
     * @return bool true=在排除列表中，false=不在
     */
    protected function isExcludedRoute(object $request): bool
    {
        $excluded = $this->config['excluded_routes'] ?? [];

        foreach ($excluded as $pattern) {
            // 闭包函数
            if ($pattern instanceof \Closure) {
                try {
                    if ($pattern($request) === true) {
                        return true;
                    }
                } catch (\Throwable $e) {
                    // 用户自定义闭包异常不应阻断请求流程，记录日志后继续
                    if ($this->config['log_enabled'] ?? true) {
                        FrameworkBridge::logWarning('[Security] 排除路由闭包执行异常', [
                            'error' => $e->getMessage(),
                            'request_id' => $this->requestId ?? '',
                        ]);
                    }
                }
                continue;
            }

            // 正则表达式
            if (is_string($pattern) && str_starts_with($pattern, '/')) {
                if ($this->safePregMatch($pattern, FrameworkBridge::requestPath($request))) {
                    return true;
                }
                continue;
            }

            // 字符串模式（支持通配符 *）
            // 防御：空字符串会导致所有路由被排除，必须过滤
            if (is_string($pattern) && $pattern !== '') {
                if (FrameworkBridge::requestIs($request, $pattern)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查IP是否在白名单中
     *
     * 支持多种格式：静态IP、CIDR、闭包、类名、可调用数组
     *
     * @param string $ip 要检查的IP地址
     * @param object $request HTTP请求对象
     * @return bool true=在白名单中，false=不在白名单
     */
    protected function isWhitelisted(string $ip, object $request): bool
    {
        // 解析 whitelist 和 trusted_ips（支持callable配置）
        $whitelist = ConfigResolver::resolve($this->config['whitelist'] ?? []);
        $trusted = ConfigResolver::resolve($this->config['trusted_ips'] ?? []);

        $merged = array_merge($whitelist, $trusted);

        if (empty($merged)) {
            return false;
        }

        return $this->ipMatcher->matches($ip, $merged, $request);
    }

    /**
     * 检查IP是否在黑名单中
     *
     * 支持多种格式：静态IP、CIDR、闭包、类名、可调用数组
     *
     * @param string $ip 要检查的IP地址
     * @param object $request HTTP请求对象
     * @return bool true=在黑名单中，false=不在黑名单
     */
    protected function isBlacklisted(string $ip, object $request): bool
    {
        $blacklist = ConfigResolver::resolve($this->config['blacklist'] ?? []);

        if (empty($blacklist)) {
            return false;
        }

        return $this->ipMatcher->matches($ip, $blacklist, $request);
    }

    /**
     * 检查指定检测层是否启用
     *
     * CLI 模式下自动禁用 HTTP 专属检测层，避免 artisan 命令、
     * 队列任务、计划任务中触发无意义的 HTTP 上下文检查，
     * 同时防止因缺失 HTTP 头/UA/IP 等数据导致的异常或误报。
     *
     * @param string $layer 检测层名称
     * @return bool true=启用，false=禁用
     */
    protected function isDetectionEnabled(string $layer): bool
    {
        $layers = $this->config['detection_layers'] ?? [];

        // CLI 模式下仅保留核心内容安全检测，跳过所有 HTTP 专属层
        if (method_exists($this, 'isCliMode') && $this->isCliMode()) {
            $httpOnlyLayers = ['user_agent', 'headers', 'body_size', 'rate_limit', 'http_method', 'url_length', 'upload'];
            if (in_array($layer, $httpOnlyLayers, true)) {
                return false;
            }
        }

        return $layers[$layer] ?? true;
    }
}
