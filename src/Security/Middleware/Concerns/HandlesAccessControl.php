<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Services\IpMatcherService;
use zxf\Security\Services\ConfigResolver;

/**
 * 访问控制检查
 *
 * 处理路由排除、IP 白名单/黑名单、检测层级开关等门控逻辑。
 * 这些检查是安全防护的第一道防线，发生在攻击检测之前。
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
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=在排除列表中，false=不在
     */
    protected function isExcludedRoute(\Illuminate\Http\Request $request): bool
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

    /**
     * 检查IP是否在白名单中
     *
     * 支持多种格式：静态IP、CIDR、闭包、类名、可调用数组
     *
     * @param string $ip 要检查的IP地址
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=在白名单中，false=不在白名单
     */
    protected function isWhitelisted(string $ip, \Illuminate\Http\Request $request): bool
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
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=在黑名单中，false=不在黑名单
     */
    protected function isBlacklisted(string $ip, \Illuminate\Http\Request $request): bool
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
