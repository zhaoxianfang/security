<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Services\IpMatcherService;

/**
 * 访问控制检查
 *
 * 处理路由排除、IP 白名单/黑名单、检测层级开关等门控逻辑。
 * 这些检查是安全防护的第一道防线，发生在攻击检测之前。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
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
     * 支持多种格式：静态IP、CIDR、闭包、类
     *
     * @param string $ip 要检查的IP地址
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=在白名单中，false=不在白名单
     */
    protected function isWhitelisted(string $ip, \Illuminate\Http\Request $request): bool
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
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=在黑名单中，false=不在黑名单
     */
    protected function isBlacklisted(string $ip, \Illuminate\Http\Request $request): bool
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
}
