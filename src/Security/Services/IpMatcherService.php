<?php

namespace zxf\Security\Services;

use zxf\Security\Contracts\IpCheckerInterface;

/**
 * IP 匹配服务 — 统一的白/黑名单 IP 判断引擎
 *
 * ══════════════════════════════════════════════════════════════════════
 * 支持的 IP 列表格式（按匹配优先级）：
 *   1. 类名字符串 — 自动实例化，支持 IpCheckerInterface 和 __invoke
 *   2. 静态 IP 字符串 — 精确匹配
 *   3. CIDR 网段 — 支持 IPv4（如 10.0.0.0/24）和 IPv6（如 ::1/128）
 *   4. Closure 闭包 — function(string $ip, object $request): bool
 *   5. IpCheckerInterface 实例 — 调用 check() 方法
 *   6. 可调用数组 — [class, method] 格式
 *
 * ══════════════════════════════════════════════════════════════════════
 * CIDR 匹配细节：
 *   - IPv4：使用 ip2long() 转换为长整型后按位与比较
 *     • 防御 64 位 PHP 符号扩展问题：通过 & 0xFFFFFFFF 强制无符号化
 *     • 支持 /0 到 /32 的完整前缀范围
 *   - IPv6：使用 inet_pton() 转换为二进制字符串后逐字节比较
 *     • 支持 /0 到 /128 的完整前缀范围
 *     • 非对齐前缀：剩余位通过掩码 & 0xFF << (8 - bits) 精确匹配
 *
 * ══════════════════════════════════════════════════════════════════════
 * 防御性设计：
 *   - 所有匹配路径均有 try/catch 保护，单个异常项不影响其他规则
 *   - ip2long() / inet_pton() 失败时返回 false 而非抛异常
 *
 * 跨框架兼容：$request 参数声明为 object，支持 Laravel 和 ThinkPHP 请求对象。
 *
 * @package zxf\Security\Services
 * @since 6.1.0
 */
class IpMatcherService
{
    /**
     * 检查IP是否在列表中
     *
     * @param string $ip 要检查的IP
     * @param array $list IP列表（支持多种格式）
     * @param object $request HTTP请求对象
     * @return bool true=在列表中
     */
    public function matches(string $ip, array $list, object $request): bool
    {
        foreach ($list as $item) {
            try {
                if ($this->matchItem($ip, $item, $request)) {
                    return true;
                }
            } catch (\Throwable) {
                // IP 检查器（闭包、类方法等）异常时不应阻断正常请求，记录后继续
                // 静默跳过异常项，避免单个错误配置导致整个访问控制失效
                continue;
            }
        }

        return false;
    }

    /**
     * 匹配单个条目
     *
     * @param string $ip IP地址
     * @param mixed $item 列表项（字符串、闭包、类等）
     * @param object $request HTTP请求
     * @return bool
     */
    protected function matchItem(string $ip, mixed $item, object $request): bool
    {
        // 1. 类名字符串（自动实例化）— 必须在普通字符串之前检查，
        //    否则所有字符串都会被 ipInRange 拦截，导致类名配置永不可达
        if (is_string($item) && class_exists($item)) {
            $instance = function_exists('app') ? app($item) : new $item();
            if ($instance instanceof IpCheckerInterface) {
                return $instance->check($ip, $request);
            }
            // 支持 __invoke 方法
            if (is_callable($instance)) {
                return $instance($ip, $request) === true;
            }
            return false;
        }

        // 2. 字符串IP或CIDR
        if (is_string($item)) {
            return $this->ipInRange($ip, $item);
        }

        // 3. 闭包函数
        if ($item instanceof \Closure) {
            return $item($ip, $request) === true;
        }

        // 4. 实现接口的类实例
        if ($item instanceof IpCheckerInterface) {
            return $item->check($ip, $request);
        }

        // 5. 可调用数组 [类名, 方法名]
        if (is_array($item) && count($item) === 2) {
            $instance = function_exists('app') ? app($item[0]) : new $item[0]();
            $result = $instance->{$item[1]}($ip, $request);
            return $result === true;
        }

        return false;
    }

    /**
     * 检查IP是否在指定范围内
     *
     * @param string $ip 要检查的IP
     * @param string $range IP范围（单IP或CIDR）
     * @return bool
     */
    protected function ipInRange(string $ip, string $range): bool
    {
        // 精确匹配
        if ($ip === $range) {
            return true;
        }

        // CIDR匹配
        if (str_contains($range, '/')) {
            return $this->cidrMatch($ip, $range);
        }

        return false;
    }

    /**
     * CIDR网段匹配
     *
     * 支持 IPv4 和 IPv6 的 CIDR 网段匹配。
     *
     * @param string $ip IP地址（IPv4 或 IPv6）
     * @param string $range CIDR格式网段
     * @return bool
     */
    protected function cidrMatch(string $ip, string $range): bool
    {
        [$subnet, $bits] = explode('/', $range);
        $bits = (int) $bits;

        // IPv6 CIDR 匹配
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->cidrMatchIPv6($ip, $subnet, $bits);
        }

        // IPv4 CIDR 匹配
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->cidrMatchIPv4($ip, $subnet, $bits);
        }

        return false;
    }

    /**
     * IPv4 CIDR 网段匹配
     *
     * @param string $ip IPv4 地址
     * @param string $subnet 子网地址
     * @param int $bits 前缀长度
     * @return bool
     */
    protected function cidrMatchIPv4(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        // 防御 64 位 PHP 的 ip2long() 符号扩展问题：
        // ip2long() 返回有符号 32 位整数，在 64 位系统上会被符号扩展。
        // 当 IP > 127.255.255.255 时结果为负，与掩码的按位与可能出错。
        // 通过 & 0xFFFFFFFF 强制截断为无符号 32 位值，确保 CIDR 匹配正确。
        $ipLong = $ipLong & 0xFFFFFFFF;
        $subnetLong = $subnetLong & 0xFFFFFFFF;

        $mask = -1 << (32 - $bits);
        $subnetLong &= $mask;

        return ($ipLong & $mask) === $subnetLong;
    }

    /**
     * IPv6 CIDR 网段匹配
     *
     * 使用 PHP 的 inet_pton 将 IPv6 地址转换为二进制字符串进行按位比较。
     *
     * @param string $ip IPv6 地址
     * @param string $subnet 子网地址
     * @param int $bits 前缀长度
     * @return bool
     */
    protected function cidrMatchIPv6(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // IPv6 地址为 128 位（16 字节）
        if (strlen($ipBin) !== 16 || strlen($subnetBin) !== 16) {
            return false;
        }

        // 按字节比较
        $fullBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        // 先比较完整字节
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBin[$i] !== $subnetBin[$i]) {
                return false;
            }
        }

        // 如果有剩余位，比较不完整字节
        if ($remainingBits > 0 && $fullBytes < 16) {
            $mask = 0xFF << (8 - $remainingBits);
            if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($subnetBin[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }
}
