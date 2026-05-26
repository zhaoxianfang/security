<?php

namespace zxf\Security\Services;

use Illuminate\Http\Request;
use zxf\Security\Contracts\IpCheckerInterface;

/**
 * IP匹配服务
 *
 * 支持多种IP列表格式：
 * 1. 静态IP字符串或CIDR
 * 2. 闭包函数
 * 3. 类名（实现 IpCheckerInterface）
 * 4. 可调用数组 [类名, 方法名]
 *
 * @package zxf\Security\Services
 */
class IpMatcherService
{
    /**
     * 检查IP是否在列表中
     *
     * @param string $ip 要检查的IP
     * @param array $list IP列表（支持多种格式）
     * @param Request $request HTTP请求对象
     * @return bool true=在列表中
     */
    public function matches(string $ip, array $list, Request $request): bool
    {
        foreach ($list as $item) {
            if ($this->matchItem($ip, $item, $request)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 匹配单个条目
     *
     * @param string $ip IP地址
     * @param mixed $item 列表项（字符串、闭包、类等）
     * @param Request $request HTTP请求
     * @return bool
     */
    protected function matchItem(string $ip, mixed $item, Request $request): bool
    {
        // 1. 字符串IP或CIDR
        if (is_string($item)) {
            return $this->ipInRange($ip, $item);
        }

        // 2. 闭包函数
        if ($item instanceof \Closure) {
            return $item($ip, $request) === true;
        }

        // 3. 实现接口的类实例
        if ($item instanceof IpCheckerInterface) {
            return $item->check($ip, $request);
        }

        // 4. 类名字符串（自动实例化）
        if (is_string($item) && class_exists($item)) {
            $instance = function_exists('app') ? app($item) : new $item();
            if ($instance instanceof IpCheckerInterface) {
                return $instance->check($ip, $request);
            }
            // 支持 __invoke 方法
            if (is_callable($instance)) {
                return $instance($ip, $request) === true;
            }
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
