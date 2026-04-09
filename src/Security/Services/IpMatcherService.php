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
            $instance = app($item);
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
            $result = app($item[0])->{$item[1]}($ip, $request);
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
     * @param string $ip IPv4地址
     * @param string $range CIDR格式网段
     * @return bool
     */
    protected function cidrMatch(string $ip, string $range): bool
    {
        [$subnet, $bits] = explode('/', $range);
        $bits = (int) $bits;

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
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
}
