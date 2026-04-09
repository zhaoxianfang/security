<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * IP检查器接口
 *
 * 实现此接口可自定义IP黑白名单检查逻辑。
 * 支持动态IP判断，如从数据库、缓存或外部API获取IP列表。
 *
 * @package zxf\Security\Contracts
 */
interface IpCheckerInterface
{
    /**
     * 检查IP是否匹配
     *
     * @param string $ip 要检查的IP地址
     * @param Request $request HTTP请求对象，可获取额外上下文
     * @return bool true=匹配，false=不匹配
     */
    public function check(string $ip, Request $request): bool;
}
