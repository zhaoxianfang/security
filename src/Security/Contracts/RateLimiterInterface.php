<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * 限流服务接口
 *
 * 定义多窗口限流控制的核心功能契约
 * 遵循接口隔离原则（ISP），客户端不应依赖它不需要的接口
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface RateLimiterInterface
{
    /**
     * 检查IP是否超限
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否未超限
     */
    public function checkRateLimit(Request $request): bool;

    /**
     * 获取当前限流状态
     *
     * @param Request $request HTTP请求对象
     * @return array 限流状态
     */
    public function getRateLimitStatus(Request $request): array;

    /**
     * 获取重试等待时间（秒）
     *
     * @return int 等待秒数
     */
    public function getRetryAfter(): int;

    /**
     * 清除指定IP的限流记录
     *
     * @param string $ip IP地址
     * @return void
     */
    public function clearRateLimit(string $ip): void;

    /**
     * 重置限流计数
     *
     * @param Request $request HTTP请求对象
     * @return void
     */
    public function resetRateLimit(Request $request): void;

    /**
     * 获取限流配置
     *
     * @return array 限流配置
     */
    public function getRateLimitConfig(): array;

    /**
     * 检查特定窗口是否超限
     *
     * @param Request $request HTTP请求对象
     * @param string $window 窗口类型（second/minute/hour/day）
     * @return bool 是否未超限
     */
    public function checkWindow(Request $request, string $window): bool;

    /**
     * 增加请求计数
     *
     * @param Request $request HTTP请求对象
     * @return void
     */
    public function increment(Request $request): void;

    /**
     * 获取IP的请求计数
     *
     * @param Request $request HTTP请求对象
     * @param string $window 窗口类型
     * @return int 请求计数
     */
    public function getCount(Request $request, string $window): int;
}
