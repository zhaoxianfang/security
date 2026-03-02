<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;
use DateTimeInterface;

/**
 * IP管理接口
 *
 * 定义IP白名单、黑名单、封禁管理等核心功能的契约
 * 遵循依赖倒置原则（DIP），高层模块不依赖低层模块，都依赖于抽象
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface IpManagerInterface
{
    /**
     * 检查IP是否在白名单
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否在白名单
     */
    public function isWhitelisted(Request $request): bool;

    /**
     * 检查IP是否在黑名单
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否在黑名单
     */
    public function isBlacklisted(Request $request): bool;

    /**
     * 记录IP访问
     *
     * @param Request $request HTTP请求对象
     * @param bool $blocked 是否被拦截
     * @param string|null $rule 触发的规则
     * @return array|null IP记录信息
     */
    public function recordAccess(Request $request, bool $blocked = false, ?string $rule = null): ?array;

    /**
     * 封禁IP
     *
     * @param Request $request HTTP请求对象
     * @param string $type 事件类型
     * @param float $threatScore 威胁评分（0-100）
     * @return bool 是否成功
     */
    public function banIp(Request $request, string $type, float $threatScore = 0): bool;

    /**
     * 解除IP封禁
     *
     * @param string $ip IP地址
     * @return bool 是否成功
     */
    public function unbanIp(string $ip): bool;

    /**
     * 获取客户端真实IP
     *
     * @param Request $request HTTP请求对象
     * @return string IP地址
     */
    public function getClientRealIp(Request $request): string;

    /**
     * 添加IP到白名单
     *
     * @param string $ip IP地址
     * @param string $reason 原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @return bool 是否成功
     */
    public function addToWhitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): bool;

    /**
     * 添加IP到黑名单
     *
     * @param string $ip IP地址
     * @param string $reason 原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return bool 是否成功
     */
    public function addToBlacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): bool;

    /**
     * 获取IP统计信息
     *
     * @param string $ip IP地址
     * @return array 统计信息
     */
    public function getIpStats(string $ip): array;

    /**
     * 获取高威胁IP列表
     *
     * @param int $limit 返回数量限制
     * @return array IP信息数组
     */
    public function getHighThreatIps(int $limit = 100): array;

    /**
     * 获取所有黑名单IP
     *
     * @return array 黑名单IP数组
     */
    public function getAllBlacklistedIps(): array;

    /**
     * 清除IP缓存
     *
     * @param string $ip IP地址
     * @return void
     */
    public function clearIpCache(string $ip): void;

    /**
     * 清除所有缓存
     *
     * @return void
     */
    public function clearCache(): void;

    /**
     * 获取服务统计信息
     *
     * @return array 统计信息
     */
    public function getServiceStats(): array;
}
