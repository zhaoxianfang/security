<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * 白名单管理接口
 *
 * 定义白名单管理的核心功能契约
 * 遵循单一职责原则（SRP），每个接口只负责一个特定的功能
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface WhitelistManagerInterface
{
    /**
     * 检查路径是否在白名单中
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否在白名单
     */
    public function checkPath(Request $request): bool;

    /**
     * 检查IP是否在白名单中
     *
     * @param string $ip IP地址
     * @return bool 是否在白名单
     */
    public function checkIp(string $ip): bool;

    /**
     * 检查用户代理是否在白名单中
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否在白名单
     */
    public function checkUserAgent(Request $request): bool;

    /**
     * 添加路径到白名单
     *
     * @param string $path 路径
     * @param array $options 额外选项
     * @return bool 是否成功
     */
    public function addPath(string $path, array $options = []): bool;

    /**
     * 移除路径白名单
     *
     * @param string $path 路径
     * @return bool 是否成功
     */
    public function removePath(string $path): bool;

    /**
     * 获取所有白名单路径
     *
     * @return array 白名单路径列表
     */
    public function getAllPaths(): array;

    /**
     * 清除白名单缓存
     *
     * @return void
     */
    public function clearCache(): void;
}
