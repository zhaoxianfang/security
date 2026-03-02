<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * 安全检查器接口
 *
 * 定义安全检查的抽象契约
 * 遵循接口隔离原则（ISP），每个检查器只负责特定的安全检查
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface SecurityCheckerInterface
{
    /**
     * 执行安全检查
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    public function check(Request $request): array;

    /**
     * 检查是否应该跳过
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否跳过
     */
    public function shouldSkip(Request $request): bool;

    /**
     * 获取检查器名称
     *
     * @return string 检查器名称
     */
    public function getName(): string;

    /**
     * 获取检查器优先级
     *
     * @return int 优先级（数值越小优先级越高）
     */
    public function getPriority(): int;

    /**
     * 获取检查器描述
     *
     * @return string 检查器描述
     */
    public function getDescription(): string;

    /**
     * 检查是否启用
     *
     * @return bool 是否启用
     */
    public function isEnabled(): bool;

    /**
     * 设置检查器状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setEnabled(bool $enabled): void;

    /**
     * 获取检查器配置
     *
     * @return array 配置数组
     */
    public function getConfig(): array;

    /**
     * 设置检查器配置
     *
     * @param array $config 配置数组
     * @return void
     */
    public function setConfig(array $config): void;
}
