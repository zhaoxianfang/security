<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * 安全中间件处理器接口
 *
 * 实现责任链模式，每个处理器可以决定是否处理请求或传递给下一个处理器
 * 遵循责任链模式（Chain of Responsibility Pattern）
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface SecurityMiddlewareHandlerInterface
{
    /**
     * 处理请求
     *
     * @param Request $request HTTP请求对象
     * @param callable $next 下一个处理器
     * @return mixed 处理结果
     */
    public function handle(Request $request, callable $next): mixed;

    /**
     * 获取处理器名称
     *
     * @return string 处理器名称
     */
    public function getName(): string;

    /**
     * 获取处理器优先级
     *
     * @return int 优先级（数值越小优先级越高）
     */
    public function getPriority(): int;

    /**
     * 检查是否应该跳过
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否跳过
     */
    public function shouldSkip(Request $request): bool;

    /**
     * 检查是否启用
     *
     * @return bool 是否启用
     */
    public function isEnabled(): bool;

    /**
     * 设置处理器状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setEnabled(bool $enabled): void;

    /**
     * 设置下一个处理器
     *
     * @param SecurityMiddlewareHandlerInterface|null $handler 下一个处理器
     * @return void
     */
    public function setNext(?SecurityMiddlewareHandlerInterface $handler): void;

    /**
     * 获取下一个处理器
     *
     * @return SecurityMiddlewareHandlerInterface|null 下一个处理器
     */
    public function getNext(): ?SecurityMiddlewareHandlerInterface;
}
