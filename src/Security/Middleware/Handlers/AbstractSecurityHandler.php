<?php

namespace zxf\Security\Middleware\Handlers;

use zxf\Security\Contracts\SecurityMiddlewareHandlerInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use zxf\Security\Services\ConfigManager;

/**
 * 抽象安全中间件处理器
 *
 * 实现责任链模式，每个处理器可以决定是否处理请求或传递给下一个处理器
 * 遵循责任链模式（Chain of Responsibility Pattern）和开闭原则（OCP）
 * 
 * 设计原则：
 * - 单一职责原则（SRP）：每个处理器只负责一个特定的安全检查
 * - 开闭原则（OCP）：对扩展开放，对修改关闭
 * - 依赖倒置原则（DIP）：依赖于抽象而非具体实现
 * - 责任链模式：将处理请求的多个处理器串联起来
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Middleware\Handlers
 */
abstract class AbstractSecurityHandler implements SecurityMiddlewareHandlerInterface
{
    /**
     * 下一个处理器
     */
    protected ?SecurityMiddlewareHandlerInterface $next = null;

    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 处理器名称
     */
    protected string $name;

    /**
     * 处理器优先级（数值越小优先级越高）
     */
    protected int $priority = 100;

    /**
     * 是否启用
     */
    protected bool $enabled = true;

    /**
     * 配置键前缀
     */
    protected string $configPrefix = '';

    /**
     * 构造函数
     *
     * @param ConfigManager $config 配置管理实例
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
        $this->enabled = $this->getConfigValue('enabled', true);
    }

    /**
     * 处理请求（模板方法）
     *
     * 定义处理的骨架流程，子类实现具体的处理逻辑
     * 
     * @param Request $request HTTP请求对象
     * @param callable $next 下一个处理器
     * @return mixed 处理结果
     */
    public function handle(Request $request, callable $next): mixed
    {
        // 1. 检查是否应该跳过
        if ($this->shouldSkip($request)) {
            $this->logDebug('处理器已跳过');
            return $next($request);
        }

        // 2. 检查是否启用
        if (!$this->isEnabled()) {
            $this->logDebug('处理器已禁用');
            return $next($request);
        }

        // 3. 执行前置处理
        $beforeResult = $this->before($request);
        if ($beforeResult !== null) {
            return $beforeResult;
        }

        // 4. 执行核心处理逻辑（由子类实现）
        $result = $this->doHandle($request, $next);

        // 5. 执行后置处理
        $this->after($request, $result);

        return $result;
    }

    /**
     * 获取处理器名称
     *
     * @return string 处理器名称
     */
    public function getName(): string
    {
        return $this->name ?? static::class;
    }

    /**
     * 获取处理器优先级
     *
     * @return int 优先级
     */
    public function getPriority(): int
    {
        return $this->priority;
    }

    /**
     * 检查是否应该跳过
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否跳过
     */
    public function shouldSkip(Request $request): bool
    {
        return false;
    }

    /**
     * 检查是否启用
     *
     * @return bool 是否启用
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * 设置处理器状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }

    /**
     * 设置下一个处理器
     *
     * @param SecurityMiddlewareHandlerInterface|null $handler 下一个处理器
     * @return void
     */
    public function setNext(?SecurityMiddlewareHandlerInterface $handler): void
    {
        $this->next = $handler;
    }

    /**
     * 获取下一个处理器
     *
     * @return SecurityMiddlewareHandlerInterface|null 下一个处理器
     */
    public function getNext(): ?SecurityMiddlewareHandlerInterface
    {
        return $this->next;
    }

    /**
     * 执行核心处理逻辑（抽象方法，由子类实现）
     *
     * @param Request $request HTTP请求对象
     * @param callable $next 下一个处理器
     * @return mixed 处理结果
     */
    abstract protected function doHandle(Request $request, callable $next): mixed;

    /**
     * 前置处理（可在子类中重写）
     *
     * @param Request $request HTTP请求对象
     * @return mixed|null 如果返回非null，将中断后续处理
     */
    protected function before(Request $request): mixed
    {
        return null;
    }

    /**
     * 后置处理（可在子类中重写）
     *
     * @param Request $request HTTP请求对象
     * @param mixed $result 处理结果
     * @return void
     */
    protected function after(Request $request, mixed $result): void
    {
        // 默认不进行后置处理
    }

    /**
     * 获取配置值
     *
     * @param string $key 配置键
     * @param mixed $default 默认值
     * @return mixed 配置值
     */
    protected function getConfigValue(string $key, mixed $default = null): mixed
    {
        if (empty($this->configPrefix)) {
            return $default;
        }

        $fullKey = $this->configPrefix . '.' . $key;
        return $this->config->get($fullKey, $default);
    }

    /**
     * 记录调试日志
     *
     * @param string $message 日志消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logDebug(string $message, array $context = []): void
    {
        $debugLogging = $this->config->get('enable_debug_logging', false);

        if ($debugLogging) {
            Log::debug('[安全中间件] ' . $message, array_merge([
                'handler' => $this->getName(),
            ], $context));
        }
    }

    /**
     * 记录信息日志
     *
     * @param string $message 日志消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logInfo(string $message, array $context = []): void
    {
        Log::info('[安全中间件] ' . $message, array_merge([
            'handler' => $this->getName(),
        ], $context));
    }

    /**
     * 记录警告日志
     *
     * @param string $message 警告消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logWarning(string $message, array $context = []): void
    {
        Log::warning('[安全中间件] ' . $message, array_merge([
            'handler' => $this->getName(),
        ], $context));
    }

    /**
     * 记录错误日志
     *
     * @param string $message 错误消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logError(string $message, array $context = []): void
    {
        Log::error('[安全中间件] ' . $message, array_merge([
            'handler' => $this->getName(),
        ], $context));
    }

    /**
     * 创建拦截响应
     *
     * @param Request $request HTTP请求对象
     * @param string $message 拦截消息
     * @param int $statusCode HTTP状态码
     * @param array $details 详细信息
     * @return \Illuminate\Http\JsonResponse 拦截响应
     */
    protected function createBlockResponse(
        Request $request,
        string $message,
        int $statusCode = 403,
        array $details = []
    ): \Illuminate\Http\JsonResponse {
        $this->logWarning($message, $details);

        return response()->json([
            'success' => false,
            'error' => $message,
            'handler' => $this->getName(),
            'details' => $details,
            'timestamp' => now()->toIso8601String(),
        ], $statusCode);
    }

    /**
     * 创建限流响应
     *
     * @param Request $request HTTP请求对象
     * @param int $retryAfter 重试等待时间（秒）
     * @return \Illuminate\Http\JsonResponse 限流响应
     */
    protected function createRateLimitResponse(Request $request, int $retryAfter): \Illuminate\Http\JsonResponse
    {
        $this->logWarning('请求频率超限', [
            'retry_after' => $retryAfter,
        ]);

        return response()->json([
            'success' => false,
            'error' => '请求过于频繁，请稍后再试',
            'handler' => $this->getName(),
            'retry_after' => $retryAfter,
            'timestamp' => now()->toIso8601String(),
        ], 429);
    }

    /**
     * 检查是否为开发环境
     *
     * @return bool 是否为开发环境
     */
    protected function isDevelopment(): bool
    {
        return app()->environment('local', 'testing');
    }

    /**
     * 检查是否为生产环境
     *
     * @return bool 是否为生产环境
     */
    protected function isProduction(): bool
    {
        return app()->environment('production');
    }
}
