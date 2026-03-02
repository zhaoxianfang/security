<?php

namespace zxf\Security\Checkers;

use zxf\Security\Contracts\SecurityCheckerInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use zxf\Security\Services\ConfigManager;

/**
 * 抽象安全检查器
 *
 * 实现安全检查器的通用功能，遵循模板方法模式
 * 
 * 设计原则：
 * - 单一职责原则（SRP）：每个检查器只负责一个特定的安全检查
 * - 开闭原则（OCP）：对扩展开放，对修改关闭
 * - 依赖倒置原则（DIP）：依赖于抽象而非具体实现
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Checkers
 */
abstract class AbstractSecurityChecker implements SecurityCheckerInterface
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 检查器名称
     */
    protected string $name;

    /**
     * 检查器优先级（数值越小优先级越高）
     */
    protected int $priority = 100;

    /**
     * 检查器描述
     */
    protected string $description = '';

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
     * 执行安全检查（模板方法）
     *
     * 定义检查的骨架流程，子类实现具体的检查逻辑
     * 
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    public function check(Request $request): array
    {
        // 1. 检查是否应该跳过
        if ($this->shouldSkip($request)) {
            return $this->skipResult($request);
        }

        // 2. 检查是否启用
        if (!$this->isEnabled()) {
            return $this->disabledResult($request);
        }

        // 3. 执行检查逻辑（由子类实现）
        return $this->doCheck($request);
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
     * 获取检查器名称
     *
     * @return string 检查器名称
     */
    public function getName(): string
    {
        return $this->name ?? static::class;
    }

    /**
     * 获取检查器优先级
     *
     * @return int 优先级
     */
    public function getPriority(): int
    {
        return $this->priority;
    }

    /**
     * 获取检查器描述
     *
     * @return string 检查器描述
     */
    public function getDescription(): string
    {
        return $this->description;
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
     * 设置检查器状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }

    /**
     * 获取检查器配置
     *
     * @return array 配置数组
     */
    public function getConfig(): array
    {
        if (empty($this->configPrefix)) {
            return [];
        }

        return $this->config->get($this->configPrefix, []);
    }

    /**
     * 设置检查器配置
     *
     * @param array $config 配置数组
     * @return void
     */
    public function setConfig(array $config): void
    {
        if (empty($this->configPrefix)) {
            return;
        }

        $this->config->set($this->configPrefix, $config);
    }

    /**
     * 执行检查逻辑（抽象方法，由子类实现）
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    abstract protected function doCheck(Request $request): array;

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
     * 生成成功结果
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    protected function successResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'success',
            'passed' => true,
            'message' => '安全检查通过',
            'details' => [],
        ];
    }

    /**
     * 生成失败结果
     *
     * @param Request $request HTTP请求对象
     * @param string $message 失败消息
     * @param array $details 详细信息
     * @return array 检查结果
     */
    protected function failureResult(Request $request, string $message, array $details = []): array
    {
        $this->logDetection($message, $details);

        return [
            'checker' => $this->getName(),
            'status' => 'failed',
            'passed' => false,
            'message' => $message,
            'details' => $details,
        ];
    }

    /**
     * 生成跳过结果
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    protected function skipResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'skipped',
            'passed' => true,
            'message' => '检查已跳过',
            'details' => [],
        ];
    }

    /**
     * 生成禁用结果
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果
     */
    protected function disabledResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'disabled',
            'passed' => true,
            'message' => '检查器已禁用',
            'details' => [],
        ];
    }

    /**
     * 记录检测日志
     *
     * @param string $message 日志消息
     * @param array $context 上下文信息
     * @return void
     */
    protected function logDetection(string $message, array $context = []): void
    {
        $debugLogging = $this->config->get('enable_debug_logging', false);

        if ($debugLogging) {
            Log::debug('[安全检查器] ' . $message, array_merge([
                'checker' => $this->getName(),
            ], $context));
        }
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
        Log::warning('[安全检查器] ' . $message, array_merge([
            'checker' => $this->getName(),
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
        Log::error('[安全检查器] ' . $message, array_merge([
            'checker' => $this->getName(),
        ], $context));
    }
}
