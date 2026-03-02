<?php

namespace zxf\Security\Exceptions;

/**
 * 安全配置异常
 *
 * 当安全配置无效或缺失时抛出
 */
class SecurityConfigException extends SecurityException
{
    protected string $threatLevel = 'error';
    protected bool $shouldLogSecurity = false;

    /**
     * 配置键名
     */
    private ?string $configKey;

    /**
     * 期望的配置值类型
     */
    private ?string $expectedType;

    /**
     * 实际的配置值
     */
    private $actualValue;

    /**
     * 构造函数
     *
     * @param string $message 异常消息
     * @param string|null $configKey 配置键名
     * @param string|null $expectedType 期望的类型
     * @param mixed $actualValue 实际值
     * @param array $context 额外上下文
     */
    public function __construct(
        string $message,
        ?string $configKey = null,
        ?string $expectedType = null,
        $actualValue = null,
        array $context = []
    ) {
        $this->configKey = $configKey;
        $this->expectedType = $expectedType;
        $this->actualValue = $actualValue;

        parent::__construct($message, array_merge($context, [
            'config_key' => $configKey,
            'expected_type' => $expectedType,
            'actual_value' => $actualValue,
        ]));
    }

    /**
     * 获取配置键名
     */
    public function getConfigKey(): ?string
    {
        return $this->configKey;
    }

    /**
     * 获取期望类型
     */
    public function getExpectedType(): ?string
    {
        return $this->expectedType;
    }

    /**
     * 获取实际值
     */
    public function getActualValue()
    {
        return $this->actualValue;
    }
}
