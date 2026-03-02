<?php

namespace zxf\Security\Exceptions;

/**
 * 威胁检测异常
 *
 * 当检测到威胁（SQL注入、XSS、命令注入等）时抛出
 */
class ThreatDetectedException extends SecurityException
{
    protected string $threatLevel = 'error';

    /**
     * 威胁类型（sql_injection, xss, command_injection, etc.）
     */
    private string $threatType;

    /**
     * 恶意内容
     */
    private ?string $maliciousContent;

    /**
     * 触发规则
     */
    private ?string $triggeredRule;

    /**
     * 请求路径
     */
    private ?string $requestPath;

    /**
     * 请求方法
     */
    private ?string $requestMethod;

    /**
     * 构造函数
     *
     * @param string $threatType 威胁类型
     * @param string|null $maliciousContent 恶意内容
     * @param string|null $triggeredRule 触发规则
     * @param string|null $requestPath 请求路径
     * @param string|null $requestMethod 请求方法
     * @param array $context 额外上下文
     */
    public function __construct(
        string $threatType,
        ?string $maliciousContent = null,
        ?string $triggeredRule = null,
        ?string $requestPath = null,
        ?string $requestMethod = null,
        array $context = []
    ) {
        $this->threatType = $threatType;
        $this->maliciousContent = $maliciousContent;
        $this->triggeredRule = $triggeredRule;
        $this->requestPath = $requestPath;
        $this->requestMethod = $requestMethod;

        $message = sprintf(
            'Threat detected: %s%s%s',
            $threatType,
            $requestPath ? sprintf(' on %s %s', $requestMethod, $requestPath) : '',
            $triggeredRule ? sprintf(' (Rule: %s)', $triggeredRule) : ''
        );

        parent::__construct($message, array_merge($context, [
            'threat_type' => $threatType,
            'malicious_content' => $maliciousContent,
            'triggered_rule' => $triggeredRule,
            'request_path' => $requestPath,
            'request_method' => $requestMethod,
        ]));
    }

    /**
     * 获取威胁类型
     */
    public function getThreatType(): string
    {
        return $this->threatType;
    }

    /**
     * 获取恶意内容
     */
    public function getMaliciousContent(): ?string
    {
        return $this->maliciousContent;
    }

    /**
     * 获取触发规则
     */
    public function getTriggeredRule(): ?string
    {
        return $this->triggeredRule;
    }

    /**
     * 获取请求路径
     */
    public function getRequestPath(): ?string
    {
        return $this->requestPath;
    }

    /**
     * 获取请求方法
     */
    public function getRequestMethod(): ?string
    {
        return $this->requestMethod;
    }
}
