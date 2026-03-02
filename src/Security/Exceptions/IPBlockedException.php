<?php

namespace zxf\Security\Exceptions;

/**
 * IP被阻止异常
 *
 * 当IP在黑名单中时抛出
 */
class IPBlockedException extends SecurityException
{
    protected string $threatLevel = 'warning';

    /**
     * 被阻止的IP地址
     */
    private string $ipAddress;

    /**
     * 阻止原因
     */
    private string $reason;

    /**
     * 过期时间
     */
    private ?string $expiresAt;

    /**
     * IP类型（whitelist/blacklist/suspicious/monitoring）
     */
    private string $ipType;

    /**
     * 威胁评分
     */
    private ?float $threatScore;

    /**
     * 构造函数
     *
     * @param string $ipAddress IP地址
     * @param string $reason 阻止原因
     * @param string|null $expiresAt 过期时间
     * @param string $ipType IP类型
     * @param float|null $threatScore 威胁评分
     * @param array $context 额外上下文
     */
    public function __construct(
        string $ipAddress,
        string $reason = 'IP blocked',
        ?string $expiresAt = null,
        string $ipType = 'blacklist',
        ?float $threatScore = null,
        array $context = []
    ) {
        $this->ipAddress = $ipAddress;
        $this->reason = $reason;
        $this->expiresAt = $expiresAt;
        $this->ipType = $ipType;
        $this->threatScore = $threatScore;

        $message = sprintf(
            'IP %s is blocked. Reason: %s, Type: %s%s',
            $ipAddress,
            $reason,
            $ipType,
            $threatScore ? sprintf(', Threat Score: %.2f', $threatScore) : ''
        );

        parent::__construct($message, array_merge($context, [
            'ip_address' => $ipAddress,
            'reason' => $reason,
            'expires_at' => $expiresAt,
            'ip_type' => $ipType,
            'threat_score' => $threatScore,
        ]));
    }

    /**
     * 获取IP地址
     */
    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    /**
     * 获取阻止原因
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * 获取过期时间
     */
    public function getExpiresAt(): ?string
    {
        return $this->expiresAt;
    }

    /**
     * 获取IP类型
     */
    public function getIpType(): string
    {
        return $this->ipType;
    }

    /**
     * 获取威胁评分
     */
    public function getThreatScore(): ?float
    {
        return $this->threatScore;
    }
}
