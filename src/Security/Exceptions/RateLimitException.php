<?php

namespace zxf\Security\Exceptions;

/**
 * 速率限制异常
 *
 * 当请求频率超过限制时抛出
 */
class RateLimitException extends SecurityException
{
    protected string $threatLevel = 'info';

    /**
     * 限制的指纹标识
     */
    private string $fingerprint;

    /**
     * 限制的时间窗口
     */
    private string $window;

    /**
     * 重试时间（秒）
     */
    private int $retryAfter;

    /**
     * 当前请求计数
     */
    private int $currentCount;

    /**
     * 限制阈值
     */
    private int $limit;

    /**
     * 构造函数
     *
     * @param string $fingerprint 指纹标识
     * @param string $window 时间窗口
     * @param int $retryAfter 重试时间（秒）
     * @param int $currentCount 当前计数
     * @param int $limit 限制阈值
     * @param array $context 额外上下文
     */
    public function __construct(
        string $fingerprint,
        string $window,
        int $retryAfter,
        int $currentCount,
        int $limit,
        array $context = []
    ) {
        $message = sprintf(
            'Rate limit exceeded for %s in %s window. Current: %d, Limit: %d. Retry after %d seconds.',
            $fingerprint,
            $window,
            $currentCount,
            $limit,
            $retryAfter
        );

        $this->fingerprint = $fingerprint;
        $this->window = $window;
        $this->retryAfter = $retryAfter;
        $this->currentCount = $currentCount;
        $this->limit = $limit;

        parent::__construct($message, array_merge($context, [
            'fingerprint' => $fingerprint,
            'window' => $window,
            'retry_after' => $retryAfter,
            'current_count' => $currentCount,
            'limit' => $limit,
        ]));
    }

    /**
     * 获取指纹标识
     */
    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    /**
     * 获取时间窗口
     */
    public function getWindow(): string
    {
        return $this->window;
    }

    /**
     * 获取重试时间（秒）
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }

    /**
     * 获取当前计数
     */
    public function getCurrentCount(): int
    {
        return $this->currentCount;
    }

    /**
     * 获取限制阈值
     */
    public function getLimit(): int
    {
        return $this->limit;
    }
}
