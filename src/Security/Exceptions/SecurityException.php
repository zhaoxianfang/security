<?php

namespace zxf\Security\Exceptions;

use Exception;
use Throwable;

/**
 * 安全异常基类
 *
 * 所有安全相关异常的基类
 * 提供统一的异常处理接口和日志记录
 */
class SecurityException extends Exception
{
    /**
     * 异常上下文信息
     */
    protected array $context = [];

    /**
     * 是否记录到安全日志
     */
    protected bool $shouldLogSecurity = true;

    /**
     * 威胁等级（影响日志级别）
     */
    protected string $threatLevel = 'warning';

    /**
     * 构造函数
     *
     * @param string $message 异常消息
     * @param array $context 上下文信息
     * @param int $code 错误码
     * @param Throwable|null $previous 前一个异常
     */
    public function __construct(
        string $message = '',
        array $context = [],
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /**
     * 获取上下文信息
     */
    public function getContext(): array
    {
        return $this->context;
    }

    /**
     * 是否记录到安全日志
     */
    public function shouldLogSecurity(): bool
    {
        return $this->shouldLogSecurity;
    }

    /**
     * 获取威胁等级
     */
    public function getThreatLevel(): string
    {
        return $this->threatLevel;
    }

    /**
     * 设置威胁等级
     */
    protected function setThreatLevel(string $level): void
    {
        $this->threatLevel = $level;
    }

    /**
     * 转换为数组（用于日志记录）
     */
    public function toArray(): array
    {
        return [
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'file' => $this->getFile(),
            'line' => $this->getLine(),
            'context' => $this->context,
            'threat_level' => $this->threatLevel,
        ];
    }

    /**
     * 转换为JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_UNICODE);
    }
}
