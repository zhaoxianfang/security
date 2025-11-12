<?php

namespace zxf\Security\Exceptions;

use Exception;

/**
 * 安全异常类
 *
 * 用于安全相关的异常处理
 * 提供详细的错误信息和上下文
 */
class SecurityException extends Exception
{
    /**
     * 异常类型
     */
    protected string $type;

    /**
     * 上下文数据
     */
    protected array $context;

    /**
     * 构造函数
     */
    public function __construct(
        string $message = "",
        string $type = 'SecurityError',
        array $context = [],
        int $code = 0,
        Exception $previous = null
    ) {
        $this->type = $type;
        $this->context = $context;

        parent::__construct($message, $code, $previous);
    }

    /**
     * 获取异常类型
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * 获取上下文数据
     */
    public function getContext(): array
    {
        return $this->context;
    }

    /**
     * 创建恶意请求异常
     */
    public static function maliciousRequest(string $details, array $context = []): self
    {
        return new self(
            "恶意请求检测: {$details}",
            'MaliciousRequest',
            $context,
            403
        );
    }

    /**
     * 创建速率限制异常
     */
    public static function rateLimitExceeded(string $window, int $current, int $limit): self
    {
        return new self(
            "速率限制超限: {$window}窗口当前{$current}次，限制{$limit}次",
            'RateLimit',
            [
                'window' => $window,
                'current' => $current,
                'limit' => $limit,
            ],
            429
        );
    }

    /**
     * 创建IP黑名单异常
     */
    public static function ipBlacklisted(string $ip): self
    {
        return new self(
            "IP地址已被列入黑名单: {$ip}",
            'IPBlacklist',
            ['ip' => $ip],
            403
        );
    }

    /**
     * 创建配置异常
     */
    public static function configurationError(string $key, string $details): self
    {
        return new self(
            "安全配置错误 [{$key}]: {$details}",
            'ConfigurationError',
            ['key' => $key, 'details' => $details],
            500
        );
    }

    /**
     * 创建检测异常
     */
    public static function detectionError(string $component, string $details): self
    {
        return new self(
            "安全检测组件异常 [{$component}]: {$details}",
            'DetectionError',
            ['component' => $component, 'details' => $details],
            500
        );
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'context' => $this->context,
            'file' => $this->getFile(),
            'line' => $this->getLine(),
        ];
    }

    /**
     * 转换为JSON字符串
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
}