<?php

namespace zxf\Security\Exceptions;

use Exception;
use Throwable;

/**
 * 安全异常类 - 优化增强版
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
     * 异常级别
     */
    protected string $level;

    /**
     * 异常严重程度级别常量
     */
    public const LEVEL_LOW = 'low';
    public const LEVEL_MEDIUM = 'medium';
    public const LEVEL_HIGH = 'high';
    public const LEVEL_CRITICAL = 'critical';

    /**
     * 异常类型常量
     */
    public const TYPE_MALICIOUS_REQUEST = 'MaliciousRequest';
    public const TYPE_RATE_LIMIT = 'RateLimit';
    public const TYPE_IP_BLACKLIST = 'IPBlacklist';
    public const TYPE_CONFIGURATION_ERROR = 'ConfigurationError';
    public const TYPE_DETECTION_ERROR = 'DetectionError';
    public const TYPE_VALIDATION_ERROR = 'ValidationError';
    public const TYPE_SYSTEM_ERROR = 'SystemError';
    public const TYPE_SECURITY_ERROR = 'SecurityError';

    /**
     * 构造函数
     */
    public function __construct(
        string $message = "",
        string $type = 'SecurityError',
        array $context = [],
        int $code = 0,
        ?Throwable $previous = null,
        string $level = self::LEVEL_MEDIUM
    ) {
        $this->type = $type;
        $this->context = $context;
        $this->level = $level;

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
     * 获取异常级别
     */
    public function getLevel(): string
    {
        return $this->level;
    }

    /**
     * 设置异常级别
     */
    public function setLevel(string $level): self
    {
        $this->level = $level;
        return $this;
    }

    /**
     * 创建恶意请求异常
     */
    public static function maliciousRequest(string $details, array $context = [], string $level = self::LEVEL_HIGH): self
    {
        return new self(
            "恶意请求检测: {$details}",
            self::TYPE_MALICIOUS_REQUEST,
            array_merge($context, ['detection_type' => 'malicious_request']),
            403,
            null,
            $level
        );
    }

    /**
     * 创建SQL注入异常
     */
    public static function sqlInjection(string $details, array $context = [], string $level = self::LEVEL_HIGH): self
    {
        return new self(
            "SQL注入攻击检测: {$details}",
            self::TYPE_MALICIOUS_REQUEST,
            array_merge($context, [
                'detection_type' => 'sql_injection',
                'attack_type' => 'sql_injection',
            ]),
            403,
            null,
            $level
        );
    }

    /**
     * 创建XSS攻击异常
     */
    public static function xssAttack(string $details, array $context = [], string $level = self::LEVEL_HIGH): self
    {
        return new self(
            "XSS跨站脚本攻击检测: {$details}",
            self::TYPE_MALICIOUS_REQUEST,
            array_merge($context, [
                'detection_type' => 'xss_attack',
                'attack_type' => 'xss',
            ]),
            403,
            null,
            $level
        );
    }

    /**
     * 创建命令注入异常
     */
    public static function commandInjection(string $details, array $context = [], string $level = self::LEVEL_HIGH): self
    {
        return new self(
            "命令注入攻击检测: {$details}",
            self::TYPE_MALICIOUS_REQUEST,
            array_merge($context, [
                'detection_type' => 'command_injection',
                'attack_type' => 'command_injection',
            ]),
            403,
            null,
            $level
        );
    }

    /**
     * 创建速率限制异常
     */
    public static function rateLimitExceeded(string $window, int $current, int $limit, array $context = []): self
    {
        return new self(
            "速率限制超限: {$window}窗口当前{$current}次，限制{$limit}次",
            self::TYPE_RATE_LIMIT,
            array_merge($context, [
                'window' => $window,
                'current' => $current,
                'limit' => $limit,
                'detection_type' => 'rate_limit',
            ]),
            429,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 创建IP黑名单异常
     */
    public static function ipBlacklisted(string $ip, array $context = []): self
    {
        return new self(
            "IP地址已被列入黑名单: {$ip}",
            self::TYPE_IP_BLACKLIST,
            array_merge($context, ['ip' => $ip]),
            403,
            null,
            self::LEVEL_HIGH
        );
    }

    /**
     * 创建配置异常
     */
    public static function configurationError(string $key, string $details, array $context = []): self
    {
        return new self(
            "安全配置错误 [{$key}]: {$details}",
            self::TYPE_CONFIGURATION_ERROR,
            array_merge($context, ['config_key' => $key, 'details' => $details]),
            500,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 创建检测异常
     */
    public static function detectionError(string $component, string $details, array $context = []): self
    {
        return new self(
            "安全检测组件异常 [{$component}]: {$details}",
            self::TYPE_DETECTION_ERROR,
            array_merge($context, ['component' => $component, 'details' => $details]),
            500,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 创建验证异常
     */
    public static function validationError(string $field, string $details, array $context = []): self
    {
        return new self(
            "安全验证失败 [{$field}]: {$details}",
            self::TYPE_VALIDATION_ERROR,
            array_merge($context, ['field' => $field, 'details' => $details]),
            422,
            null,
            self::LEVEL_LOW
        );
    }

    /**
     * 创建系统异常
     */
    public static function systemError(string $details, array $context = []): self
    {
        return new self(
            "安全系统异常: {$details}",
            self::TYPE_SYSTEM_ERROR,
            $context,
            500,
            null,
            self::LEVEL_CRITICAL
        );
    }

    /**
     * 创建安全异常（通用）
     */
    public static function securityError(string $details, array $context = [], string $level = self::LEVEL_MEDIUM): self
    {
        return new self(
            "安全异常: {$details}",
            self::TYPE_SECURITY_ERROR,
            $context,
            500,
            null,
            $level
        );
    }

    /**
     * 创建文件上传异常
     */
    public static function fileUploadError(string $filename, string $details, array $context = []): self
    {
        return new self(
            "文件上传安全检测失败 [{$filename}]: {$details}",
            self::TYPE_VALIDATION_ERROR,
            array_merge($context, [
                'filename' => $filename,
                'detection_type' => 'file_upload',
            ]),
            422,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 创建User-Agent异常
     */
    public static function userAgentError(string $userAgent, string $details, array $context = []): self
    {
        return new self(
            "User-Agent安全检测失败: {$details}",
            self::TYPE_VALIDATION_ERROR,
            array_merge($context, [
                'user_agent' => substr($userAgent, 0, 200),
                'detection_type' => 'user_agent',
            ]),
            400,
            null,
            self::LEVEL_LOW
        );
    }

    /**
     * 创建URL路径异常
     */
    public static function urlPathError(string $path, string $details, array $context = []): self
    {
        return new self(
            "URL路径安全检测失败 [{$path}]: {$details}",
            self::TYPE_VALIDATION_ERROR,
            array_merge($context, [
                'path' => $path,
                'detection_type' => 'url_path',
            ]),
            400,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 创建HTTP方法异常
     */
    public static function httpMethodError(string $method, string $details, array $context = []): self
    {
        return new self(
            "HTTP方法安全检测失败 [{$method}]: {$details}",
            self::TYPE_VALIDATION_ERROR,
            array_merge($context, [
                'method' => $method,
                'detection_type' => 'http_method',
            ]),
            405,
            null,
            self::LEVEL_LOW
        );
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'level' => $this->level,
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'context' => $this->context,
            'file' => $this->getFile(),
            'line' => $this->getLine(),
            'trace' => $this->getTraceAsString(),
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * 转换为JSON字符串
     */
    public function toJson(int $options = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE): string
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * 获取详细的错误报告
     */
    public function getReport(): array
    {
        return [
            'error_id' => md5($this->getMessage() . $this->getFile() . $this->getLine()),
            'type' => $this->type,
            'level' => $this->level,
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'context_summary' => $this->getContextSummary(),
            'occurred_at' => date('Y-m-d H:i:s'),
            'stack_trace' => $this->getTrace(),
        ];
    }

    /**
     * 获取上下文摘要
     */
    protected function getContextSummary(): array
    {
        $summary = [];

        foreach ($this->context as $key => $value) {
            if (is_string($value) && strlen($value) > 100) {
                $summary[$key] = substr($value, 0, 100) . '...';
            } elseif (is_array($value) || is_object($value)) {
                $summary[$key] = gettype($value);
            } else {
                $summary[$key] = $value;
            }
        }

        return $summary;
    }

    /**
     * 检查是否为严重异常
     */
    public function isCritical(): bool
    {
        return $this->level === self::LEVEL_CRITICAL;
    }

    /**
     * 检查是否为高危异常
     */
    public function isHigh(): bool
    {
        return $this->level === self::LEVEL_HIGH || $this->isCritical();
    }

    /**
     * 检查是否需要立即处理
     */
    public function requiresImmediateAttention(): bool
    {
        return in_array($this->type, [
                self::TYPE_SYSTEM_ERROR,
                self::TYPE_CONFIGURATION_ERROR,
                self::TYPE_DETECTION_ERROR,
            ]) || $this->isCritical();
    }

    /**
     * 获取建议的处理措施
     */
    public function getSuggestedAction(): string
    {
        try {
            return match($this->type) {
                self::TYPE_MALICIOUS_REQUEST => '记录攻击并考虑封禁IP',
                self::TYPE_RATE_LIMIT => '建议用户等待后重试',
                self::TYPE_IP_BLACKLIST => 'IP已在黑名单，无需额外处理',
                self::TYPE_CONFIGURATION_ERROR => '检查并修复配置文件',
                self::TYPE_DETECTION_ERROR => '检查安全检测组件',
                self::TYPE_VALIDATION_ERROR => '验证用户输入并返回错误信息',
                self::TYPE_SYSTEM_ERROR => '检查系统日志并联系管理员',
                default => '记录异常并监控',
            };
        } catch (Throwable $e) {
            return '记录异常并监控';
        }
    }

    /**
     * 创建带时间戳的异常
     */
    public static function withTimestamp(string $message, string $type, array $context = []): self
    {
        return new self(
            $message,
            $type,
            array_merge($context, ['timestamp' => microtime(true)]),
            0,
            null,
            self::LEVEL_MEDIUM
        );
    }

    /**
     * 魔术方法：字符串表示
     */
    public function __toString(): string
    {
        return sprintf(
            "[%s] %s: %s in %s:%s\nContext: %s\nStack trace:\n%s",
            $this->level,
            $this->type,
            $this->getMessage(),
            $this->getFile(),
            $this->getLine(),
            json_encode($this->context, JSON_UNESCAPED_UNICODE),
            $this->getTraceAsString()
        );
    }
}
