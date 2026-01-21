<?php

namespace zxf\Security\Utils;

use Exception;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * 安全异常处理工具类
 *
 * 提供统一的异常处理和日志记录功能：
 * 1. 异常捕获和日志记录
 * 2. 错误分类和级别判断
 * 3. 上下文信息收集
 * 4. 性能监控集成
 * 5. 调试信息输出
 */
class ExceptionHandler
{
    /**
     * 安全相关异常类
     */
    protected static array $securityExceptions = [
        'SecurityException',
        'ValidationException',
        'AuthenticationException',
        'AuthorizationException',
    ];

    /**
     * 关键异常类（需要立即处理）
     */
    protected static array $criticalExceptions = [
        'FatalErrorException',
        'OutOfMemoryException',
        'MaximumExecutionTimeExceededException',
        'StackOverflowException',
    ];

    /**
     * 处理异常并记录日志
     *
     * @param Throwable $exception 异常对象
     * @param array $context 上下文信息
     * @param string $channel 日志通道
     * @return array 处理结果
     */
    public static function handle(Throwable $exception, array $context = [], string $channel = 'stack'): array
    {
        $result = [
            'exception' => get_class($exception),
            'message' => $exception->getMessage(),
            'code' => $exception->getCode(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
            'level' => self::getLogLevel($exception),
            'is_security' => self::isSecurityException($exception),
            'is_critical' => self::isCriticalException($exception),
        ];

        // 记录日志
        self::log($result['level'], $exception, $context, $channel);

        // 关键异常需要特殊处理
        if ($result['is_critical']) {
            self::handleCritical($result, $context);
        }

        return $result;
    }

    /**
     * 获取日志级别
     *
     * @param Throwable $exception 异常对象
     * @return string
     */
    protected static function getLogLevel(Throwable $exception): string
    {
        // 关键异常
        if (self::isCriticalException($exception)) {
            return 'critical';
        }

        // 安全相关异常
        if (self::isSecurityException($exception)) {
            return 'error';
        }

        // 根据错误代码判断
        $code = $exception->getCode();
        if ($code >= 500) {
            return 'error';
        } elseif ($code >= 400) {
            return 'warning';
        }

        // 默认级别
        return 'debug';
    }

    /**
     * 判断是否为安全异常
     *
     * @param Throwable $exception 异常对象
     * @return bool
     */
    protected static function isSecurityException(Throwable $exception): bool
    {
        $className = get_class($exception);

        foreach (self::$securityExceptions as $securityClass) {
            if (str_contains($className, $securityClass)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否为关键异常
     *
     * @param Throwable $exception 异常对象
     * @return bool
     */
    protected static function isCriticalException(Throwable $exception): bool
    {
        $className = get_class($exception);

        foreach (self::$criticalExceptions as $criticalClass) {
            if (str_contains($className, $criticalClass)) {
                return true;
            }
        }

        // 检查特殊消息
        $message = $exception->getMessage();
        $criticalKeywords = [
            'Maximum call stack size',
            'Allowed memory size',
            'Maximum execution time',
            'Out of memory',
            'Stack overflow',
        ];

        foreach ($criticalKeywords as $keyword) {
            if (str_contains(strtolower($message), strtolower($keyword))) {
                return true;
            }
        }

        return false;
    }

    /**
     * 记录日志
     *
     * @param string $level 日志级别
     * @param Throwable $exception 异常对象
     * @param array $context 上下文信息
     * @param string $channel 日志通道
     */
    protected static function log(string $level, Throwable $exception, array $context, string $channel): void
    {
        $logData = array_merge([
            'exception' => get_class($exception),
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
        ], $context);

        // 根据级别记录日志
        switch ($level) {
            case 'critical':
                Log::channel($channel)->critical($exception->getMessage(), $logData);
                break;
            case 'error':
                Log::channel($channel)->error($exception->getMessage(), $logData);
                break;
            case 'warning':
                Log::channel($channel)->warning($exception->getMessage(), $logData);
                break;
            case 'info':
                Log::channel($channel)->info($exception->getMessage(), $logData);
                break;
            case 'debug':
            default:
                Log::channel($channel)->debug($exception->getMessage(), $logData);
                break;
        }
    }

    /**
     * 处理关键异常
     *
     * @param array $result 异常信息
     * @param array $context 上下文信息
     */
    protected static function handleCritical(array $result, array $context): void
    {
        // 添加额外的上下文信息
        $criticalContext = array_merge($context, [
            'memory_usage_mb' => round(memory_get_usage(true) / 1024 / 1024, 2),
            'memory_peak_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'timestamp' => date('Y-m-d H:i:s'),
        ]);

        // 记录到单独的关键错误日志
        Log::channel('security_critical')->critical(
            '检测到关键异常: ' . $result['message'],
            array_merge($result, $criticalContext)
        );

        // 检查是否为栈溢出
        if (str_contains(strtolower($result['message']), 'stack overflow')) {
            Log::critical('检测到栈溢出异常，可能存在无限递归', [
                'exception' => $result['exception'],
                'file' => $result['file'],
                'line' => $result['line'],
            ]);
        }
    }

    /**
     * 安全执行闭包
     *
     * @param callable $callback 要执行的闭包
     * @param mixed $default 默认返回值
     * @param string $context 上下文描述
     * @return mixed
     */
    public static function safeExecute(callable $callback, mixed $default = null, string $context = ''): mixed
    {
        try {
            return $callback();
        } catch (Throwable $e) {
            self::handle($e, ['context' => $context]);

            return $default;
        }
    }

    /**
     * 安全执行并重新抛出异常
     *
     * @param callable $callback 要执行的闭包
     * @param string $context 上下文描述
     * @throws Throwable
     */
    public static function safeExecuteRethrow(callable $callback, string $context = ''): mixed
    {
        try {
            return $callback();
        } catch (Throwable $e) {
            self::handle($e, ['context' => $context]);

            throw $e;
        }
    }

    /**
     * 带超时执行
     *
     * @param callable $callback 要执行的闭包
     * @param int $timeout 超时时间（秒）
     * @param mixed $default 默认返回值
     * @return mixed
     */
    public static function safeExecuteWithTimeout(callable $callback, int $timeout, mixed $default = null): mixed
    {
        $startTime = microtime(true);

        try {
            $result = $callback();

            // 检查是否超时
            $elapsed = microtime(true) - $startTime;
            if ($elapsed > $timeout) {
                Log::warning('执行超时', [
                    'elapsed' => $elapsed,
                    'timeout' => $timeout,
                ]);
                return $default;
            }

            return $result;

        } catch (Throwable $e) {
            self::handle($e, [
                'elapsed' => microtime(true) - $startTime,
                'timeout' => $timeout,
            ]);

            return $default;
        }
    }

    /**
     * 收集调试信息
     *
     * @return array
     */
    public static function collectDebugInfo(): array
    {
        return [
            'memory_usage_mb' => round(memory_get_usage(true) / 1024 / 1024, 2),
            'memory_peak_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'timestamp' => date('Y-m-d H:i:s'),
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'environment' => app()->environment(),
            'debug_mode' => config('app.debug', false),
            'execution_time' => microtime(true) - LARAVEL_START,
        ];
    }

    /**
     * 格式化异常信息
     *
     * @param Throwable $exception 异常对象
     * @return string
     */
    public static function formatException(Throwable $exception): string
    {
        $format = "[%s] %s in %s:%d\n";
        $message = sprintf(
            $format,
            get_class($exception),
            $exception->getMessage(),
            $exception->getFile(),
            $exception->getLine()
        );

        // 添加堆栈跟踪（仅在调试模式下）
        if (config('app.debug', false)) {
            $message .= "\nStack trace:\n" . $exception->getTraceAsString();
        }

        return $message;
    }

    /**
     * 检查是否为递归异常
     *
     * @param Throwable $exception 异常对象
     * @return bool
     */
    public static function isRecursionException(Throwable $exception): bool
    {
        $message = $exception->getMessage();
        $recursionKeywords = [
            'maximum call stack',
            'stack overflow',
            'infinite recursion',
            'recursion limit',
        ];

        foreach ($recursionKeywords as $keyword) {
            if (str_contains(strtolower($message), strtolower($keyword))) {
                return true;
            }
        }

        return false;
    }

    /**
     * 生成堆栈跟踪摘要
     *
     * @param array $trace 堆栈跟踪
     * @param int $limit 限制数量
     * @return array
     */
    public static function summarizeTrace(array $trace, int $limit = 10): array
    {
        $summary = [];

        foreach (array_slice($trace, 0, $limit) as $index => $frame) {
            $summary[] = [
                'index' => $index,
                'file' => $frame['file'] ?? 'unknown',
                'line' => $frame['line'] ?? 0,
                'function' => $frame['function'] ?? 'unknown',
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? null,
            ];
        }

        return $summary;
    }
}
