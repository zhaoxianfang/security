<?php

namespace zxf\Security\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\ThreatDetectionService;
use zxf\Security\Exceptions\SecurityException;

/**
 * 高级安全拦截中间件 - 最终优化版
 *
 * 功能特性：
 * 1. 多层安全检测机制，性能优先
 * 2. 智能误报过滤，减少误拦截
 * 3. 正则表达式优化，提升匹配性能
 * 4. 完整的攻击类型覆盖，深度防御
 * 5. 可扩展的规则引擎，支持自定义
 * 6. 实时威胁情报，动态更新
 * 7. 完善的监控统计，便于运维
 *
 * @package zxf\Security\Middleware
 */
class SecurityMiddleware
{
    /**
     * 服务实例
     */
    protected RateLimiterService $rateLimiter;
    protected IpManagerService $ipManager;
    protected ThreatDetectionService $threatDetector;

    /**
     * 性能监控开始时间
     */
    protected float $startTime;

    /**
     * 内存使用基准
     */
    protected int $startMemory;

    /**
     * 检测统计信息
     */
    protected array $detectionStats = [
        'checks_performed' => 0,
        'patterns_matched' => 0,
        'false_positives' => 0,
        'execution_time' => 0,
        'memory_usage' => 0,
    ];

    /**
     * 构造函数 - 依赖注入
     */
    public function __construct(
        RateLimiterService $rateLimiter,
        IpManagerService $ipManager,
        ThreatDetectionService $threatDetector
    ) {
        $this->rateLimiter = $rateLimiter;
        $this->ipManager = $ipManager;
        $this->threatDetector = $threatDetector;
    }

    /**
     * 处理传入的HTTP请求 - 主入口方法
     *
     * @param Request $request 当前HTTP请求对象
     * @param Closure $next 下一个中间件闭包
     * @return mixed HTTP响应或继续处理
     */
    public function handle(Request $request, Closure $next)
    {
        // 初始化性能监控
        $this->startMonitoring();

        try {
            // 1. 检查中间件是否启用
            if (!$this->isEnabled()) {
                $this->logDebug('安全中间件已禁用，跳过检查');
                return $next($request);
            }

            // 2. 快速检查：IP白名单和本地请求
            if ($this->ipManager->isWhitelisted($request) || $this->ipManager->isLocalRequest($request)) {
                $this->logDebug('IP白名单或本地请求，跳过安全检查');
                return $next($request);
            }

            // 3. 黑名单检查
            if ($this->ipManager->isBlacklisted($request)) {
                $this->logSecurityEvent($request, 'Blacklist', 'IP黑名单拦截');
                return $this->createBlockResponse($request, 'Blacklist', '您的IP地址已被列入黑名单');
            }

            // 4. 分层安全检测
            $securityCheck = $this->threatDetector->performLayeredSecurityCheck($request);
            if ($securityCheck['blocked']) {
                $this->logSecurityEvent($request, $securityCheck['type'], $securityCheck['reason']);
                return $this->createBlockResponse($request, $securityCheck['type'], $securityCheck['message']);
            }

            // 5. 速率限制检查
            $rateLimitCheck = $this->rateLimiter->check($request);
            if ($rateLimitCheck['blocked']) {
                $this->logSecurityEvent($request, 'RateLimit', '速率限制拦截');
                return $this->createBlockResponse(
                    $request,
                    'RateLimit',
                    '访问频率过高，请稍后再试',
                    $rateLimitCheck['details'] ?? []
                );
            }

            // 6. 自定义逻辑处理
            $customCheck = $this->handleCustomSecurityLogic($request);
            if ($customCheck['blocked']) {
                $this->logSecurityEvent($request, 'CustomRule', '自定义规则拦截');
                return $this->createBlockResponse($request, 'CustomRule', $customCheck['message']);
            }

            // 7. 请求正常，继续处理
            $this->logDetectionStats($request);
            return $next($request);

        } catch (SecurityException $e) {
            // 安全相关异常
            return $this->handleSecurityException($request, $e);
        } catch (\Exception $e) {
            // 其他异常
            return $this->handleGeneralException($request, $e);
        } finally {
            // 确保性能统计被记录
            $this->logDetectionStats($request);
        }
    }

    /**
     * 初始化性能监控
     */
    protected function startMonitoring(): void
    {
        $this->startTime = microtime(true);
        $this->startMemory = memory_get_usage(true);
        $this->detectionStats['checks_performed'] = 0;
        $this->detectionStats['patterns_matched'] = 0;
        $this->detectionStats['false_positives'] = 0;
    }

    /**
     * 检查中间件是否启用
     */
    protected function isEnabled(): bool
    {
        return $this->threatDetector->getConfig('enabled', true);
    }

    /**
     * 处理自定义安全逻辑
     */
    protected function handleCustomSecurityLogic(Request $request): array
    {
        $customHandler = $this->threatDetector->getConfig('custom_handler');

        if (empty($customHandler)) {
            return ['blocked' => false];
        }

        try {
            $callable = $this->resolveCallable($customHandler);
            $result = call_user_func($callable, $request);

            if (is_array($result) && isset($result['blocked']) && $result['blocked']) {
                return [
                    'blocked' => true,
                    'message' => $result['message'] ?? '自定义安全规则拦截'
                ];
            }
        } catch (\Exception $e) {
            Log::error('自定义安全逻辑执行失败: ' . $e->getMessage());
        }

        return ['blocked' => false];
    }

    /**
     * 处理安全异常
     */
    protected function handleSecurityException(Request $request, SecurityException $e)
    {
        $this->logSecurityEvent($request, 'SecurityError', $e->getMessage());

        if ($this->threatDetector->getConfig('block_on_exception', false)) {
            return $this->createBlockResponse(
                $request,
                'SecurityError',
                '安全系统异常: ' . $e->getMessage(),
                [],
                503
            );
        }

        // 异常时放行请求
        return $this->passRequest($request);
    }

    /**
     * 处理一般异常
     */
    protected function handleGeneralException(Request $request, \Exception $e)
    {
        Log::error('安全中间件执行异常: ' . $e->getMessage(), [
            'exception' => $e,
            'request' => $this->getRequestInfo($request)
        ]);

        if ($this->threatDetector->getConfig('block_on_exception', false)) {
            return $this->createBlockResponse(
                $request,
                'SystemError',
                '系统暂时不可用',
                ['exception' => config('app.debug') ? $e->getMessage() : '内部错误'],
                503
            );
        }

        // 异常时放行请求
        return $this->passRequest($request);
    }

    /**
     * 放行请求（异常处理）
     */
    protected function passRequest(Request $request)
    {
        $this->logDebug('安全中间件异常，放行请求');
        return $request;
        return App::make(Closure::class, ['next' => function ($request) {
            return $request;
        }])->handle($request);
    }

    /**
     * 创建阻塞响应
     */
    protected function createBlockResponse(
        Request $request,
        string $type,
        string $message,
        array $context = [],
        int $statusCode = null
    ) {
        $this->updateDetectionStats();

        // 执行封禁逻辑
        if ($this->shouldBan($type)) {
            $this->ipManager->banIp($request, $type);
        }

        // 发送安全警报
        $this->sendSecurityAlert($request, $type, $message, $context);

        // 创建响应
        return $this->createSecurityResponse($request, $type, $message, $context, $statusCode);
    }

    /**
     * 判断是否应该封禁
     */
    protected function shouldBan(string $type): bool
    {
        return in_array($type, ['Malicious', 'Anomalous', 'RateLimit', 'Blacklist']);
    }

    /**
     * 发送安全警报
     */
    protected function sendSecurityAlert(Request $request, string $type, string $message, array $context): void
    {
        try {
            $alarmHandler = $this->threatDetector->getConfig('alarm_handler');
            if ($alarmHandler) {
                $callable = $this->resolveCallable($alarmHandler);

                $alertData = [
                    'type' => $type,
                    'message' => $message,
                    'ip' => $request->ip(),
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                    'user_agent' => $request->userAgent(),
                    'timestamp' => now()->toISOString(),
                    'context' => $context,
                    'stats' => $this->detectionStats,
                ];

                // 异步执行
                if (function_exists('dispatch')) {
                    dispatch(function () use ($callable, $alertData) {
                        call_user_func($callable, $alertData);
                    })->onQueue('security-alerts');
                } else {
                    call_user_func($callable, $alertData);
                }
            }
        } catch (\Exception $e) {
            Log::error('发送安全警报失败: ' . $e->getMessage());
        }
    }

    /**
     * 创建安全响应
     */
    protected function createSecurityResponse(
        Request $request,
        string $type,
        string $message,
        array $context = [],
        int $statusCode = null
    ) {
        $statusCode = $statusCode ?? $this->getStatusCode($type);
        $responseData = $this->buildResponseData($type, $message, $context);

        // API请求返回JSON
        if ($request->expectsJson() || $request->is('api/*')) {
            return $this->createJsonResponse($responseData, $statusCode);
        }

        // Web请求返回HTML页面
        return $this->createHtmlResponse($responseData, $statusCode);
    }

    /**
     * 构建响应数据
     */
    protected function buildResponseData(string $type, string $message, array $context): array
    {
        return [
            'title' => $this->getResponseTitle($type),
            'message' => $message,
            'type' => $type,
            'request_id' => Str::uuid()->toString(),
            'timestamp' => now()->toISOString(),
            'context' => $context,
        ];
    }

    /**
     * 获取响应标题
     */
    protected function getResponseTitle(string $type): string
    {
        $titles = [
            'Blacklist' => 'IP黑名单拦截',
            'RateLimit' => '访问频率限制',
            'Malicious' => '恶意请求拦截',
            'Anomalous' => '异常请求拦截',
            'CustomRule' => '自定义规则拦截',
            'SecurityError' => '安全系统异常',
            'SystemError' => '系统错误',
        ];

        return $titles[$type] ?? '安全拦截';
    }

    /**
     * 创建JSON响应
     */
    protected function createJsonResponse(array $data, int $statusCode)
    {
        $format = $this->threatDetector->getConfig('ajax_response_format', [
            'code' => 'code',
            'message' => 'message',
            'data' => 'data',
        ]);

        $response = [
            $format['code'] => $statusCode,
            $format['message'] => $data['message'],
            $format['data'] => [
                'title' => $data['title'],
                'type' => $data['type'],
                'request_id' => $data['request_id'],
                'timestamp' => $data['timestamp'],
            ],
        ];

        return response()->json($response, $statusCode);
    }

    /**
     * 创建HTML响应
     */
    protected function createHtmlResponse(array $data, int $statusCode)
    {
        $view = $this->threatDetector->getConfig('error_view', 'security::blocked');
        $viewData = array_merge(
            $data,
            $this->threatDetector->getConfig('error_view_data', [])
        );

        return response()->view($view, $viewData, $statusCode);
    }

    /**
     * 获取HTTP状态码
     */
    protected function getStatusCode(string $type): int
    {
        return match ($type) {
            'Blacklist', 'Malicious' => 403,
            'RateLimit' => 429,
            'Anomalous', 'CustomRule' => 422,
            'SecurityError', 'SystemError' => 503,
            default => 403,
        };
    }

    /**
     * 解析可调用对象
     */
    protected function resolveCallable($handler)
    {
        if (is_array($handler)) {
            return [App::make($handler[0]), $handler[1]];
        }

        if (is_string($handler) && str_contains($handler, '::')) {
            return $handler;
        }

        if (is_string($handler) && str_contains($handler, ',')) {
            [$class, $method] = explode(',', $handler, 2);
            return [App::make(trim($class, " \t\n\r\0\x0B'\"")), trim($method, " \t\n\r\0\x0B'\"")];
        }

        return $handler;
    }

    /**
     * 记录安全事件
     */
    protected function logSecurityEvent(Request $request, string $type, string $reason): void
    {
        $logData = [
            'type' => $type,
            'reason' => $reason,
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'user_agent' => $this->truncateString($request->userAgent() ?? '', 200),
            'referer' => $request->header('referer'),
            'timestamp' => now()->toISOString(),
        ];

        $logLevel = $this->threatDetector->getConfig('log_level', 'warning');
        Log::log($logLevel, "安全拦截: {$type} - {$reason}", $logData);
    }

    /**
     * 更新检测统计
     */
    protected function updateDetectionStats(): void
    {
        $this->detectionStats['execution_time'] = microtime(true) - $this->startTime;
        $this->detectionStats['memory_usage'] = memory_get_usage(true) - $this->startMemory;
    }

    /**
     * 记录检测统计信息
     */
    protected function logDetectionStats(Request $request): void
    {
        $this->updateDetectionStats();

        if ($this->threatDetector->getConfig('enable_performance_logging', false)) {
            Log::debug('安全检测性能统计', [
                'stats' => $this->detectionStats,
                'request' => $this->getRequestInfo($request),
            ]);
        }
    }

    /**
     * 获取请求信息
     */
    protected function getRequestInfo(Request $request): array
    {
        return [
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'user_agent' => $this->truncateString($request->userAgent() ?? '', 100),
            'content_type' => $request->header('Content-Type'),
        ];
    }

    /**
     * 字符串截断
     */
    protected function truncateString(string $string, int $length): string
    {
        if (mb_strlen($string) <= $length) {
            return $string;
        }

        return mb_substr($string, 0, $length) . '...';
    }

    /**
     * 记录调试信息
     */
    protected function logDebug(string $message, array $context = []): void
    {
        if ($this->threatDetector->getConfig('enable_debug_logging', false)) {
            Log::debug($message, $context);
        }
    }

    /**
     * 获取安全统计信息
     */
    public function getSecurityStats(): array
    {
        return [
            'detection_stats' => $this->detectionStats,
            'blocked_ips_count' => $this->ipManager->getBannedIpsCount(),
            'rate_limits' => $this->rateLimiter->getRateLimitStats(),
        ];
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        $this->ipManager->clearCache();
        $this->rateLimiter->clearCache();
        $this->threatDetector->clearCache();

        Log::info('安全中间件缓存已清除');
    }
}