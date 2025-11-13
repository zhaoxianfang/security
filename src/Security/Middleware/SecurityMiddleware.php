<?php

namespace zxf\Security\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\ThreatDetectionService;
use zxf\Security\Exceptions\SecurityException;

/**
 * 高级安全拦截中间件
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
        'total_requests' => 0,
        'blocked_requests' => 0,
    ];

    /**
     * 错误信息列表
     */
    protected array $errorList = [];

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
        $this->detectionStats['total_requests']++;

        try {
            // 1. 检查中间件是否启用
            if (!$this->isEnabled()) {
                $this->logDebug('安全中间件已禁用，跳过检查');
                return $next($request);
            }

            // 跳过资源文件的安全检查
            if ($this->threatDetector->isResourcePath($request)) {
                return $next($request);
            }

            // 2. 快速检查：IP白名单和本地请求
            if ($this->ipManager->isWhitelisted($request) || $this->ipManager->isLocalRequest($request)) {
                $this->logDebug('IP白名单或本地请求，跳过安全检查');
                return $next($request);
            }

            // 3. 黑名单检查
            if ($this->ipManager->isBlacklisted($request)) {
                $this->detectionStats['blocked_requests']++;
                $this->logSecurityEvent($request, 'Blacklist', 'IP黑名单拦截');
                return $this->createBlockResponse($request, 'Blacklist', '您的IP地址已被列入黑名单');
            }

            // 4. 分层安全检测
            $securityCheck = $this->threatDetector->performLayeredSecurityCheck($request);
            if ($securityCheck['blocked']) {
                $this->detectionStats['blocked_requests']++;
                $this->logSecurityEvent($request, $securityCheck['type'], $securityCheck['reason']);
                return $this->createBlockResponse($request, $securityCheck['type'], $securityCheck['message']);
            }

            // 5. 速率限制检查
            $rateLimitCheck = $this->rateLimiter->check($request);
            if ($rateLimitCheck['blocked']) {
                $this->detectionStats['blocked_requests']++;
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
                $this->detectionStats['blocked_requests']++;
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
            config('app.debug') && dd($e);
            // 其他异常，很可能试图文件异常，改为json 响应
            return response()->json([
                'code' => 500,
                'message' => '处理安全拦截时出现异常！'
            ], 500, [], JSON_UNESCAPED_UNICODE);
        }finally {
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
        $this->errorList = [];
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
            Log::error('自定义安全逻辑执行失败: ' . $e->getMessage(), [
                'custom_handler' => $customHandler,
                'exception' => $e
            ]);
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
            $this->detectionStats['blocked_requests']++;
            return $this->createBlockResponse(
                $request,
                'SecurityError',
                '安全系统异常: ' . $e->getMessage(),
                $e->getContext(),
                503
            );
        }
        $message = config('app.debug') ? $e->getMessage() : '系统进行安全拦截时异常!';
        return $this->createBlockResponse($request, 'Anomalous', $message,$e->getContext(),500);
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
            $this->detectionStats['blocked_requests']++;
            return $this->createBlockResponse(
                $request,
                'SystemError',
                '系统暂时不可用',
                ['exception' => config('app.debug') ? $e->getMessage() : '内部错误'],
                503
            );
        }
        $message = config('app.debug') ? $e->getMessage() : '系统进行安全拦截时异常!';

        return $this->createBlockResponse($request, 'Anomalous', $message,[],500);
    }

    /**
     * 放行请求（异常处理）
     * 修复了原来的错误实现
     */
    protected function passRequest(Request $request, Closure $next)
    {
        try {
            // 直接调用下一个中间件
            return $next($request);
        } catch (\Exception $e) {
            // 如果下一个中间件也异常，返回错误响应
            Log::error('请求处理链异常: ' . $e->getMessage());

            return response()->json([
                'code' => 500,
                'message' => '服务器内部错误',
                'data' => [
                    'error' => config('app.debug') ? $e->getMessage() : '服务暂时不可用'
                ]
            ], 500, [], JSON_UNESCAPED_UNICODE);
        }
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
        $banTypes = ['Malicious', 'Anomalous', 'RateLimit', 'Blacklist'];
        return in_array($type, $banTypes);
    }

    /**
     * 发送安全警报
     */
    protected function sendSecurityAlert(Request $request, string $type, string $message, array $context): void
    {
        try {
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
                'errors' => $this->errorList,
            ];

            $handler = $this->threatDetector->getConfig('alarm_handler', null, $alertData);
            if (is_array($handler)) {
                app()->call($handler, $alertData);
            }
            $this->logDebug('安全警报已发送: ' . $type);
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
        if ($request->expectsJson() || $request->is('api/*') || $request->ajax()) {
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
            'errors' => $this->errorList,
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
    protected function createJsonResponse(array $data, int $statusCode): JsonResponse
    {
        $format = $this->threatDetector->getConfig('ajax_response_format', [
            'code' => 'code',
            'message' => 'message',
            'data' => 'data',
        ]);

        $responseData = [
            $format['code'] => $statusCode,
            $format['message'] => $data['message'],
            $format['data'] => [
                'title' => $data['title'],
                'type' => $data['type'],
                'request_id' => $data['request_id'],
                'timestamp' => $data['timestamp'],
            ],
        ];

        // 调试模式下包含更多信息
        if (config('app.debug')) {
            $responseData[$format['data']]['context'] = $data['context'];
            $responseData[$format['data']]['errors'] = $data['errors'];
        }

        return response()->json($responseData, $statusCode, [], JSON_UNESCAPED_UNICODE)
            ->header('X-Security-Blocked', 'true')
            ->header('X-Security-Type', $data['type'])
            ->header('X-Request-ID', $data['request_id']);
    }

    /**
     * 创建HTML响应
     */
    protected function createHtmlResponse(array $data, int $statusCode): Response
    {
        $view = $this->threatDetector->getConfig('error_view', 'security::blocked');
        $viewData = array_merge(
            $data,
            $this->threatDetector->getConfig('error_view_data', [])
        );

        return response()->view($view, $viewData, $statusCode)
            ->header('X-Security-Blocked', 'true')
            ->header('X-Security-Type', $data['type'])
            ->header('X-Request-ID', $data['request_id']);
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
        if (is_callable($handler)) {
            return $handler;
        }

        if (is_array($handler) && count($handler) === 2) {
            $class = $handler[0];
            $method = $handler[1];

            if (is_string($class) && class_exists($class)) {
                return [App::make($class), $method];
            }

            return $handler;
        }

        if (is_string($handler)) {
            // 处理 Class::method 格式
            if (str_contains($handler, '::')) {
                [$class, $method] = explode('::', $handler, 2);
                if (class_exists($class)) {
                    return [App::make($class), $method];
                }
            }

            // 处理 [Class,method] 格式
            if (preg_match('/^\[(.+),(.+)\]$/', $handler, $matches)) {
                $class = trim($matches[1]);
                $method = trim($matches[2]);
                if (class_exists($class)) {
                    return [App::make($class), $method];
                }
            }

            // 直接返回字符串（可能是函数名）
            return $handler;
        }

        throw new \InvalidArgumentException('无法解析的可调用对象: ' . gettype($handler));
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
            'stats' => $this->detectionStats,
            'errors' => $this->errorList,
        ];

        $logLevel = $this->threatDetector->getConfig('log_level', 'warning');

        switch ($logLevel) {
            case 'emergency':
                Log::emergency("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'alert':
                Log::alert("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'critical':
                Log::critical("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'error':
                Log::error("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'warning':
                Log::warning("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'notice':
                Log::notice("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'info':
                Log::info("安全拦截: {$type} - {$reason}", $logData);
                break;
            case 'debug':
                Log::debug("安全拦截: {$type} - {$reason}", $logData);
                break;
            default:
                Log::warning("安全拦截: {$type} - {$reason}", $logData);
        }
    }

    /**
     * 更新检测统计
     */
    protected function updateDetectionStats(): void
    {
        $this->detectionStats['execution_time'] = microtime(true) - $this->startTime;
        $this->detectionStats['memory_usage'] = memory_get_peak_usage(true) - $this->startMemory;
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

        // 记录到监控系统
        $this->recordMetrics();
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
            'query_params' => count($request->query()),
            'post_params' => count($request->post()),
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
     * 记录指标数据
     */
    protected function recordMetrics(): void
    {
        // 可以集成到监控系统如 Prometheus, DataDog 等
        $metrics = [
            'security_checks_total' => $this->detectionStats['checks_performed'],
            'security_patterns_matched' => $this->detectionStats['patterns_matched'],
            'security_false_positives' => $this->detectionStats['false_positives'],
            'security_execution_time' => $this->detectionStats['execution_time'],
            'security_memory_usage' => $this->detectionStats['memory_usage'],
            'security_total_requests' => $this->detectionStats['total_requests'],
            'security_blocked_requests' => $this->detectionStats['blocked_requests'],
        ];

        // 这里可以添加监控系统集成代码
        // 例如: $this->metrics->increment('security.requests.total');
    }

    /**
     * 添加错误信息
     */
    protected function addError(string $message, array $context = []): void
    {
        $this->errorList[] = [
            'message' => $message,
            'context' => $context,
            'timestamp' => now()->toISOString(),
        ];
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
            'recent_errors' => array_slice($this->errorList, -10), // 最近10个错误
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

        $this->detectionStats = [
            'checks_performed' => 0,
            'patterns_matched' => 0,
            'false_positives' => 0,
            'execution_time' => 0,
            'memory_usage' => 0,
            'total_requests' => 0,
            'blocked_requests' => 0,
        ];

        $this->errorList = [];

        Log::info('安全中间件缓存已清除');
    }

    /**
     * 重新加载配置
     */
    public function reloadConfig(array $newConfig = []): void
    {
        $this->threatDetector->clearCache();
        $this->clearCache();

        Log::info('安全中间件配置已重新加载', ['new_config_keys' => array_keys($newConfig)]);
    }
}
