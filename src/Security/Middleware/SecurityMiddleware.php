<?php

namespace zxf\Security\Middleware;

use Closure;
use Exception;
use Throwable;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use InvalidArgumentException;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\ThreatDetectionService;
use zxf\Security\Services\WhitelistSecurityService;
use zxf\Security\Services\ConfigHotReloadService;
use zxf\Security\Exceptions\SecurityException;
use zxf\Security\Constants\SecurityEvent;
use zxf\Security\Utils\ExceptionHandler;

/**
 * 安全拦截中间件
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
    protected ?WhitelistSecurityService $whitelistService = null;
    protected ?ConfigHotReloadService $hotReloadService = null;

    /**
     * 是否正在重载配置
     */
    protected bool $isReloadingConfig = false;

    /**
     * 检测统计信息
     */
    protected array $detectionStats = [
        'total_requests' => 0,
        'blocked_requests' => 0,
        'start_time' => 0,
        'end_time' => 0,
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

        // 懒加载白名单服务（使用异常处理）
        $this->whitelistService = ExceptionHandler::safeExecute(
            fn() => app(WhitelistSecurityService::class),
            null,
            'WhitelistService initialization'
        );

        // 懒加载热重载服务（使用异常处理）
        $this->hotReloadService = ExceptionHandler::safeExecute(
            fn() => app(ConfigHotReloadService::class),
            null,
            'ConfigHotReloadService initialization'
        );
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
        // 初始化统计
        $this->detectionStats['total_requests']++;
        $this->detectionStats['start_time'] = microtime(true);

        try {
            // 检查配置热重载（带异常保护）
            if ($this->hotReloadService && !$this->isReloadingConfig) {
                $this->isReloadingConfig = true;
                try {
                    $this->hotReloadService->reloadConfig();
                } catch (Throwable $e) {
                    // 记录但继续执行
                    Log::warning('配置热重载失败，继续执行安全检查', [
                        'error' => $e->getMessage(),
                    ]);
                } finally {
                    $this->isReloadingConfig = false;
                }
            }

            // 1. 检查中间件是否启用
            if (!$this->isEnabled()) {
                $this->logDebug('安全中间件已禁用，跳过检查');
                return $next($request);
            }

            // 2. 检查是否为本地请求（如果配置忽略）
            if ($this->shouldIgnoreLocalRequest($request)) {
                $this->logDebug('本地环境请求，跳过安全检查');
                return $next($request);
            }

            // 跳过资源文件的安全检查
            if ($this->threatDetector->isResourcePath($request)) {
                return $next($request);
            }

            // 3. 执行多层安全检测
            $blockResult = $this->performSecurityChecks($request);

            if ($blockResult['blocked']) {
                $this->detectionStats['blocked_requests']++;
                return $this->handleBlockedRequest($request, $blockResult);
            }

            // 4. 请求正常，继续处理
            return $this->handleNormalRequest($request, $next);

        } catch (SecurityException $e) {
            // 安全相关异常
            ExceptionHandler::handle($e, ['request_path' => $request->path()]);
            return $this->handleSecurityException($request, $e);
        } catch (Throwable $e) {
            // 其他异常（包括递归、内存等）
            ExceptionHandler::handle($e, ['request_path' => $request->path()]);

            // 检查是否为递归异常
            if (ExceptionHandler::isRecursionException($e)) {
                Log::critical('检测到递归异常，安全检查失败，放行请求', [
                    'error' => $e->getMessage(),
                    'request_path' => $request->path(),
                ]);
                // 递归异常时放行请求，避免死循环
                return $next($request);
            }

            return $this->handleGeneralException($request, $e);
        } finally {
            // 记录性能统计
            $this->detectionStats['end_time'] = microtime(true);
        }
    }

    /**
     * 检查中间件是否启用
     */
    protected function isEnabled(): bool
    {
        return $this->threatDetector->getConfig('enabled', true);
    }

    /**
     * 检查是否应该忽略本地请求
     */
    protected function shouldIgnoreLocalRequest(Request $request): bool
    {
        if (!$this->threatDetector->getConfig('ignore_local', false)) {
            return false;
        }

        return $this->ipManager->isLocalRequest($request);
    }

    /**
     * 执行多层安全检测
     */
    protected function performSecurityChecks(Request $request): array
    {
        // 获取防御层配置
        $defenseLayers = $this->threatDetector->getConfig('defense_layers', []);

        // 按配置顺序执行检测
        foreach ($defenseLayers as $layer => $enabled) {
            if (!$enabled) {
                continue;
            }

            $checkResult = $this->executeDefenseLayer($request, $layer);
            if ($checkResult['blocked']) {
                // 拦截
                return $checkResult;
            }else{
                // 不拦截且放行
                if (isset($checkResult['release']) && $checkResult['release']) {
                    return $checkResult;
                }
            }
        }

        return ['blocked' => false];
    }

    /**
     * 执行特定防御层检测
     */
    protected function executeDefenseLayer(Request $request, string $layer): array
    {
        return match ($layer) {
            'ip_whitelist' => $this->checkIpWhitelist($request),
            'ip_blacklist' => $this->checkIpBlacklist($request),
            'method_check' => $this->checkHttpMethod($request),
            'user_agent_check' => $this->checkUserAgent($request),
            'header_check' => $this->checkHeaders($request),
            'url_check' => $this->checkUrl($request),
            'upload_check' => $this->checkUploads($request),
            'body_check' => $this->checkRequestBody($request),
            'anomaly_check' => $this->checkAnomalies($request),
            'rate_limit' => $this->checkRateLimit($request),
            'sql_check' => $this->checkSQLInjection($request),
            'xss_check' => $this->checkXSSAttack($request),
            'command_check' => $this->checkCommandInjection($request),
            'custom_check' => $this->checkCustomRules($request),
            default => ['blocked' => false],
        };
    }

    /**
     * 检查IP白名单
     */
    protected function checkIpWhitelist(Request $request): array
    {
        if ($this->ipManager->isWhitelisted($request)) {
            $this->logDebug('IP白名单，跳过安全检查');
            // 记录访问但不拦截
            $this->ipManager->recordAccess($request, false, SecurityEvent::WHITELIST);
            return ['blocked' => false, 'release' => true];
        }

        return ['blocked' => false];
    }

    /**
     * 检查IP黑名单
     */
    protected function checkIpBlacklist(Request $request): array
    {
        if ($this->ipManager->isBlacklisted($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::BLACKLIST);
            $this->logSecurityEvent($request, SecurityEvent::BLACKLIST, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::BLACKLIST,
                'reason' => '您的IP地址已被列入黑名单',
                'message' => '访问被拒绝：IP地址在黑名单中',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查HTTP方法
     */
    protected function checkHttpMethod(Request $request): array
    {
        $method = strtoupper($request->method());
        $allowedMethods = $this->threatDetector->getConfig('allowed_methods', []);
        $suspiciousMethods = $this->threatDetector->getConfig('suspicious_methods', []);

        // 检查是否允许的方法
        if (!in_array($method, $allowedMethods)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::METHOD_CHECK);
            $this->logSecurityEvent($request, SecurityEvent::METHOD_CHECK, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::METHOD_CHECK,
                'reason' => "不允许的HTTP方法: {$method}",
                'message' => '请求方法不被允许',
            ];
        }

        // 检查可疑方法
        if (in_array($method, $suspiciousMethods)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::SUSPICIOUS_METHOD);
            $this->logSecurityEvent($request, SecurityEvent::SUSPICIOUS_METHOD, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::SUSPICIOUS_METHOD,
                'reason' => "可疑的HTTP方法: {$method}",
                'message' => '请求方法可疑',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查User-Agent
     */
    protected function checkUserAgent(Request $request): array
    {
        $userAgent = $request->userAgent();

        // 检查是否允许空User-Agent
        if (empty($userAgent) && !$this->threatDetector->getConfig('allow_empty_user_agent', false)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::EMPTY_USER_AGENT);
            $this->logSecurityEvent($request, SecurityEvent::EMPTY_USER_AGENT, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::EMPTY_USER_AGENT,
                'reason' => 'User-Agent为空',
                'message' => 'User-Agent不能为空',
            ];
        }

        // 检查User-Agent长度
        $maxLength = $this->threatDetector->getConfig('max_user_agent_length', 512);
        if (strlen($userAgent) > $maxLength) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::USER_AGENT_TOO_LONG);
            $this->logSecurityEvent($request, SecurityEvent::USER_AGENT_TOO_LONG, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::USER_AGENT_TOO_LONG,
                'reason' => "User-Agent长度超过{$maxLength}字符",
                'message' => 'User-Agent过长',
            ];
        }

        // 检查可疑User-Agent
        if ($this->threatDetector->hasSuspiciousUserAgent($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::SUSPICIOUS_USER_AGENT);
            $this->logSecurityEvent($request, SecurityEvent::SUSPICIOUS_USER_AGENT, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::SUSPICIOUS_USER_AGENT,
                'reason' => '可疑的User-Agent模式',
                'message' => 'User-Agent可疑',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查请求头
     */
    protected function checkHeaders(Request $request): array
    {
        // 检查请求头数量
        $maxHeaderCount = $this->threatDetector->getConfig('max_header_count', 50);
        if (count($request->headers->all()) > $maxHeaderCount) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::TOO_MANY_HEADERS);
            $this->logSecurityEvent($request, SecurityEvent::TOO_MANY_HEADERS, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::TOO_MANY_HEADERS,
                'reason' => "请求头数量超过{$maxHeaderCount}个",
                'message' => '请求头过多',
            ];
        }

        // 检查可疑请求头
        if ($this->threatDetector->hasSuspiciousHeaders($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::SUSPICIOUS_HEADERS);
            $this->logSecurityEvent($request, SecurityEvent::SUSPICIOUS_HEADERS, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::SUSPICIOUS_HEADERS,
                'reason' => '包含可疑的请求头',
                'message' => '请求头可疑',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查URL
     */
    /**
     * 检查URL安全性 - 优化增强版
     *
     * 使用安全白名单服务，支持分级控制和方法限制
     */
    protected function checkUrl(Request $request): array
    {
        // 检查URL长度
        $maxUrlLength = $this->threatDetector->getConfig('max_url_length', 2048);
        if (strlen($request->fullUrl()) > $maxUrlLength) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::URL_TOO_LONG);
            $this->logSecurityEvent($request, SecurityEvent::URL_TOO_LONG, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::URL_TOO_LONG,
                'reason' => "URL长度超过{$maxUrlLength}字符",
                'message' => 'URL过长',
            ];
        }

        // 检查URL白名单（使用新的安全白名单服务）
        if ($this->whitelistService) {
            $whitelistConfig = $this->whitelistService->isWhitelisted($request);

            if ($whitelistConfig) {
                // 获取需要保留的安全检查
                $requiredChecks = $this->whitelistService->getRequiredChecks($whitelistConfig);

                // 执行必须的安全检查
                foreach ($requiredChecks as $check) {
                    $result = $this->executeRequiredCheck($request, $check);
                    if ($result['blocked']) {
                        return $result;
                    }
                }

                // 所有检查通过，放行
                $this->logDebug('URL白名单（带安全检查）', [
                    'path' => $request->path(),
                    'level' => $whitelistConfig['level'] ?? 'low',
                    'required_checks' => $requiredChecks,
                ]);

                return ['blocked' => false, 'release' => true];
            }
        }

        // 不在白名单，执行完整的URL安全检查
        if (!$this->threatDetector->isSafeUrl($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::ILLEGAL_URL);
            $this->logSecurityEvent($request, SecurityEvent::ILLEGAL_URL, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::ILLEGAL_URL,
                'reason' => '访问了非法的URL路径',
                'message' => 'URL路径非法',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 执行白名单路径必须的安全检查
     *
     * @param Request $request HTTP请求
     * @param string $check 检查类型
     * @return array 检查结果
     */
    protected function executeRequiredCheck(Request $request, string $check): array
    {
        return match ($check) {
            'ip_blacklist' => $this->checkIpBlacklist($request),
            'rate_limit' => $this->checkRateLimit($request),
            'body_patterns' => $this->checkRequestBody($request),
            'file_upload' => $this->checkUploads($request),
            'sql_injection' => $this->checkSQLInjection($request),
            'xss_attack' => $this->checkXSSAttack($request),
            'command_injection' => $this->checkCommandInjection($request),
            'method_check' => $this->checkHttpMethod($request),
            'user_agent_check' => $this->checkUserAgent($request),
            'header_check' => $this->checkHeaders($request),
            default => ['blocked' => false],
        };
    }

    /**
     * 检查文件上传
     */
    protected function checkUploads(Request $request): array
    {
        if (!$this->threatDetector->getConfig('enable_file_check', true)) {
            return ['blocked' => false];
        }

        if ($this->threatDetector->hasDangerousUploads($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::DANGEROUS_UPLOAD);
            $this->logSecurityEvent($request, SecurityEvent::DANGEROUS_UPLOAD, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::DANGEROUS_UPLOAD,
                'reason' => '检测到危险的文件上传',
                'message' => '文件上传被拒绝',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查请求体
     */
    protected function checkRequestBody(Request $request): array
    {
        // 检查是否为白名单路径
        if ($this->threatDetector->isWhitelistPath($request)) {
            return ['blocked' => false, 'release' => true];
        }

        // 检查请求体内容
        if ($this->threatDetector->isMaliciousRequest($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::MALICIOUS_REQUEST);
            $this->logSecurityEvent($request, SecurityEvent::MALICIOUS_REQUEST, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::MALICIOUS_REQUEST,
                'reason' => '检测到恶意的请求内容',
                'message' => '请求内容包含恶意代码',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查异常行为
     */
    protected function checkAnomalies(Request $request): array
    {
        if (!$this->threatDetector->getConfig('enable_anomaly_detection', true)) {
            return ['blocked' => false];
        }

        if ($this->threatDetector->hasAnomalousParameters($request)) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::ANOMALOUS_PARAMETERS);
            $this->logSecurityEvent($request, SecurityEvent::ANOMALOUS_PARAMETERS, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::ANOMALOUS_PARAMETERS,
                'reason' => '检测到异常的请求参数',
                'message' => '请求参数异常',
            ];
        }

        return ['blocked' => false];
    }

    /**
     * 检查速率限制
     */
    protected function checkRateLimit(Request $request): array
    {
        if (!$this->threatDetector->getConfig('enable_rate_limiting', true)) {
            return ['blocked' => false];
        }

        $rateLimitCheck = $this->rateLimiter->check($request);
        if ($rateLimitCheck['blocked']) {
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::RATE_LIMIT);
            $this->logSecurityEvent($request, SecurityEvent::RATE_LIMIT, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::RATE_LIMIT,
                'reason' => '访问频率过高',
                'message' => '访问频率过高，请稍后再试',
                'details' => $rateLimitCheck['details'] ?? [],
            ];
        }

        return ['blocked' => false];
    }

    /**
     * SQL 注入安全检查
     * @param Request $request
     * @return false[]
     */
    protected function checkSQLInjection(Request $request)
    {
        if($this->threatDetector->hasSQLInjection($request)){
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::SQL_INJECTION);
            $this->logSecurityEvent($request, SecurityEvent::SQL_INJECTION, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::SQL_INJECTION,
                'reason' => 'SQL注入拦截',
                'message' => '请求信息可能存在SQL注入风险',
            ];
        }
        return ['blocked' => false];
    }


    /**
     * 检查XSS攻击
     * @param Request $request
     * @return false[]
     */
    protected function checkXSSAttack(Request $request)
    {
        if($this->threatDetector->hasXSSAttack($request)){
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::XSS_ATTACK);
            $this->logSecurityEvent($request, SecurityEvent::XSS_ATTACK, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::XSS_ATTACK,
                'reason' => 'XSS攻击',
                'message' => '请求信息可能存在XSS攻击',
            ];
        }
        return ['blocked' => false];
    }

    /**
     * 检查命令注入
     * @param Request $request
     * @return false[]
     */
    protected function checkCommandInjection(Request $request)
    {
        if($this->threatDetector->hasCommandInjection($request)){
            $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::COMMAND_INJECTION);
            $this->logSecurityEvent($request, SecurityEvent::COMMAND_INJECTION, $ipRecord);
            return [
                'blocked' => true,
                'type' => SecurityEvent::COMMAND_INJECTION,
                'reason' => '命令注入',
                'message' => '请求信息可能存在命令注入',
            ];
        }
        return ['blocked' => false];
    }

    /**
     * 检查自定义规则
     */
    protected function checkCustomRules(Request $request): array
    {
        $customHandler = $this->threatDetector->getConfig('custom_handler', null);

        if (empty($customHandler)) {
            return ['blocked' => false];
        }

        try {
            $callable = $this->resolveCallable($customHandler);
            $result = call_user_func($callable, $request);

            if (is_array($result) && isset($result['blocked']) && $result['blocked']) {
                $ipRecord = $this->ipManager->recordAccess($request, true, SecurityEvent::CUSTOM_RULE);
                $this->logSecurityEvent($request, SecurityEvent::CUSTOM_RULE, $ipRecord);
                return [
                    'blocked' => true,
                    'type' => SecurityEvent::CUSTOM_RULE,
                    'reason' => $result['reason'] ?? '自定义安全规则拦截',
                    'message' => $result['message'] ?? '自定义安全规则拦截',
                ];
            }
        } catch (Exception $e) {
            Log::error('自定义安全逻辑执行失败: ' . $e->getMessage(), [
                'custom_handler' => $customHandler,
                'exception' => $e
            ]);
        }

        return ['blocked' => false];
    }

    /**
     * 处理被拦截的请求
     */
    protected function handleBlockedRequest(Request $request, array $blockResult)
    {
        // 执行封禁逻辑
        if ($this->shouldBan($blockResult['type'])) {
            $this->ipManager->banIp($request, $blockResult['type']);
        }

        // 发送安全警报
        $this->sendSecurityAlert($request, $blockResult);

        // 创建响应
        return $this->createBlockResponse($request, $blockResult);
    }

    /**
     * 处理正常请求
     */
    protected function handleNormalRequest(Request $request, Closure $next)
    {
        // 记录成功访问
        $this->ipManager->recordAccess($request, false, null);

        // 记录主日志（如果配置了详细日志）
        if ($this->threatDetector->getConfig('log_details', false)) {
            $this->logMainSecurityEvent($request, 'Allowed', '请求允许通过');
        }

        return $next($request);
    }

    /**
     * 处理安全异常 - 优化增强版
     *
     * 改进点：
     * 1. 增加详细的异常日志记录
     * 2. 提供更友好的错误信息
     * 3. 确保系统在异常时不会崩溃
     *
     * @param Request $request HTTP请求对象
     * @param SecurityException $e 安全异常
     * @return Response|JsonResponse HTTP响应
     */
    protected function handleSecurityException(Request $request, SecurityException $e)
    {
        // 记录详细的异常信息
        $this->logSecurityEvent($request, SecurityEvent::ERROR, $e->getMessage());

        // 添加到错误列表
        $this->addError('安全异常: ' . $e->getMessage(), [
            'exception' => get_class($e),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => config('app.debug') ? $e->getTraceAsString() : null,
            'context' => $e->getContext(),
        ]);

        // 根据配置决定是否拦截
        if ($this->threatDetector->getConfig('block_on_exception', false)) {
            $this->detectionStats['blocked_requests']++;

            return $this->createBlockResponse(
                $request,
                [
                    'blocked' => true,
                    'type' => SecurityEvent::ERROR,
                    'reason' => '安全系统异常',
                    'message' => config('app.debug')
                        ? '安全检查时发生异常: ' . $e->getMessage()
                        : '系统进行安全检查时出现异常，请稍后重试',
                    'details' => [
                        'exception_type' => get_class($e),
                        'request_id' => Str::uuid()->toString(),
                    ],
                ]
            );
        }

        // 异常时放行请求（默认行为，避免影响正常业务）
        Log::warning('安全中间件异常但放行请求', [
            'exception' => $e->getMessage(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);

        return $this->handleNormalRequest($request, fn($req) => $this->passRequest($req));
    }

    /**
     * 处理一般异常 - 优化增强版
     *
     * 改进点：
     * 1. 增加详细的异常日志记录
     * 2. 提供更友好的错误信息
     * 3. 确保系统在异常时不会崩溃
     *
     * @param Request $request HTTP请求对象
     * @param Throwable $e 一般异常
     * @return Response|JsonResponse HTTP响应
     */
    protected function handleGeneralException(Request $request, Throwable $e)
    {
        // 记录详细的异常信息
        Log::error('安全中间件执行异常', [
            'exception' => $e->getMessage(),
            'exception_type' => get_class($e),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => config('app.debug') ? $e->getTraceAsString() : null,
            'request' => $this->getRequestInfo($request),
        ]);

        // 添加到错误列表
        $this->addError('系统异常: ' . $e->getMessage(), [
            'exception' => get_class($e),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ]);

        // 根据配置决定是否拦截
        if ($this->threatDetector->getConfig('block_on_exception', false)) {
            $this->detectionStats['blocked_requests']++;

            return $this->createBlockResponse(
                $request,
                [
                    'blocked' => true,
                    'type' => SecurityEvent::ERROR,
                    'reason' => '系统暂时不可用',
                    'message' => config('app.debug')
                        ? '系统异常: ' . $e->getMessage()
                        : '系统暂时不可用，请稍后重试',
                    'details' => [
                        'exception_type' => get_class($e),
                        'request_id' => Str::uuid()->toString(),
                    ],
                ]
            );
        }

        // 异常时放行请求（默认行为，避免影响正常业务）
        Log::warning('安全中间件异常但放行请求', [
            'exception' => $e->getMessage(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);

        return $this->handleNormalRequest($request, fn($req) => $this->passRequest($req));
    }

    /**
     * 放行请求
     */
    protected function passRequest(Request $request)
    {
        // 这里可以添加一些处理逻辑，比如记录日志等
        $response = app()->handle($request);

        // 确保响应被发送
        if (!$response->isSent()) {
            $response->send();
        }

        return $response;
    }

    /**
     * 判断是否应该封禁
     */
    protected function shouldBan(string $type): bool
    {
        $banTypes = ['MaliciousRequest', 'AnomalousParameters', 'RateLimit', 'Blacklist', 'IllegalUrl'];
        return in_array($type, $banTypes);
    }

    /**
     * 发送安全警报
     */
    protected function sendSecurityAlert(Request $request, array $blockResult): void
    {
        try {
            $alarmHandler = $this->threatDetector->getConfig('alarm_handler', null);

            if (!empty($alarmHandler)) {
                $alertData = [
                    'type' => $blockResult['type'],
                    'reason' => $blockResult['reason'],
                    'message' => $blockResult['message'],
                    'ip' => $request->ip(),
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                    'user_agent' => $request->userAgent(),
                    'timestamp' => now()->toISOString(),
                    'details' => $blockResult['details'] ?? [],
                    'request_info' => $this->getRequestInfo($request),
                ];

                $callable = $this->resolveCallable($alarmHandler);
                call_user_func($callable, $alertData);

                $this->logDebug('安全警报已发送: ' . $blockResult['type']);
            }
        } catch (Exception $e) {
            Log::error('发送安全警报失败: ' . $e->getMessage());
        }
    }

    /**
     * 创建拦截响应
     */
    protected function createBlockResponse(Request $request, array $blockResult): Response|JsonResponse
    {
        $responseData = $this->buildResponseData($blockResult);
        $statusCode = $this->getStatusCode($blockResult['type']);

        // API请求返回JSON
        if (($request->expectsJson() || $request->is('api/*') || $request->ajax()) && $this->threatDetector->getConfig('enable_api_mode', true)) {
            return $this->createJsonResponse($responseData, $statusCode);
        }

        // Web请求返回HTML页面
        return $this->createHtmlResponse($responseData, $statusCode);
    }

    /**
     * 构建响应数据
     */
    protected function buildResponseData(array $blockResult): array
    {
        return [
            'title' => $this->getResponseTitle($blockResult['type']),
            'message' => $blockResult['message'],
            'type' => $blockResult['type'],
            'reason' => $blockResult['reason'],
            'request_id' => Str::uuid()->toString(),
            'timestamp' => now()->toISOString(),
            'details' => $blockResult['details'] ?? [],
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
            'MaliciousRequest' => '恶意请求拦截',
            'AnomalousParameters' => '异常请求拦截',
            'IllegalUrl' => '非法URL拦截',
            'DangerousUpload' => '危险文件拦截',
            'SuspiciousUserAgent' => '可疑User-Agent拦截',
            'SuspiciousHeaders' => '可疑请求头拦截',
            'MethodCheck' => 'HTTP方法检查拦截',
            'EmptyUserAgent' => '空User-Agent拦截',
            'UrlTooLong' => 'URL过长拦截',
            'UserAgentTooLong' => 'User-Agent过长拦截',
            'TooManyHeaders' => '请求头过多拦截',
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
                'reason' => $data['reason'],
                'request_id' => $data['request_id'],
                'timestamp' => $data['timestamp'],
            ],
        ];

        // 调试模式下包含更多信息
        if (config('app.debug')) {
            $responseData[$format['data']]['details'] = $data['details'];
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

        !empty($viewData['context']) && ($viewData['context'] = array_to_pretty_json($viewData['context']));
        !empty($viewData['errors']) && ($viewData['errors'] = array_to_pretty_json($viewData['errors']));

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
        $statusCodes = $this->threatDetector->getConfig('response_status_codes', [
            'Blacklist' => 403,
            'RateLimit' => 429,
            'MaliciousRequest' => 403,
            'AnomalousParameters' => 422,
            'SuspiciousUserAgent' => 400,
            'SecurityError' => 503,
            'SystemError' => 503,
        ]);

        return $statusCodes[$type] ?? 403;
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

        throw new InvalidArgumentException('无法解析的可调用对象: ' . gettype($handler));
    }

    /**
     * 记录安全事件（主日志）
     */
    protected function logSecurityEvent(Request $request, string $type, mixed $ipRecord = []): void
    {
        $reason = SecurityEvent::getEventName($type);
        $logData = [
            'type' => $type,
            'security_id' => !empty($ipRecord) && $ipRecord['id'] ? $ipRecord['id'] : null,
            'reason' => $reason,
            'ip' => $request->ip(),
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'user_agent' => $this->truncateString($request->userAgent() ?? '', 200),
            'referer' => $request->header('referer'),
            'timestamp' => now()->toISOString(),
            'execution_time' => $this->getExecutionTime(),
            'request_info' => $this->getRequestInfo($request),
        ];

        // 添加IP记录信息
        if (!empty($ipRecord) && is_array($ipRecord)) {
            $logData['ip_record'] = [
                'id' => $ipRecord['id'] ?? null,
                'threat_score' => $ipRecord['threat_score'] ?? null,
                'request_count' => $ipRecord['request_count'] ?? null,
                'blocked_count' => $ipRecord['blocked_count'] ?? null,
            ];
        }

        // 记录主日志
        $this->logMainSecurityEvent($request, $type, $reason, $logData);
    }

    /**
     * 记录主安全事件日志
     */
    protected function logMainSecurityEvent(Request $request, string $type, string $reason, array $context = []): void
    {
        $logLevel = $this->threatDetector->getConfig('log_level', 'warning');

        // 构建日志消息
        $message = sprintf(
            '安全拦截: %s - %s - IP: %s - URL: %s',
            $type,
            $reason,
            $request->ip(),
            $request->path()
        );

        // 记录日志
        Log::$logLevel($message, $context);
    }

    /**
     * 获取配置值（添加便捷方法）
     */
    protected function getConfig(string $key, mixed $default = null): mixed
    {
        return $this->threatDetector->getConfig($key, $default);
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
            'full_url' => $this->truncateString($request->fullUrl(), 500),
            'user_agent' => $this->truncateString($request->userAgent() ?? '', 100),
            'content_type' => $request->header('Content-Type'),
            'query_params' => count($request->query()),
            'post_params' => count($request->post()),
            'has_files' => !empty($request->allFiles()),
        ];
    }

    /**
     * 获取执行时间
     */
    protected function getExecutionTime(): float
    {
        if (isset($this->detectionStats['start_time']) && isset($this->detectionStats['end_time'])) {
            return round($this->detectionStats['end_time'] - $this->detectionStats['start_time'], 4);
        }
        return 0.0;
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
            'rate_limits' => $this->rateLimiter->getRateLimitStats(),
            'recent_errors' => array_slice($this->errorList, -10),
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
            'total_requests' => 0,
            'blocked_requests' => 0,
            'start_time' => 0,
            'end_time' => 0,
        ];

        $this->errorList = [];

        if ($this->threatDetector->getConfig('enable_debug_logging', false)) {
            Log::info('安全中间件缓存已清除');
        }
    }
}
