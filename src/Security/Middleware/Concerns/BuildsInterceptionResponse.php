<?php

namespace zxf\Security\Middleware\Concerns;

use DateTimeImmutable;
use zxf\Security\Bridge\FrameworkBridge;
use zxf\Security\Dto\InterceptionContext;
use zxf\Security\ThreatData;

/**
 * 拦截响应构建与安全审计
 *
 * 负责：
 *  - 构建标准化拦截响应（JSON / 视图）
 *  - 自定义视图渲染（支持闭包/类/视图名）
 *  - 拦截决策回调（before_block_callback）
 *  - 安全威胁日志记录（多级别、可选完整请求数据）
 *  - 拦截上下文对象创建
 *
 * 跨框架兼容：所有 Request/Response/Log/View 操作均通过 FrameworkBridge 封装，
 * 支持 Laravel 11+ 和 ThinkPHP 8+。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.1.0
 */
trait BuildsInterceptionResponse
{
    /**
     * 拦截请求并返回响应
     *
     * @param object $request HTTP请求对象（Laravel Request 或 ThinkPHP Request）
     * @param string $message 拦截提示消息
     * @param int $status HTTP状态码
     * @param string $threatType 威胁类型
     * @return object 响应对象（跨框架兼容）
     */
    protected function blockRequest(object $request, string $message, int $status = 403, string $threatType = '')
    {
        $defaultStatus = $this->config['response']['blocked_status'] ?? 403;
        $status = $status === 429
            ? ($this->config['response']['rate_limit_status'] ?? 429)
            : $defaultStatus;

        $showDetails = $this->config['response']['show_threat_details'] ?? false;

        // 根据威胁类型获取更详细的拦截消息
        $detailedMessage = $this->getBlockMessage($threatType, $message);

        // 构建标准化的拦截响应数据
        $interceptionData = $this->buildInterceptionData(
            $request,
            $detailedMessage,
            $threatType,
            $status,
            $showDetails
        );

        // 安全响应头
        $securityHeaders = ThreatData::getResponseHeaders();

        // JSON 响应（CLI 模式或 API 请求优先返回 JSON）
        if (FrameworkBridge::requestExpectsJson($request)
            || FrameworkBridge::requestIsApi($request)
            || FrameworkBridge::requestIsAjax($request)
            || $this->isCliMode()
        ) {
            return FrameworkBridge::responseWithHeaders(
                FrameworkBridge::jsonResponse($interceptionData, $status),
                $securityHeaders
            );
        }

        // 检查是否配置了自定义视图
        $viewConfig = $this->config['response']['view'] ?? null;

        if ($viewConfig !== null && $viewConfig !== '') {
            return FrameworkBridge::responseWithHeaders(
                $this->renderViewResponse($viewConfig, $interceptionData, $status),
                $securityHeaders
            );
        }

        // 使用默认的安全拦截视图 security::error
        // CLI 或视图未注册时降级为 JSON 响应，避免抛出 View 异常终止进程
        try {
            return FrameworkBridge::responseWithHeaders(
                FrameworkBridge::viewResponse('security::error', $interceptionData, $status),
                $securityHeaders
            );
        } catch (\Throwable $e) {
            if ($this->config['log_enabled'] ?? true) {
                FrameworkBridge::logWarning('[Security] 默认拦截视图渲染失败，已降级为 JSON 响应', [
                    'exception' => $e->getMessage(),
                    'request_id' => $this->requestId ?? '',
                ]);
            }
            return FrameworkBridge::responseWithHeaders(
                FrameworkBridge::jsonResponse($interceptionData, $status),
                $securityHeaders
            );
        }
    }

    /**
     * 获取拦截消息
     * 根据威胁类型返回配置的详细消息
     *
     * @param string $threatType 威胁类型
     * @param string $defaultMessage 默认消息
     * @return string 拦截消息
     */
    protected function getBlockMessage(string $threatType, string $defaultMessage): string
    {
        if (empty($threatType)) {
            return $defaultMessage;
        }

        $messages = \zxf\Security\Config\DefaultConfig::getResponseMessages($this->config);

        return $messages[$threatType] ?? ThreatData::getBlockMessage($threatType, $defaultMessage);
    }

    /**
     * 获取威胁的风险等级
     *
     * @param string $threatType 威胁类型
     * @return string 风险等级：high, medium, low, unknown
     */
    protected function getRiskLevel(string $threatType): string
    {
        $levels = $this->config['threat_risk_levels'] ?? [];

        return ThreatData::getRiskLevel($threatType, $levels);
    }

    /**
     * 获取威胁类型的中文描述
     *
     * @param string $threatType 威胁类型
     * @return string 威胁描述
     */
    protected function getThreatDescription(string $threatType): string
    {
        return ThreatData::getDescription($threatType);
    }

    /**
     * 获取威胁分类
     *
     * @param string $threatType 威胁类型
     * @return string 威胁分类
     */
    protected function getThreatCategory(string $threatType): string
    {
        return ThreatData::getCategory($threatType);
    }

    /**
     * 构建标准化的拦截响应数据
     *
     * 统一 JSON 和视图响应的数据结构，确保一致性
     *
     * @param object $request 请求对象（跨框架兼容）
     * @param string $message 拦截消息
     * @param string $threatType 威胁类型
     * @param int $status HTTP状态码
     * @param bool $showDetails 是否显示详细信息
     * @return array 标准化的响应数据
     */
    protected function buildInterceptionData(
        object $request,
        string $message,
        string $threatType,
        int $status,
        bool $showDetails
    ): array {
        $riskLevel = $this->getRiskLevel($threatType);
        $threats = array_values(array_unique($this->threats));

        // 基础数据结构
        $data = [
            'success' => false,
            'blocked' => true,
            'message' => $message,
            'request_id' => $this->requestId,
            'timestamp' => FrameworkBridge::nowIso8601(),
            'http_status' => $status,
        ];

        // 请求元数据
        $data['request'] = [
            'url' => FrameworkBridge::requestFullUrl($request),
            'method' => FrameworkBridge::requestMethod($request),
            'ip' => FrameworkBridge::requestIp($request) ?? 'unknown',
            'user_agent' => FrameworkBridge::requestUserAgent($request) ?? '',
        ];

        // 威胁信息（始终包含基础信息）
        $data['threat'] = [
            'type' => $threatType,
            'risk_level' => $riskLevel,
            'category' => $this->getThreatCategory($threatType),
        ];

        // 详细信息（根据配置决定是否包含）
        if ($showDetails) {
            $data['threat']['identifiers'] = $threats;
            $data['threat']['matched_pattern'] = $this->lastMatchedPattern;
            $data['threat']['matched_content'] = $this->lastMatchedContent;
            $data['threat']['description'] = $this->getThreatDescription($threatType);
        }

        // 兼容性字段（用于 Blade 视图）
        $data['threat_type'] = $threatType;
        $data['risk_level'] = $riskLevel;
        $data['threats'] = $threats;
        $data['matched_pattern'] = $this->lastMatchedPattern;
        $data['matched_content'] = $this->lastMatchedContent;

        // 联系我们链接
        $data['contact_url'] = $this->config['contact_url'] ?? '';

        // 框架无关的应用名称（避免视图中直接调用 config()）
        $data['app_name'] = FrameworkBridge::config('app.name', 'Security System');

        return $data;
    }

    /**
     * 渲染自定义视图响应
     *
     * 支持多种配置格式：
     * - 字符串视图名：'errors.security'
     * - 闭包函数：function($data) { return view(...); }
     * - 类方法：['App\Http\Controllers\SecurityController', 'block']
     * - 可调用类：App\Security\CustomResponseHandler::class
     *
     * @param mixed $viewConfig 视图配置
     * @param array $data 响应数据
     * @param int $status HTTP状态码
     * @return object 响应对象（跨框架兼容）
     */
    protected function renderViewResponse(mixed $viewConfig, array $data, int $status): object
    {
        try {
            // 1. 闭包函数
            if ($viewConfig instanceof \Closure) {
                $result = $viewConfig($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 2. 可调用数组 [类名, 方法名]
            if (is_array($viewConfig) && count($viewConfig) === 2) {
                $instance = FrameworkBridge::appMake($viewConfig[0]) ?? new $viewConfig[0]();
                $result = $instance->{$viewConfig[1]}($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 3. 类名字符串（自动实例化并调用 __invoke）
            if (is_string($viewConfig) && class_exists($viewConfig)) {
                $instance = FrameworkBridge::appMake($viewConfig) ?? new $viewConfig();
                $result = $instance($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 4. 字符串视图名
            if (is_string($viewConfig) && FrameworkBridge::viewExists($viewConfig)) {
                return FrameworkBridge::viewResponse($viewConfig, $data, $status);
            }

            // 配置无效，返回默认响应
            if ($this->config['log_enabled'] ?? true) {
                FrameworkBridge::logWarning('[Security] 自定义视图配置无效，使用默认响应', [
                    'view_config' => $viewConfig,
                ]);
            }

            return FrameworkBridge::plainResponse($data['message'], $status);
        } catch (\Throwable $e) {
            if ($this->config['log_enabled'] ?? true) {
                FrameworkBridge::logError('[Security] 自定义视图渲染失败', [
                    'exception' => $e->getMessage(),
                    'view_config' => $viewConfig,
                ]);
            }

            return FrameworkBridge::plainResponse($data['message'], $status);
        }
    }

    /**
     * 规范化视图响应
     *
     * @param mixed $result 视图返回结果
     * @param int $status HTTP状态码
     * @return object 响应对象（跨框架兼容）
     */
    protected function normalizeViewResponse(mixed $result, int $status): object
    {
        if (is_object($result)) {
            // Laravel Response / ThinkPHP Response
            if (method_exists($result, 'getContent') || method_exists($result, 'withHeaders')) {
                return $result;
            }

            // Laravel View / ThinkPHP View
            if (method_exists($result, 'render')) {
                $rendered = $result->render();
                return FrameworkBridge::plainResponse(is_string($rendered) ? $rendered : (string) $rendered, $status);
            }
        }

        return FrameworkBridge::plainResponse((string) $result, $status);
    }

    // ==================== 拦截决策回调 ====================

    /**
     * 判断是否应拦截请求
     *
     * @param InterceptionContext $context 拦截上下文
     * @return bool true=拦截，false=放行
     */
    protected function shouldBlock(InterceptionContext $context): bool
    {
        $callback = $this->config['before_block_callback'] ?? null;

        if ($callback === null || $callback === false) {
            return true;
        }

        if ($callback === true) {
            return true;
        }

        try {
            $result = $this->executeCallback($callback, $context);

            if ($result === false) {
                return false;
            }

            return true;
        } catch (\Throwable $e) {
            if ($this->config['log_enabled'] ?? true) {
                FrameworkBridge::logError('[Security] 拦截回调执行异常', [
                    'exception' => $e->getMessage(),
                    'threat_type' => $context->threatType,
                    'ip' => $context->clientIp,
                    'request_id' => $this->requestId,
                ]);
            }

            return true;
        }
    }

    /**
     * 执行回调函数
     *
     * @param mixed $callback 回调
     * @param InterceptionContext $context 拦截上下文
     * @return mixed 回调返回值
     */
    protected function executeCallback(mixed $callback, InterceptionContext $context): mixed
    {
        if (is_string($callback) && class_exists($callback)) {
            $instance = FrameworkBridge::appMake($callback) ?? new $callback();
            return $instance($context);
        }

        if (is_callable($callback)) {
            return $callback($context);
        }

        // 不可调用的配置值，视为默认拦截（避免 fatal error）
        if ($this->config['log_enabled'] ?? true) {
            FrameworkBridge::logWarning('[Security] before_block_callback 配置值不可调用，默认执行拦截', [
                'type' => get_debug_type($callback),
            ]);
        }
        return true;
    }

    /**
     * 创建拦截上下文对象
     *
     * @param object $request HTTP请求对象（跨框架兼容）
     * @param string $threatType 威胁类型
     * @return InterceptionContext 拦截上下文对象
     */
    protected function createInterceptionContext(object $request, string $threatType): InterceptionContext
    {
        $requestData = [
            'query_keys' => array_keys(FrameworkBridge::requestQuery($request)),
            'post_keys' => array_keys(FrameworkBridge::requestPost($request)),
            'content_type' => FrameworkBridge::requestGetHeader($request, 'Content-Type') ?? '',
        ];

        return new InterceptionContext(
            request: $request,
            threatType: $threatType,
            timestamp: new DateTimeImmutable(),
            matchedPattern: $this->lastMatchedPattern,
            matchedContent: $this->lastMatchedContent,
            clientIp: FrameworkBridge::requestIp($request) ?? '',
            method: FrameworkBridge::requestMethod($request),
            url: FrameworkBridge::requestFullUrl($request),
            allThreats: array_unique($this->threats),
            requestData: $requestData,
            request_id: $this->requestId,
        );
    }

    // ==================== 安全日志 ====================

    /**
     * 记录安全威胁日志
     *
     * @param object $request HTTP请求对象（跨框架兼容）
     * @param string $type 威胁类型
     * @param string $details 详细信息
     */
    protected function logThreat(object $request, string $type, string $details): void
    {
        if (!($this->config['log_enabled'] ?? true)) {
            return;
        }

        try {
            $logLevel = $this->config['log_level'] ?? 'warning';
            $logFullRequest = $this->config['log_full_request'] ?? false;

            $logData = [
                'type' => $type,
                'ip' => FrameworkBridge::requestIp($request) ?? 'unknown',
                'method' => FrameworkBridge::requestMethod($request),
                'url' => FrameworkBridge::requestFullUrl($request),
                'user_agent' => FrameworkBridge::requestUserAgent($request) ?? '',
                'details' => $details,
                'threat_type' => $this->currentThreatType,
                'threat_type_text' => isset($this->context) ? $this->context->getThreatTypeDescription() : '未知威胁',
                'risk_level' => $this->getRiskLevel($type),
                'request_id' => $this->requestId,
                'timestamp' => FrameworkBridge::nowIso8601(),
            ];

            // 如果开启完整请求记录，添加更多数据
            if ($logFullRequest) {
                $logData['headers'] = FrameworkBridge::requestHeaders($request);
                $logData['query'] = FrameworkBridge::requestQuery($request);
                // 兼容 ThinkPHP（无 except 方法）：手动排除敏感字段
                $allInput = array_merge(
                    FrameworkBridge::requestQuery($request),
                    FrameworkBridge::requestPost($request)
                );
                foreach (['password', 'token', 'secret'] as $key) {
                    unset($allInput[$key]);
                }
                $logData['body'] = $allInput;
                $logData['matched_pattern'] = $this->lastMatchedPattern;
                $logData['matched_content'] = $this->lastMatchedContent;
            }

            // 根据日志级别使用不同的日志方法
            match ($logLevel) {
                'debug' => FrameworkBridge::logDebug('[Security] 安全威胁检测', $logData),
                'info' => FrameworkBridge::logInfo('[Security] 安全威胁检测', $logData),
                'error' => FrameworkBridge::logError('[Security] 安全威胁检测', $logData),
                'critical' => FrameworkBridge::logCritical('[Security] 安全威胁检测', $logData),
                default => FrameworkBridge::logWarning('[Security] 安全威胁检测', $logData),
            };
        } catch (\Throwable) {
            // 日志系统异常（如磁盘满、驱动不可用）时不应阻断正常流程。
            // CLI 模式下尤其关键：artisan 命令、队列任务不能因日志失败而崩溃。
            // 静默降级，已在其他地方抛出异常或拦截则无需重复处理。
        }
    }
}
