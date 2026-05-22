<?php

namespace zxf\Security\Middleware\Concerns;

use DateTimeImmutable;
use Illuminate\Support\Facades\Log;
use zxf\Security\Dto\InterceptionContext;
use zxf\Security\ThreatData;

/**
 * 拦截响应构建与安全审计
 *
 * 负责：
 *  - 构建标准化拦截响应（JSON / Blade 视图）
 *  - 自定义视图渲染（支持闭包/类/视图名）
 *  - 拦截决策回调（before_block_callback）
 *  - 安全威胁日志记录（多级别、可选完整请求数据）
 *  - 拦截上下文对象创建
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 */
trait BuildsInterceptionResponse
{
    /**
     * 拦截请求并返回响应
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @param string $message 拦截提示消息
     * @param int $status HTTP状态码
     * @param string $threatType 威胁类型
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\Response
     */
    protected function blockRequest(\Illuminate\Http\Request $request, string $message, int $status = 403, string $threatType = '')
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

        // JSON 响应
        if ($request->expectsJson() || $request->is('api/*') || $request->ajax()) {
            return response()->json($interceptionData, $status)
                ->withHeaders($securityHeaders);
        }

        // 检查是否配置了自定义视图
        $viewConfig = $this->config['response']['view'] ?? null;

        if ($viewConfig !== null && $viewConfig !== '') {
            return $this->renderViewResponse($viewConfig, $interceptionData, $status)
                ->withHeaders($securityHeaders);
        }

        // 使用默认的安全拦截视图 security::error
        return response()->view('security::error', $interceptionData, $status)
            ->withHeaders($securityHeaders);
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

        $messages = $this->config['response']['messages'] ?? [];

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
     * 统一 JSON 和 Blade 响应的数据结构，确保一致性
     *
     * @param \Illuminate\Http\Request $request 请求对象
     * @param string $message 拦截消息
     * @param string $threatType 威胁类型
     * @param int $status HTTP状态码
     * @param bool $showDetails 是否显示详细信息
     * @return array 标准化的响应数据
     */
    protected function buildInterceptionData(
        \Illuminate\Http\Request $request,
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
            'timestamp' => now()->toIso8601String(),
            'http_status' => $status,
        ];

        // 请求元数据
        $data['request'] = [
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
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
     * @return \Illuminate\Http\Response
     */
    protected function renderViewResponse(mixed $viewConfig, array $data, int $status): \Illuminate\Http\Response
    {
        try {
            // 1. 闭包函数
            if ($viewConfig instanceof \Closure) {
                $result = $viewConfig($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 2. 可调用数组 [类名, 方法名]
            if (is_array($viewConfig) && count($viewConfig) === 2) {
                $instance = app($viewConfig[0]);
                $result = $instance->{$viewConfig[1]}($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 3. 类名字符串（自动实例化并调用 __invoke）
            if (is_string($viewConfig) && class_exists($viewConfig)) {
                $instance = app($viewConfig);
                $result = $instance($data);
                return $this->normalizeViewResponse($result, $status);
            }

            // 4. 字符串视图名
            if (is_string($viewConfig) && view()->exists($viewConfig)) {
                return response()->view($viewConfig, $data, $status);
            }

            // 配置无效，返回默认响应
            Log::warning('[Security] 自定义视图配置无效，使用默认响应', [
                'view_config' => $viewConfig,
            ]);

            return response($data['message'], $status);
        } catch (\Throwable $e) {
            Log::error('[Security] 自定义视图渲染失败', [
                'exception' => $e->getMessage(),
                'view_config' => $viewConfig,
            ]);

            return response($data['message'], $status);
        }
    }

    /**
     * 规范化视图响应
     *
     * @param mixed $result 视图返回结果
     * @param int $status HTTP状态码
     * @return \Illuminate\Http\Response
     */
    protected function normalizeViewResponse(mixed $result, int $status): \Illuminate\Http\Response
    {
        if ($result instanceof \Illuminate\Http\Response) {
            return $result;
        }

        if ($result instanceof \Illuminate\View\View) {
            return response($result->render(), $status);
        }

        return response((string) $result, $status);
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
            Log::error('[Security] 拦截回调执行异常', [
                'exception' => $e->getMessage(),
                'threat_type' => $context->threatType,
                'ip' => $context->clientIp,
                'request_id' => $this->requestId,
            ]);

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
            $instance = app($callback);
            return $instance($context);
        }

        if (is_callable($callback)) {
            return $callback($context);
        }

        return $callback($context);
    }

    /**
     * 创建拦截上下文对象
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @param string $threatType 威胁类型
     * @return InterceptionContext 拦截上下文对象
     */
    protected function createInterceptionContext(\Illuminate\Http\Request $request, string $threatType): InterceptionContext
    {
        $requestData = [
            'query_keys' => array_keys($request->query()),
            'post_keys' => array_keys($request->post()),
            'content_type' => $request->header('Content-Type'),
        ];

        return new InterceptionContext(
            request: $request,
            threatType: $threatType,
            timestamp: new DateTimeImmutable(),
            matchedPattern: $this->lastMatchedPattern,
            matchedContent: $this->lastMatchedContent,
            clientIp: $request->ip() ?? '',
            method: $request->method(),
            url: $request->fullUrl(),
            allThreats: array_unique($this->threats),
            requestData: $requestData,
            request_id: $this->requestId,
        );
    }

    // ==================== 安全日志 ====================

    /**
     * 记录安全威胁日志
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @param string $type 威胁类型
     * @param string $details 详细信息
     */
    protected function logThreat(\Illuminate\Http\Request $request, string $type, string $details): void
    {
        if (!($this->config['log_enabled'] ?? true)) {
            return;
        }

        $logLevel = $this->config['log_level'] ?? 'warning';
        $logFullRequest = $this->config['log_full_request'] ?? false;

        $logData = [
            'type' => $type,
            'ip' => $request->ip(),
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'user_agent' => $request->userAgent(),
            'details' => $details,
            'threat_type' => $this->currentThreatType,
            'threat_type_text' => isset($this->context) ? $this->context->getThreatTypeDescription() : '未知威胁',
            'risk_level' => $this->getRiskLevel($type),
            'request_id' => $this->requestId,
            'timestamp' => now()->toIso8601String(),
        ];

        // 如果开启完整请求记录，添加更多数据
        if ($logFullRequest) {
            $logData['headers'] = $request->headers->all();
            $logData['query'] = $request->query();
            $logData['body'] = $request->except(['password', 'token', 'secret']);
            $logData['matched_pattern'] = $this->lastMatchedPattern;
            $logData['matched_content'] = $this->lastMatchedContent;
        }

        // 根据日志级别使用不同的日志方法
        match ($logLevel) {
            'debug' => Log::debug('[Security] 安全威胁检测', $logData),
            'info' => Log::info('[Security] 安全威胁检测', $logData),
            'error' => Log::error('[Security] 安全威胁检测', $logData),
            'critical' => Log::critical('[Security] 安全威胁检测', $logData),
            default => Log::warning('[Security] 安全威胁检测', $logData),
        };
    }
}
