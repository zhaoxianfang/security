<?php

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use zxf\Security\Models\SecurityIp;
use zxf\Security\Services\ConfigManager;
use zxf\Security\Services\ThreatDetectionService;

if (! function_exists('security_config')) {
    /**
     * 获取安全包的配置值
     *
     * 这是一个便捷的助手函数，用于获取安全包的配置值。
     * 支持获取单个配置项或所有配置，支持默认值。
     *
     * @param string|null $key 配置键名。如果为null，返回所有配置。
     * @param mixed $default 默认值，当配置不存在时返回此值。
     * @return mixed 配置值或所有配置数组。
     *
     * @example
     * // 获取所有配置
     * $allConfig = security_config();
     *
     * // 获取单个配置项
     * $enabled = security_config('enabled');
     *
     * // 获取配置项，如果不存在返回默认值
     * $timeout = security_config('timeout', 30);
     *
     * // 获取嵌套配置
     * $threshold = security_config('ip_auto_detection.blacklist_threshold');
     *
     * // 动态配置支持（闭包、类方法等）
     * $patterns = security_config('body_patterns');
     */
    function security_config(?string $key = null, mixed $default = null): mixed
    {
        $configManager = ConfigManager::instance();

        if (is_null($key)) {
            return $configManager->all();
        }

        // 特殊处理：确保数值类型的配置正确转换
        $value = $configManager->get($key, $default);

        // 如果是阈值相关的配置，确保返回正确的数值类型
        $thresholdKeys = [
            'ip_auto_detection.blacklist_threshold',
            'ip_auto_detection.suspicious_threshold',
            'ip_auto_detection.add_threat_score',
            'ip_auto_detection.reduce_threat_score',
            'ip_auto_detection.decay_rate_per_hour',
            'ip_auto_detection.max_triggers',
        ];

        foreach ($thresholdKeys as $thresholdKey) {
            if ($key === $thresholdKey || str_starts_with($key, $thresholdKey . '.')) {
                if (is_numeric($value)) {
                    return is_float($default) ? (float) $value : (int) $value;
                }
            }
        }

        return $value;
    }
}

if (! function_exists('security_is_whitelisted')) {
    /**
     * 检查IP是否在白名单中
     *
     * 检查指定IP地址是否在安全白名单中。
     * 支持单个IP和IP段检查。
     *
     * @param string $ip 要检查的IP地址
     * @return bool IP是否在白名单中
     *
     * @example
     * // 检查当前请求IP
     * $isWhitelisted = security_is_whitelisted(request()->ip());
     *
     * // 检查指定IP
     * $isWhitelisted = security_is_whitelisted('192.168.1.100');
     */
    function security_is_whitelisted(string $ip): bool
    {
        return SecurityIp::isWhitelisted($ip);
    }
}

if (! function_exists('security_is_blacklisted')) {
    /**
     * 检查IP是否在黑名单中
     *
     * 检查指定IP地址是否在安全黑名单中。
     * 支持单个IP和IP段检查。
     *
     * @param string $ip 要检查的IP地址
     * @return bool IP是否在黑名单中
     *
     * @example
     * // 检查当前请求IP
     * $isBlacklisted = security_is_blacklisted(request()->ip());
     *
     * // 检查指定IP
     * $isBlacklisted = security_is_blacklisted('10.0.0.1');
     */
    function security_is_blacklisted(string $ip): bool
    {
        return SecurityIp::isBlacklisted($ip);
    }
}

if (! function_exists('security_record_access')) {
    /**
     * 记录IP访问请求
     *
     * 记录IP地址的访问请求，用于统计和威胁分析。
     * 可以标记请求是否被拦截以及触发规则。
     *
     * @param string $ip 访问IP地址
     * @param bool $blocked 是否被拦截
     * @param string|null $rule 触发规则名称
     * @return array|null IP记录信息或null
     *
     * @example
     * // 记录成功访问
     * $record = security_record_access('192.168.1.100', false);
     *
     * // 记录被拦截的访问
     * $record = security_record_access('10.0.0.1', true, 'SQLInjection');
     *
     * // 在中间件中使用
     * $record = security_record_access($request->ip(), $blocked, $rule);
     */
    function security_record_access(string $ip, bool $blocked = false, ?string $rule = null): ?array
    {
        $record = SecurityIp::recordRequest($ip, $blocked, $rule);

        if ($record) {
            return [
                'id' => $record->id,
                'ip_address' => $record->ip_address,
                'type' => $record->type,
                'threat_score' => $record->threat_score,
                'request_count' => $record->request_count,
                'blocked_count' => $record->blocked_count,
                'success_count' => $record->success_count,
                'trigger_count' => $record->trigger_count,
                'last_request_at' => $record->last_request_at,
                'first_seen_at' => $record->first_seen_at,
            ];
        }

        return null;
    }
}

if (! function_exists('security_add_to_whitelist')) {
    /**
     * 添加IP到白名单
     *
     * 将IP地址添加到安全白名单，支持单个IP和IP段。
     * 可以设置过期时间和添加原因。
     *
     * @param string $ip IP地址或IP段（如：192.168.1.1 或 192.168.1.0/24）
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间，null表示永久有效
     * @return bool 操作是否成功
     *
     * @example
     * // 添加单个IP到白名单
     * security_add_to_whitelist('192.168.1.100', '内部服务器');
     *
     * // 添加IP段到白名单，设置过期时间
     * security_add_to_whitelist('192.168.1.0/24', '内部网络', now()->addMonth());
     *
     * // 永久添加到白名单
     * security_add_to_whitelist('10.0.0.1', '管理服务器');
     */
    function security_add_to_whitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): bool
    {
        try {
            SecurityIp::addToWhitelist($ip, $reason, $expiresAt);
            return true;
        } catch (Exception $e) {
            Log::error('添加IP到白名单失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'reason' => $reason,
                'exception' => $e
            ]);
            return false;
        }
    }
}

if (! function_exists('security_add_to_blacklist')) {
    /**
     * 添加IP到黑名单
     *
     * 将IP地址添加到安全黑名单，支持单个IP和IP段。
     * 可以设置过期时间、添加原因和标记是否自动检测。
     *
     * @param string $ip IP地址或IP段（如：192.168.1.1 或 192.168.1.0/24）
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间，null表示永久有效
     * @param bool $autoDetected 是否自动检测添加
     * @return bool 操作是否成功
     *
     * @example
     * // 添加单个IP到黑名单
     * security_add_to_blacklist('10.0.0.100', '恶意攻击');
     *
     * // 添加IP段到黑名单，设置过期时间
     * security_add_to_blacklist('10.0.0.0/24', '僵尸网络', now()->addWeek());
     *
     * // 自动检测添加
     * security_add_to_blacklist('172.16.0.1', '自动检测威胁', null, true);
     */
    function security_add_to_blacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): bool
    {
        try {
            SecurityIp::addToBlacklist($ip, $reason, $expiresAt, $autoDetected);
            return true;
        } catch (Exception $e) {
            Log::error('添加IP到黑名单失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'reason' => $reason,
                'exception' => $e
            ]);
            return false;
        }
    }
}

if (! function_exists('security_get_ip_stats')) {
    /**
     * 获取IP统计信息
     *
     * 获取指定IP地址的详细统计信息，包括访问次数、拦截次数、威胁评分等。
     *
     * @param string $ip IP地址
     * @return array IP统计信息
     *
     * @example
     * // 获取IP统计信息
     * $stats = security_get_ip_stats('192.168.1.100');
     *
     * // 使用统计信息
     * if ($stats['threat_score'] > 50) {
     *     // 高威胁IP处理
     * }
     */
    function security_get_ip_stats(string $ip): array
    {
        return SecurityIp::getIpStats($ip);
    }
}

if (! function_exists('security_get_high_threat_ips')) {
    /**
     * 获取高威胁IP列表
     *
     * 获取威胁评分较高的IP地址列表，用于安全分析和监控。
     *
     * @param int $limit 返回数量限制，默认100
     * @return array 高威胁IP列表
     *
     * @example
     * // 获取前50个高威胁IP
     * $threatIps = security_get_high_threat_ips(50);
     *
     * // 分析高威胁IP
     * foreach ($threatIps as $ip) {
     *     echo "IP: {$ip['ip_address']}, 威胁评分: {$ip['threat_score']}\n";
     * }
     */
    function security_get_high_threat_ips(int $limit = 100): array
    {
        $ips = SecurityIp::getHighThreatIps($limit);
        return $ips->toArray();
    }
}

if (! function_exists('security_cleanup_expired')) {
    /**
     * 清理过期的IP记录
     *
     * 清理数据库中过期的IP记录，包括过期黑名单、白名单等。
     * 返回清理的记录数量。
     *
     * @return int 清理的记录数量
     *
     * @example
     * // 清理过期记录
     * $cleanedCount = security_cleanup_expired();
     * echo "清理了 {$cleanedCount} 条过期记录";
     *
     * // 在定时任务中使用
     * $schedule->call(function () {
     *     security_cleanup_expired();
     * })->daily();
     */
    function security_cleanup_expired(): int
    {
        return SecurityIp::cleanupExpired();
    }
}

if (! function_exists('security_log_event')) {
    /**
     * 记录安全事件日志
     *
     * 记录安全相关事件日志，支持不同日志级别。
     * 自动包含请求上下文信息。
     *
     * @param string $message 日志消息
     * @param string $level 日志级别（debug, info, warning, error等）
     * @param array $context 额外上下文信息
     * @param Request|null $request 请求对象，为null时自动获取当前请求
     *
     * @example
     * // 记录安全警告
     * security_log_event('检测到SQL注入尝试', 'warning', [
     *     'sql_pattern' => $pattern,
     *     'parameter' => $paramName
     * ]);
     *
     * // 记录安全错误
     * security_log_event('安全中间件异常', 'error', [
     *     'exception' => $e->getMessage()
     * ]);
     *
     * // 记录调试信息
     * security_log_event('安全检测完成', 'debug', [
     *     'execution_time' => $time
     * ]);
     */
    function security_log_event(string $message, string $level = 'info', array $context = [], ?Request $request = null): void
    {
        if (is_null($request) && function_exists('request')) {
            $request = \request();
        }

        $logData = [
            'timestamp' => \now()->toISOString(),
            'message' => $message,
            'level' => $level,
            'context' => $context,
        ];

        if ($request) {
            $logData['request'] = [
                'ip' => $request->ip(),
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'user_agent' => substr($request->userAgent() ?? '', 0, 200),
            ];
        }

        // 根据日志级别记录
        switch (strtolower($level)) {
            case 'debug':
                Log::debug($message, $logData);
                break;
            case 'info':
                Log::info($message, $logData);
                break;
            case 'warning':
            case 'warn':
                Log::warning($message, $logData);
                break;
            case 'error':
                Log::error($message, $logData);
                break;
            case 'critical':
                Log::critical($message, $logData);
                break;
            default:
                Log::info($message, $logData);
        }
    }
}

if (! function_exists('security_check_rate_limit')) {
    /**
     * 检查速率限制
     *
     * 检查指定标识符的速率限制，支持分钟、小时、天级别限制。
     *
     * @param string $identifier 限制标识符（如IP、用户ID等）
     * @param array $limits 限制配置，默认使用配置文件中的配置
     * @return array 检查结果，包含是否被限制和详细信息
     *
     * @example
     * // 检查IP速率限制
     * $result = security_check_rate_limit(request()->ip());
     * if ($result['blocked']) {
     *     return response()->json(['error' => '请求过于频繁'], 429);
     * }
     *
     * // 使用自定义限制
     * $result = security_check_rate_limit($userId, [
     *     'minute' => 10,
     *     'hour' => 100,
     *     'day' => 1000
     * ]);
     */
    function security_check_rate_limit(string $identifier, array $limits = []): array
    {
        try {
            // 验证identifier
            if (empty($identifier)) {
                Log::warning('速率限制检查失败：标识符为空');
                return [
                    'blocked' => false,
                    'details' => [],
                ];
            }

            if (empty($limits)) {
                $limits = security_config('rate_limits', [
                    'minute' => 60,
                    'hour' => 1000,
                    'day' => 10000,
                ]);
            }

            // 验证limits
            if (!is_array($limits) || empty($limits)) {
                Log::warning('速率限制配置无效');
                return [
                    'blocked' => false,
                    'details' => [],
                ];
            }

            $results = [];

            foreach ($limits as $window => $limit) {
                // 验证limit为正整数
                if (!is_int($limit) || $limit <= 0) {
                    Log::warning("无效的限流阈值: {$window}", ['limit' => $limit]);
                    continue;
                }

                $cacheKey = "security:rate_limit:{$window}:" . md5($identifier);
                $count = Cache::get($cacheKey, 0);

                // 验证count为数值
                if (!is_numeric($count)) {
                    $count = 0;
                }

                $results[$window] = [
                    'current' => $count,
                    'limit' => $limit,
                    'blocked' => $count >= $limit,
                ];

                if ($count >= $limit) {
                    return [
                        'blocked' => true,
                        'window' => $window,
                        'current' => $count,
                        'limit' => $limit,
                        'retry_after' => match($window) {
                            'minute' => 60,
                            'hour' => 3600,
                            'day' => 86400,
                            default => 60,
                        },
                        'details' => $results,
                    ];
                }
            }

            return [
                'blocked' => false,
                'details' => $results,
            ];
        } catch (Throwable $e) {
            Log::error('速率限制检查异常: ' . $e->getMessage(), [
                'identifier' => $identifier ?? 'unknown',
                'exception' => $e
            ]);
            return [
                'blocked' => false,
                'details' => [],
            ];
        }
    }
}

if (! function_exists('security_increment_rate_limit')) {
    /**
     * 增加速率限制计数器
     *
     * 增加指定标识符的速率限制计数器。
     *
     * @param string $identifier 限制标识符
     *
     * @example
     * // 在请求处理成功后增加计数器
     * security_increment_rate_limit(request()->ip());
     *
     * // 为用户操作增加计数器
     * security_increment_rate_limit("user:{$userId}:action");
     */
    function security_increment_rate_limit(string $identifier): void
    {
        try {
            // 验证identifier
            if (empty($identifier)) {
                Log::warning('增加速率限制计数器失败：标识符为空');
                return;
            }

            $limits = security_config('rate_limits', [
                'minute' => 60,
                'hour' => 1000,
                'day' => 10000,
            ]);

            // 验证limits
            if (!is_array($limits) || empty($limits)) {
                return;
            }

            foreach ($limits as $window => $limit) {
                $cacheKey = "security:rate_limit:{$window}:" . md5($identifier);
                $count = Cache::get($cacheKey, 0);

                // 验证count为数值
                if (!is_numeric($count)) {
                    $count = 0;
                }

                $ttl = match($window) {
                    'minute' => 60,
                    'hour' => 3600,
                    'day' => 86400,
                    default => 60,
                };

                Cache::put($cacheKey, $count + 1, $ttl);
            }
        } catch (Throwable $e) {
            Log::error('增加速率限制计数器异常: ' . $e->getMessage(), [
                'identifier' => $identifier ?? 'unknown',
                'exception' => $e
            ]);
        }
    }
}

if (! function_exists('security_clear_rate_limit')) {
    /**
     * 清除速率限制计数器
     *
     * 清除指定标识符的速率限制计数器。
     *
     * @param string $identifier 限制标识符
     *
     * @example
     * // 清除IP的速率限制
     * security_clear_rate_limit(request()->ip());
     *
     * // 清除用户的速率限制
     * security_clear_rate_limit("user:{$userId}");
     */
    function security_clear_rate_limit(string $identifier): void
    {
        $windows = ['minute', 'hour', 'day'];

        foreach ($windows as $window) {
            $cacheKey = "security:rate_limit:{$window}:" . md5($identifier);
            Cache::forget($cacheKey);
        }
    }
}

if (! function_exists('security_detect_threat')) {
    /**
     * 检测请求威胁
     *
     * 对请求进行安全威胁检测，返回检测结果。
     * 可以用于手动检测或自定义检测逻辑。
     *
     * @param Request $request 请求对象
     * @return array 威胁检测结果
     *
     * @example
     * // 在控制器中手动检测
     * $threatResult = security_detect_threat($request);
     * if ($threatResult['blocked']) {
     *     return response()->json(['error' => '安全威胁检测'], 403);
     * }
     *
     * // 获取详细检测信息
     * $threatResult = security_detect_threat($request);
     * if ($threatResult['has_sql_injection']) {
     *     // SQL注入处理
     * }
     */
    function security_detect_threat(Request $request): array
    {
        /** @var ThreatDetectionService $threatDetector */
        $threatDetector = \app(ThreatDetectionService::class);

        return [
            'blocked' => false, // 需要调用具体检测方法
            'is_resource_path' => $threatDetector->isResourcePath($request),
            'has_sql_injection' => $threatDetector->hasSQLInjection($request),
            'has_xss_attack' => $threatDetector->hasXSSAttack($request),
            'has_command_injection' => $threatDetector->hasCommandInjection($request),
            'has_malicious_request' => $threatDetector->isMaliciousRequest($request),
            'has_anomalous_parameters' => $threatDetector->hasAnomalousParameters($request),
            'has_dangerous_uploads' => $threatDetector->hasDangerousUploads($request),
            'has_suspicious_user_agent' => $threatDetector->hasSuspiciousUserAgent($request),
            'has_suspicious_headers' => $threatDetector->hasSuspiciousHeaders($request),
            'is_safe_url' => $threatDetector->isSafeUrl($request),
        ];
    }
}

if (! function_exists('security_response')) {
    /**
     * 创建安全响应
     *
     * 创建标准化的安全拦截响应，支持JSON和HTML格式。
     *
     * @param string $type 拦截类型
     * @param string $message 拦截提示消息
     * @param array $context 额外上下文信息
     * @param int $statusCode HTTP状态码
     * @param array $errors 异常信息
     * @param Request|null $request 请求对象
     * @return Response|JsonResponse 响应对象
     *
     * @example
     * // 创建JSON响应
     * return security_response('RateLimit', '访问频率过高', [], 429);
     *
     * // 创建HTML响应
     * return security_response('Blacklist', 'IP在黑名单中', [
     *     'ip' => request()->ip()
     * ], 403);
     *
     * // 在自定义处理器中使用
     * if ($customCheckFailed) {
     *     return security_response('CustomRule', '自定义规则拦截', $details);
     * }
     */
    function security_response(string $type, string $message, array $context = [], int $statusCode = 403, array $errors = [], ?Request $request = null)
    {
        if (is_null($request) && function_exists('request')) {
            $request = \request();
        }

        $title = \zxf\Security\Constants\SecurityEvent::getEventName($type, $message);

        $responseData = [
            'title' => $title,
            'type' => $type,
            'message' => $message,
            'reason' => $title,
            'request_id' => Str::uuid()->toString(),
            'timestamp' => \now()->toISOString(),
            'details' => $context['details'] ?? [],
            'errors' => $errors,
            'context' => $context,
        ];

        // 判断是否返回JSON
        if (!$request || $request->expectsJson() || $request->is('api/*') || $request->ajax()) {
            $format = security_config('ajax_response_format', [
                'code' => 'code',
                'message' => 'message',
                'data' => 'data',
            ]);

            return \response()->json([
                $format['code'] => $statusCode,
                $format['message'] => $message,
                $format['data'] => array_merge( $responseData, security_config('error_view_data', []) ),
            ], $statusCode, [
                'X-Security-Blocked' => 'true',
                'X-Security-Type' => $type,
                'X-Request-ID' => $responseData['request_id'],
            ], JSON_UNESCAPED_UNICODE);
        }

        // 返回HTML响应
        $view = security_config('error_view', 'security::blocked');
        $viewData = array_merge( $responseData, security_config('error_view_data', []) );

        !empty($viewData['context']) && ($viewData['context'] = array_to_pretty_json($viewData['context']));
        !empty($viewData['errors']) && ($viewData['errors'] = array_to_pretty_json($viewData['errors']));

        return response()->view($view, $viewData, $statusCode)
            ->header('X-Security-Blocked', 'true')
            ->header('X-Security-Type', $type)
            ->header('X-Request-ID', $responseData['request_id']);
    }
}

if (! function_exists('array_to_pretty_json')) {
    /**
     * 显示数组/对象为 格式化的json 字符串
     */
    function array_to_pretty_json(array|object|string $array=[]): string
    {
        // 如果是对象，先转换为数组
        if (!is_array($array)) {
            $array = (array) $array;
        }
        // 进行格式化 | 不转义 Unicode 字符 | 不转义斜杠
        return json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}

if (! function_exists('get_all_cache_keys')) {
    /**
     * 获取所有安全包的缓存键 - 文件缓存版本
     *
     * 使用文件缓存驱动获取所有security:前缀的缓存键
     * 注意：此功能仅适用于文件缓存驱动
     *
     * @param string $prefix 键名前缀
     * @param int|null $maxSize 最大返回数量限制
     * @param bool $removePrefix 是否移除缓存键中的前缀
     * @return array 缓存键名数组
     *
     * @example
     *       get_all_cache_keys(); // 获取所有缓存键
     *       get_all_cache_keys('security:'); // 获取指定前缀的缓存键
     *       get_all_cache_keys('', 100); // 限制返回数量
     */
    function get_all_cache_keys(string $prefix = '', ?int $maxSize = null, bool $removePrefix = true): array
    {
        try {
            // 获取缓存存储实例
            $store = Cache::getStore();
            
            // 检查是否为文件缓存驱动
            if ($store instanceof \Illuminate\Cache\FileStore) {
                $cachePath = \storage_path('framework/cache/data');

                $keys = [];
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($cachePath, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $key = $file->getFilename();

                        // Laravel文件缓存的文件名会进行base64编码
                        // 需要解码才能获取原始键名
                        try {
                            $decodedKey = base64_decode(str_replace('.php', '', $key), true);

                            // 只返回security:前缀的键
                            if (empty($prefix) || str_starts_with($decodedKey, $prefix)) {
                                if ($removePrefix && !empty($prefix)) {
                                    $decodedKey = substr($decodedKey, strlen($prefix));
                                }
                                $keys[] = $decodedKey;

                                // 限制返回数量
                                if ($maxSize && count($keys) >= $maxSize) {
                                    break; // 修复：移除break 2，只跳出当前循环
                                }
                            }
                        } catch (\Exception) {
                            // 忽略解码失败的文件
                            continue;
                        }
                    }
                }

                return $keys;
            }
            
            // 非文件缓存驱动，返回空数组
            Log::warning('get_all_cache_keys函数仅支持文件缓存驱动');
            return [];
            
        } catch (\Throwable $e) {
            Log::error('获取缓存键失败: ' . $e->getMessage());
            return [];
        }
    }
}

if (! function_exists('clean_security_cache')) {
    /**
     * 删除 zxf/security 包的所有缓存
     */
    function clean_security_cache(): bool
    {
        try {
            // 获取所有security:前缀的缓存键
            $keys = get_all_cache_keys('security:', null, false);
            
            if (empty($keys)) {
                return true;
            }
            
            // 批量删除
            foreach ($keys as $key) {
                Cache::forget($key);
            }
            
            // 清除服务层缓存
            if (class_exists(\zxf\Security\Services\IpManagerService::class)) {
                $ipManager = \app(\zxf\Security\Services\IpManagerService::class);
                if (method_exists($ipManager, 'clearCache')) {
                    $ipManager->clearCache();
                }
            }

            if (class_exists(\zxf\Security\Services\ThreatDetectionService::class)) {
                $threatDetector = \app(\zxf\Security\Services\ThreatDetectionService::class);
                if (method_exists($threatDetector, 'clearCache')) {
                    $threatDetector->clearCache();
                }
            }

            if (class_exists(\zxf\Security\Services\RateLimiterService::class)) {
                $rateLimiter = \app(\zxf\Security\Services\RateLimiterService::class);
                if (method_exists($rateLimiter, 'clearCache')) {
                    $rateLimiter->clearCache();
                }
            }
            
            return true;
            
        } catch (Throwable $e) {
            Log::error('清除安全缓存失败: ' . $e->getMessage());
            return false;
        }
    }
}

if (! function_exists('is_intranet_ip')) {
    /**
     * 检查IP地址是否为内网/私有地址
     *
     * 核心判定规则
     *
     * 1. 标准私有地址（永远是内网）：
     *    ├─ IPv4：10.0.0.0/8（A类）、172.16.0.0/12（B类）、192.168.0.0/16（C类）
     *    └─ IPv6：fc00::/7（唯一本地地址）
     *
     * 2. 回环地址（默认内网，可禁用）：
     *    ├─ IPv4：127.0.0.0/8（整个127段都是回环）
     *    └─ IPv6：::1/128（仅这一个地址）
     *
     * 3. 链路本地地址（默认内网，可禁用）：
     *    ├─ IPv4：169.254.0.0/16（APIPA自动配置）
     *    └─ IPv6：fe80::/10（本地链路通信）
     *
     * 4. 自定义范围（用户指定）：
     *    └─ 任意CIDR格式，如：'10.0.0.0/8'、'192.168.0.0/16'、'fc00::/7'
     *
     * 配置选项
     *
     * @param array{
     *     loopback?: bool,   // true=回环算内网(默认) false=回环算公网
     *     linklocal?: bool,  // true=链路本地算内网(默认) false=链路本地算公网
     *     custom?: string[]  // 自定义CIDR数组，如：['10.0.0.0/8', '172.16.0.0/12']
     * } $opt
     *
     * @param string $ip 要检查的IP地址（支持IPv4和IPv6）
     * @return bool true=内网IP，false=公网IP
     * @throws InvalidArgumentException IP格式非法时抛出
     */
    function is_intranet_ip(string $ip, array $opt = []): bool {
        // ========== 1. 配置解析 ==========
        $loopback = $opt['loopback'] ?? true;   // 回环开关：127.x.x.x 和 ::1 是否算内网
        $linklocal = $opt['linklocal'] ?? true; // 链路本地开关：169.254.x.x 和 fe80::/10 是否算内网
        $custom = $opt['custom'] ?? [];         // 自定义CIDR数组

        // ========== 2. IP格式验证 ==========
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("无效的IP地址: {$ip}");
        }

        // ========== 3. 二进制转换 ==========
        $ipBin = inet_pton($ip);                    // 二进制IP：IPv4=4字节，IPv6=16字节
        $isV4 = strlen($ipBin) === 4;               // IPv4标志
        $isV6 = strlen($ipBin) === 16;              // IPv6标志

        // ========== 4. CIDR匹配引擎 ==========
        $match = function(string $cidr) use ($ipBin, $isV4): bool {
            // ------------------------------------------------------------
            // CIDR格式说明：
            // - 带掩码：'192.168.1.0/24' 表示前24位是网络位，后8位是主机位
            // - 不带掩码：'192.168.1.1' 表示单个IP，必须完全匹配
            // ------------------------------------------------------------

            // 4.1 处理单个IP（无掩码）
            if (!str_contains($cidr, '/')) {
                $target = inet_pton($cidr);
                return $target !== false && $ipBin === $target;
            }

            // 4.2 解析CIDR：分离网络地址和掩码长度
            [$network, $maskLen] = explode('/', $cidr);
            $maskLen = (int)$maskLen;                // 掩码长度：IPv4范围0-32，IPv6范围0-128

            // 4.3 网络地址转二进制
            $netBin = inet_pton($network);
            if ($netBin === false) return false;    // 防御性编程

            // 4.4 构建网络掩码（这是CIDR匹配的核心）
            $bytes = $isV4 ? 4 : 16;                 // 总字节数
            $fullBytes = intdiv($maskLen, 8);        // 完整字节数：掩码中有几个完整的8位
            $remBits = $maskLen % 8;                  // 剩余位数：不足8位的部分

            // ------------------------------------------------------------
            // 掩码构建原理：
            // 以 192.168.1.0/27 为例，掩码长度27位：
            // - 完整字节：27÷8=3个完整字节 → 3个\xff（11111111 11111111 11111111）
            // - 剩余位：27%8=3位 → 1个字节的高3位为1 → 11100000 (\xE0)
            // - 补齐：总共4字节，已有3+1=4字节，无需补齐
            // 最终掩码：11111111.11111111.11111111.11100000
            // ------------------------------------------------------------

            $mask = '';                              // 初始化掩码

            // 4.4.1 添加完整的字节（全1）
            if ($fullBytes > 0) {
                $mask .= str_repeat("\xff", $fullBytes);
            }

            // 4.4.2 处理剩余的位（如/27的3个剩余位，生成11100000）
            if ($remBits > 0) {
                // 0xff << (8 - 3) = 0xff << 5 = 0xE0 = 11100000
                $mask .= chr(0xff << (8 - $remBits));
                $fullBytes++;  // 消耗了一个字节
            }

            // 4.4.3 补全剩余的字节（全0）
            if ($fullBytes < $bytes) {
                $mask .= str_repeat("\x00", $bytes - $fullBytes);
            }

            // 4.5 执行位运算比较
            // (&)是按位与：只有掩码为1的位才参与比较
            return ($ipBin & $mask) === ($netBin & $mask);
        };

        // ========== 5. 预定义私有范围 ==========
        // 格式：[CIDR, IP版本(4/6), 类型]
        // 类型说明：
        //   0 = 标准私有（永远内网，不受配置影响）
        //   1 = 回环地址（受loopback开关控制）
        //   2 = 链路本地（受linklocal开关控制）
        $ranges = [
            // 5.1 标准私有IPv4（RFC 1918）- 永远内网
            ['10.0.0.0/8', 4, 0],      // 10.0.0.0 - 10.255.255.255
            ['172.16.0.0/12', 4, 0],   // 172.16.0.0 - 172.31.255.255
            ['192.168.0.0/16', 4, 0],  // 192.168.0.0 - 192.168.255.255

            // 5.2 标准私有IPv6（RFC 4193）- 永远内网
            ['fc00::/7', 6, 0],        // fc00:: - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

            // 5.3 回环地址 - 受loopback控制
            ['127.0.0.0/8', 4, 1],     // 127.0.0.0 - 127.255.255.255（整个127段）
            ['::1/128', 6, 1],         // ::1（仅这一个地址）

            // 5.4 链路本地地址 - 受linklocal控制
            ['169.254.0.0/16', 4, 2],  // 169.254.0.0 - 169.254.255.255
            ['fe80::/10', 6, 2]        // fe80:: - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        ];

        // ========== 6. 遍历检查内置范围 ==========
        foreach ($ranges as [$cidr, $version, $type]) {
            // 6.1 IP版本过滤：只检查同版本的范围
            if (($version === 4 && !$isV4) || ($version === 6 && !$isV6)) {
                continue;
            }

            // 6.2 类型过滤：根据配置决定是否检查
            if ($type === 1 && !$loopback) continue;   // 回环被禁用，跳过
            if ($type === 2 && !$linklocal) continue;  // 链路本地被禁用，跳过

            // 6.3 执行CIDR匹配
            if ($match($cidr)) {
                return true;  // 匹配成功，是内网IP
            }
        }

        // ========== 7. 检查自定义范围 ==========
        foreach ($custom as $cidr) {
            if ($match($cidr)) {
                return true;  // 匹配自定义范围，也是内网IP
            }
        }

        // ========== 8. 都不是，判定为公网IP ==========
        return false;
    }
}
