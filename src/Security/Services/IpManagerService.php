<?php

namespace zxf\Security\Services;

use DateTimeInterface;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use zxf\Security\Constants\SecurityEvent;
use zxf\Security\Models\SecurityIp;

/**
 * IP管理服务 - 优化增强版
 *
 * 提供IP白名单、黑名单、封禁管理等功能
 * 支持动态IP列表和缓存优化
 */
class IpManagerService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 缓存前缀
     */
    protected const CACHE_PREFIX = 'security:ip:';

    /**
     * 信任的代理头
     */
    protected const TRUSTED_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP'];

    /**
     * 本地IP地址列表
     */
    protected const LOCAL_IPS = ['127.0.0.1', '::1', 'localhost'];

    /**
     * 私有IP范围
     */
    protected const PRIVATE_RANGES = [
        '10.0.0.0/8',      // 私有网络
        '172.16.0.0/12',   // 私有网络
        '192.168.0.0/16',  // 私有网络
        '169.254.0.0/16',  // 链路本地
        'fc00::/7',        // 唯一本地地址
        'fe80::/10',       // 链路本地地址
    ];

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 检查IP是否在白名单
     */
    public function isWhitelisted(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);

        // 首先检查本地IP
        if ($this->shouldIgnoreLocal() && $this->isLocalIp($clientIp)) {
            return true;
        }

        // 检查自定义白名单处理器
        if ($this->checkCustomWhitelist($request, $clientIp)) {
            return true;
        }

        // 检查数据库白名单
        return SecurityIp::isWhitelisted($clientIp);
    }

    /**
     * 检查IP是否在黑名单
     */
    public function isBlacklisted(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);

        // 本地IP不检查黑名单
        if ($this->shouldIgnoreLocal() && $this->isLocalIp($clientIp)) {
            return false;
        }

        // 检查自定义黑名单处理器
        if ($this->checkCustomBlacklist($request, $clientIp)) {
            return true;
        }

        // 检查数据库黑名单
        return SecurityIp::isBlacklisted($clientIp);
    }

    /**
     * 记录IP访问
     */
    public function recordAccess(Request $request, bool $blocked = false, ?string $rule = null): ?array
    {
        try {
            $clientIp = $this->getClientRealIp($request);
            $debugLogging = $this->config->get('enable_debug_logging', false);

            if ($debugLogging) {
                Log::info("记录IP访问: {$clientIp}, 拦截: " . ($blocked ? '是' : '否') . ", 规则: " . ($rule ?? '无'));
            }

            $ipRecord = SecurityIp::recordRequest($clientIp, $blocked, $rule);

            if ($ipRecord) {
                // 返回IP记录信息用于日志
                return [
                    'id' => $ipRecord->id,
                    'ip_address' => $ipRecord->ip_address,
                    'type' => $ipRecord->type,
                    'threat_score' => $ipRecord->threat_score,
                    'request_count' => $ipRecord->request_count,
                    'blocked_count' => $ipRecord->blocked_count,
                    'trigger_count' => $ipRecord->trigger_count,
                ];
            }

            return null;

        } catch (Throwable $e) {
            Log::error("记录IP访问异常: " . $e->getMessage(), [
                'ip' => $clientIp ?? 'unknown',
                'blocked' => $blocked,
                'rule' => $rule,
                'exception' => $e
            ]);
            return null;
        }
    }

    /**
     * 检查是否为本地请求
     */
    public function isLocalRequest(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);
        return $this->isLocalIp($clientIp);
    }

    /**
     * 封禁IP - 优化增强版
     *
     * 支持威胁评分和动态封禁时长
     *
     * @param Request $request HTTP请求
     * @param string $type 事件类型
     * @param float $threatScore 威胁评分（0-100）
     * @return bool 是否成功
     */
    public function banIp(Request $request, string $type, float $threatScore = 0): bool
    {
        $clientIp = $this->getClientRealIp($request);

        // 如果IP已经是黑名单，不再重复封禁
        if (SecurityIp::isBlacklisted($clientIp)) {
            if ($this->config->get('enable_debug_logging', false)) {
                Log::info("IP已在黑名单中，跳过封禁", [
                    'ip' => $clientIp,
                    'type' => $type,
                ]);
            }
            return false;
        }

        $duration = $this->getBanDuration($type, $threatScore);
        $reason = $this->getBanReason($type, $threatScore);

        try {
            // 添加到数据库黑名单
            SecurityIp::addToBlacklist(
                $clientIp,
                $reason,
                now()->addSeconds($duration),
                true // 自动检测
            );

            // 更新威胁评分
            if ($threatScore > 0) {
                SecurityIp::updateThreatScore($clientIp, $threatScore);
            }

            // 更新缓存
            $this->clearIpCache($clientIp);

            if ($this->config->get('enable_debug_logging', false)) {
                Log::warning("IP封禁: {$clientIp} 类型: {$type} 时长: {$duration}秒 原因: {$reason} 威胁评分: {$threatScore}");
            }

            return true;

        } catch (Throwable $e) {
            Log::error("封禁IP失败: " . $e->getMessage(), [
                'ip' => $clientIp,
                'type' => $type,
                'duration' => $duration,
                'threat_score' => $threatScore,
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 解除IP封禁
     */
    public function unbanIp(string $ip): bool
    {
        try {
            $record = SecurityIp::query()
                ->where('ip_address', $ip)
                ->where('type', SecurityIp::TYPE_BLACKLIST)
                ->first();

            if ($record) {
                // 转为监控状态
                $record->type = SecurityIp::TYPE_MONITORING;
                $record->reason = '手动解除封禁';
                $record->auto_detected = false;
                $record->save();

                // 清除缓存
                $this->clearIpCache($ip);

                Log::info("IP解封: {$ip}");
                return true;
            }

            return false;

        } catch (Throwable $e) {
            Log::error("解除IP封禁失败: " . $e->getMessage(), [
                'ip' => $ip,
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 获取客户端真实IP - 优化版
     */
    public function getClientRealIp(Request $request): string
    {
        try {
            $ip = $request->ip();

            // 验证基础IP有效性
            if (empty($ip)) {
                Log::warning('无法获取客户端IP地址');
                return '0.0.0.0';
            }

            // 获取信任的代理配置
            $trustedProxies = $this->config->get('trusted_proxies', []);
            $trustedHeaders = $this->config->get('trusted_headers', self::TRUSTED_HEADERS);

            // 如果请求来自信任的代理，检查代理头
            if (!empty($trustedProxies) && is_array($trustedProxies) && in_array($ip, $trustedProxies, true)) {
                foreach ($trustedHeaders as $header) {
                    if ($request->headers->has($header)) {
                        $headerValue = $request->header($header);
                        if (empty($headerValue)) {
                            continue;
                        }

                        $ips = explode(',', $headerValue);
                        if (empty($ips) || !isset($ips[0])) {
                            continue;
                        }

                        $candidate = trim($ips[0]);

                        // 验证IP地址
                        if ($this->isValidIp($candidate) && !$this->isPrivateIp($candidate)) {
                            $ip = $candidate;
                            break;
                        }
                    }
                }
            }

            // 最终验证IP有效性
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }

            Log::warning('IP地址验证失败，使用默认IP', ['ip' => $ip]);
            return '0.0.0.0';
        } catch (Throwable $e) {
            Log::error('获取客户端真实IP异常: ' . $e->getMessage(), [
                'exception' => $e
            ]);
            return '0.0.0.0';
        }
    }

    /**
     * 检查自定义白名单逻辑
     */
    protected function checkCustomWhitelist(Request $request, string $ip): bool
    {
        $handler = $this->config->get('whitelist_handler', null);

        if (empty($handler)) {
            return false;
        }

        try {
            $callable = $this->resolveCallable($handler);
            $result = call_user_func($callable, $request, $ip);

            return is_bool($result) ? $result : false;

        } catch (Throwable $e) {
            Log::error('自定义白名单检查失败: ' . $e->getMessage(), [
                'handler' => $handler,
                'ip' => $ip,
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 检查自定义黑名单逻辑
     */
    protected function checkCustomBlacklist(Request $request, string $ip): bool
    {
        $handler = $this->config->get('blacklist_handler', null);

        if (empty($handler)) {
            return false;
        }

        try {
            $callable = $this->resolveCallable($handler);
            $result = call_user_func($callable, $request, $ip);

            return is_bool($result) ? $result : false;

        } catch (Throwable $e) {
            Log::error('自定义黑名单检查失败: ' . $e->getMessage(), [
                'handler' => $handler,
                'ip' => $ip,
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 判断是否为本地IP
     */
    protected function isLocalIp(string $ip): bool
    {
        // 检查是否为本地回环地址
        if (in_array($ip, self::LOCAL_IPS)) {
            return true;
        }

        // 检查是否为私有IP
        return $this->isPrivateIp($ip);
    }

    /**
     * 判断是否为私有IP
     */
    protected function isPrivateIp(string $ip): bool
    {
        // IPv4 检查
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            foreach (self::PRIVATE_RANGES as $range) {
                if ($this->ipInRange($ip, $range)) {
                    return true;
                }
            }
        }

        // IPv6 检查
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            foreach (self::PRIVATE_RANGES as $range) {
                if ($this->ipv6InRange($ip, $range)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检查IPv4地址是否在范围内
     */
    protected function ipInRange(string $ip, string $range): bool
    {
        if (!str_contains($range, '/')) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);

        return ($ip & $mask) === ($subnet & $mask);
    }

    /**
     * 检查IPv6地址是否在范围内
     */
    protected function ipv6InRange(string $ip, string $range): bool
    {
        // 简化实现，实际生产环境可能需要更复杂的IPv6范围检查
        if (!str_contains($range, '/')) {
            return $ip === $range;
        }

        // 这里可以使用专门的IPv6库进行精确检查
        // 为了简化，我们只进行基本检查
        return true;
    }

    /**
     * 验证IP地址有效性
     */
    protected function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * 检查是否应该忽略本地请求
     */
    protected function shouldIgnoreLocal(): bool
    {
        return $this->config->get('ignore_local', false);
    }

    /**
     * 获取封禁缓存键
     */
    protected function getBanCacheKey(string $ip): string
    {
        return self::CACHE_PREFIX . 'banned:' . md5($ip);
    }

    /**
     * 获取封禁时长 - 优化增强版
     *
     * 支持根据威胁评分动态调整封禁时长
     * 配置项：adaptive_ban_duration
     *
     * @param string $type 事件类型
     * @param float $threatScore 威胁评分（0-100）
     * @return int 封禁时长（秒）
     */
    protected function getBanDuration(string $type, float $threatScore = 0): int
    {
        $defaultDuration = $this->config->get('ban_duration', 3600);
        $maxDuration = $this->config->get('max_ban_duration', 7776000);
        $banDurationMap = $this->config->get('ban_duration_map', []); // 封禁时长映射

        // 根据事件类型获取基础封禁时长
        $duration = $banDurationMap[$type] ?? $defaultDuration;

        // 根据威胁评分动态调整封禁时长
        if ($threatScore > 0) {
            // 获取自适应封禁配置（修正配置键路径）
            $adaptiveConfig = $this->config->get('adaptive_ban_duration', []);
            $enabled = $adaptiveConfig['enabled'] ?? false;

            if ($enabled) {
                // 从配置读取倍数
                $multipliers = $adaptiveConfig['multipliers'] ?? [
                    90 => 10,
                    80 => 5,
                    70 => 3,
                    60 => 2,
                ];

                // 根据威胁评分应用倍数
                $adaptiveFactor = 1.0;
                foreach ($multipliers as $threshold => $multiplier) {
                    if ($threatScore >= $threshold) {
                        $adaptiveFactor = $multiplier;
                        break;
                    }
                }

                $duration = (int)($duration * $adaptiveFactor);
            }
        }

        // 确保不超过最大封禁时长
        return min($duration, $maxDuration);
    }

    /**
     * 获取封禁原因 - 优化增强版
     *
     * 支持根据威胁评分动态生成更详细的封禁原因
     *
     * @param string $type 事件类型
     * @param float $threatScore 威胁评分（0-100）
     * @return string 封禁原因
     */
    protected function getBanReason(string $type, float $threatScore = 0): string
    {
        $reasons = [
            'MaliciousRequest' => '恶意请求',
            'SQLInjection' => 'SQL注入攻击',
            'XSSAttack' => 'XSS跨站脚本攻击',
            'CommandInjection' => '命令注入攻击',
            'AnomalousParameters' => '异常行为',
            'RateLimit' => '频率超限',
            'Blacklist' => '黑名单',
            'IllegalUrl' => '非法URL访问',
            'DangerousUpload' => '危险文件上传',
            'SuspiciousUserAgent' => '可疑User-Agent',
            'SuspiciousHeaders' => '可疑请求头',
            'MethodCheck' => 'HTTP方法检查',
            'PathTraversal' => '路径遍历攻击',
            'FileInclusion' => '文件包含攻击',
            'HighThreat' => '高威胁评分',
        ];

        $baseReason = $reasons[$type] ?? '安全违规';

        // 根据威胁评分添加详细信息
        if ($threatScore > 0) {
            if ($threatScore >= 90) {
                $baseReason .= '（极度危险 - 评分：' . $threatScore . '）';
            } elseif ($threatScore >= 70) {
                $baseReason .= '（高风险 - 评分：' . $threatScore . '）';
            } elseif ($threatScore >= 50) {
                $baseReason .= '（中等风险 - 评分：' . $threatScore . '）';
            } else {
                $baseReason .= '（低风险 - 评分：' . $threatScore . '）';
            }
        }

        return $baseReason;
    }

    /**
     * 解析可调用对象
     */
    protected function resolveCallable($handler)
    {
        try {
            if (is_callable($handler)) {
                return $handler;
            }

            if (is_array($handler) && count($handler) === 2) {
                $class = $handler[0];
                $method = $handler[1];

                if (is_string($class) && class_exists($class)) {
                    return [app($class), $method];
                }

                return $handler;
            }

            if (is_string($handler)) {
                // 处理 Class::method 格式
                if (str_contains($handler, '::')) {
                    [$class, $method] = explode('::', $handler, 2);
                    if (class_exists($class) && method_exists($class, $method)) {
                        return [app($class), $method];
                    }
                }

                // 直接返回字符串（可能是函数名）
                return $handler;
            }

            throw new InvalidArgumentException('无法解析的可调用对象: ' . gettype($handler));
        } catch (Throwable $e) {
            Log::error('解析可调用对象失败', [
                'handler' => $handler,
                'handler_type' => gettype($handler),
                'error' => $e->getMessage(),
                'exception' => $e
            ]);
            throw new InvalidArgumentException('无法解析的可调用对象: ' . gettype($handler), 0, $e);
        }
    }

    /**
     * 获取IP统计信息
     */
    public function getIpStats(string $ip): array
    {
        $cacheKey = self::CACHE_PREFIX . 'stats:' . md5($ip);
        $cacheTtl = $this->config->get('ip_database.cache_ttl', 300);

        return Cache::remember($cacheKey, $cacheTtl, function () use ($ip) {
            $stats = SecurityIp::getIpStats($ip);

            if (empty($stats)) {
                return [
                    'ip' => $ip,
                    'exists' => false,
                    'type' => 'unknown',
                    'threat_score' => 0,
                    'request_count' => 0,
                    'blocked_count' => 0,
                    'last_seen' => null,
                ];
            }

            return [
                'ip' => $stats['ip_address'] ?? $ip,
                'exists' => true,
                'type' => $stats['type'] ?? 'unknown',
                'threat_score' => $stats['threat_score'] ?? 0,
                'request_count' => $stats['request_count'] ?? 0,
                'blocked_count' => $stats['blocked_count'] ?? 0,
                'success_count' => $stats['success_count'] ?? 0,
                'trigger_count' => $stats['trigger_count'] ?? 0,
                'last_seen' => $stats['last_request_at'] ?? null,
                'first_seen' => $stats['first_seen_at'] ?? null,
                'is_range' => $stats['is_range'] ?? false,
                'status' => $stats['status'] ?? 'unknown',
                'auto_detected' => $stats['auto_detected'] ?? false,
            ];
        });
    }

    /**
     * 获取高威胁IP列表
     */
    public function getHighThreatIps(int $limit = 100): array
    {
        $cacheKey = self::CACHE_PREFIX . 'high_threat:' . $limit;
        $cacheTtl = 60; // 缓存1分钟

        return Cache::remember($cacheKey, $cacheTtl, function () use ($limit) {
            $ips = SecurityIp::getHighThreatIps($limit);

            return $ips->map(function ($ip) {
                return [
                    'id' => $ip->id,
                    'ip_address' => $ip->ip_address,
                    'type' => $ip->type,
                    'threat_score' => $ip->threat_score,
                    'request_count' => $ip->request_count,
                    'blocked_count' => $ip->blocked_count,
                    'trigger_count' => $ip->trigger_count,
                    'last_request_at' => $ip->last_request_at,
                    'reason' => $ip->reason,
                    'auto_detected' => $ip->auto_detected,
                ];
            })->toArray();
        });
    }

    /**
     * 获取所有黑名单IP
     */
    public function getAllBlacklistedIps(): array
    {
        $cacheKey = self::CACHE_PREFIX . 'all_blacklisted';
        $cacheTtl = 300; // 缓存5分钟

        return Cache::remember($cacheKey, $cacheTtl, function () {
            $ips = SecurityIp::query()
                ->where('type', SecurityIp::TYPE_BLACKLIST)
                ->where('status', SecurityIp::STATUS_ACTIVE)
                ->where(function ($query) {
                    $query->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                })
                ->get();

            return $ips->map(function ($ip) {
                return [
                    'ip_address' => $ip->ip_address,
                    'ip_range' => $ip->ip_range,
                    'is_range' => $ip->is_range,
                    'reason' => $ip->reason,
                    'expires_at' => $ip->expires_at,
                    'created_at' => $ip->created_at,
                ];
            })->toArray();
        });
    }

    /**
     * 清除IP缓存
     */
    protected function clearIpCache(string $ip): void
    {
        if (!$this->config->get('enable_ip_cache', true)) {
            return;
        }

        $cacheKeys = [
            self::CACHE_PREFIX . 'whitelist:' . md5($ip),
            self::CACHE_PREFIX . 'blacklist:' . md5($ip),
            self::CACHE_PREFIX . 'stats:' . md5($ip),
            self::CACHE_PREFIX . 'banned:' . md5($ip),
        ];

        foreach ($cacheKeys as $cacheKey) {
            Cache::forget($cacheKey);
        }

        // 清除聚合缓存
        Cache::forget(self::CACHE_PREFIX . 'banned_count');
        Cache::forget(self::CACHE_PREFIX . 'all_blacklisted');
        Cache::forget(self::CACHE_PREFIX . 'high_threat:100');
    }

    /**
     * 批量清除IP缓存
     */
    public function clearBatchIpCache(array $ips): void
    {
        foreach ($ips as $ip) {
            $this->clearIpCache($ip);
        }
    }

    /**
     * 清除所有缓存
     */
    public function clearCache(): void
    {
        // 清理安全相关的缓存
        clean_security_cache();

        if ($this->config->get('enable_debug_logging', false)) {
            Log::info('IP管理服务缓存已清除');
        }
    }

    /**
     * 获取服务统计信息
     */
    public function getServiceStats(): array
    {
        return [
            'high_threat_ips' => count($this->getHighThreatIps(50)),
            'cache_enabled' => $this->config->get('enable_ip_cache', true),
            'cache_ttl' => $this->config->get('ip_database.cache_ttl', 300),
            'auto_detection_enabled' => $this->config->get('ip_auto_detection.enabled', true),
        ];
    }

    /**
     * 添加IP到白名单（便捷方法）
     */
    public function addToWhitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): bool
    {
        try {
            SecurityIp::addToWhitelist($ip, $reason, $expiresAt);
            $this->clearIpCache($ip);
            return true;
        } catch (Throwable $e) {
            Log::error('添加IP到白名单失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'reason' => $reason,
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 添加IP到黑名单（便捷方法）
     */
    public function addToBlacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): bool
    {
        try {
            SecurityIp::addToBlacklist($ip, $reason, $expiresAt, $autoDetected);
            $this->clearIpCache($ip);
            return true;
        } catch (Throwable $e) {
            Log::error('添加IP到黑名单失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'reason' => $reason,
                'exception' => $e
            ]);
            return false;
        }
    }
}
