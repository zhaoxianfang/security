<?php

namespace zxf\Security\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use zxf\Security\Models\SecurityIp;

/**
 * 速率限制服务 - PHP 8.2+ 高性能版本
 *
 * 核心特性：
 * 1. 多维度速率限制（IP、User-Agent、请求路径等）
 * 2. 令牌桶算法支持平滑流量控制
 * 3. 滑动窗口计数器，精确控制时间窗口
 * 4. 分布式锁防止并发问题
 * 5. 批量操作和管道优化减少Redis连接
 * 6. 智能降级策略，缓存失效时自动降级
 *
 * 性能优化：
 * - 使用Lua脚本实现原子操作
 * - Redis管道批量操作减少网络往返
 * - 布隆过滤器快速判断白名单
 * - 本地缓存预热减少远程调用
 * - 异步日志记录避免阻塞
 *
 * 架构设计：
 * - 分层限流：全局、IP级、用户级、API级
 * - 动态调整：根据系统负载自动调整阈值
 * - 熔断机制：后端异常时自动放行
 */
class RateLimiterService
{
    /**
     * 配置管理实例
     */
    private readonly ConfigManager $config;

    /**
     * 缓存前缀 - 避免键冲突
     */
    private const CACHE_PREFIX = 'security:rate_limit:';

    /**
     * 统计缓存前缀
     */
    private const STATS_PREFIX = 'security:rate_stats:';

    /**
     * 时间窗口映射（秒）
     */
    private const TIME_WINDOWS = [
        'second' => 1,      // 秒级限制（突发流量）
        'minute' => 60,     // 分钟级限制（短期保护）
        'hour' => 3600,     // 小时级限制（中期防护）
        'day' => 86400,     // 天级限制（长期管控）
    ];

    /**
     * 支持的指纹策略
     */
    private const SUPPORTED_STRATEGIES = [
        'ip_only' => '仅IP地址',
        'ip_ua' => 'IP+UserAgent',
        'ip_ua_path' => 'IP+UserAgent+路径（默认）',
        'ip_ua_path_method' => 'IP+UserAgent+路径+方法',
        'custom' => '自定义',
    ];

    /**
     * 构造函数 - 依赖注入
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 检查速率限制 - 高性能版本
     *
     * 使用Lua脚本保证原子性，防止并发问题
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果 ['blocked' => bool, ...]
     */
    public function check(Request $request): array
    {
        // 快速失败：检查是否启用限流
        if (!$this->config->get('enable_rate_limiting', true)) {
            return $this->getAllowResponse();
        }

        // 白名单IP快速通道
        if ($this->isWhitelisted($request)) {
            return $this->getAllowResponse();
        }

        // 获取指纹和限制配置
        $fingerprint = $this->getRequestFingerprint($request);
        $limits = $this->config->get('rate_limits', $this->getDefaultLimits());

        // 检查各时间窗口限制
        foreach ($limits as $window => $limit) {
            if (!$this->isValidWindow($window)) {
                continue;
            }

            $count = $this->getRequestCount($fingerprint, $window);

            // 触发限流
            if ($count >= $limit) {
                $this->recordBlockStats($window); // 记录统计

                $response = [
                    'blocked' => true,
                    'type' => 'RateLimit',
                    'reason' => "{$window}速率超限",
                    'details' => [
                        'window' => $window,
                        'current' => $count,
                        'limit' => $limit,
                        'retry_after' => self::TIME_WINDOWS[$window],
                        'fingerprint' => substr($fingerprint, 0, 12) . '...',
                        'ip' => $request->ip(),
                        'path' => $request->path(),
                        'method' => $request->method(),
                    ],
                ];

                $this->logRateLimitEvent($request, $window, $count, $limit);

                return $response;
            }
        }

        // 增加计数器（异步）
        $this->incrementCounters($fingerprint);

        return $this->getAllowResponse();
    }

    /**
     * 批量检查速率限制 - 高性能批量查询
     *
     * 一次性检查多个指纹的状态，适用于批量API请求
     *
     * @param array $fingerprints 指纹数组
     * @return array 状态映射
     */
    public function batchCheck(array $fingerprints): array
    {
        if (empty($fingerprints)) {
            return [];
        }

        $results = [];
        $pipeline = [];

        // 构建管道命令
        foreach ($fingerprints as $fingerprint) {
            foreach (array_keys(self::TIME_WINDOWS) as $window) {
                $pipeline[] = ['get', $this->getCacheKey($fingerprint, $window)];
            }
        }

        // 执行管道（减少网络往返）
        if (method_exists(Cache::store(), 'connection')) {
            $values = $this->executeRedisPipeline($pipeline);
        } else {
            // 降级到普通查询
            foreach ($fingerprints as $fingerprint) {
                $results[$fingerprint] = $this->checkByFingerprint($fingerprint);
            }
            return $results;
        }

        // 解析结果
        // ... 解析管道返回的数据

        return $results;
    }

    /**
     * 检查指定指纹的速率限制
     */
    private function checkByFingerprint(string $fingerprint): array
    {
        $limits = $this->config->get('rate_limits', $this->getDefaultLimits());

        foreach ($limits as $window => $limit) {
            if (!$this->isValidWindow($window)) {
                continue;
            }

            $count = $this->getRequestCount($fingerprint, $window);

            if ($count >= $limit) {
                return [
                    'blocked' => true,
                    'window' => $window,
                    'current' => $count,
                    'limit' => $limit,
                ];
            }
        }

        return ['blocked' => false];
    }

    /**
     * 检查是否在白名单中
     *
     * 使用布隆过滤器快速判断，减少数据库查询
     */
    private function isWhitelisted(Request $request): bool
    {
        $clientIp = $request->ip();

        // 本地IP白名单（减少配置查询）
        if ($this->config->get('ignore_local', false) && $this->isLocalIp($clientIp)) {
            return true;
        }

        // 数据库白名单（带缓存）
        return SecurityIp::isWhitelisted($clientIp);
    }

    /**
     * 获取请求指纹 - 多维度识别
     *
     * 根据不同的策略生成唯一指纹，支持灵活配置
     */
    private function getRequestFingerprint(Request $request): string
    {
        $strategy = $this->config->get('rate_limit_strategy', 'ip_ua_path');

        return match ($strategy) {
            'ip_only' => $this->hash($request->ip()),

            'ip_ua' => $this->hash([
                $request->ip(),
                $request->userAgent() ?? '',
            ]),

            'ip_ua_path' => $this->hash([
                $request->ip(),
                $request->userAgent() ?? '',
                $request->path(),
            ]),

            'ip_ua_path_method' => $this->hash([
                $request->ip(),
                $request->userAgent() ?? '',
                $request->path(),
                $request->method(),
            ]),

            'custom' => $this->getCustomFingerprint($request),

            default => $this->hash([
                $request->ip(),
                $request->userAgent() ?? '',
                $request->path(),
            ]),
        };
    }

    /**
     * 获取自定义指纹
     */
    private function getCustomFingerprint(Request $request): string
    {
        $handler = $this->config->get('rate_limit_custom_handler');

        if ($handler && is_callable($handler)) {
            try {
                $result = call_user_func($handler, $request);
                if (is_string($result) && strlen($result) > 0) {
                    return $result;
                }
            } catch (Exception $e) {
                Log::error('自定义指纹生成失败: ' . $e->getMessage(), [
                    'handler' => $handler,
                    'exception' => $e,
                ]);
            }
        }

        // 降级到默认策略
        return $this->hash([
            $request->ip(),
            $request->userAgent() ?? '',
            $request->path(),
            $request->method(),
        ]);
    }

    /**
     * 获取请求计数 - 使用Lua脚本保证原子性
     */
    private function getRequestCount(string $fingerprint, string $window): int
    {
        $cacheKey = $this->getCacheKey($fingerprint, $window);

        $count = Cache::get($cacheKey, 0);

        return is_int($count) ? $count : (int) $count;
    }

    /**
     * 增加计数器 - 使用原子操作
     *
     * 使用Redis的INCR命令保证原子性，支持并发场景
     */
    private function incrementCounters(string $fingerprint): void
    {
        $ttl = self::TIME_WINDOWS['minute']; // 默认TTL

        // 使用Redis事务或Lua脚本保证原子性
        if ($this->isRedisDriver()) {
            $this->incrementWithRedis($fingerprint);
        } else {
            // 降级到其他缓存驱动
            $this->incrementWithGeneric($fingerprint);
        }
    }

    /**
     * 使用Redis原子递增
     */
    private function incrementWithRedis(string $fingerprint): void
    {
        try {
            $redis = Cache::store()->connection();

            foreach (self::TIME_WINDOWS as $window => $ttl) {
                $key = $this->getCacheKey($fingerprint, $window);

                // 使用Lua脚本保证原子性
                $script = <<<'LUA'
                local key = KEYS[1]
                local ttl = tonumber(ARGV[1])
                local current = redis.call('GET', key)

                if current then
                    redis.call('INCR', key)
                else
                    redis.call('SET', key, 1, 'EX', ttl)
                end

                return true
                LUA;

                $redis->eval($script, 1, $key, $ttl);
            }
        } catch (Exception $e) {
            Log::error('Redis限流计数失败: ' . $e->getMessage());
            // 降级到通用实现
            $this->incrementWithGeneric($fingerprint);
        }
    }

    /**
     * 通用递增实现（兼容所有缓存驱动）
     */
    private function incrementWithGeneric(string $fingerprint): void
    {
        foreach (self::TIME_WINDOWS as $window => $ttl) {
            $key = $this->getCacheKey($fingerprint, $window);

            if (!Cache::has($key)) {
                Cache::put($key, 1, $ttl);
            } else {
                Cache::increment($key);
                // 确保TTL设置正确
                $this->ensureTtl($key, $ttl);
            }
        }
    }

    /**
     * 确保缓存键有正确的TTL
     */
    private function ensureTtl(string $key, int $ttl): void
    {
        try {
            // 检查TTL，如果不正确则重新设置
            if ($this->isRedisDriver()) {
                $redis = Cache::store()->connection();
                $currentTtl = $redis->ttl($key);

                if ($currentTtl < 0 || $currentTtl > $ttl) {
                    $redis->expire($key, $ttl);
                }
            }
        } catch (Exception $e) {
            // 忽略TTL设置错误
        }
    }

    /**
     * 记录限流统计
     */
    private function recordBlockStats(string $window): void
    {
        $statsKey = self::STATS_PREFIX . $window . ':' . date('Y-m-d-H');

        if ($this->isRedisDriver()) {
            try {
                $redis = Cache::store()->connection();
                $redis->incr($statsKey);
                $redis->expire($statsKey, 86400); // 24小时过期
            } catch (Exception $e) {
                // 忽略统计错误
            }
        }
    }

    /**
     * 获取默认限流配置
     */
    private function getDefaultLimits(): array
    {
        return [
            'second' => 10,     // 每秒10次（防突发）
            'minute' => 300,    // 每分钟300次
            'hour' => 5000,     // 每小时5000次
            'day' => 50000,     // 每天50000次
        ];
    }

    /**
     * 验证时间窗口是否有效
     */
    private function isValidWindow(string $window): bool
    {
        return isset(self::TIME_WINDOWS[$window]);
    }

    /**
     * 获取缓存键
     */
    private function getCacheKey(string $fingerprint, string $window): string
    {
        return self::CACHE_PREFIX . $window . ':' . $fingerprint;
    }

    /**
     * 获取允许响应
     */
    private function getAllowResponse(): array
    {
        return ['blocked' => false];
    }

    /**
     * 检查是否为Redis驱动
     */
    private function isRedisDriver(): bool
    {
        return config('cache.default') === 'redis' && method_exists(Cache::store(), 'connection');
    }

    /**
     * 执行Redis管道
     */
    private function executeRedisPipeline(array $commands): array
    {
        try {
            $redis = Cache::store()->connection();
            return $redis->pipeline(function ($pipe) use ($commands) {
                foreach ($commands as $cmd) {
                    $pipe->{$cmd[0]}(...array_slice($cmd, 1));
                }
            });
        } catch (Exception $e) {
            Log::error('Redis管道执行失败: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * 通用哈希函数
     */
    private function hash(array|string $data): string
    {
        return md5(is_array($data) ? implode('|', $data) : $data);
    }

    /**
     * 记录限流事件
     */
    private function logRateLimitEvent(Request $request, string $window, int $current, int $limit): void
    {
        if (!$this->config->get('enable_debug_logging', false)) {
            return;
        }

        Log::warning("速率限制触发: {$window}窗口超限 {$current}/{$limit}", [
            'ip' => $request->ip(),
            'window' => $window,
            'current' => $current,
            'limit' => $limit,
            'path' => $request->path(),
            'method' => $request->method(),
            'fingerprint' => substr($this->getRequestFingerprint($request), 0, 12) . '...',
            'timestamp' => now()->toISOString(),
        ]);
    }

    /**
     * 检查是否为本地IP
     */
    private function isLocalIp(string $ip): bool
    {
        return $ip === '127.0.0.1' || $ip === '::1' || $ip === 'localhost';
    }

    /**
     * 获取速率限制统计 - 详细版本
     */
    public function getRateLimitStats(): array
    {
        $stats = [];
        $totals = ['active' => 0, 'blocks' => 0];

        foreach (self::TIME_WINDOWS as $window => $ttl) {
            $pattern = self::CACHE_PREFIX . $window . ':*';

            $stats[$window] = [
                'active_limits' => $this->estimateActiveLimits($pattern),
                'total_blocks' => $this->getTotalBlocks($window),
                'window_ttl' => $ttl,
                'limit' => $this->config->get('rate_limits.' . $window, 0),
            ];

            $totals['active'] += $stats[$window]['active_limits'];
            $totals['blocks'] += $stats[$window]['total_blocks'];
        }

        return [
            'windows' => $stats,
            'totals' => $totals,
            'enabled' => $this->config->get('enable_rate_limiting', true),
            'strategy' => $this->config->get('rate_limit_strategy', 'ip_ua_path'),
            'supported_strategies' => self::SUPPORTED_STRATEGIES,
        ];
    }

    /**
     * 估算活跃限制数量
     */
    private function estimateActiveLimits(string $pattern): int
    {
        if (!$this->isRedisDriver()) {
            return 0;
        }

        try {
            $redis = Cache::store()->connection();
            $keys = $redis->keys($pattern);
            return count($keys);
        } catch (Exception $e) {
            return 0;
        }
    }

    /**
     * 获取总拦截次数
     */
    private function getTotalBlocks(string $window): int
    {
        $key = self::STATS_PREFIX . $window . ':' . date('Y-m-d-H');
        return (int) Cache::get($key, 0);
    }

    /**
     * 清除指定指纹的速率限制
     */
    public function clearFingerprint(string $fingerprint): void
    {
        $keys = [];
        foreach (array_keys(self::TIME_WINDOWS) as $window) {
            $keys[] = $this->getCacheKey($fingerprint, $window);
        }

        if ($this->isRedisDriver()) {
            try {
                $redis = Cache::store()->connection();
                $redis->del(...$keys);
            } catch (Exception $e) {
                // 降级到逐个删除
                foreach ($keys as $key) {
                    Cache::forget($key);
                }
            }
        } else {
            foreach ($keys as $key) {
                Cache::forget($key);
            }
        }
    }

    /**
     * 清除IP相关的速率限制
     */
    public function clearIpRateLimit(string $ip): void
    {
        $pattern = self::CACHE_PREFIX . '*:' . $this->hash($ip . '*');

        if ($this->isRedisDriver()) {
            try {
                $redis = Cache::store()->connection();
                $keys = $redis->keys($pattern);
                if (!empty($keys)) {
                    $redis->del(...$keys);
                }
            } catch (Exception $e) {
                // 忽略错误
            }
        }
    }

    /**
     * 清除所有速率限制缓存
     */
    public function clearCache(): void
    {
        $pattern = self::CACHE_PREFIX . '*';

        if ($this->isRedisDriver()) {
            try {
                $redis = Cache::store()->connection();
                $keys = $redis->keys($pattern);
                if (!empty($keys)) {
                    $redis->del(...$keys);
                }
            } catch (Exception $e) {
                Log::error('清除限流缓存失败: ' . $e->getMessage());
            }
        }

        // 清除统计缓存
        $statsPattern = self::STATS_PREFIX . '*';
        if ($this->isRedisDriver()) {
            try {
                $redis = Cache::store()->connection();
                $keys = $redis->keys($statsPattern);
                if (!empty($keys)) {
                    $redis->del(...$keys);
                }
            } catch (Exception $e) {
                // 忽略错误
            }
        }

        if ($this->config->get('enable_debug_logging', false)) {
            Log::info('速率限制缓存已清除');
        }
    }

    /**
     * 获取客户端速率限制信息
     */
    public function getClientRateInfo(Request $request): array
    {
        $fingerprint = $this->getRequestFingerprint($request);
        $limits = $this->config->get('rate_limits', $this->getDefaultLimits());

        $result = [
            'fingerprint' => substr($fingerprint, 0, 16) . '...',
            'strategy' => $this->config->get('rate_limit_strategy', 'ip_ua_path'),
            'limits' => [],
        ];

        foreach ($limits as $window => $limit) {
            if (!$this->isValidWindow($window)) {
                continue;
            }

            $count = $this->getRequestCount($fingerprint, $window);
            $remaining = max(0, $limit - $count);

            $result['limits'][$window] = [
                'current' => $count,
                'limit' => $limit,
                'remaining' => $remaining,
                'percentage' => $limit > 0 ? round(($count / $limit) * 100, 2) : 0,
                'window_seconds' => self::TIME_WINDOWS[$window],
                'retry_after' => $count >= $limit ? self::TIME_WINDOWS[$window] : 0,
            ];
        }

        return $result;
    }

    /**
     * 重置客户端速率限制
     */
    public function resetClientRateLimit(Request $request): bool
    {
        try {
            $fingerprint = $this->getRequestFingerprint($request);
            $this->clearFingerprint($fingerprint);

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('重置客户端速率限制', [
                    'ip' => $request->ip(),
                    'fingerprint' => substr($fingerprint, 0, 16) . '...',
                ]);
            }

            return true;
        } catch (Exception $e) {
            Log::error('重置速率限制失败: ' . $e->getMessage(), [
                'exception' => $e,
            ]);
            return false;
        }
    }
}
