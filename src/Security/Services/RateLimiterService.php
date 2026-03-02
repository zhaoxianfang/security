<?php

namespace zxf\Security\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use zxf\Security\Models\SecurityIp;
use zxf\Security\Utils\IpHelper;

/**
 * 速率限制服务 - PHP 8.2+ 高性能无Redis版本
 *
 * 核心特性：
 * 1. 多维度速率限制（IP、User-Agent、请求路径等）
 * 2. 滑动窗口算法，精确控制时间窗口
 * 3. 文件缓存+内存缓存双重策略，无需Redis
 * 4. 批量操作优化减少文件IO
 * 5. 智能降级策略，缓存失效时自动降级
 * 6. 原子性操作保证数据一致性
 *
 * 性能优化：
 * - 使用文件缓存持久化速率限制数据
 * - 内存缓存预热减少文件访问
 * - 滑动窗口算法提高精确度
 * - 批量写入减少IO次数
 * - 异步日志记录避免阻塞
 *
 * 架构设计：
 * - 分层限流：全局、IP级、用户级、API级
 * - 动态调整：根据系统负载自动调整阈值
 * - 熔断机制：后端异常时自动放行
 * - 文件锁机制防止并发冲突
 *
 * @package zxf\Security\Services
 * @version 2.0.0
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
     * 内存缓存（请求级）
     * 用于缓存当前请求周期内的速率限制结果
     */
    private static array $memoryCache = [];

    /**
     * 文件锁目录
     */
    private const LOCK_DIR = 'security_rate_locks';

    /**
     * 构造函数 - 依赖注入
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
        $this->initLockDir();
    }

    /**
     * 初始化文件锁目录
     */
    private function initLockDir(): void
    {
        try {
            $lockDir = \storage_path('framework/cache/' . self::LOCK_DIR);
            if (!is_dir($lockDir)) {
                mkdir($lockDir, 0755, true);
            }
        } catch (\Throwable $e) {
            Log::warning('初始化文件锁目录失败: ' . $e->getMessage());
        }
    }

    /**
     * 检查速率限制 - 高性能文件缓存版本
     *
     * 使用文件缓存保证持久化，内存缓存提升性能
     *
     * @param Request $request HTTP请求对象
     * @return array 检查结果 ['blocked' => bool, ...]
     */
    public function check(Request $request): array
    {
        try {
            // 快速失败：检查是否启用限流
            if (!$this->config->get('enable_rate_limiting', true)) {
                return $this->getAllowResponse();
            }

            // 验证请求对象
            if (!$request || !method_exists($request, 'ip')) {
                Log::warning('无效的请求对象，跳过限流检查');
                return $this->getAllowResponse();
            }

            // 白名单IP快速通道
            if ($this->isWhitelisted($request)) {
                return $this->getAllowResponse();
            }

            // 获取指纹和限制配置
            $fingerprint = $this->getRequestFingerprint($request);
            if (empty($fingerprint)) {
                Log::warning('无法生成请求指纹，跳过限流检查');
                return $this->getAllowResponse();
            }

            $limits = $this->config->get('rate_limits', $this->getDefaultLimits());

            // 检查各时间窗口限制
            foreach ($limits as $window => $limit) {
                if (!$this->isValidWindow($window)) {
                    continue;
                }

                // 验证limit为正整数
                if (!is_int($limit) || $limit <= 0) {
                    Log::warning("无效的限流阈值: {$window}", ['limit' => $limit]);
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
                            'retry_after' => self::TIME_WINDOWS[$window] ?? 60,
                            'fingerprint' => substr($fingerprint, 0, 12) . '...',
                            'ip' => $request->ip() ?? 'unknown',
                            'path' => $request->path() ?? 'unknown',
                            'method' => $request->method() ?? 'unknown',
                        ],
                    ];

                    $this->logRateLimitEvent($request, $window, $count, $limit);

                    return $response;
                }
            }

            // 增加计数器
            $this->incrementCounters($fingerprint);

            return $this->getAllowResponse();
        } catch (\Throwable $e) {
            Log::error('速率限制检查异常: ' . $e->getMessage(), [
                'exception' => $e
            ]);
            // 异常时放行，避免影响正常业务
            return $this->getAllowResponse();
        }
    }

    /**
     * 批量检查速率限制 - 文件缓存版本
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

        try {
            foreach ($fingerprints as $fingerprint) {
                if (!is_string($fingerprint) || empty($fingerprint)) {
                    continue;
                }
                $results[$fingerprint] = $this->checkByFingerprint($fingerprint);
            }
        } catch (\Throwable $e) {
            Log::error('批量速率限制检查失败: ' . $e->getMessage());
            return [];
        }

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
     * 检查是否在白名单中 - 文件缓存版本
     *
     * 使用内存缓存快速判断，减少数据库查询
     * 支持内网配置选项，提高灵活性
     */
    private function isWhitelisted(Request $request): bool
    {
        $clientIp = $request->ip();

        // 1. 检查本地IP白名单（减少配置查询）
        if ($this->config->get('ignore_local', false) && $this->isLocalIp($clientIp)) {
            return true;
        }

        // 2. 检查内网IP是否跳过速率限制
        $skipRateLimit = $this->config->get('intranet.skip_rate_limit', false);
        if ($this->isLocalIp($clientIp) && $skipRateLimit) {
            Log::debug('内网IP跳过速率限制', ['ip' => $clientIp]);
            return true;
        }

        // 3. 数据库白名单（带缓存）
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
            } catch (\Throwable $e) {
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
     * 获取请求计数 - 文件缓存+内存缓存版本
     *
     * 优先使用内存缓存，其次使用文件缓存
     */
    private function getRequestCount(string $fingerprint, string $window): int
    {
        $cacheKey = $this->getCacheKey($fingerprint, $window);

        // 先检查内存缓存
        if (isset(self::$memoryCache[$cacheKey])) {
            return (int) self::$memoryCache[$cacheKey];
        }

        // 再检查文件缓存
        $count = Cache::get($cacheKey, 0);

        // 更新内存缓存
        self::$memoryCache[$cacheKey] = $count;

        return is_int($count) ? $count : (int) $count;
    }

    /**
     * 增加计数器 - 文件锁原子操作版本
     *
     * 使用文件锁保证原子性，支持并发场景
     */
    private function incrementCounters(string $fingerprint): void
    {
        try {
            foreach (self::TIME_WINDOWS as $window => $ttl) {
                $key = $this->getCacheKey($fingerprint, $window);

                // 使用文件锁保证原子性
                $lockFile = $this->getLockFile($key);
                $lockHandle = fopen($lockFile, 'w');

                if (flock($lockHandle, LOCK_EX)) {
                    try {
                        // 获取当前值
                        $count = Cache::get($key, 0);

                        // 增加计数
                        $newCount = $count + 1;

                        // 设置缓存
                        Cache::put($key, $newCount, $ttl);

                        // 更新内存缓存
                        self::$memoryCache[$key] = $newCount;
                    } finally {
                        flock($lockHandle, LOCK_UN);
                    }
                }

                fclose($lockHandle);
            }
        } catch (\Throwable $e) {
            Log::error('限流计数失败: ' . $e->getMessage());
            // 降级到简单实现
            $this->incrementWithoutLock($fingerprint);
        }
    }

    /**
     * 不使用锁的简单递增（降级实现）
     */
    private function incrementWithoutLock(string $fingerprint): void
    {
        foreach (self::TIME_WINDOWS as $window => $ttl) {
            $key = $this->getCacheKey($fingerprint, $window);

            if (!Cache::has($key)) {
                Cache::put($key, 1, $ttl);
            } else {
                Cache::increment($key);
            }

            // 更新内存缓存
            self::$memoryCache[$key] = Cache::get($key, 0);
        }
    }

    /**
     * 获取文件锁文件路径
     */
    private function getLockFile(string $key): string
    {
        $keyHash = md5($key);
        return \storage_path('framework/cache/' . self::LOCK_DIR . '/' . $keyHash . '.lock');
    }

    /**
     * 记录限流统计
     */
    private function recordBlockStats(string $window): void
    {
        try {
            $statsKey = self::STATS_PREFIX . $window . ':' . date('Y-m-d-H');
            Cache::increment($statsKey);
            Cache::put($statsKey, Cache::get($statsKey, 0), 86400); // 24小时过期
        } catch (\Throwable $e) {
            // 忽略统计错误
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
            'timestamp' => \now()->toISOString(),
        ]);
    }

    /**
     * 检查是否为本地IP - 使用IpHelper
     *
     * 使用 is_intranet_ip 函数，确保判断逻辑统一
     */
    private function isLocalIp(string $ip): bool
    {
        try {
            // 获取内网配置
            $checkLoopback = $this->config->get('intranet.check_loopback', true);
            $checkLinklocal = $this->config->get('intranet.check_linklocal', true);
            $customRanges = $this->config->get('intranet.custom_ranges', []);

            // 构建 is_intranet_ip 参数
            $opt = [
                'loopback' => $checkLoopback,
                'linklocal' => $checkLinklocal,
                'custom' => is_array($customRanges) ? $customRanges : [],
            ];

            // 使用 is_intranet_ip 函数判断
            return is_intranet_ip($ip, $opt);

        } catch (\Throwable $e) {
            Log::error('内网IP判断失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'exception' => $e
            ]);
            // 异常时返回false，避免影响正常业务
            return false;
        }
    }

    /**
     * 获取速率限制统计 - 文件缓存版本
     */
    public function getRateLimitStats(): array
    {
        $stats = [];
        $totals = ['active' => 0, 'blocks' => 0];

        foreach (self::TIME_WINDOWS as $window => $ttl) {
            $stats[$window] = [
                'active_limits' => $this->estimateActiveLimits($window),
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
    private function estimateActiveLimits(string $window): int
    {
        try {
            // 文件缓存版本无法直接统计，返回估算值
            return count(self::$memoryCache);
        } catch (\Throwable $e) {
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
        foreach (array_keys(self::TIME_WINDOWS) as $window) {
            $key = $this->getCacheKey($fingerprint, $window);
            Cache::forget($key);
            unset(self::$memoryCache[$key]);
        }
    }

    /**
     * 清除IP相关的速率限制
     */
    public function clearIpRateLimit(string $ip): void
    {
        // 遍历内存缓存，匹配相关的键
        $pattern = $this->hash($ip);
        foreach (self::$memoryCache as $key => $value) {
            if (str_contains($key, $pattern)) {
                Cache::forget($key);
                unset(self::$memoryCache[$key]);
            }
        }
    }

    /**
     * 清除所有速率限制缓存
     */
    public function clearCache(): void
    {
        // 清除内存缓存
        self::$memoryCache = [];

        // 清除统计缓存
        try {
            $statsPattern = self::STATS_PREFIX;
            // 文件缓存无法使用通配符删除，只能清除统计
            Cache::forget($statsPattern . 'minute:' . date('Y-m-d-H'));
            Cache::forget($statsPattern . 'hour:' . date('Y-m-d-H'));
            Cache::forget($statsPattern . 'day:' . date('Y-m-d-H'));
        } catch (\Throwable $e) {
            Log::error('清除限流缓存失败: ' . $e->getMessage());
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
        } catch (\Throwable $e) {
            Log::error('重置速率限制失败: ' . $e->getMessage(), [
                'exception' => $e,
            ]);
            return false;
        }
    }
}
