<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use zxf\Security\Models\SecurityIp;
use Throwable;

/**
 * 安全监控服务
 *
 * 提供实时监控、统计分析和健康检查功能
 * 特性：
 * - 实时性能监控
 * - 安全事件统计
 * - 系统健康检查
 * - 趋势分析
 */
class SecurityMonitor
{
    /**
     * 统计缓存前缀
     */
    protected const STATS_PREFIX = 'security:monitor:';

    /**
     * 性能指标窗口（秒）
     */
    protected const METRICS_WINDOW = 300; // 5分钟

    /**
     * 获取完整监控仪表板数据
     */
    public function getDashboard(): array
    {
        return [
            'summary' => $this->getSummary(),
            'performance' => $this->getPerformanceMetrics(),
            'threats' => $this->getThreatMetrics(),
            'system' => $this->getSystemHealth(),
            'trends' => $this->getTrends(),
            'timestamp' => now()->toISOString(),
        ];
    }

    /**
     * 获取概览统计
     */
    public function getSummary(): array
    {
        try {
            // 使用缓存减少查询压力
            return Cache::remember(self::STATS_PREFIX . 'summary', 60, function () {
                return [
                    'total_ips_tracked' => SecurityIp::query()->count(),
                    'active_blacklist' => SecurityIp::query()
                        ->where('type', SecurityIp::TYPE_BLACKLIST)
                        ->where('status', SecurityIp::STATUS_ACTIVE)
                        ->count(),
                    'active_whitelist' => SecurityIp::query()
                        ->where('type', SecurityIp::TYPE_WHITELIST)
                        ->where('status', SecurityIp::STATUS_ACTIVE)
                        ->count(),
                    'high_threat_ips' => SecurityIp::query()
                        ->where('threat_score', '>=', 50)
                        ->where('status', SecurityIp::STATUS_ACTIVE)
                        ->count(),
                    'blocked_today' => $this->getBlockedToday(),
                    'auto_detected' => SecurityIp::query()
                        ->where('auto_detected', true)
                        ->count(),
                ];
            });
        } catch (Throwable $e) {
            Log::error('获取安全概览失败: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * 获取性能指标
     */
    public function getPerformanceMetrics(): array
    {
        $configManager = ConfigManager::instance();

        return [
            'config' => $configManager->getPreloadStats(),
            'rate_limiter' => $this->getRateLimiterStats(),
            'cache_hit_rate' => $this->getCacheHitRate(),
            'deferred_writes' => SecurityIp::getDeferredWriteStats(),
            'avg_response_time' => $this->getAverageResponseTime(),
        ];
    }

    /**
     * 获取速率限制统计
     */
    protected function getRateLimiterStats(): array
    {
        $stats = [];
        $windows = ['second', 'minute', 'hour', 'day'];

        foreach ($windows as $window) {
            $key = self::STATS_PREFIX . 'blocks:' . $window;
            $blocks = Cache::get($key, 0);

            $stats[$window] = [
                'blocks' => $blocks,
                'window_seconds' => match($window) {
                    'second' => 1,
                    'minute' => 60,
                    'hour' => 3600,
                    'day' => 86400,
                    default => 60,
                },
            ];
        }

        return $stats;
    }

    /**
     * 获取缓存命中率
     */
    protected function getCacheHitRate(): array
    {
        // IP模型缓存统计
        $ipStats = [
            'request_cache_size' => 0, // 从模型获取
        ];

        return [
            'ip_cache' => $ipStats,
            'timestamp' => now()->toISOString(),
        ];
    }

    /**
     * 获取威胁指标
     */
    public function getThreatMetrics(): array
    {
        try {
            return Cache::remember(self::STATS_PREFIX . 'threats', 120, function () {
                // 按威胁等级统计
                $byLevel = [
                    'critical' => SecurityIp::query()->where('threat_score', '>=', 80)->count(),
                    'high' => SecurityIp::query()
                        ->where('threat_score', '>=', 50)
                        ->where('threat_score', '<', 80)
                        ->count(),
                    'medium' => SecurityIp::query()
                        ->where('threat_score', '>=', 20)
                        ->where('threat_score', '<', 50)
                        ->count(),
                    'low' => SecurityIp::query()
                        ->where('threat_score', '>=', 0)
                        ->where('threat_score', '<', 20)
                        ->count(),
                ];

                // 按类型统计
                $byType = [
                    'blacklist' => SecurityIp::query()->where('type', SecurityIp::TYPE_BLACKLIST)->count(),
                    'suspicious' => SecurityIp::query()->where('type', SecurityIp::TYPE_SUSPICIOUS)->count(),
                    'monitoring' => SecurityIp::query()->where('type', SecurityIp::TYPE_MONITORING)->count(),
                    'whitelist' => SecurityIp::query()->where('type', SecurityIp::TYPE_WHITELIST)->count(),
                ];

                // 今日新增威胁
                $newToday = SecurityIp::query()
                    ->where('created_at', '>=', now()->startOfDay())
                    ->where('threat_score', '>', 0)
                    ->count();

                return [
                    'by_level' => $byLevel,
                    'by_type' => $byType,
                    'new_today' => $newToday,
                    'top_threats' => $this->getTopThreats(10),
                ];
            });
        } catch (Throwable $e) {
            Log::error('获取威胁指标失败: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * 获取顶级威胁IP
     */
    protected function getTopThreats(int $limit = 10): array
    {
        try {
            $ips = SecurityIp::query()
                ->select(['ip_address', 'threat_score', 'type', 'blocked_count', 'last_request_at'])
                ->where('threat_score', '>=', 50)
                ->orderByDesc('threat_score')
                ->limit($limit)
                ->get();

            return $ips->map(fn($ip) => [
                'ip' => $ip->ip_address,
                'threat_score' => $ip->threat_score,
                'type' => $ip->type,
                'blocked_count' => $ip->blocked_count,
                'last_seen' => $ip->last_request_at,
            ])->toArray();
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * 获取系统健康状态
     */
    public function getSystemHealth(): array
    {
        $checks = [
            'database' => $this->checkDatabase(),
            'cache' => $this->checkCache(),
            'queue' => $this->checkQueue(),
            'config' => $this->checkConfig(),
        ];

        $allHealthy = !in_array(false, array_column($checks, 'status'), true);

        return [
            'overall_status' => $allHealthy ? 'healthy' : 'degraded',
            'checks' => $checks,
        ];
    }

    /**
     * 检查数据库连接
     */
    protected function checkDatabase(): array
    {
        try {
            $start = microtime(true);
            DB::select('SELECT 1');
            $latency = round((microtime(true) - $start) * 1000, 2);

            return [
                'status' => true,
                'latency_ms' => $latency,
                'message' => 'Database connection OK',
            ];
        } catch (Throwable $e) {
            return [
                'status' => false,
                'latency_ms' => null,
                'message' => 'Database connection failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * 检查缓存连接
     */
    protected function checkCache(): array
    {
        try {
            $start = microtime(true);
            $testKey = self::STATS_PREFIX . 'health:check';
            Cache::put($testKey, 'ok', 10);
            $value = Cache::get($testKey);
            Cache::forget($testKey);
            $latency = round((microtime(true) - $start) * 1000, 2);

            return [
                'status' => $value === 'ok',
                'latency_ms' => $latency,
                'message' => $value === 'ok' ? 'Cache OK' : 'Cache read/write mismatch',
            ];
        } catch (Throwable $e) {
            return [
                'status' => false,
                'latency_ms' => null,
                'message' => 'Cache check failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * 检查队列连接
     */
    protected function checkQueue(): array
    {
        try {
            // 简单检查队列配置
            $queueDriver = config('queue.default');

            return [
                'status' => true,
                'driver' => $queueDriver,
                'message' => 'Queue configured with ' . $queueDriver,
            ];
        } catch (Throwable $e) {
            return [
                'status' => false,
                'driver' => null,
                'message' => 'Queue check failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * 检查配置
     */
    protected function checkConfig(): array
    {
        try {
            $configManager = ConfigManager::instance();
            $stats = $configManager->getPreloadStats();

            return [
                'status' => true,
                'preloaded' => $stats['is_preloaded'],
                'keys_count' => count($stats['preloaded_keys'] ?? []),
                'message' => 'Config manager OK',
            ];
        } catch (Throwable $e) {
            return [
                'status' => false,
                'preloaded' => false,
                'keys_count' => 0,
                'message' => 'Config check failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * 获取趋势数据
     */
    public function getTrends(): array
    {
        try {
            // 过去24小时每小时的拦截数
            $hourlyBlocks = [];
            for ($i = 23; $i >= 0; $i--) {
                $hour = now()->subHours($i);
                $key = self::STATS_PREFIX . 'blocks:hour:' . $hour->format('Y-m-d-H');
                $count = Cache::get($key, 0);
                $hourlyBlocks[] = [
                    'hour' => $hour->format('H:00'),
                    'blocks' => $count,
                ];
            }

            return [
                'hourly_blocks' => $hourlyBlocks,
                'threat_score_trend' => $this->getThreatScoreTrend(),
            ];
        } catch (Throwable $e) {
            Log::error('获取趋势数据失败: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * 获取威胁评分趋势
     */
    protected function getThreatScoreTrend(): array
    {
        try {
            // 过去7天的平均威胁评分
            $trend = [];
            for ($i = 6; $i >= 0; $i--) {
                $date = now()->subDays($i);
                $avg = SecurityIp::query()
                    ->whereDate('created_at', $date)
                    ->avg('threat_score') ?? 0;

                $trend[] = [
                    'date' => $date->format('m-d'),
                    'avg_threat_score' => round((float)$avg, 2),
                ];
            }

            return $trend;
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * 获取今日拦截数
     */
    protected function getBlockedToday(): int
    {
        $total = 0;
        for ($i = 0; $i <= now()->hour; $i++) {
            $key = self::STATS_PREFIX . 'blocks:hour:' . now()->format('Y-m-d-') . str_pad((string)$i, 2, '0', STR_PAD_LEFT);
            $total += Cache::get($key, 0);
        }
        return $total;
    }

    /**
     * 获取平均响应时间
     */
    protected function getAverageResponseTime(): float
    {
        $key = self::STATS_PREFIX . 'response_times';
        $times = Cache::get($key, []);

        if (empty($times)) {
            return 0.0;
        }

        // 只保留最近100个样本
        $times = array_slice($times, -100);
        return round(array_sum($times) / count($times), 4);
    }

    /**
     * 记录响应时间
     */
    public static function recordResponseTime(float $time): void
    {
        $key = self::STATS_PREFIX . 'response_times';
        $times = Cache::get($key, []);
        $times[] = $time;

        // 保持最多1000个样本
        if (count($times) > 1000) {
            $times = array_slice($times, -1000);
        }

        Cache::put($key, $times, self::METRICS_WINDOW);
    }

    /**
     * 记录拦截事件
     */
    public static function recordBlock(string $type, string $window = 'hour'): void
    {
        $key = self::STATS_PREFIX . "blocks:{$window}:" . match($window) {
            'hour' => date('Y-m-d-H'),
            'day' => date('Y-m-d'),
            default => date('Y-m-d-H'),
        };

        Cache::increment($key);
        Cache::put($key, Cache::get($key, 0), 86400 * 7); // 保留7天
    }

    /**
     * 清除所有监控数据
     */
    public function clearMetrics(): void
    {
        $keys = [
            'summary',
            'threats',
            'response_times',
        ];

        foreach ($keys as $key) {
            Cache::forget(self::STATS_PREFIX . $key);
        }

        // 清除小时统计
        for ($i = 0; $i < 24; $i++) {
            $hourKey = self::STATS_PREFIX . 'blocks:hour:' . now()->subHours($i)->format('Y-m-d-H');
            Cache::forget($hourKey);
        }
    }
}
