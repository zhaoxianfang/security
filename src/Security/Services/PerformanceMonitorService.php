<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

/**
 * 性能监控服务
 *
 * 监控安全中间件的性能和资源消耗：
 * 1. 请求处理时间统计
 * 2. 内存使用统计
 * 3. 缓存命中率
 * 4. 检测层性能分析
 * 5. 性能瓶颈识别
 */
class PerformanceMonitorService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 性能统计缓存
     */
    protected array $statsCache = [];

    /**
     * 当前请求的开始时间
     */
    protected float $requestStartTime = 0;

    /**
     * 当前请求的内存使用
     */
    protected int $requestStartMemory = 0;

    /**
     * 检测层耗时统计
     */
    protected array $layerTimings = [];

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 开始监控请求
     */
    public function startRequestMonitoring(): void
    {
        $this->requestStartTime = microtime(true);
        $this->requestStartMemory = memory_get_usage(true);
        $this->layerTimings = [];
    }

    /**
     * 结束监控请求
     *
     * @return array 性能数据
     */
    public function endRequestMonitoring(): array
    {
        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $duration = ($endTime - $this->requestStartTime) * 1000; // 毫秒
        $memoryUsed = ($endMemory - $this->requestStartMemory) / 1024 / 1024; // MB

        $stats = [
            'duration_ms' => $duration,
            'memory_mb' => $memoryUsed,
            'layer_timings' => $this->layerTimings,
            'timestamp' => time(),
        ];

        // 记录到统计缓存
        $this->updateStatsCache($stats);

        // 检查性能阈值
        $this->checkPerformanceThresholds($stats);

        return $stats;
    }

    /**
     * 开始监控检测层
     *
     * @param string $layer 检测层名称
     */
    public function startLayerTiming(string $layer): void
    {
        $this->layerTimings[$layer] = [
            'start' => microtime(true),
            'duration' => 0,
        ];
    }

    /**
     * 结束监控检测层
     *
     * @param string $layer 检测层名称
     */
    public function endLayerTiming(string $layer): void
    {
        if (isset($this->layerTimings[$layer])) {
            $startTime = $this->layerTimings[$layer]['start'];
            $duration = (microtime(true) - $startTime) * 1000; // 毫秒
            $this->layerTimings[$layer]['duration'] = $duration;
        }
    }

    /**
     * 更新统计缓存
     *
     * @param array $stats 性能数据
     */
    protected function updateStatsCache(array $stats): void
    {
        $cacheKey = 'security:performance:stats';

        // 获取现有统计
        $existingStats = Cache::get($cacheKey, [
            'total_requests' => 0,
            'total_duration' => 0,
            'total_memory' => 0,
            'max_duration' => 0,
            'max_memory' => 0,
            'layer_stats' => [],
        ]);

        // 更新统计
        $existingStats['total_requests']++;
        $existingStats['total_duration'] += $stats['duration_ms'];
        $existingStats['total_memory'] += $stats['memory_mb'];
        $existingStats['max_duration'] = max($existingStats['max_duration'], $stats['duration_ms']);
        $existingStats['max_memory'] = max($existingStats['max_memory'], $stats['memory_mb']);

        // 更新检测层统计
        foreach ($stats['layer_timings'] as $layer => $timing) {
            if (!isset($existingStats['layer_stats'][$layer])) {
                $existingStats['layer_stats'][$layer] = [
                    'total_duration' => 0,
                    'count' => 0,
                    'max_duration' => 0,
                ];
            }

            $existingStats['layer_stats'][$layer]['total_duration'] += $timing['duration'];
            $existingStats['layer_stats'][$layer]['count']++;
            $existingStats['layer_stats'][$layer]['max_duration'] = max(
                $existingStats['layer_stats'][$layer]['max_duration'],
                $timing['duration']
            );
        }

        // 缓存更新（1分钟）
        Cache::put($cacheKey, $existingStats, 60);
    }

    /**
     * 检查性能阈值
     *
     * @param array $stats 性能数据
     */
    protected function checkPerformanceThresholds(array $stats): void
    {
        $thresholds = [
            'warning_duration' => 100, // 100ms
            'critical_duration' => 500, // 500ms
            'warning_memory' => 10, // 10MB
            'critical_memory' => 50, // 50MB
        ];

        if ($stats['duration_ms'] > $thresholds['critical_duration']) {
            Log::warning('安全检测耗时过长', [
                'duration_ms' => $stats['duration_ms'],
                'memory_mb' => $stats['memory_mb'],
                'layer_timings' => $stats['layer_timings'],
            ]);
        } elseif ($stats['duration_ms'] > $thresholds['warning_duration']) {
            Log::debug('安全检测耗时较高', [
                'duration_ms' => $stats['duration_ms'],
                'memory_mb' => $stats['memory_mb'],
            ]);
        }

        if ($stats['memory_mb'] > $thresholds['critical_memory']) {
            Log::warning('安全检测内存消耗过高', [
                'memory_mb' => $stats['memory_mb'],
                'duration_ms' => $stats['duration_ms'],
            ]);
        } elseif ($stats['memory_mb'] > $thresholds['warning_memory']) {
            Log::debug('安全检测内存消耗较高', [
                'memory_mb' => $stats['memory_mb'],
            ]);
        }
    }

    /**
     * 获取性能统计
     *
     * @return array
     */
    public function getPerformanceStats(): array
    {
        $cacheKey = 'security:performance:stats';
        $stats = Cache::get($cacheKey, [
            'total_requests' => 0,
            'total_duration' => 0,
            'total_memory' => 0,
            'max_duration' => 0,
            'max_memory' => 0,
            'layer_stats' => [],
        ]);

        // 计算平均值
        $avgDuration = $stats['total_requests'] > 0
            ? $stats['total_duration'] / $stats['total_requests']
            : 0;

        $avgMemory = $stats['total_requests'] > 0
            ? $stats['total_memory'] / $stats['total_requests']
            : 0;

        // 计算各层平均耗时
        $layerAverages = [];
        foreach ($stats['layer_stats'] as $layer => $layerStats) {
            if ($layerStats['count'] > 0) {
                $layerAverages[$layer] = [
                    'avg_duration_ms' => $layerStats['total_duration'] / $layerStats['count'],
                    'max_duration_ms' => $layerStats['max_duration'],
                    'count' => $layerStats['count'],
                ];
            }
        }

        return [
            'total_requests' => $stats['total_requests'],
            'avg_duration_ms' => round($avgDuration, 2),
            'max_duration_ms' => round($stats['max_duration'], 2),
            'avg_memory_mb' => round($avgMemory, 2),
            'max_memory_mb' => round($stats['max_memory'], 2),
            'layer_stats' => $layerAverages,
            'generated_at' => time(),
        ];
    }

    /**
     * 识别性能瓶颈
     *
     * @return array
     */
    public function identifyBottlenecks(): array
    {
        $stats = $this->getPerformanceStats();
        $bottlenecks = [];

        // 检查检测层耗时
        foreach ($stats['layer_stats'] as $layer => $layerStats) {
            if ($layerStats['avg_duration_ms'] > 10) { // 平均超过10ms
                $bottlenecks[] = [
                    'type' => 'slow_layer',
                    'layer' => $layer,
                    'avg_duration_ms' => $layerStats['avg_duration_ms'],
                    'severity' => $layerStats['avg_duration_ms'] > 50 ? 'critical' : 'warning',
                    'recommendation' => "检测层 {$layer} 耗时较长，建议优化",
                ];
            }
        }

        // 检查整体性能
        if ($stats['avg_duration_ms'] > 50) {
            $bottlenecks[] = [
                'type' => 'overall_performance',
                'avg_duration_ms' => $stats['avg_duration_ms'],
                'severity' => $stats['avg_duration_ms'] > 100 ? 'critical' : 'warning',
                'recommendation' => '整体检测耗时较长，建议检查配置和优化规则',
            ];
        }

        return $bottlenecks;
    }

    /**
     * 重置统计
     */
    public function resetStats(): void
    {
        $cacheKey = 'security:performance:stats';
        Cache::forget($cacheKey);

        Log::info('性能统计已重置');
    }

    /**
     * 获取系统资源使用情况
     *
     * @return array
     */
    public function getSystemResources(): array
    {
        return [
            'memory_usage_mb' => round(memory_get_usage(true) / 1024 / 1024, 2),
            'memory_peak_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'cpu_load' => $this->getCpuLoad(),
        ];
    }

    /**
     * 获取CPU负载
     *
     * @return array
     */
    protected function getCpuLoad(): array
    {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            return [
                'load_1min' => $load[0] ?? 0,
                'load_5min' => $load[1] ?? 0,
                'load_15min' => $load[2] ?? 0,
            ];
        }

        return [
            'load_1min' => 0,
            'load_5min' => 0,
            'load_15min' => 0,
        ];
    }
}
