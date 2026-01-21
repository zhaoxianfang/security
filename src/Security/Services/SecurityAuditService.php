<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

/**
 * 安全审计服务
 *
 * 提供安全审计和监控功能：
 * 1. 安全事件记录
 * 2. 威胁趋势分析
 * 3. 异常行为检测
 * 4. 安全报告生成
 * 5. 审计日志管理
 */
class SecurityAuditService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 审计缓存
     */
    protected array $auditCache = [];

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 记录安全事件
     *
     * @param array $event 事件数据
     */
    public function logEvent(array $event): void
    {
        $eventData = [
            'timestamp' => now()->toDateTimeString(),
            'ip' => $event['ip'] ?? null,
            'type' => $event['type'] ?? 'unknown',
            'level' => $event['level'] ?? 'info',
            'message' => $event['message'] ?? '',
            'data' => $event['data'] ?? [],
        ];

        // 记录到日志
        $this->logByLevel($eventData['level'], $eventData);

        // 记录到审计缓存
        $this->addToAuditCache($eventData);

        // 记录到数据库（如果启用）
        if ($this->config->get('enable_audit_database', false)) {
            $this->saveToDatabase($eventData);
        }
    }

    /**
     * 添加到审计缓存
     *
     * @param array $event 事件数据
     */
    protected function addToAuditCache(array $event): void
    {
        $cacheKey = 'security:audit:events';
        $events = Cache::get($cacheKey, []);

        $events[] = $event;

        // 保留最近1000条记录
        if (count($events) > 1000) {
            $events = array_slice($events, -1000);
        }

        Cache::put($cacheKey, $events, 3600);
    }

    /**
     * 按级别记录日志
     *
     * @param string $level 日志级别
     * @param array $event 事件数据
     */
    protected function logByLevel(string $level, array $event): void
    {
        $message = $event['message'];
        $context = [
            'ip' => $event['ip'],
            'type' => $event['type'],
            'data' => $event['data'],
        ];

        switch ($level) {
            case 'debug':
                Log::debug($message, $context);
                break;
            case 'info':
                Log::info($message, $context);
                break;
            case 'warning':
                Log::warning($message, $context);
                break;
            case 'error':
                Log::error($message, $context);
                break;
            case 'critical':
                Log::critical($message, $context);
                break;
            default:
                Log::info($message, $context);
        }
    }

    /**
     * 保存到数据库
     *
     * @param array $event 事件数据
     */
    protected function saveToDatabase(array $event): void
    {
        try {
            // 这里可以根据需要创建审计表
            // 暂时跳过，避免依赖具体表结构
        } catch (\Exception $e) {
            Log::error('保存审计日志到数据库失败', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * 获取审计事件统计
     *
     * @param int $hours 统计小时数
     * @return array
     */
    public function getEventStats(int $hours = 24): array
    {
        $cacheKey = 'security:audit:events';
        $events = Cache::get($cacheKey, []);

        $stats = [
            'total' => count($events),
            'by_type' => [],
            'by_level' => [],
            'by_ip' => [],
            'top_ips' => [],
        ];

        $threshold = now()->subHours($hours);

        foreach ($events as $event) {
            $eventTime = Carbon::parse($event['timestamp']);

            // 过滤时间范围
            if ($eventTime->lt($threshold)) {
                continue;
            }

            // 按类型统计
            $type = $event['type'];
            if (!isset($stats['by_type'][$type])) {
                $stats['by_type'][$type] = 0;
            }
            $stats['by_type'][$type]++;

            // 按级别统计
            $level = $event['level'];
            if (!isset($stats['by_level'][$level])) {
                $stats['by_level'][$level] = 0;
            }
            $stats['by_level'][$level]++;

            // 按IP统计
            $ip = $event['ip'] ?? 'unknown';
            if (!isset($stats['by_ip'][$ip])) {
                $stats['by_ip'][$ip] = 0;
            }
            $stats['by_ip'][$ip]++;
        }

        // 获取Top 10 IP
        arsort($stats['by_ip']);
        $stats['top_ips'] = array_slice($stats['by_ip'], 0, 10, true);

        return $stats;
    }

    /**
     * 获取威胁趋势
     *
     * @param int $hours 统计小时数
     * @return array
     */
    public function getThreatTrends(int $hours = 24): array
    {
        $cacheKey = 'security:audit:events';
        $events = Cache::get($cacheKey, []);

        $trends = [];
        $threshold = now()->subHours($hours);

        // 初始化小时统计
        for ($i = $hours - 1; $i >= 0; $i--) {
            $hour = now()->subHours($i)->format('Y-m-d H:00');
            $trends[$hour] = [
                'total' => 0,
                'blocked' => 0,
                'threats' => 0,
            ];
        }

        foreach ($events as $event) {
            $eventTime = Carbon::parse($event['timestamp']);

            if ($eventTime->lt($threshold)) {
                continue;
            }

            $hour = $eventTime->format('Y-m-d H:00');

            if (isset($trends[$hour])) {
                $trends[$hour]['total']++;

                if ($event['type'] === 'blocked') {
                    $trends[$hour]['blocked']++;
                }

                if (in_array($event['level'], ['warning', 'error', 'critical'])) {
                    $trends[$hour]['threats']++;
                }
            }
        }

        return $trends;
    }

    /**
     * 生成安全报告
     *
     * @param int $hours 报告小时数
     * @return array
     */
    public function generateReport(int $hours = 24): array
    {
        $stats = $this->getEventStats($hours);
        $trends = $this->getThreatTrends($hours);

        return [
            'period' => "最近{$hours}小时",
            'generated_at' => now()->toDateTimeString(),
            'event_stats' => $stats,
            'threat_trends' => $trends,
            'summary' => $this->generateSummary($stats),
        ];
    }

    /**
     * 生成摘要
     *
     * @param array $stats 统计数据
     * @return array
     */
    protected function generateSummary(array $stats): array
    {
        return [
            'total_events' => $stats['total'],
            'blocked_requests' => $stats['by_type']['blocked'] ?? 0,
            'top_threat_type' => $this->getTopThreatType($stats['by_type']),
            'most_active_ip' => $this->getMostActiveIp($stats['top_ips']),
            'security_level' => $this->calculateSecurityLevel($stats),
        ];
    }

    /**
     * 获取最高威胁类型
     *
     * @param array $byType 按类型统计
     * @return string
     */
    protected function getTopThreatType(array $byType): string
    {
        arsort($byType);
        $topType = array_key_first($byType) ?: '无';

        return $topType;
    }

    /**
     * 获取最活跃IP
     *
     * @param array $topIps Top IP列表
     * @return string
     */
    protected function getMostActiveIp(array $topIps): string
    {
        return array_key_first($topIps) ?: '无';
    }

    /**
     * 计算安全等级
     *
     * @param array $stats 统计数据
     * @return string
     */
    protected function calculateSecurityLevel(array $stats): string
    {
        $threats = ($stats['by_level']['critical'] ?? 0) +
                   ($stats['by_level']['error'] ?? 0) +
                   ($stats['by_level']['warning'] ?? 0);

        $ratio = $stats['total'] > 0 ? $threats / $stats['total'] : 0;

        if ($ratio > 0.5) {
            return '高风险';
        } elseif ($ratio > 0.2) {
            return '中等风险';
        } else {
            return '安全';
        }
    }

    /**
     * 检测异常行为
     *
     * @return array
     */
    public function detectAnomalies(): array
    {
        $stats = $this->getEventStats(1); // 最近1小时
        $anomalies = [];

        // 检查高频率IP
        foreach ($stats['by_ip'] as $ip => $count) {
            if ($count > 100) { // 1小时超过100次
                $anomalies[] = [
                    'type' => 'high_frequency_ip',
                    'ip' => $ip,
                    'count' => $count,
                    'severity' => $count > 500 ? 'critical' : 'warning',
                    'recommendation' => 'IP请求频率异常，建议检查是否为攻击',
                ];
            }
        }

        // 检查异常事件类型
        foreach ($stats['by_type'] as $type => $count) {
            if ($count > 50) {
                $anomalies[] = [
                    'type' => 'high_frequency_event',
                    'event_type' => $type,
                    'count' => $count,
                    'severity' => 'warning',
                    'recommendation' => "事件类型 {$type} 频率较高",
                ];
            }
        }

        return $anomalies;
    }

    /**
     * 清理过期审计日志
     *
     * @param int $days 保留天数
     * @return int 清理数量
     */
    public function cleanupOldLogs(int $days = 7): int
    {
        $cacheKey = 'security:audit:events';
        $events = Cache::get($cacheKey, []);

        $threshold = now()->subDays($days);
        $originalCount = count($events);

        $filteredEvents = array_filter($events, function ($event) use ($threshold) {
            $eventTime = Carbon::parse($event['timestamp']);
            return $eventTime->gte($threshold);
        });

        $cleanedCount = $originalCount - count($filteredEvents);

        if ($cleanedCount > 0) {
            Cache::put($cacheKey, array_values($filteredEvents), 3600);
            Log::info("清理了 {$cleanedCount} 条过期审计日志", [
                'retention_days' => $days,
            ]);
        }

        return $cleanedCount;
    }
}
