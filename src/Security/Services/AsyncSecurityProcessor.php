<?php

namespace zxf\Security\Services;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Throwable;
use zxf\Security\Models\SecurityIp;

/**
 * 异步安全处理器
 *
 * 将耗时操作放入队列异步处理，提高响应速度
 * 支持：
 * - 批量IP记录更新
 * - 威胁分析
 * - 日志记录
 * - 缓存预热
 */
class AsyncSecurityProcessor implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * 任务类型
     */
    public const TYPE_BATCH_RECORD = 'batch_record';
    public const TYPE_THREAT_ANALYSIS = 'threat_analysis';
    public const TYPE_CACHE_WARMUP = 'cache_warmup';
    public const TYPE_CLEANUP = 'cleanup';
    public const TYPE_LOG_AGGREGATION = 'log_aggregation';

    /**
     * 任务类型
     */
    protected string $type;

    /**
     * 任务数据
     */
    protected array $data;

    /**
     * 任务重试次数
     */
    public int $tries = 3;

    /**
     * 任务超时时间（秒）
     */
    public int $timeout = 120;

    /**
     * 构造函数
     *
     * @param string $type 任务类型
     * @param array $data 任务数据
     */
    public function __construct(string $type, array $data = [])
    {
        $this->type = $type;
        $this->data = $data;

        // 根据任务类型设置队列
        $this->onQueue(match($type) {
            self::TYPE_BATCH_RECORD => 'security:records',
            self::TYPE_THREAT_ANALYSIS => 'security:analysis',
            self::TYPE_CACHE_WARMUP => 'security:warmup',
            self::TYPE_CLEANUP => 'security:cleanup',
            default => 'security:default',
        });
    }

    /**
     * 执行任务
     */
    public function handle(): void
    {
        $startTime = microtime(true);

        try {
            match ($this->type) {
                self::TYPE_BATCH_RECORD => $this->processBatchRecord(),
                self::TYPE_THREAT_ANALYSIS => $this->processThreatAnalysis(),
                self::TYPE_CACHE_WARMUP => $this->processCacheWarmup(),
                self::TYPE_CLEANUP => $this->processCleanup(),
                self::TYPE_LOG_AGGREGATION => $this->processLogAggregation(),
                default => Log::warning("未知的安全异步任务类型: {$this->type}"),
            };

            $elapsed = round((microtime(true) - $startTime) * 1000, 2);
            Log::debug("安全异步任务完成", [
                'type' => $this->type,
                'elapsed_ms' => $elapsed,
            ]);

        } catch (Throwable $e) {
            Log::error("安全异步任务失败: {$this->type}", [
                'error' => $e->getMessage(),
                'data' => $this->data,
                'exception' => $e,
            ]);
            throw $e;
        }
    }

    /**
     * 处理批量记录
     */
    protected function processBatchRecord(): void
    {
        $records = $this->data['records'] ?? [];

        if (empty($records)) {
            return;
        }

        // 使用模型的批量记录方法
        SecurityIp::batchRecordRequests($records);

        Log::info("批量IP记录处理完成", [
            'count' => count($records),
        ]);
    }

    /**
     * 处理威胁分析
     */
    protected function processThreatAnalysis(): void
    {
        $ip = $this->data['ip'] ?? null;
        $events = $this->data['events'] ?? [];

        if (!$ip || empty($events)) {
            return;
        }

        // 获取IP记录
        $record = SecurityIp::query()
            ->where('ip_address', $ip)
            ->first();

        if (!$record) {
            return;
        }

        // 计算威胁评分
        $threatScore = $this->calculateThreatScore($events);

        // 更新威胁评分
        $record->threat_score = min(100.00, max(0.00, $threatScore));
        $record->checkAndUpdateType();
        $record->save();

        // 清除缓存
        SecurityIp::clearIpCache($ip);

        Log::info("威胁分析完成", [
            'ip' => $ip,
            'threat_score' => $threatScore,
            'events_count' => count($events),
        ]);
    }

    /**
     * 处理缓存预热
     */
    protected function processCacheWarmup(): void
    {
        $ips = $this->data['ips'] ?? [];

        if (empty($ips)) {
            return;
        }

        // 预热IP白名单/黑名单缓存
        foreach ($ips as $ip) {
            SecurityIp::isWhitelisted($ip);
            SecurityIp::isBlacklisted($ip);
        }

        Log::info("缓存预热完成", [
            'ips_count' => count($ips),
        ]);
    }

    /**
     * 处理清理任务
     */
    protected function processCleanup(): void
    {
        // 清理过期记录
        $deleted = SecurityIp::cleanupExpired();

        // 清理过期缓存
        clean_security_cache();

        Log::info("安全清理任务完成", [
            'deleted_records' => $deleted,
        ]);
    }

    /**
     * 处理日志聚合
     */
    protected function processLogAggregation(): void
    {
        $logs = $this->data['logs'] ?? [];

        if (empty($logs)) {
            return;
        }

        // 按IP聚合日志
        $aggregated = [];
        foreach ($logs as $log) {
            $ip = $log['ip'] ?? 'unknown';
            if (!isset($aggregated[$ip])) {
                $aggregated[$ip] = [
                    'requests' => 0,
                    'blocked' => 0,
                    'events' => [],
                ];
            }
            $aggregated[$ip]['requests']++;
            if ($log['blocked'] ?? false) {
                $aggregated[$ip]['blocked']++;
            }
            $aggregated[$ip]['events'][] = $log['event'] ?? 'unknown';
        }

        // 更新IP统计
        foreach ($aggregated as $ip => $stats) {
            SecurityIp::recordRequest($ip, $stats['blocked'] > 0, implode(',', array_unique($stats['events'])));
        }

        Log::info("日志聚合处理完成", [
            'logs_count' => count($logs),
            'unique_ips' => count($aggregated),
        ]);
    }

    /**
     * 计算威胁评分
     */
    protected function calculateThreatScore(array $events): float
    {
        $score = 0;
        $weights = [
            'SQLInjection' => 30,
            'XSSAttack' => 25,
            'CommandInjection' => 35,
            'RateLimit' => 10,
            'Blacklist' => 50,
            'MaliciousRequest' => 20,
        ];

        foreach ($events as $event) {
            $score += $weights[$event] ?? 5;
        }

        return min(100, $score);
    }

    /**
     * 任务失败处理
     */
    public function failed(Throwable $exception): void
    {
        Log::error("安全异步任务最终失败", [
            'type' => $this->type,
            'data' => $this->data,
            'error' => $exception->getMessage(),
        ]);
    }

    /**
     * 创建批量记录任务
     */
    public static function batchRecord(array $records): void
    {
        if (empty($records)) {
            return;
        }

        // 如果记录数较少，直接处理
        if (count($records) < 10) {
            SecurityIp::batchRecordRequests($records);
            return;
        }

        // 大量记录使用队列
        self::dispatch(new self(self::TYPE_BATCH_RECORD, ['records' => $records]));
    }

    /**
     * 创建威胁分析任务
     */
    public static function analyzeThreat(string $ip, array $events): void
    {
        self::dispatch(new self(self::TYPE_THREAT_ANALYSIS, [
            'ip' => $ip,
            'events' => $events,
        ]));
    }

    /**
     * 创建缓存预热任务
     */
    public static function warmupCache(array $ips): void
    {
        if (empty($ips)) {
            return;
        }

        // 分批处理，每批100个
        $chunks = array_chunk($ips, 100);
        foreach ($chunks as $chunk) {
            self::dispatch(new self(self::TYPE_CACHE_WARMUP, ['ips' => $chunk]));
        }
    }

    /**
     * 创建清理任务
     */
    public static function scheduleCleanup(): void
    {
        self::dispatch(new self(self::TYPE_CLEANUP));
    }

    /**
     * 创建日志聚合任务
     */
    public static function aggregateLogs(array $logs): void
    {
        if (empty($logs)) {
            return;
        }

        // 分批处理，每批1000条
        $chunks = array_chunk($logs, 1000);
        foreach ($chunks as $chunk) {
            self::dispatch(new self(self::TYPE_LOG_AGGREGATION, ['logs' => $chunk]));
        }
    }
}
