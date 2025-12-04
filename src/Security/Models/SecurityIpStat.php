<?php

namespace zxf\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;

/**
 * 安全IP统计模型 - 优化增强版
 *
 * 功能说明：
 * 1. 记录每日IP统计信息
 * 2. 支持趋势分析和报表生成
 * 3. 优化统计查询性能
 * 4. 提供数据分析和监控功能
 */
class SecurityIpStat extends Model
{
    /**
     * 表名
     */
    protected $table = 'security_ip_stats';

    /**
     * 可批量赋值字段
     */
    protected $fillable = [
        'stat_date',
        'ip_type',
        'total_ips',
        'total_requests',
        'total_blocks',
        'avg_threat_score',
    ];

    /**
     * 属性类型转换
     */
    protected $casts = [
        'stat_date' => 'date',
        'total_ips' => 'integer',
        'total_requests' => 'integer',
        'total_blocks' => 'integer',
        'avg_threat_score' => 'decimal:2',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * 关闭时间戳自动维护
     */
    public $timestamps = true;

    /**
     * 获取统计趋势数据
     *
     * @param string $type IP类型
     * @param int $days 天数
     * @return array
     */
    public static function getTrend(string $type, int $days = 30): array
    {
        return self::query()
            ->where('ip_type', $type)
            ->where('stat_date', '>=', now()->subDays($days))
            ->orderBy('stat_date')
            ->get()
            ->toArray();
    }

    /**
     * 获取日统计汇总
     *
     * @param string $date 日期（格式：Y-m-d）
     * @return array
     */
    public static function getDailySummary(string $date): array
    {
        $stats = self::query()
            ->where('stat_date', $date)
            ->get();

        if ($stats->isEmpty()) {
            return [
                'date' => $date,
                'total_requests' => 0,
                'total_blocks' => 0,
                'total_ips' => 0,
                'avg_threat_score' => 0,
                'details' => [],
            ];
        }

        return [
            'date' => $date,
            'total_requests' => $stats->sum('total_requests'),
            'total_blocks' => $stats->sum('total_blocks'),
            'total_ips' => $stats->sum('total_ips'),
            'avg_threat_score' => round($stats->avg('avg_threat_score'), 2),
            'block_rate' => $stats->sum('total_requests') > 0
                ? round($stats->sum('total_blocks') / $stats->sum('total_requests') * 100, 2)
                : 0,
            'details' => $stats->toArray(),
        ];
    }

    /**
     * 获取时间段统计
     *
     * @param string $startDate 开始日期
     * @param string $endDate 结束日期
     * @return array
     */
    public static function getPeriodStats(string $startDate, string $endDate): array
    {
        $stats = self::query()
            ->whereBetween('stat_date', [$startDate, $endDate])
            ->get()
            ->groupBy('stat_date');

        $result = [];
        foreach ($stats as $date => $dateStats) {
            $result[$date] = [
                'total_requests' => $dateStats->sum('total_requests'),
                'total_blocks' => $dateStats->sum('total_blocks'),
                'total_ips' => $dateStats->sum('total_ips'),
                'avg_threat_score' => round($dateStats->avg('avg_threat_score'), 2),
                'block_rate' => $dateStats->sum('total_requests') > 0
                    ? round($dateStats->sum('total_blocks') / $dateStats->sum('total_requests') * 100, 2)
                    : 0,
            ];
        }

        return $result;
    }

    /**
     * 获取IP类型统计
     *
     * @param string $startDate 开始日期
     * @param string $endDate 结束日期
     * @return array
     */
    public static function getTypeStats(string $startDate, string $endDate): array
    {
        return self::query()
            ->select('ip_type')
            ->selectRaw('SUM(total_ips) as total_ips')
            ->selectRaw('SUM(total_requests) as total_requests')
            ->selectRaw('SUM(total_blocks) as total_blocks')
            ->selectRaw('AVG(avg_threat_score) as avg_threat_score')
            ->whereBetween('stat_date', [$startDate, $endDate])
            ->groupBy('ip_type')
            ->orderBy('total_requests', 'desc')
            ->get()
            ->toArray();
    }

    /**
     * 获取最近N天统计数据
     *
     * @param int $days 天数
     * @return array
     */
    public static function getRecentStats(int $days = 7): array
    {
        return self::getPeriodStats(
            now()->subDays($days)->format('Y-m-d'),
            now()->format('Y-m-d')
        );
    }

    /**
     * 获取月度统计
     *
     * @param int $year 年份
     * @param int $month 月份
     * @return array
     */
    public static function getMonthlyStats(int $year, int $month): array
    {
        $startDate = sprintf('%04d-%02d-01', $year, $month);
        $endDate = date('Y-m-t', strtotime($startDate));

        return self::getPeriodStats($startDate, $endDate);
    }

    /**
     * 获取年度统计
     *
     * @param int $year 年份
     * @return array
     */
    public static function getYearlyStats(int $year): array
    {
        $startDate = sprintf('%04d-01-01', $year);
        $endDate = sprintf('%04d-12-31', $year);

        return self::getPeriodStats($startDate, $endDate);
    }

    /**
     * 获取最高威胁日
     *
     * @param int $limit 限制数量
     * @return array
     */
    public static function getHighestThreatDays(int $limit = 10): array
    {
        return self::query()
            ->select('stat_date')
            ->selectRaw('SUM(total_blocks) as total_blocks')
            ->selectRaw('AVG(avg_threat_score) as avg_threat_score')
            ->groupBy('stat_date')
            ->orderBy('total_blocks', 'desc')
            ->limit($limit)
            ->get()
            ->toArray();
    }

    /**
     * 获取最高请求日
     *
     * @param int $limit 限制数量
     * @return array
     */
    public static function getHighestRequestDays(int $limit = 10): array
    {
        return self::query()
            ->select('stat_date')
            ->selectRaw('SUM(total_requests) as total_requests')
            ->selectRaw('SUM(total_blocks) as total_blocks')
            ->groupBy('stat_date')
            ->orderBy('total_requests', 'desc')
            ->limit($limit)
            ->get()
            ->toArray();
    }

    /**
     * 检查统计数据是否存在
     *
     * @param string $date 日期
     * @param string $type IP类型
     * @return bool
     */
    public static function exists(string $date, string $type): bool
    {
        return self::query()
            ->where('stat_date', $date)
            ->where('ip_type', $type)
            ->exists();
    }

    /**
     * 批量更新或创建统计数据
     *
     * @param array $stats 统计数组
     * @return void
     */
    public static function batchUpsert(array $stats): void
    {
        if (empty($stats)) {
            return;
        }

        $chunks = array_chunk($stats, 100);
        foreach ($chunks as $chunk) {
            self::upsert(
                $chunk,
                ['stat_date', 'ip_type'],
                ['total_ips', 'total_requests', 'total_blocks', 'avg_threat_score', 'updated_at']
            );
        }
    }

    /**
     * 清除旧统计数据
     *
     * @param int $keepDays 保留天数
     * @return int 删除的记录数
     */
    public static function cleanupOldStats(int $keepDays = 365): int
    {
        return self::query()
            ->where('stat_date', '<', now()->subDays($keepDays))
            ->delete();
    }

    /**
     * 范围查询：按日期范围查询
     */
    public function scopeDateRange(Builder $query, string $startDate, string $endDate): Builder
    {
        return $query->whereBetween('stat_date', [$startDate, $endDate]);
    }

    /**
     * 范围查询：按IP类型查询
     */
    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('ip_type', $type);
    }

    /**
     * 范围查询：按高拦截率查询
     */
    public function scopeHighBlockRate(Builder $query, float $threshold = 10.0): Builder
    {
        return $query->whereRaw('total_blocks / NULLIF(total_requests, 0) * 100 >= ?', [$threshold]);
    }

    /**
     * 范围查询：按高威胁评分查询
     */
    public function scopeHighThreatScore(Builder $query, float $threshold = 50.0): Builder
    {
        return $query->where('avg_threat_score', '>=', $threshold);
    }

    /**
     * 获取类型显示名称
     */
    public function getTypeNameAttribute(): string
    {
        return match($this->ip_type) {
            'whitelist' => '白名单',
            'blacklist' => '黑名单',
            'suspicious' => '可疑IP',
            'monitoring' => '监控中',
            default => $this->ip_type,
        };
    }

    /**
     * 获取拦截率
     */
    public function getBlockRateAttribute(): float
    {
        if ($this->total_requests == 0) {
            return 0.0;
        }

        return round($this->total_blocks / $this->total_requests * 100, 2);
    }

    /**
     * 获取统计日期（格式化）
     */
    public function getFormattedDateAttribute(): string
    {
        return $this->stat_date->format('Y年m月d日');
    }

    /**
     * 获取周几
     */
    public function getDayOfWeekAttribute(): string
    {
        $days = ['日', '一', '二', '三', '四', '五', '六'];
        return $days[$this->stat_date->dayOfWeek] ?? '未知';
    }
}
