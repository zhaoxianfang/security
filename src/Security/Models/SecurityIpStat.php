<?php

namespace zxf\Security\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 安全IP统计模型
 *
 * 功能说明：
 * 1. 记录每日IP统计信息
 * 2. 支持趋势分析和报表生成
 * 3. 优化统计查询性能
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
}