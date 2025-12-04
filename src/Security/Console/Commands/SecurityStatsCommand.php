<?php

namespace zxf\Security\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use zxf\Security\Models\SecurityIp;
use zxf\Security\Models\SecurityIpStat;

/**
 * 安全统计命令
 *
 * 功能说明：
 * 1. 显示安全系统统计信息
 * 2. 导出安全数据报表
 * 3. 分析安全威胁趋势
 */
class SecurityStatsCommand extends Command
{
    /**
     * 命令名称和签名
     */
    protected $signature = 'security:stats 
                            {--export : 导出统计报表}
                            {--format=csv : 导出格式 (csv, json, html)}
                            {--days=30 : 统计天数}
                            {--detail : 显示详细统计}';

    /**
     * 命令描述
     */
    protected $description = '显示安全系统统计信息和报表';

    /**
     * 执行命令
     */
    public function handle(): int
    {
        $this->info('📊 安全系统统计信息');
        $this->line('');

        try {
            if ($this->option('export')) {
                return $this->exportStats();
            }

            $this->displayStats();

            return self::SUCCESS;

        } catch (Exception $e) {
            $this->error('获取统计信息失败: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    /**
     * 显示统计信息
     */
    protected function displayStats(): void
    {
        // 总体统计
        $this->displayGeneralStats();

        // IP统计
        $this->displayIpStats();

        // 威胁统计
        $this->displayThreatStats();

        // 趋势分析
        $this->displayTrendStats();
    }

    /**
     * 显示总体统计
     */
    protected function displayGeneralStats(): void
    {
        $this->info('📈 总体统计');

        $totalRequests = SecurityIp::sum('request_count');
        $totalBlocks = SecurityIp::sum('blocked_count');
        $totalSuccess = SecurityIp::sum('success_count');

        $blockRate = $totalRequests > 0 ? round($totalBlocks / $totalRequests * 100, 2) : 0;

        $this->table(
            ['指标', '数值'],
            [
                ['总请求数', number_format($totalRequests)],
                ['拦截请求数', number_format($totalBlocks)],
                ['成功请求数', number_format($totalSuccess)],
                ['拦截率', $blockRate . '%'],
                ['IP记录总数', number_format(SecurityIp::count())],
            ]
        );

        $this->line('');
    }

    /**
     * 显示IP统计
     */
    protected function displayIpStats(): void
    {
        $this->info('🌐 IP统计');

        $ipStats = DB::table('security_ips')
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->get();

        $tableData = [];
        foreach ($ipStats as $stat) {
            $tableData[] = [
                '类型' => $this->getTypeName($stat->type),
                '数量' => number_format($stat->count),
                '占比' => $this->calculatePercentage($stat->count, SecurityIp::count()) . '%',
            ];
        }

        $this->table(['类型', '数量', '占比'], $tableData);
        $this->line('');
    }

    /**
     * 显示威胁统计
     */
    protected function displayThreatStats(): void
    {
        if (!$this->option('detail')) {
            return;
        }

        $this->info('⚠️  威胁统计');

        $threatStats = DB::table('security_ips')
            ->select(
                DB::raw('COUNT(*) as total'),
                DB::raw('SUM(CASE WHEN threat_score >= 80 THEN 1 ELSE 0 END) as critical'),
                DB::raw('SUM(CASE WHEN threat_score >= 50 AND threat_score < 80 THEN 1 ELSE 0 END) as high'),
                DB::raw('SUM(CASE WHEN threat_score >= 20 AND threat_score < 50 THEN 1 ELSE 0 END) as medium'),
                DB::raw('SUM(CASE WHEN threat_score < 20 THEN 1 ELSE 0 END) as low')
            )
            ->first();

        $this->table(
            ['威胁等级', '数量', '占比'],
            [
                ['严重 (≥80)', number_format($threatStats->critical), $this->calculatePercentage($threatStats->critical, $threatStats->total) . '%'],
                ['高 (50-79)', number_format($threatStats->high), $this->calculatePercentage($threatStats->high, $threatStats->total) . '%'],
                ['中 (20-49)', number_format($threatStats->medium), $this->calculatePercentage($threatStats->medium, $threatStats->total) . '%'],
                ['低 (<20)', number_format($threatStats->low), $this->calculatePercentage($threatStats->low, $threatStats->total) . '%'],
            ]
        );

        $this->line('');
    }

    /**
     * 显示趋势统计
     */
    protected function displayTrendStats(): void
    {
        $days = (int) $this->option('days');

        $this->info('📅 最近 ' . $days . ' 天趋势');

        $trendStats = SecurityIpStat::where('stat_date', '>=', now()->subDays($days))
            ->orderBy('stat_date')
            ->get()
            ->groupBy('stat_date');

        $tableData = [];
        foreach ($trendStats as $date => $stats) {
            $dateRequests = $stats->sum('total_requests');
            $dateBlocks = $stats->sum('total_blocks');
            $blockRate = $dateRequests > 0 ? round($dateBlocks / $dateRequests * 100, 2) : 0;

            $tableData[] = [
                '日期' => $date,
                '请求数' => number_format($dateRequests),
                '拦截数' => number_format($dateBlocks),
                '拦截率' => $blockRate . '%',
                'IP数量' => number_format($stats->sum('total_ips')),
            ];
        }

        if (!empty($tableData)) {
            $this->table(['日期', '请求数', '拦截数', '拦截率', 'IP数量'], $tableData);
        } else {
            $this->line('暂无趋势数据');
        }

        $this->line('');
    }

    /**
     * 导出统计报表
     */
    protected function exportStats(): int
    {
        $format = $this->option('format');
        $days = (int) $this->option('days');

        $this->info('📤 导出统计报表 (格式: ' . $format . ', 天数: ' . $days . ')');

        $data = $this->collectExportData($days);

        return match ($format) {
            'json' => $this->exportJson($data),
            'html' => $this->exportHtml($data),
            default => $this->exportCsv($data),
        };
    }

    /**
     * 收集导出数据
     */
    protected function collectExportData(int $days): array
    {
        return [
            'export_time' => now()->toISOString(),
            'period_days' => $days,
            'general_stats' => $this->getGeneralStats(),
            'ip_stats' => $this->getIpStats(),
            'threat_stats' => $this->getThreatStats(),
            'trend_stats' => $this->getTrendStats($days),
            'high_threat_ips' => SecurityIp::getHighThreatIps(100)->toArray(),
        ];
    }

    /**
     * 获取总体统计
     */
    protected function getGeneralStats(): array
    {
        $totalRequests = SecurityIp::sum('request_count');
        $totalBlocks = SecurityIp::sum('blocked_count');

        return [
            'total_requests' => $totalRequests,
            'total_blocks' => $totalBlocks,
            'total_success' => SecurityIp::sum('success_count'),
            'block_rate' => $totalRequests > 0 ? round($totalBlocks / $totalRequests * 100, 2) : 0,
            'total_ips' => SecurityIp::count(),
            'enabled' => security_config('enabled', true),
            'rate_limiting_enabled' => security_config('enable_rate_limiting', true),
            'auto_detection_enabled' => security_config('ip_auto_detection.enabled', true),
        ];
    }

    /**
     * 获取IP统计
     */
    protected function getIpStats(): array
    {
        return DB::table('security_ips')
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->get()
            ->mapWithKeys(function ($item) {
                return [$item->type => [
                    'count' => $item->count,
                    'name' => $this->getTypeName($item->type),
                ]];
            })
            ->toArray();
    }

    /**
     * 获取威胁统计
     */
    protected function getThreatStats(): array
    {
        $stats = DB::table('security_ips')
            ->select(
                DB::raw('COUNT(*) as total'),
                DB::raw('AVG(threat_score) as avg_score'),
                DB::raw('MAX(threat_score) as max_score'),
                DB::raw('SUM(CASE WHEN threat_score >= 80 THEN 1 ELSE 0 END) as critical'),
                DB::raw('SUM(CASE WHEN threat_score >= 50 AND threat_score < 80 THEN 1 ELSE 0 END) as high'),
                DB::raw('SUM(CASE WHEN threat_score >= 20 AND threat_score < 50 THEN 1 ELSE 0 END) as medium'),
                DB::raw('SUM(CASE WHEN threat_score < 20 THEN 1 ELSE 0 END) as low')
            )
            ->first();

        return [
            'total' => $stats->total,
            'avg_score' => round($stats->avg_score, 2),
            'max_score' => $stats->max_score,
            'critical' => $stats->critical,
            'high' => $stats->high,
            'medium' => $stats->medium,
            'low' => $stats->low,
        ];
    }

    /**
     * 获取趋势统计
     */
    protected function getTrendStats(int $days): array
    {
        return SecurityIpStat::where('stat_date', '>=', now()->subDays($days))
            ->orderBy('stat_date')
            ->get()
            ->groupBy('stat_date')
            ->map(function ($stats, $date) {
                return [
                    'date' => $date,
                    'total_requests' => $stats->sum('total_requests'),
                    'total_blocks' => $stats->sum('total_blocks'),
                    'total_ips' => $stats->sum('total_ips'),
                    'avg_threat_score' => round($stats->avg('avg_threat_score'), 2),
                ];
            })
            ->values()
            ->toArray();
    }

    /**
     * 导出JSON格式
     */
    protected function exportJson(array $data): int
    {
        $filename = 'security_stats_' . date('Ymd_His') . '.json';
        $filepath = storage_path('app/' . $filename);

        file_put_contents($filepath, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        $this->info('✅ 统计报表已导出: ' . $filepath);
        return self::SUCCESS;
    }

    /**
     * 导出CSV格式
     */
    protected function exportCsv(array $data): int
    {
        $filename = 'security_stats_' . date('Ymd_His') . '.csv';
        $filepath = storage_path('app/' . $filename);

        $fp = fopen($filepath, 'w');

        // 写入总体统计
        fputcsv($fp, ['总体统计']);
        fputcsv($fp, ['指标', '数值']);
        foreach ($data['general_stats'] as $key => $value) {
            fputcsv($fp, [$key, $value]);
        }
        fputcsv($fp, []); // 空行

        // 写入IP统计
        fputcsv($fp, ['IP类型统计']);
        fputcsv($fp, ['类型', '数量']);
        foreach ($data['ip_stats'] as $stats) {
            fputcsv($fp, [$stats['name'], $stats['count']]);
        }
        fputcsv($fp, []); // 空行

        // 写入趋势统计
        fputcsv($fp, ['趋势统计']);
        fputcsv($fp, ['日期', '请求数', '拦截数', 'IP数量', '平均威胁评分']);
        foreach ($data['trend_stats'] as $trend) {
            fputcsv($fp, [
                $trend['date'],
                $trend['total_requests'],
                $trend['total_blocks'],
                $trend['total_ips'],
                $trend['avg_threat_score'],
            ]);
        }

        fclose($fp);

        $this->info('✅ 统计报表已导出: ' . $filepath);
        return self::SUCCESS;
    }

    /**
     * 导出HTML格式
     */
    protected function exportHtml(array $data): int
    {
        $filename = 'security_stats_' . date('Ymd_His') . '.html';
        $filepath = storage_path('app/' . $filename);

        $html = view('security::stats_report', $data)->render();
        file_put_contents($filepath, $html);

        $this->info('✅ 统计报表已导出: ' . $filepath);
        return self::SUCCESS;
    }

    /**
     * 获取类型名称
     */
    protected function getTypeName(string $type): string
    {
        return match($type) {
            'whitelist' => '白名单',
            'blacklist' => '黑名单',
            'suspicious' => '可疑IP',
            'monitoring' => '监控中',
            default => $type,
        };
    }

    /**
     * 计算百分比
     */
    protected function calculatePercentage(int $part, int $total): string
    {
        if ($total === 0) {
            return '0.00';
        }

        return number_format($part / $total * 100, 2);
    }
}
