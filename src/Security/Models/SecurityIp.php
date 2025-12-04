<?php

namespace zxf\Security\Models;

use DateTimeInterface;
use Exception;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * 安全IP管理模型 - 优化增强版
 *
 * 功能说明：
 * 1. 统一管理白名单、黑名单、可疑IP
 * 2. 支持IP段范围检查和匹配
 * 3. 自动威胁检测和状态转换
 * 4. 高性能统计和查询优化
 * 5. 智能缓存和批量处理
 */
class SecurityIp extends Model
{
    /**
     * 表名
     */
    protected $table = 'security_ips';

    /**
     * 可批量赋值字段
     */
    protected $fillable = [
        'ip_address',
        'ip_range',
        'is_range',
        'type',
        'status',
        'reason',
        'request_count',
        'blocked_count',
        'success_count',
        'threat_score',
        'last_request_at',
        'first_seen_at',
        'auto_detected',
        'trigger_count',
        'trigger_rules',
        'expires_at',
    ];

    /**
     * 属性类型转换
     */
    protected $casts = [
        'is_range' => 'boolean',
        'auto_detected' => 'boolean',
        'threat_score' => 'decimal:2',
        'request_count' => 'integer',
        'blocked_count' => 'integer',
        'success_count' => 'integer',
        'trigger_count' => 'integer',
        'trigger_rules' => 'array',
        'last_request_at' => 'datetime',
        'first_seen_at' => 'datetime',
        'expires_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * IP类型常量
     */
    const TYPE_WHITELIST = 'whitelist';    // 白名单
    const TYPE_BLACKLIST = 'blacklist';    // 黑名单
    const TYPE_SUSPICIOUS = 'suspicious';  // 可疑IP
    const TYPE_MONITORING = 'monitoring';  // 监控中

    /**
     * 状态常量
     */
    const STATUS_ACTIVE = 'active';    // 激活
    const STATUS_INACTIVE = 'inactive'; // 禁用
    const STATUS_PENDING = 'pending';   // 待审核

    /**
     * 缓存键前缀
     */
    const CACHE_PREFIX = 'security:ip:';

    /**
     * 缓存时间（秒）
     */
    const CACHE_TTL = 300; // 5分钟

    /**
     * 批量处理大小
     */
    const BATCH_SIZE = 1000;

    /**
     * 检查IP是否在白名单中
     *
     * @param string $ip 要检查的IP地址
     * @return bool 是否在白名单中
     */
    public static function isWhitelisted(string $ip): bool
    {
        $cacheKey = self::CACHE_PREFIX . 'whitelist:' . md5($ip);

        // 如果禁用IP缓存，直接查询数据库
        if (!security_config('enable_ip_cache', true)) {
            return self::queryWhitelist($ip);
        }

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($ip) {
            return self::queryWhitelist($ip);
        });
    }

    /**
     * 查询白名单
     */
    protected static function queryWhitelist(string $ip): bool
    {
        return self::query()
            ->where('status', self::STATUS_ACTIVE)
            ->where('type', self::TYPE_WHITELIST)
            ->where(function (Builder $query) use ($ip) {
                $query->where(function (Builder $q) use ($ip) {
                    // 精确匹配单个IP
                    $q->where('is_range', false)
                        ->where('ip_address', $ip);
                })->orWhere(function (Builder $q) use ($ip) {
                    // IP段匹配
                    $q->where('is_range', true)
                        ->whereRaw('INET_ATON(?) BETWEEN INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) AND (INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) + (POW(2, 32 - CAST(SUBSTRING_INDEX(ip_range, \'/\', -1) AS UNSIGNED)) - 1))', [$ip]);
                });
            })
            ->where(function (Builder $query) {
                // 检查过期时间
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }

    /**
     * 检查IP是否在黑名单中
     *
     * @param string $ip 要检查的IP地址
     * @return bool 是否在黑名单中
     */
    public static function isBlacklisted(string $ip): bool
    {
        $cacheKey = self::CACHE_PREFIX . 'blacklist:' . md5($ip);

        // 如果禁用IP缓存，直接查询数据库
        if (!security_config('enable_ip_cache', true)) {
            return self::queryBlacklist($ip);
        }

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($ip) {
            return self::queryBlacklist($ip);
        });
    }

    /**
     * 查询黑名单
     */
    protected static function queryBlacklist(string $ip): bool
    {
        return self::query()
            ->where('status', self::STATUS_ACTIVE)
            ->where('type', self::TYPE_BLACKLIST)
            ->where(function (Builder $query) use ($ip) {
                $query->where(function (Builder $q) use ($ip) {
                    // 精确匹配单个IP
                    $q->where('is_range', false)
                        ->where('ip_address', $ip);
                })->orWhere(function (Builder $q) use ($ip) {
                    // IP段匹配
                    $q->where('is_range', true)
                        ->whereRaw('INET_ATON(?) BETWEEN INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) AND (INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) + (POW(2, 32 - CAST(SUBSTRING_INDEX(ip_range, \'/\', -1) AS UNSIGNED)) - 1))', [$ip]);
                });
            })
            ->where(function (Builder $query) {
                // 检查过期时间
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }

    /**
     * 记录IP访问请求 - 优化版
     *
     * @param string $ip 访问IP
     * @param bool $blocked 是否被拦截
     * @param string|null $rule 触发规则
     * @return self|null 返回IP记录实例
     */
    public static function recordRequest(string $ip, bool $blocked = false, ?string $rule = null): ?self
    {
        $debugLogging = security_config('enable_debug_logging', false);

        if ($debugLogging) {
            Log::info("开始记录IP请求: {$ip}, 拦截: " . ($blocked ? '是' : '否') . ", 规则: " . ($rule ?? '无'));
        }

        try {
            DB::beginTransaction();

            // 查找或创建IP记录
            /** @var self $ipRecord */
            $ipRecord = self::firstOrCreate(
                ['ip_address' => $ip, 'is_range' => false],
                [
                    'type' => self::TYPE_MONITORING,
                    'status' => self::STATUS_ACTIVE,
                    'first_seen_at' => now(),
                    'threat_score' => 0.00,
                    'request_count' => 0,
                    'blocked_count' => 0,
                    'success_count' => 0,
                    'auto_detected' => false,
                    'trigger_count' => 0,
                ]
            );

            if ($debugLogging) {
                Log::info("找到或创建IP记录: ID={$ipRecord->id}, IP={$ipRecord->ip_address}, 当前类型={$ipRecord->type}, 威胁评分={$ipRecord->threat_score}, 触发次数={$ipRecord->trigger_count}");
            }

            // 保存原始值用于比较
            $originalType = $ipRecord->type;
            $originalThreatScore = $ipRecord->threat_score;
            $originalTriggerCount = $ipRecord->trigger_count;

            // 更新统计信息
            $ipRecord->request_count++;
            $ipRecord->last_request_at = now();

            // 设置原因（如果有）
            if ($rule) {
                $ipRecord->reason = $rule;
            }

            if ($blocked) {
                $ipRecord->blocked_count++;

                // 拦截时增加威胁评分
                $addScore = (float) security_config('ip_auto_detection.add_threat_score', 10.00);
                $newThreatScore = $ipRecord->threat_score + $addScore;
                $ipRecord->threat_score = min(100.00, $newThreatScore);

                if ($debugLogging) {
                    Log::info("IP拦截记录: 威胁评分 {$originalThreatScore} -> {$ipRecord->threat_score} (+{$addScore})");
                }

                // 记录触发规则
                if ($rule) {
                    $ipRecord->trigger_count++;

                    $triggerRules = $ipRecord->trigger_rules ?? [];

                    if (!in_array($rule, $triggerRules)) {
                        $triggerRules[] = $rule;
                        $ipRecord->trigger_rules = array_slice($triggerRules, 0, 10); // 最多保存10条规则
                    }

                    $ipRecord->auto_detected = true;

                    if ($debugLogging) {
                        Log::info("记录触发规则: {$rule}, 触发次数 {$originalTriggerCount} -> {$ipRecord->trigger_count}");
                    }
                }
            } else {
                $ipRecord->success_count++;

                // 成功请求时降低威胁评分
                $reduceScore = (float) security_config('ip_auto_detection.reduce_threat_score', 1.00);
                $newThreatScore = $ipRecord->threat_score - $reduceScore;
                $ipRecord->threat_score = max(0.00, $newThreatScore);

                if ($debugLogging && $reduceScore > 0) {
                    Log::info("IP成功记录: 威胁评分 {$originalThreatScore} -> {$ipRecord->threat_score} (-{$reduceScore})");
                }
            }

            // 应用自然衰减
            $ipRecord->applyNaturalDecay();

            // 在保存前检查类型转换
            if ($blocked && $rule) {
                if ($debugLogging) {
                    Log::info("准备检查类型转换: 当前类型={$ipRecord->type}, 威胁评分={$ipRecord->threat_score}, 触发次数={$ipRecord->trigger_count}");
                }

                $ipRecord->checkAndUpdateType();

                if ($debugLogging) {
                    Log::info("检查后类型: {$ipRecord->type}");
                }
            }

            // 保存记录
            $ipRecord->save();

            if ($debugLogging) {
                if ($originalType !== $ipRecord->type) {
                    Log::info("IP类型变更: {$originalType} -> {$ipRecord->type}, 原因: {$ipRecord->reason}");
                }
                Log::info("IP记录保存成功: ID={$ipRecord->id}, 最终类型={$ipRecord->type}");
            }

            // 清除相关缓存
            self::clearIpCache($ip);

            // 异步更新统计表
            if ($blocked) {
                self::updateDailyStatsAsync();
            }

            DB::commit();

            return $ipRecord;

        } catch (Exception $e) {
            DB::rollBack();
            Log::error('记录IP访问失败: ' . $e->getMessage(), [
                'ip' => $ip,
                'blocked' => $blocked,
                'rule' => $rule,
                'exception' => $e
            ]);
            return null;
        }
    }

    /**
     * 异步更新统计信息
     */
    protected static function updateDailyStatsAsync(): void
    {
        // 如果禁用批量处理，直接更新
        if (!security_config('enable_batch_processing', true)) {
            self::updateDailyStats();
            return;
        }

        // 使用延迟队列更新统计
        if (function_exists('dispatch') && class_exists(Dispatchable::class)) {
            dispatch(function () {
                self::updateDailyStats();
            })->delay(now()->addSeconds(10));
        } else {
            // 如果没有队列，直接执行
            self::updateDailyStats();
        }
    }

    /**
     * 检查并自动更新IP类型
     */
    public function checkAndUpdateType(): void
    {
        $config = security_config('ip_auto_detection', []);

        if (!$config['enabled'] ?? true) {
            return;
        }

        // 确保正确获取阈值配置
        $thresholds = [
            'blacklist' => (float) ($config['blacklist_threshold'] ?? 80.0),
            'suspicious' => (float) ($config['suspicious_threshold'] ?? 50.0),
        ];

        $maxTriggers = (int) ($config['max_triggers'] ?? 5);
        $debugLogging = security_config('enable_debug_logging', false);

        if ($debugLogging) {
            Log::info("检查IP类型转换: IP={$this->ip_address}, 当前威胁评分={$this->threat_score}, 触发次数={$this->trigger_count}");
            Log::info("配置阈值: 黑名单={$thresholds['blacklist']}, 可疑={$thresholds['suspicious']}, 最大触发={$maxTriggers}");
        }

        $originalType = $this->type;
        $changed = false;

        // 严格检查：只有当威胁评分或触发次数达到阈值时才转换
        $shouldBlacklist = false;
        $shouldSuspicious = false;

        // 检查是否应该转为黑名单
        if ($this->threat_score >= $thresholds['blacklist'] || $this->trigger_count >= $maxTriggers) {
            $shouldBlacklist = true;

            if ($debugLogging) {
                $reason = '';
                if ($this->threat_score >= $thresholds['blacklist']) {
                    $reason = "威胁评分 {$this->threat_score} >= 阈值 {$thresholds['blacklist']}";
                }
                if ($this->trigger_count >= $maxTriggers) {
                    $reason .= ($reason ? ', ' : '') . "触发次数 {$this->trigger_count} >= 阈值 {$maxTriggers}";
                }
                Log::info("满足黑名单条件: {$reason}");
            }
        }

        // 检查是否应该转为可疑IP（但不满足黑名单条件）
        if (!$shouldBlacklist && $this->threat_score >= $thresholds['suspicious']) {
            $shouldSuspicious = true;

            if ($debugLogging) {
                Log::info("满足可疑IP条件: 威胁评分 {$this->threat_score} >= 阈值 {$thresholds['suspicious']}");
            }
        }

        // 应用类型转换
        if ($shouldBlacklist) {
            // 自动转为黑名单
            if ($this->type !== self::TYPE_BLACKLIST) {
                $this->type = self::TYPE_BLACKLIST;
                $this->reason = $this->getAutoDetectionReason('blacklist', $thresholds, $maxTriggers);
                $this->auto_detected = true;
                $changed = true;

                if ($debugLogging) {
                    Log::info("IP自动转为黑名单: {$this->ip_address}");
                }
            }
        } elseif ($shouldSuspicious) {
            // 转为可疑IP
            if ($this->type !== self::TYPE_SUSPICIOUS) {
                $this->type = self::TYPE_SUSPICIOUS;
                $this->reason = $this->getAutoDetectionReason('suspicious', $thresholds, $maxTriggers);
                $this->auto_detected = true;
                $changed = true;

                if ($debugLogging) {
                    Log::info("IP自动转为可疑: {$this->ip_address}");
                }
            }
        } else {
            // 如果当前是黑名单或可疑IP，但已不满足条件，可以考虑降级
            if ($this->type === self::TYPE_BLACKLIST || $this->type === self::TYPE_SUSPICIOUS) {
                // 检查是否可以降级为监控状态
                if ($this->threat_score < $thresholds['suspicious'] && $this->trigger_count < $maxTriggers) {
                    $this->type = self::TYPE_MONITORING;
                    $this->reason = '自动降级: 威胁评分和触发次数已恢复正常';
                    $this->auto_detected = true;
                    $changed = true;

                    if ($debugLogging) {
                        Log::info("IP自动降级为监控: {$this->ip_address}");
                    }
                }
            }
        }

        // 如果类型变更，清除缓存
        if ($changed && $originalType !== $this->type) {
            self::clearIpCache($this->ip_address);

            if ($debugLogging) {
                Log::info("IP类型已变更: {$originalType} -> {$this->type}");
            }
        }
    }

    /**
     * 获取自动检测原因
     */
    protected function getAutoDetectionReason(string $type, array $thresholds, int $maxTriggers): string
    {
        $reasons = [];

        if ($this->threat_score >= $thresholds['blacklist']) {
            $reasons[] = "威胁评分过高 ({$this->threat_score}/{$thresholds['blacklist']})";
        }

        if ($this->trigger_count >= $maxTriggers) {
            $reasons[] = "触发规则过多 ({$this->trigger_count}/{$maxTriggers})";
        }

        if ($type === 'suspicious' && $this->threat_score >= $thresholds['suspicious']) {
            $reasons[] = "威胁评分较高 ({$this->threat_score}/{$thresholds['suspicious']})";
        }

        return '自动检测: ' . implode(', ', $reasons);
    }

    /**
     * 添加IP到白名单
     *
     * @param string $ip IP地址或IP段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @return self
     */
    public static function addToWhitelist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null): self
    {
        return self::addIp($ip, self::TYPE_WHITELIST, $reason, $expiresAt, false);
    }

    /**
     * 添加IP到黑名单
     *
     * @param string $ip IP地址或IP段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return self
     */
    public static function addToBlacklist(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): self
    {
        return self::addIp($ip, self::TYPE_BLACKLIST, $reason, $expiresAt, $autoDetected);
    }

    /**
     * 添加IP到可疑列表
     *
     * @param string $ip IP地址或IP段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return self
     */
    public static function addToSuspicious(string $ip, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): self
    {
        return self::addIp($ip, self::TYPE_SUSPICIOUS, $reason, $expiresAt, $autoDetected);
    }

    /**
     * 添加IP记录
     */
    protected static function addIp(string $ip, string $type, string $reason = '', ?DateTimeInterface $expiresAt = null, bool $autoDetected = false): self
    {
        $isRange = str_contains($ip, '/');

        $data = [
            'ip_address' => $isRange ? self::extractBaseIp($ip) : $ip,
            'ip_range' => $isRange ? $ip : null,
            'is_range' => $isRange,
            'type' => $type,
            'status' => self::STATUS_ACTIVE,
            'reason' => $reason,
            'expires_at' => $expiresAt,
            'auto_detected' => $autoDetected,
            'first_seen_at' => now(),
            'last_request_at' => now(),
        ];

        $ipRecord = self::updateOrCreate(
            [
                'ip_address' => $data['ip_address'],
                'is_range' => $isRange,
            ],
            $data
        );

        // 清除缓存
        self::clearIpCache($ip);

        return $ipRecord;
    }

    /**
     * 从IP段中提取基础IP
     */
    protected static function extractBaseIp(string $ipRange): string
    {
        return explode('/', $ipRange)[0];
    }

    /**
     * 清除IP相关缓存
     */
    protected static function clearIpCache(string $ip): void
    {
        if (!security_config('enable_ip_cache', true)) {
            return;
        }

        $cacheKeys = [
            self::CACHE_PREFIX . 'whitelist:' . md5($ip),
            self::CACHE_PREFIX . 'blacklist:' . md5($ip),
            self::CACHE_PREFIX . 'suspicious:' . md5($ip),
        ];

        foreach ($cacheKeys as $cacheKey) {
            Cache::forget($cacheKey);
        }
    }

    /**
     * 更新每日统计信息 - 优化版
     */
    public static function updateDailyStats(): void
    {
        $today = now()->format('Y-m-d');

        try {
            // 使用批量处理
            $stats = self::query()
                ->select([
                    'type',
                    DB::raw('COUNT(*) as total_ips'),
                    DB::raw('SUM(request_count) as total_requests'),
                    DB::raw('SUM(blocked_count) as total_blocks'),
                    DB::raw('AVG(threat_score) as avg_threat_score'),
                ])
                ->where('status', self::STATUS_ACTIVE)
                ->groupBy('type')
                ->get();

            foreach ($stats as $stat) {
                SecurityIpStat::updateOrCreate(
                    [
                        'stat_date' => $today,
                        'ip_type' => $stat->type,
                    ],
                    [
                        'total_ips' => $stat->total_ips,
                        'total_requests' => $stat->total_requests,
                        'total_blocks' => $stat->total_blocks,
                        'avg_threat_score' => $stat->avg_threat_score,
                    ]
                );
            }

        } catch (Exception $e) {
            Log::error('更新IP统计信息失败: ' . $e->getMessage());
        }
    }

    /**
     * 获取IP统计信息
     */
    public static function getIpStats(string $ip): array
    {
        return self::query()
            ->where('ip_address', $ip)
            ->where('is_range', false)
            ->first()
            ?->toArray() ?? [];
    }

    /**
     * 获取高威胁IP列表
     */
    public static function getHighThreatIps(int $limit = 100): Collection
    {
        return self::query()
            ->where('status', self::STATUS_ACTIVE)
            ->where('threat_score', '>=', security_config('ip_auto_detection.suspicious_threshold', 50.0))
            ->orderByDesc('threat_score')
            ->orderByDesc('last_request_at')
            ->limit($limit)
            ->get();
    }

    /**
     * 清理过期IP记录 - 优化版
     */
    public static function cleanupExpired(): int
    {
        if (!security_config('ip_auto_detection.auto_cleanup', true)) {
            return 0;
        }

        try {
            // 清理过期记录
            $deleted = self::query()
                ->where('expires_at', '<', now())
                ->whereNotNull('expires_at')
                ->delete();

            // 清理长时间未活动的监控IP
            $monitoringExpireDays = security_config('ip_auto_detection.monitoring_expire_days', 7);
            $monitoringDeleted = self::query()
                ->where('type', self::TYPE_MONITORING)
                ->where('last_request_at', '<', now()->subDays($monitoringExpireDays))
                ->delete();

            $totalDeleted = $deleted + $monitoringDeleted;

            if ($totalDeleted > 0) {
                Log::info("清理了 {$totalDeleted} 条IP记录（过期: {$deleted}, 监控过期: {$monitoringDeleted}）");
            }

            return $totalDeleted;

        } catch (Exception $e) {
            Log::error('清理IP记录失败: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * 批量处理IP记录
     */
    public static function batchProcess(callable $callback, int $batchSize = null): void
    {
        $batchSize = $batchSize ?? self::BATCH_SIZE;

        self::query()->chunk($batchSize, function ($ips) use ($callback) {
            foreach ($ips as $ip) {
                $callback($ip);
            }
        });
    }

    /**
     * 范围查询：获取活跃的黑名单IP数量
     */
    public function scopeActiveBlacklistCount(Builder $query): int
    {
        return $query->where('type', self::TYPE_BLACKLIST)
            ->where('status', self::STATUS_ACTIVE)
            ->count();
    }

    /**
     * 范围查询：获取需要监控的IP
     */
    public function scopeNeedMonitoring(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_MONITORING)
            ->where('status', self::STATUS_ACTIVE)
            ->where('threat_score', '>', 0)
            ->orderByDesc('threat_score');
    }

    /**
     * 范围查询：获取即将过期的IP
     */
    public function scopeExpiringSoon(Builder $query, int $hours = 24): Builder
    {
        return $query->whereNotNull('expires_at')
            ->where('expires_at', '>', now())
            ->where('expires_at', '<', now()->addHours($hours))
            ->orderBy('expires_at');
    }

    /**
     * 获取显示类型名称
     */
    public function getTypeNameAttribute(): string
    {
        return match($this->type) {
            self::TYPE_WHITELIST => '白名单',
            self::TYPE_BLACKLIST => '黑名单',
            self::TYPE_SUSPICIOUS => '可疑IP',
            self::TYPE_MONITORING => '监控中',
            default => '未知',
        };
    }

    /**
     * 获取显示状态名称
     */
    public function getStatusNameAttribute(): string
    {
        return match($this->status) {
            self::STATUS_ACTIVE => '激活',
            self::STATUS_INACTIVE => '禁用',
            self::STATUS_PENDING => '待审核',
            default => '未知',
        };
    }

    /**
     * 检查是否已过期
     */
    public function getIsExpiredAttribute(): bool
    {
        return $this->expires_at && $this->expires_at->isPast();
    }

    /**
     * 检查是否为活动状态
     */
    public function getIsActiveAttribute(): bool
    {
        return $this->status === self::STATUS_ACTIVE && !$this->is_expired;
    }

    /**
     * 获取威胁等级
     */
    public function getThreatLevelAttribute(): string
    {
        if ($this->threat_score >= 80) {
            return 'critical';
        } elseif ($this->threat_score >= 50) {
            return 'high';
        } elseif ($this->threat_score >= 20) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * 获取最后活动时间（分钟）
     */
    public function getLastActivityMinutesAttribute(): ?int
    {
        if (!$this->last_request_at) {
            return null;
        }

        return $this->last_request_at->diffInMinutes(now());
    }
}
