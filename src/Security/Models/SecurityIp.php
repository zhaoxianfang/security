<?php

namespace zxf\Security\Models;

use DateTimeInterface;
use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * 安全IP管理模型
 *
 * 功能说明：
 * 1. 统一管理白名单、黑名单、可疑IP
 * 2. 支持IP段范围检查和匹配
 * 3. 自动威胁检测和状态转换
 * 4. 高性能统计和查询优化
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
     * 检查IP是否在白名单中
     *
     * @param string $ip 要检查的IP地址
     * @return bool 是否在白名单中
     */
    public static function isWhitelisted(string $ip): bool
    {
        $cacheKey = self::CACHE_PREFIX . 'whitelist:' . md5($ip);

        return Cache::remember($cacheKey, 300, function () use ($ip) { // 缓存5分钟
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
        });
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

        return Cache::remember($cacheKey, 300, function () use ($ip) { // 缓存5分钟
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
        });
    }

    /**
     * 记录IP访问请求
     *
     * @param string $ip 访问IP
     * @param bool $blocked 是否被拦截
     * @param string|null $rule 触发规则
     * @return self|null 返回IP记录实例
     */
    public static function recordRequest(string $ip, bool $blocked = false, ?string $rule = null): ?self
    {
        security_config('enable_debug_logging',false) && Log::info("开始记录IP请求: {$ip}, 拦截: " . ($blocked ? '是' : '否') . ", 规则: " . ($rule ?? '无'));

        try {
            DB::beginTransaction();

            // 查找或创建IP记录
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
                ]
            );

            security_config('enable_debug_logging',false) && Log::info("找到或创建IP记录: ID={$ipRecord->id}, IP={$ipRecord->ip_address}");

            // 更新统计信息
            $ipRecord->request_count++;
            $ipRecord->reason = $rule;

            if ($blocked) {
                $ipRecord->blocked_count++;
                // 拦截时增加威胁评分
                $add_threat_score = config('security.add_threat_score', 10);
                $ipRecord->threat_score = min(100, $ipRecord->threat_score + $add_threat_score);
                security_config('enable_debug_logging',false) && Log::info("IP拦截记录: 威胁评分增加至 {$ipRecord->threat_score}");
            } else {
                $ipRecord->success_count++;
                // 成功请求时轻微降低威胁评分
                $reduce_threat_score = config('security.add_threat_score', 10);
                $ipRecord->threat_score = max(0, $ipRecord->threat_score - $reduce_threat_score);
            }

            // 更新时间窗口统计（简化版本，避免复杂查询）
            $ipRecord->last_request_at = now();

            if (!$ipRecord->first_seen_at) {
                $ipRecord->first_seen_at = now();
            }

            // 记录触发规则
            if ($rule && $blocked) {
                $ipRecord->trigger_count++;
                $triggerRules = $ipRecord->trigger_rules ?? [];
                if (!in_array($rule, $triggerRules)) {
                    $triggerRules[] = $rule;
                    $ipRecord->trigger_rules = array_slice($triggerRules, 0, 10); // 最多保存10条规则
                }
                security_config('enable_debug_logging',false) && Log::info("记录触发规则: {$rule}, 总触发次数: {$ipRecord->trigger_count}");

                // 自动检测和状态转换
                $ipRecord->auto_detected = true;
                $ipRecord->checkAndUpdateType();
                security_config('enable_debug_logging',false) && Log::info("自动检测后IP类型: {$ipRecord->type}");
            }

            // 保存记录
            $saved = $ipRecord->save();

            if ($saved) {
                security_config('enable_debug_logging',false) && Log::info("IP记录保存成功: ID={$ipRecord->id}");
            } else {
                security_config('enable_debug_logging',false) && Log::error("IP记录保存失败: ID={$ipRecord->id}");
            }

            // 更新统计表（异步处理，避免阻塞）
            if ($blocked) {
                self::updateDailyStatsAsync();
            }

            DB::commit();

            // 清除相关缓存
            self::clearIpCache($ip);

            security_config('enable_debug_logging',false) && Log::info("IP请求记录完成: {$ip}");

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
        // 使用队列或延迟执行来更新统计，避免阻塞主流程
        if (function_exists('dispatch')) {
            dispatch(function () {
                self::updateDailyStats();
            })->delay(now()->addSeconds(10));
        } else {
            // 如果没有队列，直接执行
            self::updateDailyStats();
        }
    }

    /**
     * 获取最近时间窗口内的请求次数
     *
     * @param string $ip IP地址
     * @param int $seconds 时间窗口（秒）
     * @return int 请求次数
     */
    protected static function getRecentRequestCount(string $ip, int $seconds): int
    {
        return self::query()
            ->where('ip_address', $ip)
            ->where('last_request_at', '>=', now()->subSeconds($seconds))
            ->value(DB::raw('COALESCE(SUM(request_count), 0)')) ?? 0;
    }

    /**
     * 检查并自动更新IP类型
     */
    public function checkAndUpdateType(): void
    {
        $config = security_config('ip_auto_detection', []);

        // 设置默认阈值
        $thresholds = [
            'blacklist' => $config['blacklist_threshold'] ?? 80.0,  // 黑名单阈值
            'suspicious' => $config['suspicious_threshold'] ?? 50.0, // 可疑阈值
        ];

        $maxTriggers = $config['max_triggers'] ?? 5; // 最大触发次数

        security_config('enable_debug_logging',false) && Log::info("检查IP类型转换: 当前威胁评分={$this->threat_score}, 触发次数={$this->trigger_count}");

        $originalType = $this->type;

        if ($this->threat_score >= $thresholds['blacklist'] || $this->trigger_count >= $maxTriggers) {
            // 自动转为黑名单
            if ($this->type !== self::TYPE_BLACKLIST) {
                $this->type = self::TYPE_BLACKLIST;
                $this->reason = '自动检测: 威胁评分过高或触发规则过多';
                $this->auto_detected = true;
                security_config('enable_debug_logging',false) && Log::info("IP自动转为黑名单: {$this->ip_address}, 威胁评分: {$this->threat_score}");
            }
        } elseif ($this->threat_score >= $thresholds['suspicious']) {
            // 转为可疑IP
            if ($this->type !== self::TYPE_SUSPICIOUS) {
                $this->type = self::TYPE_SUSPICIOUS;
                $this->reason = '自动检测: 威胁评分较高';
                $this->auto_detected = true;
                security_config('enable_debug_logging',false) && Log::info("IP自动转为可疑: {$this->ip_address}, 威胁评分: {$this->threat_score}");
            }
        }

        if ($originalType !== $this->type) {
            security_config('enable_debug_logging',false) &&Log::info("IP类型已变更: {$originalType} -> {$this->type}");
        }
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
     * 添加IP记录
     *
     * @param string $ip IP地址或IP段
     * @param string $type IP类型
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return self
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
     *
     * @param string $ipRange IP段
     * @return string 基础IP
     */
    protected static function extractBaseIp(string $ipRange): string
    {
        return explode('/', $ipRange)[0];
    }

    /**
     * 清除IP相关缓存
     *
     * @param string $ip IP地址
     */
    protected static function clearIpCache(string $ip): void
    {
        Cache::forget(self::CACHE_PREFIX . 'whitelist:' . md5($ip));
        Cache::forget(self::CACHE_PREFIX . 'blacklist:' . md5($ip));
    }

    /**
     * 更新每日统计信息
     */
    public static function updateDailyStats(): void
    {
        $today = now()->format('Y-m-d');

        // 使用窗口函数进行高效统计
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
            \zxf\Security\Models\SecurityIpStat::updateOrCreate(
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
    }

    /**
     * 获取IP统计信息
     *
     * @param string $ip IP地址
     * @return array 统计信息
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
     *
     * @param int $limit 数量限制
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public static function getHighThreatIps(int $limit = 100): \Illuminate\Database\Eloquent\Collection
    {
        return self::query()
            ->where('status', self::STATUS_ACTIVE)
            ->where('threat_score', '>=', config('security.ip_auto_detection.suspicious_threshold', 50.0))
            ->orderByDesc('threat_score')
            ->orderByDesc('last_request_at')
            ->limit($limit)
            ->get();
    }

    /**
     * 清理过期IP记录
     *
     * @return int 删除的记录数
     */
    public static function cleanupExpired(): int
    {
        return self::query()
            ->where('expires_at', '<', now())
            ->whereNotNull('expires_at')
            ->delete();
    }

    /**
     * 范围查询：获取活跃的黑名单IP数量
     *
     * @param Builder $query
     * @return int
     */
    public function scopeActiveBlacklistCount(Builder $query): int
    {
        return $query->where('type', self::TYPE_BLACKLIST)
            ->where('status', self::STATUS_ACTIVE)
            ->count();
    }

    /**
     * 范围查询：获取需要监控的IP
     *
     * @param Builder $query
     * @return Builder
     */
    public function scopeNeedMonitoring(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_MONITORING)
            ->where('status', self::STATUS_ACTIVE)
            ->where('threat_score', '>', 0)
            ->orderByDesc('threat_score');
    }

    /**
     * 获取显示类型名称
     *
     * @return string
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
     *
     * @return string
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
     *
     * @return bool
     */
    public function getIsExpiredAttribute(): bool
    {
        return $this->expires_at && $this->expires_at->isPast();
    }
}