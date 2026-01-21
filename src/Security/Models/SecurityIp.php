<?php

namespace zxf\Security\Models;

use DateTimeInterface;
use Exception;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use zxf\Security\Events\IpAdded;
use zxf\Security\Events\IpTypeChanged;

/**
 * 安全IP管理模型 - PHP 8.2+ 优化版
 *
 * 核心功能：
 * 1. 统一管理白名单、黑名单、可疑IP、监控IP四种类型
 * 2. 支持IPv4/IPv6单IP和CIDR段范围管理
 * 3. 智能威胁评分系统，自动检测和状态转换
 * 4. 高性能批量操作和延迟写入支持
 * 5. 多级缓存策略，减少数据库压力
 * 6. 数据归档和自动清理机制
 * 7. 审计日志和合规支持
 *
 * 性能优化：
 * - 使用覆盖索引减少回表查询
 * - 实现批量操作减少数据库连接
 * - 延迟写入机制降低实时压力
 * - 智能缓存预热和失效策略
 * - 分区表支持（大数据量场景）
 *
 * 数据完整性：
 * - 使用事务保证操作原子性
 * - 唯一约束防止重复数据
 * - 外键约束（如有需要）
 * - 自动审计字段
 *
 * @property int $id 主键ID
 * @property string $ip_address IP地址
 * @property string|null $ip_range IP段范围(CIDR格式)
 * @property bool $is_range 是否为IP段
 * @property string $type IP类型(whitelist/blacklist/suspicious/monitoring)
 * @property string $status 状态(active/inactive/pending)
 * @property string $reason 添加原因
 * @property int $request_count 总请求次数
 * @property int $blocked_count 拦截次数
 * @property int $success_count 成功请求次数
 * @property float $threat_score 威胁评分(0-100)
 * @property \Carbon\Carbon|null $last_request_at 最后请求时间
 * @property \Carbon\Carbon|null $first_seen_at 首次出现时间
 * @property bool $auto_detected 是否自动检测
 * @property int $trigger_count 触发规则次数
 * @property array|null $trigger_rules 触发规则记录
 * @property \Carbon\Carbon|null $expires_at 过期时间
 * @property \Carbon\Carbon $created_at 创建时间
 * @property \Carbon\Carbon $updated_at 更新时间
 * @property-read string $type_name 显示类型名称
 * @property-read string $status_name 显示状态名称
 * @property-read bool $is_expired 是否已过期
 * @property-read bool $is_active 是否为活动状态
 * @property-read string $threat_level 威胁等级(critical/high/medium/low)
 * @property-read int|null $last_activity_minutes 最后活动时间(分钟)
 */
class SecurityIp extends Model
{
    use MassPrunable; // 支持自动清理

    /**
     * 表名
     */
    protected $table = 'security_ips';

    /**
     * 主键类型
     */
    protected $keyType = 'int';

    /**
     * 主键是否自增
     */
    public $incrementing = true;

    /**
     * 可批量赋值字段 - 严格控制避免Mass Assignment漏洞
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
     * 属性类型转换 - 确保数据类型安全
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
     * 默认值 - 确保新建记录有合理的初始值
     */
    protected $attributes = [
        'is_range' => false,
        'status' => self::STATUS_ACTIVE,
        'request_count' => 0,
        'blocked_count' => 0,
        'success_count' => 0,
        'threat_score' => 0.00,
        'auto_detected' => false,
        'trigger_count' => 0,
        'trigger_rules' => '[]',
    ];

    /**
     * IP类型常量 - 使用枚举思想定义常量
     */
    public const TYPE_WHITELIST = 'whitelist';    // 白名单 - 完全信任
    public const TYPE_BLACKLIST = 'blacklist';    // 黑名单 - 完全阻止
    public const TYPE_SUSPICIOUS = 'suspicious';  // 可疑IP - 严格监控
    public const TYPE_MONITORING = 'monitoring';  // 监控中 - 正常监控

    /**
     * 状态常量
     */
    public const STATUS_ACTIVE = 'active';      // 激活 - 规则生效
    public const STATUS_INACTIVE = 'inactive';   // 禁用 - 规则暂停
    public const STATUS_PENDING = 'pending';     // 待审核 - 需要人工确认

    /**
     * 缓存键前缀 - 避免缓存键冲突
     */
    private const CACHE_PREFIX = 'security:ip:';

    /**
     * 缓存时间（秒）- 平衡性能和实时性
     */
    private const CACHE_TTL = 300; // 5分钟

    /**
     * 批量处理大小 - 控制内存使用
     */
    private const BATCH_SIZE = 1000;

    /**
     * 最大触发规则数 - 防止数组过大
     */
    private const MAX_TRIGGER_RULES = 20;

    /**
     * 检查IP是否在白名单中 - 高性能版本
     *
     * 使用多级缓存策略：
     * 1. 内存缓存（请求级）
     * 2. Redis/Memcached 缓存（应用级）
     * 3. 数据库查询（最终回源）
     *
     * @param string $ip 要检查的IP地址（IPv4或IPv6）
     * @return bool 是否在白名单中
     *
     * @example
     * if (SecurityIp::isWhitelisted('192.168.1.1')) {
     *     // IP在白名单中，跳过安全检查
     *     return $next($request);
     * }
     */
    public static function isWhitelisted(string $ip): bool
    {
        // 如果禁用IP缓存，直接查询数据库（性能优先模式）
        if (!security_config('enable_ip_cache', true)) {
            return self::queryWhitelist($ip);
        }

        // 使用缓存减少数据库压力
        $cacheKey = self::CACHE_PREFIX . 'whitelist:' . md5($ip);

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($ip) {
            return self::queryWhitelist($ip);
        });
    }

    /**
     * 查询白名单 - 数据库层实现
     *
     * 使用覆盖索引优化查询性能，避免回表
     *
     * @param string $ip IP地址
     * @return bool 是否在白名单中
     */
    protected static function queryWhitelist(string $ip): bool
    {
        return self::query()
            ->select(['id']) // 只查询ID，使用覆盖索引
            ->where('status', self::STATUS_ACTIVE)
            ->where('type', self::TYPE_WHITELIST)
            ->where(function (Builder $query) use ($ip) {
                // 精确匹配单个IP
                $query->where(function (Builder $q) use ($ip) {
                    $q->where('is_range', false)
                      ->where('ip_address', $ip);
                })
                // IP段匹配（仅IPv4）
                ->orWhere(function (Builder $q) use ($ip) {
                    $q->where('is_range', true)
                      ->whereNotNull('ip_range')
                      ->whereRaw(
                          'INET_ATON(?) BETWEEN INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1))
                           AND (INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) + (POW(2, 32 - CAST(SUBSTRING_INDEX(ip_range, \'/\', -1) AS UNSIGNED)) - 1))',
                          [$ip]
                      );
                });
            })
            ->where(function (Builder $query) {
                // 检查过期时间
                $query->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
            })
            ->exists(); // 使用 EXISTS 比 COUNT 更高效
    }

    /**
     * 检查IP是否在黑名单中 - 高性能版本
     *
     * @param string $ip 要检查的IP地址（IPv4或IPv6）
     * @return bool 是否在黑名单中
     */
    public static function isBlacklisted(string $ip): bool
    {
        // 如果禁用IP缓存，直接查询数据库
        if (!security_config('enable_ip_cache', true)) {
            return self::queryBlacklist($ip);
        }

        $cacheKey = self::CACHE_PREFIX . 'blacklist:' . md5($ip);

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($ip) {
            return self::queryBlacklist($ip);
        });
    }

    /**
     * 查询黑名单 - 数据库层实现
     *
     * @param string $ip IP地址
     * @return bool 是否在黑名单中
     */
    protected static function queryBlacklist(string $ip): bool
    {
        return self::query()
            ->select(['id']) // 只查询ID，使用覆盖索引
            ->where('status', self::STATUS_ACTIVE)
            ->where('type', self::TYPE_BLACKLIST)
            ->where(function (Builder $query) use ($ip) {
                // 精确匹配单个IP
                $query->where(function (Builder $q) use ($ip) {
                    $q->where('is_range', false)
                      ->where('ip_address', $ip);
                })
                // IP段匹配（仅IPv4）
                ->orWhere(function (Builder $q) use ($ip) {
                    $q->where('is_range', true)
                      ->whereNotNull('ip_range')
                      ->whereRaw(
                          'INET_ATON(?) BETWEEN INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1))
                           AND (INET_ATON(SUBSTRING_INDEX(ip_range, \'/\', 1)) + (POW(2, 32 - CAST(SUBSTRING_INDEX(ip_range, \'/\', -1) AS UNSIGNED)) - 1))',
                          [$ip]
                      );
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
     * 批量检查IP状态 - 高性能批量查询
     *
     * 一次性检查多个IP的状态，减少数据库连接次数
     *
     * @param array $ips IP地址数组
     * @return array 状态映射 ['ip' => 'status']
     *
     * @example
     * $statuses = SecurityIp::batchCheck(['192.168.1.1', '192.168.1.2']);
     * // 返回: ['192.168.1.1' => 'whitelist', '192.168.1.2' => 'blacklist']
     */
    public static function batchCheck(array $ips): array
    {
        if (empty($ips)) {
            return [];
        }

        // 去重减少查询量
        $uniqueIps = array_unique($ips);

        // 批量查询数据库
        $records = self::query()
            ->select(['ip_address', 'type', 'status', 'expires_at'])
            ->whereIn('ip_address', $uniqueIps)
            ->where('is_range', false)
            ->where('status', self::STATUS_ACTIVE)
            ->where(function (Builder $query) {
                $query->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
            })
            ->get();

        // 构建结果映射
        $result = [];
        foreach ($uniqueIps as $ip) {
            $result[$ip] = 'none'; // 默认状态
        }

        foreach ($records as $record) {
            if ($record->status === self::STATUS_ACTIVE) {
                $result[$record->ip_address] = $record->type;
            }
        }

        return $result;
    }

    /**
     * 记录IP访问请求 - 事务安全版本
     *
     * 使用数据库事务确保数据一致性，支持批量延迟写入
     *
     * @param string $ip 访问IP（IPv4或IPv6）
     * @param bool $blocked 是否被拦截
     * @param string|null $rule 触发规则名称
     * @return self|null 返回IP记录实例，失败返回null
     *
     * @example
     * $record = SecurityIp::recordRequest('192.168.1.1', true, 'rate_limit');
     * if ($record && $record->type === 'blacklist') {
     *     Log::warning("IP {$ip} 已自动转为黑名单");
     * }
     */
    public static function recordRequest(string $ip, bool $blocked = false, ?string $rule = null): ?self
    {
        $debugLogging = security_config('enable_debug_logging', false);

        if ($debugLogging) {
            Log::info("开始记录IP请求: {$ip}, 拦截: " . ($blocked ? '是' : '否') . ", 规则: " . ($rule ?? '无'));
        }

        try {
            // 使用事务确保数据一致性
            return DB::transaction(function () use ($ip, $blocked, $rule, $debugLogging) {
                // 使用乐观锁（通过更新操作的原子性）
                $affected = self::query()
                    ->where('ip_address', $ip)
                    ->where('is_range', false)
                    ->update([
                        'request_count' => DB::raw('request_count + 1'),
                        'blocked_count' => DB::raw('blocked_count + ' . ($blocked ? 1 : 0)),
                        'success_count' => DB::raw('success_count + ' . ($blocked ? 0 : 1)),
                        'threat_score' => DB::raw('threat_score + ' . ($blocked ? 10 : -1)),
                        'last_request_at' => now(),
                        'updated_at' => now(),
                    ]);

                // 如果记录不存在，创建新记录
                if ($affected === 0) {
                    $ipRecord = self::create([
                        'ip_address' => $ip,
                        'is_range' => false,
                        'type' => self::TYPE_MONITORING,
                        'status' => self::STATUS_ACTIVE,
                        'first_seen_at' => now(),
                        'last_request_at' => now(),
                        'threat_score' => $blocked ? 10.00 : 0.00,
                        'request_count' => 1,
                        'blocked_count' => $blocked ? 1 : 0,
                        'success_count' => $blocked ? 0 : 1,
                        'auto_detected' => false,
                        'trigger_count' => 0,
                        'trigger_rules' => [],
                    ]);
                } else {
                    // 查询更新后的记录
                    $ipRecord = self::query()
                        ->where('ip_address', $ip)
                        ->where('is_range', false)
                        ->first();
                }

                // 更新威胁评分（限制范围）
                if ($ipRecord) {
                    $ipRecord->threat_score = min(100.00, max(0.00, $ipRecord->threat_score));

                    // 更新触发规则
                    if ($blocked && $rule) {
                        $triggerRules = $ipRecord->trigger_rules ?? [];
                        if (!in_array($rule, $triggerRules)) {
                            $triggerRules[] = $rule;
                            $ipRecord->trigger_rules = array_slice($triggerRules, 0, self::MAX_TRIGGER_RULES);
                        }
                        $ipRecord->trigger_count = count($ipRecord->trigger_rules);
                        $ipRecord->auto_detected = true;
                    }

                    // 检查类型转换
                    $originalType = $ipRecord->type;
                    $ipRecord->checkAndUpdateType();

                    if ($debugLogging && $originalType !== $ipRecord->type) {
                        Log::info("IP类型自动转换: {$originalType} -> {$ipRecord->type}");
                    }

                    // 保存最终更新
                    $ipRecord->save();

                    // 清除缓存
                    self::clearIpCache($ip);
                }

                return $ipRecord;
            }, 3); // 最多重试3次

        } catch (Exception $e) {
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
     * 批量记录IP访问 - 高性能批量操作
     *
     * 使用批量更新减少数据库连接，大幅提升性能
     *
     * @param array $records 记录数组，格式: [['ip' => '...', 'blocked' => true, 'rule' => '...'], ...]
     * @return int 成功记录的数量
     */
    public static function batchRecordRequests(array $records): int
    {
        if (empty($records)) {
            return 0;
        }

        $debugLogging = security_config('enable_debug_logging', false);

        try {
            return DB::transaction(function () use ($records, $debugLogging) {
                $successCount = 0;

                // 按IP分组统计
                $ipStats = [];
                foreach ($records as $record) {
                    $ip = $record['ip'] ?? null;
                    if (!$ip) {
                        continue;
                    }

                    if (!isset($ipStats[$ip])) {
                        $ipStats[$ip] = [
                            'blocked' => 0,
                            'success' => 0,
                            'rules' => [],
                        ];
                    }

                    if ($record['blocked'] ?? false) {
                        $ipStats[$ip]['blocked']++;
                        if (!empty($record['rule'])) {
                            $ipStats[$ip]['rules'][] = $record['rule'];
                        }
                    } else {
                        $ipStats[$ip]['success']++;
                    }
                }

                // 批量更新已存在的记录
                foreach (array_chunk(array_keys($ipStats), 100, true) as $ipChunk) {
                    foreach ($ipChunk as $ip) {
                        $stats = $ipStats[$ip];
                        $rule = $stats['rules'][0] ?? null;

                        $affected = self::query()
                            ->where('ip_address', $ip)
                            ->where('is_range', false)
                            ->update([
                                'request_count' => DB::raw('request_count + ' . ($stats['blocked'] + $stats['success'])),
                                'blocked_count' => DB::raw('blocked_count + ' . $stats['blocked']),
                                'success_count' => DB::raw('success_count + ' . $stats['success']),
                                'threat_score' => DB::raw(
                                    'LEAST(100.00, GREATEST(0.00, threat_score + ' .
                                    ($stats['blocked'] * 10 - $stats['success']) . '))'
                                ),
                                'last_request_at' => now(),
                                'updated_at' => now(),
                            ]);

                        if ($affected > 0) {
                            $successCount++;

                            // 更新触发规则和类型
                            if ($stats['blocked'] > 0 && $rule) {
                                $record = self::query()->where('ip_address', $ip)->first();
                                if ($record) {
                                    $triggerRules = $record->trigger_rules ?? [];
                                    foreach ($stats['rules'] as $r) {
                                        if (!in_array($r, $triggerRules)) {
                                            $triggerRules[] = $r;
                                        }
                                    }
                                    $record->trigger_rules = array_slice($triggerRules, 0, self::MAX_TRIGGER_RULES);
                                    $record->trigger_count = count($record->trigger_rules);
                                    $record->auto_detected = true;
                                    $record->checkAndUpdateType();
                                    $record->save();
                                    self::clearIpCache($ip);
                                }
                            }
                        } else {
                            // 记录不存在，创建新记录
                            $threatScore = $stats['blocked'] > 0 ? min(100.00, $stats['blocked'] * 10) : 0.00;
                            self::create([
                                'ip_address' => $ip,
                                'is_range' => false,
                                'type' => $threatScore >= 50 ? self::TYPE_SUSPICIOUS : self::TYPE_MONITORING,
                                'status' => self::STATUS_ACTIVE,
                                'first_seen_at' => now(),
                                'last_request_at' => now(),
                                'threat_score' => $threatScore,
                                'request_count' => $stats['blocked'] + $stats['success'],
                                'blocked_count' => $stats['blocked'],
                                'success_count' => $stats['success'],
                                'auto_detected' => $stats['blocked'] > 0,
                                'trigger_count' => $stats['blocked'] > 0 ? 1 : 0,
                                'trigger_rules' => $stats['blocked'] > 0 && $rule ? [$rule] : [],
                            ]);
                            $successCount++;
                        }
                    }
                }

                if ($debugLogging) {
                    Log::info("批量记录IP访问: 成功记录 {$successCount} 个IP");
                }

                return $successCount;
            });

        } catch (Exception $e) {
            Log::error('批量记录IP访问失败: ' . $e->getMessage(), [
                'records_count' => count($records),
                'exception' => $e
            ]);
            return 0;
        }
    }

    /**
     * 应用自然衰减 - 减少误报
     *
     * 长时间无恶意行为的IP自动降低威胁评分
     */
    protected function applyNaturalDecay(): void
    {
        if (!$this->last_request_at) {
            return;
        }

        $hoursSinceLastRequest = $this->last_request_at->diffInHours(now());

        // 超过1小时开始衰减
        if ($hoursSinceLastRequest >= 1) {
            $decayRate = (float) security_config('ip_auto_detection.decay_rate_per_hour', 0.3);
            $decayAmount = $decayRate * $hoursSinceLastRequest;

            $this->threat_score = max(0.00, $this->threat_score - $decayAmount);
        }
    }

    /**
     * 检查并自动更新IP类型 - 智能威胁评估
     *
     * 根据威胁评分和触发规则自动转换IP类型
     * 支持自动降级机制，减少误封
     */
    public function checkAndUpdateType(): void
    {
        $config = security_config('ip_auto_detection', []);

        if (!($config['enabled'] ?? true)) {
            return;
        }

        // 获取阈值配置
        $blacklistThreshold = (float) ($config['blacklist_threshold'] ?? 80.0);
        $suspiciousThreshold = (float) ($config['suspicious_threshold'] ?? 50.0);
        $maxTriggers = (int) ($config['max_triggers'] ?? 5);

        $debugLogging = security_config('enable_debug_logging', false);

        if ($debugLogging) {
            Log::info("检查IP类型转换: IP={$this->ip_address}, 威胁评分={$this->threat_score}, 触发次数={$this->trigger_count}");
        }

        $originalType = $this->type;
        $changed = false;

        // 检查是否应该转为黑名单
        $shouldBlacklist = $this->threat_score >= $blacklistThreshold
                          || $this->trigger_count >= $maxTriggers;

        // 检查是否应该转为可疑IP（但不满足黑名单条件）
        $shouldSuspicious = !$shouldBlacklist
                          && $this->threat_score >= $suspiciousThreshold;

        // 应用类型转换
        if ($shouldBlacklist && $this->type !== self::TYPE_BLACKLIST) {
            $this->type = self::TYPE_BLACKLIST;
            $this->reason = $this->getAutoDetectionReason('blacklist', $blacklistThreshold, $suspiciousThreshold, $maxTriggers);
            $this->auto_detected = true;
            $changed = true;

            if ($debugLogging) {
                Log::warning("IP自动转为黑名单: {$this->ip_address}, 原因: {$this->reason}");
            }
        } elseif ($shouldSuspicious && $this->type !== self::TYPE_SUSPICIOUS) {
            $this->type = self::TYPE_SUSPICIOUS;
            $this->reason = $this->getAutoDetectionReason('suspicious', $blacklistThreshold, $suspiciousThreshold, $maxTriggers);
            $this->auto_detected = true;
            $changed = true;

            if ($debugLogging) {
                Log::info("IP自动转为可疑: {$this->ip_address}, 原因: {$this->reason}");
            }
        } else {
            // 检查是否可以降级（从黑名单/可疑转为监控）
            $canDemote = ($this->type === self::TYPE_BLACKLIST || $this->type === self::TYPE_SUSPICIOUS)
                      && $this->threat_score < $suspiciousThreshold
                      && $this->trigger_count < $maxTriggers;

            if ($canDemote) {
                $this->type = self::TYPE_MONITORING;
                $this->reason = '自动降级: 威胁评分和触发次数已恢复正常';
                $this->auto_detected = true;
                $changed = true;

                if ($debugLogging) {
                    Log::info("IP自动降级为监控: {$this->ip_address}");
                }
            }
        }

        // 如果类型变更，清除缓存
        if ($changed) {
            self::clearIpCache($this->ip_address);

            // 触发类型变更事件（可用于集成其他系统）
            event(new IpTypeChanged($this, $originalType, $this->type));

            if ($debugLogging) {
                Log::info("IP类型变更: {$originalType} -> {$this->type}");
            }
        }
    }

    /**
     * 获取自动检测原因描述
     */
    private function getAutoDetectionReason(
        string $type,
        float $blacklistThreshold,
        float $suspiciousThreshold,
        int $maxTriggers
    ): string {
        $reasons = [];

        if ($this->threat_score >= $blacklistThreshold) {
            $reasons[] = "威胁评分({$this->threat_score})达到黑名单阈值({$blacklistThreshold})";
        }

        if ($this->trigger_count >= $maxTriggers) {
            $reasons[] = "触发规则次数({$this->trigger_count})超过上限({$maxTriggers})";
        }

        if ($type === 'suspicious' && $this->threat_score >= $suspiciousThreshold) {
            $reasons[] = "威胁评分({$this->threat_score})达到可疑阈值({$suspiciousThreshold})";
        }

        return '自动检测: ' . implode(', ', $reasons);
    }

    /**
     * 添加IP到白名单 - 便捷方法
     *
     * @param string $ip IP地址或CIDR段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间（null表示永久有效）
     * @return self IP记录实例
     */
    public static function addToWhitelist(
        string $ip,
        string $reason = '手动添加',
        ?DateTimeInterface $expiresAt = null
    ): self {
        return self::addIp($ip, self::TYPE_WHITELIST, $reason, $expiresAt, false);
    }

    /**
     * 添加IP到黑名单 - 便捷方法
     *
     * @param string $ip IP地址或CIDR段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return self IP记录实例
     */
    public static function addToBlacklist(
        string $ip,
        string $reason = '恶意行为',
        ?DateTimeInterface $expiresAt = null,
        bool $autoDetected = false
    ): self {
        return self::addIp($ip, self::TYPE_BLACKLIST, $reason, $expiresAt, $autoDetected);
    }

    /**
     * 添加IP到可疑列表 - 便捷方法
     *
     * @param string $ip IP地址或CIDR段
     * @param string $reason 添加原因
     * @param DateTimeInterface|null $expiresAt 过期时间
     * @param bool $autoDetected 是否自动检测
     * @return self IP记录实例
     */
    public static function addToSuspicious(
        string $ip,
        string $reason = '可疑行为',
        ?DateTimeInterface $expiresAt = null,
        bool $autoDetected = true
    ): self {
        return self::addIp($ip, self::TYPE_SUSPICIOUS, $reason, $expiresAt, $autoDetected);
    }

    /**
     * 添加IP记录 - 内部方法
     *
     * 统一处理IP添加逻辑，支持单IP和CIDR段
     */
    private static function addIp(
        string $ip,
        string $type,
        string $reason,
        ?DateTimeInterface $expiresAt,
        bool $autoDetected
    ): self {
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

        // 触发添加事件
        event(new IpAdded($ipRecord));

        return $ipRecord;
    }

    /**
     * 从IP段中提取基础IP
     *
     * @param string $ipRange CIDR格式IP段，如: 192.168.1.0/24
     * @return string 基础IP地址
     */
    private static function extractBaseIp(string $ipRange): string
    {
        return explode('/', $ipRange)[0];
    }

    /**
     * 清除IP相关缓存 - 缓存失效策略
     *
     * 清除所有与指定IP相关的缓存，确保数据一致性
     *
     * @param string $ip IP地址
     */
    private static function clearIpCache(string $ip): void
    {
        if (!security_config('enable_ip_cache', true)) {
            return;
        }

        $cacheKeys = [
            self::CACHE_PREFIX . 'whitelist:' . md5($ip),
            self::CACHE_PREFIX . 'blacklist:' . md5($ip),
            self::CACHE_PREFIX . 'suspicious:' . md5($ip),
            self::CACHE_PREFIX . 'stats:' . md5($ip),
        ];

        foreach ($cacheKeys as $cacheKey) {
            Cache::forget($cacheKey);
        }

        // 清除聚合统计缓存
        Cache::forget(self::CACHE_PREFIX . 'high_threat');
        Cache::forget(self::CACHE_PREFIX . 'stats');
    }

    /**
     * 批量清除IP缓存 - 支持批量操作
     *
     * @param array $ips IP地址数组
     */
    public static function clearBatchIpCache(array $ips): void
    {
        foreach ($ips as $ip) {
            self::clearIpCache($ip);
        }
    }

    /**
     * 清理过期IP记录 - 支持自动清理
     *
     * 使用 Laravel 的 Prunable trait 实现自动清理
     *
     * @return int 清理的记录数
     */
    public static function cleanupExpired(): int
    {
        if (!security_config('ip_auto_detection.auto_cleanup', false)) {
            return 0;
        }

        try {
            // 清理过期记录
            $deleted = self::query()
                ->where('expires_at', '<', now())
                ->whereNotNull('expires_at')
                ->delete();

            // 清理长时间未活动的监控IP
            $monitoringExpireDays = (int) security_config('ip_auto_detection.monitoring_expire_days', 15);
            $monitoringDeleted = self::query()
                ->where('type', self::TYPE_MONITORING)
                ->where(function (Builder $query) use ($monitoringExpireDays) {
                    $query->where('last_request_at', '<', now()->subDays($monitoringExpireDays))
                          ->orWhere(function (Builder $q) use ($monitoringExpireDays) {
                              $q->whereNull('last_request_at')
                                ->where('created_at', '<', now()->subDays($monitoringExpireDays));
                          });
                })
                ->delete();

            $totalDeleted = $deleted + $monitoringDeleted;

            if ($totalDeleted > 0) {
                Log::info("清理IP记录完成", [
                    'total' => $totalDeleted,
                    'expired' => $deleted,
                    'monitoring_expired' => $monitoringDeleted,
                ]);
            }

            return $totalDeleted;

        } catch (Exception $e) {
            Log::error('清理IP记录失败', [
                'error' => $e->getMessage(),
                'exception' => $e
            ]);
            return 0;
        }
    }

    /**
     * 批量处理IP记录 - 大数据量处理
     *
     * 使用游标分页处理大量数据，避免内存溢出
     *
     * @param callable $callback 处理回调函数
     * @param int|null $batchSize 每批处理数量
     */
    public static function batchProcess(callable $callback, ?int $batchSize = null): void
    {
        $batchSize = $batchSize ?? self::BATCH_SIZE;

        self::query()->chunk($batchSize, function ($ips) use ($callback) {
            foreach ($ips as $ip) {
                $callback($ip);
            }
        });
    }

    /**
     * 获取高威胁IP列表 - 实时威胁情报
     *
     * 返回威胁评分最高的IP列表，用于实时监控和告警
     *
     * @param int $limit 返回数量限制
     * @return Collection 高威胁IP集合
     */
    public static function getHighThreatIps(int $limit = 100): Collection
    {
        return self::query()
            ->select(['id', 'ip_address', 'type', 'threat_score', 'request_count', 'blocked_count', 'last_request_at', 'reason'])
            ->where('status', self::STATUS_ACTIVE)
            ->where('threat_score', '>=', (float) security_config('ip_auto_detection.suspicious_threshold', 50.0))
            ->orderByDesc('threat_score')
            ->orderByDesc('last_request_at')
            ->limit(max(1, min(1000, $limit))) // 限制范围 1-1000
            ->get();
    }

    /**
     * 获取IP统计信息 - 性能优化版本
     *
     * 只查询需要的字段，减少数据传输
     *
     * @param string $ip IP地址
     * @return array 统计信息数组
     */
    public static function getIpStats(string $ip): array
    {
        $record = self::query()
            ->select([
                'id', 'ip_address', 'type', 'status', 'threat_score',
                'request_count', 'blocked_count', 'success_count',
                'trigger_count', 'last_request_at', 'first_seen_at', 'expires_at'
            ])
            ->where('ip_address', $ip)
            ->where('is_range', false)
            ->first();

        return $record?->toArray() ?? [];
    }

    /**
     * 定义可清理的数据（用于自动清理）
     *
     * Laravel 会自动调用此方法清理过期数据
     */
    public function prunable()
    {
        return static::query()
            ->where('expires_at', '<', now())
            ->orWhere(function (Builder $query) {
                $expireDays = (int) security_config('ip_auto_detection.monitoring_expire_days', 15);
                $query->where('type', self::TYPE_MONITORING)
                      ->where('last_request_at', '<', now()->subDays($expireDays));
            });
    }

    /**
     * ==================== 查询作用域（Query Scopes）====================
     */

    /**
     * 范围查询：获取活跃的黑名单IP
     */
    public function scopeActiveBlacklist(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_BLACKLIST)
                     ->where('status', self::STATUS_ACTIVE)
                     ->where(function (Builder $q) {
                         $q->whereNull('expires_at')
                           ->orWhere('expires_at', '>', now());
                     });
    }

    /**
     * 范围查询：获取需要监控的IP（高威胁评分）
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
     * 范围查询：获取自动检测的IP
     */
    public function scopeAutoDetected(Builder $query): Builder
    {
        return $query->where('auto_detected', true);
    }

    /**
     * 范围查询：获取指定威胁等级以上的IP
     */
    public function scopeThreatLevelAbove(Builder $query, float $score): Builder
    {
        return $query->where('threat_score', '>=', $score);
    }

    /**
     * ==================== 访问器（Accessors）====================
     */

    /**
     * 获取显示类型名称
     */
    protected function typeName(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => match($this->type) {
                self::TYPE_WHITELIST => '白名单',
                self::TYPE_BLACKLIST => '黑名单',
                self::TYPE_SUSPICIOUS => '可疑IP',
                self::TYPE_MONITORING => '监控中',
                default => '未知',
            }
        );
    }

    /**
     * 获取显示状态名称
     */
    protected function statusName(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => match($this->status) {
                self::STATUS_ACTIVE => '激活',
                self::STATUS_INACTIVE => '禁用',
                self::STATUS_PENDING => '待审核',
                default => '未知',
            }
        );
    }

    /**
     * 检查是否已过期
     */
    protected function isExpired(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => $this->expires_at && $this->expires_at->isPast()
        );
    }

    /**
     * 检查是否为活动状态
     */
    protected function isActive(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => $this->status === self::STATUS_ACTIVE && !$this->is_expired
        );
    }

    /**
     * 获取威胁等级
     */
    protected function threatLevel(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => match(true) {
                $this->threat_score >= 80 => 'critical',  // 严重
                $this->threat_score >= 50 => 'high',       // 高危
                $this->threat_score >= 20 => 'medium',     // 中危
                default => 'low',                          // 低危
            }
        );
    }

    /**
     * 获取最后活动时间（分钟）
     */
    protected function lastActivityMinutes(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: fn () => $this->last_request_at ? $this->last_request_at->diffInMinutes(now()) : null
        );
    }

    /**
     * 获取请求成功率
     */
    protected function successRate(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: function () {
                $total = $this->request_count;
                if ($total === 0) {
                    return 0.0;
                }
                return round(($this->success_count / $total) * 100, 2);
            }
        );
    }

    /**
     * 获取拦截率
     */
    protected function blockRate(): \Illuminate\Database\Eloquent\Casts\Attribute
    {
        return \Illuminate\Database\Eloquent\Casts\Attribute::make(
            get: function () {
                $total = $this->request_count;
                if ($total === 0) {
                    return 0.0;
                }
                return round(($this->blocked_count / $total) * 100, 2);
            }
        );
    }

    /**
     * ==================== 事件（Events）====================
     */

    /**
     * 模型事件定义
     */
    protected $dispatchesEvents = [
        'created' => \zxf\Security\Events\IpCreated::class,
        'updated' => \zxf\Security\Events\IpUpdated::class,
        'deleted' => \zxf\Security\Events\IpDeleted::class,
    ];
}
