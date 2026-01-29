<?php

namespace zxf\Security\Services;

use Throwable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;

/**
 * 规则引擎服务 - 高级版
 *
 * 提供灵活、高效、可控的安全规则管理功能：
 * 1. 规则优先级和权重管理
 * 2. 动态规则配置和运行时调整
 * 3. 规则学习和自适应能力
 * 4. 智能拦截决策机制
 * 5. 规则性能优化和缓存
 * 6. 规则统计和监控
 * 7. 规则测试和验证
 *
 * @package zxf\Security\Services
 */
class RuleEngineService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 规则缓存
     */
    protected array $ruleCache = [];

    /**
     * 规则统计
     */
    protected array $ruleStats = [];

    /**
     * 缓存前缀
     */
    protected const CACHE_PREFIX = 'security:rule:';

    /**
     * 缓存TTL
     */
    protected const CACHE_TTL = 300; // 5分钟

    /**
     * 规则类型
     */
    public const TYPE_CRITICAL = 'critical';
    public const TYPE_HIGH = 'high';
    public const TYPE_MEDIUM = 'medium';
    public const TYPE_LOW = 'low';

    /**
     * 规则动作
     */
    public const ACTION_BLOCK = 'block';
    public const ACTION_MONITOR = 'monitor';
    public const ACTION_WARN = 'warn';
    public const ACTION_PASS = 'pass';

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 评估请求的威胁程度
     *
     * 基于规则引擎，智能评估请求的威胁程度
     *
     * @param Request $request HTTP请求
     * @param array $detectionResults 检测结果
     * @return array 评估结果
     */
    public function evaluateThreat(Request $request, array $detectionResults): array
    {
        // 获取所有规则
        $rules = $this->getRules();

        // 计算威胁评分
        $threatScore = 0;
        $matchedRules = [];
        $blocked = false;
        $action = self::ACTION_PASS;

        foreach ($rules as $rule) {
            // 检查规则是否启用
            if (!$this->isRuleEnabled($rule)) {
                continue;
            }

            // 评估规则匹配
            $matchResult = $this->evaluateRule($rule, $request, $detectionResults);

            if ($matchResult['matched']) {
                // 记录匹配的规则
                $matchedRules[] = [
                    'rule_id' => $rule['id'],
                    'rule_name' => $rule['name'],
                    'rule_type' => $rule['type'],
                    'action' => $rule['action'],
                    'score' => $rule['score'],
                    'confidence' => $matchResult['confidence'],
                    'reason' => $matchResult['reason'],
                ];

                // 累加威胁评分（考虑权重）
                $weightedScore = $rule['score'] * $rule['weight'] * ($matchResult['confidence'] / 100);
                $threatScore += $weightedScore;

                // 更新规则统计
                $this->updateRuleStats($rule['id'], $matchResult['confidence']);

                // 确定动作
                if ($rule['action'] === self::ACTION_BLOCK) {
                    $blocked = true;
                    $action = self::ACTION_BLOCK;
                } elseif ($rule['action'] === self::ACTION_MONITOR && $action !== self::ACTION_BLOCK) {
                    $action = self::ACTION_MONITOR;
                } elseif ($rule['action'] === self::ACTION_WARN && $action === self::ACTION_PASS) {
                    $action = self::ACTION_WARN;
                }
            }
        }

        // 应用威胁评分限制
        $maxThreatScore = $this->config->get('max_threat_score', 100);
        $threatScore = min($threatScore, $maxThreatScore);

        // 应用学习机制（如果启用）
        if ($this->config->get('enable_adaptive_learning', false)) {
            $threatScore = $this->applyAdaptiveLearning($threatScore, $matchedRules);
        }

        // 返回评估结果
        return [
            'blocked' => $blocked,
            'action' => $action,
            'threat_score' => round($threatScore, 2),
            'threat_level' => $this->getThreatLevel($threatScore),
            'matched_rules' => $matchedRules,
            'rule_count' => count($matchedRules),
        ];
    }

    /**
     * 获取所有规则
     *
     * @return array 规则列表
     */
    public function getRules(): array
    {
        $cacheKey = self::CACHE_PREFIX . 'all';

        if (isset($this->ruleCache[$cacheKey])) {
            return $this->ruleCache[$cacheKey];
        }

        // 尝试从缓存获取
        $cachedRules = Cache::get($cacheKey);
        if ($cachedRules !== null) {
            $this->ruleCache[$cacheKey] = $cachedRules;
            return $cachedRules;
        }

        // 加载默认规则
        $rules = $this->loadDefaultRules();

        // 合并自定义规则
        $customRules = $this->config->get('custom_rules', []);
        foreach ($customRules as $customRule) {
            $rules[] = $this->normalizeRule($customRule);
        }

        // 缓存规则
        Cache::put($cacheKey, $rules, self::CACHE_TTL);
        $this->ruleCache[$cacheKey] = $rules;

        return $rules;
    }

    /**
     * 加载默认规则
     *
     * @return array 默认规则列表
     */
    protected function loadDefaultRules(): array
    {
        return [
            // IP黑名单规则
            [
                'id' => 'ip_blacklist',
                'name' => 'IP黑名单',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 100,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['ip_blacklisted' => true],
                'description' => 'IP地址在黑名单中',
            ],

            // IP白名单规则
            [
                'id' => 'ip_whitelist',
                'name' => 'IP白名单',
                'type' => self::TYPE_LOW,
                'action' => self::ACTION_PASS,
                'score' => 0,
                'weight' => 0,
                'enabled' => true,
                'conditions' => ['ip_whitelisted' => true],
                'description' => 'IP地址在白名单中',
            ],

            // SQL注入规则
            [
                'id' => 'sql_injection',
                'name' => 'SQL注入攻击',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 90,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['sql_injection_detected' => true],
                'description' => '检测到SQL注入攻击',
            ],

            // XSS攻击规则
            [
                'id' => 'xss_attack',
                'name' => 'XSS跨站脚本攻击',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 85,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['xss_attack_detected' => true],
                'description' => '检测到XSS跨站脚本攻击',
            ],

            // 命令注入规则
            [
                'id' => 'command_injection',
                'name' => '命令注入攻击',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 95,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['command_injection_detected' => true],
                'description' => '检测到命令注入攻击',
            ],

            // 非法URL规则
            [
                'id' => 'illegal_url',
                'name' => '非法URL访问',
                'type' => self::TYPE_HIGH,
                'action' => self::ACTION_BLOCK,
                'score' => 75,
                'weight' => 0.9,
                'enabled' => true,
                'conditions' => ['illegal_url_detected' => true],
                'description' => '检测到非法URL访问',
            ],

            // HTTP方法检查规则
            [
                'id' => 'invalid_http_method',
                'name' => '非法HTTP方法',
                'type' => self::TYPE_HIGH,
                'action' => self::ACTION_BLOCK,
                'score' => 70,
                'weight' => 0.9,
                'enabled' => true,
                'conditions' => ['invalid_http_method' => true],
                'description' => '使用了不允许的HTTP方法',
            ],

            // 可疑User-Agent规则
            [
                'id' => 'suspicious_user_agent',
                'name' => '可疑User-Agent',
                'type' => self::TYPE_MEDIUM,
                'action' => self::ACTION_MONITOR,
                'score' => 50,
                'weight' => 0.7,
                'enabled' => true,
                'conditions' => ['suspicious_user_agent' => true],
                'description' => '检测到可疑的User-Agent',
            ],

            // 可疑请求头规则
            [
                'id' => 'suspicious_headers',
                'name' => '可疑请求头',
                'type' => self::TYPE_MEDIUM,
                'action' => self::ACTION_MONITOR,
                'score' => 45,
                'weight' => 0.7,
                'enabled' => true,
                'conditions' => ['suspicious_headers' => true],
                'description' => '检测到可疑的请求头',
            ],

            // 危险文件上传规则
            [
                'id' => 'dangerous_upload',
                'name' => '危险文件上传',
                'type' => self::TYPE_HIGH,
                'action' => self::ACTION_BLOCK,
                'score' => 80,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['dangerous_upload_detected' => true],
                'description' => '检测到危险文件上传',
            ],

            // 频率限制规则
            [
                'id' => 'rate_limit_exceeded',
                'name' => '访问频率超限',
                'type' => self::TYPE_MEDIUM,
                'action' => self::ACTION_MONITOR,
                'score' => 40,
                'weight' => 0.6,
                'enabled' => true,
                'conditions' => ['rate_limit_exceeded' => true],
                'description' => '访问频率超过限制',
            ],

            // 异常参数规则
            [
                'id' => 'anomalous_parameters',
                'name' => '异常参数',
                'type' => self::TYPE_MEDIUM,
                'action' => self::ACTION_MONITOR,
                'score' => 35,
                'weight' => 0.6,
                'enabled' => true,
                'conditions' => ['anomalous_parameters' => true],
                'description' => '检测到异常的请求参数',
            ],

            // 路径遍历规则
            [
                'id' => 'path_traversal',
                'name' => '路径遍历攻击',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 88,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['path_traversal_detected' => true],
                'description' => '检测到路径遍历攻击',
            ],

            // 文件包含规则
            [
                'id' => 'file_inclusion',
                'name' => '文件包含攻击',
                'type' => self::TYPE_CRITICAL,
                'action' => self::ACTION_BLOCK,
                'score' => 92,
                'weight' => 1.0,
                'enabled' => true,
                'conditions' => ['file_inclusion_detected' => true],
                'description' => '检测到文件包含攻击',
            ],
        ];
    }

    /**
     * 评估单个规则
     *
     * @param array $rule 规则
     * @param Request $request HTTP请求
     * @param array $detectionResults 检测结果
     * @return array 评估结果
     */
    protected function evaluateRule(array $rule, Request $request, array $detectionResults): array
    {
        // 检查规则条件
        $matched = $this->checkRuleConditions($rule['conditions'], $detectionResults);

        if (!$matched) {
            return ['matched' => false];
        }

        // 计算置信度（0-100）
        $confidence = $this->calculateConfidence($rule, $request, $detectionResults);

        // 获取匹配原因
        $reason = $this->getMatchReason($rule, $detectionResults);

        return [
            'matched' => true,
            'confidence' => $confidence,
            'reason' => $reason,
        ];
    }

    /**
     * 检查规则条件
     *
     * @param array $conditions 条件
     * @param array $detectionResults 检测结果
     * @return bool 是否匹配
     */
    protected function checkRuleConditions(array $conditions, array $detectionResults): bool
    {
        foreach ($conditions as $key => $expectedValue) {
            $actualValue = $detectionResults[$key] ?? null;

            if (is_bool($expectedValue)) {
                if ($actualValue !== $expectedValue) {
                    return false;
                }
            } elseif (is_callable($expectedValue)) {
                if (!$expectedValue($actualValue, $detectionResults)) {
                    return false;
                }
            } else {
                if ($actualValue != $expectedValue) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * 计算置信度
     *
     * @param array $rule 规则
     * @param Request $request HTTP请求
     * @param array $detectionResults 检测结果
     * @return float 置信度（0-100）
     */
    protected function calculateConfidence(array $rule, Request $request, array $detectionResults): float
    {
        // 默认置信度
        $confidence = 80.0;

        // 根据规则类型调整置信度
        switch ($rule['type']) {
            case self::TYPE_CRITICAL:
                $confidence = 95.0;
                break;
            case self::TYPE_HIGH:
                $confidence = 85.0;
                break;
            case self::TYPE_MEDIUM:
                $confidence = 70.0;
                break;
            case self::TYPE_LOW:
                $confidence = 60.0;
                break;
        }

        // 根据检测次数调整（多次检测，置信度更高）
        $triggerCount = $detectionResults['trigger_count'] ?? 1;
        if ($triggerCount > 1) {
            $confidence = min($confidence + ($triggerCount - 1) * 5, 100);
        }

        return min($confidence, 100);
    }

    /**
     * 获取匹配原因
     *
     * @param array $rule 规则
     * @param array $detectionResults 检测结果
     * @return string 原因
     */
    protected function getMatchReason(array $rule, array $detectionResults): string
    {
        return $rule['description'] ?? '规则匹配';
    }

    /**
     * 检查规则是否启用
     *
     * @param array $rule 规则
     * @return bool 是否启用
     */
    protected function isRuleEnabled(array $rule): bool
    {
        // 检查全局启用状态
        if (!($rule['enabled'] ?? true)) {
            return false;
        }

        // 检查配置中是否禁用了该规则
        $disabledRules = $this->config->get('disabled_rules', []);
        if (in_array($rule['id'], $disabledRules)) {
            return false;
        }

        return true;
    }

    /**
     * 获取威胁等级
     *
     * @param float $threatScore 威胁评分
     * @return string 威胁等级
     */
    protected function getThreatLevel(float $threatScore): string
    {
        $thresholds = $this->config->get('threat_thresholds', [
            'critical' => 80,
            'high' => 60,
            'medium' => 40,
            'low' => 20,
        ]);

        if ($threatScore >= $thresholds['critical']) {
            return 'critical';
        } elseif ($threatScore >= $thresholds['high']) {
            return 'high';
        } elseif ($threatScore >= $thresholds['medium']) {
            return 'medium';
        } elseif ($threatScore >= $thresholds['low']) {
            return 'low';
        } else {
            return 'safe';
        }
    }

    /**
     * 应用自适应学习
     *
     * @param float $threatScore 原始威胁评分
     * @param array $matchedRules 匹配的规则
     * @return float 调整后的威胁评分
     */
    protected function applyAdaptiveLearning(float $threatScore, array $matchedRules): float
    {
        // 获取历史统计数据
        $learningStats = $this->getLearningStats();

        // 根据统计数据调整评分
        foreach ($matchedRules as $matchedRule) {
            $ruleId = $matchedRule['rule_id'];

            // 如果某个规则经常误报，降低其权重
            $falsePositiveRate = $learningStats[$ruleId]['false_positive_rate'] ?? 0;
            if ($falsePositiveRate > 0.3) {
                $threatScore *= 0.7;
            } elseif ($falsePositiveRate > 0.2) {
                $threatScore *= 0.85;
            }

            // 如果某个规则检测准确率高，提高其权重
            $accuracyRate = $learningStats[$ruleId]['accuracy_rate'] ?? 0;
            if ($accuracyRate > 0.9) {
                $threatScore *= 1.1;
            } elseif ($accuracyRate > 0.8) {
                $threatScore *= 1.05;
            }
        }

        return min($threatScore, 100);
    }

    /**
     * 获取学习统计数据
     *
     * @return array 统计数据
     */
    protected function getLearningStats(): array
    {
        $cacheKey = self::CACHE_PREFIX . 'learning_stats';
        $stats = Cache::get($cacheKey);

        if ($stats === null) {
            $stats = [];
            Cache::put($cacheKey, $stats, 3600); // 1小时
        }

        return $stats;
    }

    /**
     * 更新规则统计
     *
     * @param string $ruleId 规则ID
     * @param float $confidence 置信度
     * @return void
     */
    protected function updateRuleStats(string $ruleId, float $confidence): void
    {
        if (!isset($this->ruleStats[$ruleId])) {
            $this->ruleStats[$ruleId] = [
                'total_matches' => 0,
                'total_confidence' => 0,
            ];
        }

        $this->ruleStats[$ruleId]['total_matches']++;
        $this->ruleStats[$ruleId]['total_confidence'] += $confidence;

        // 每100次匹配，持久化一次统计
        if ($this->ruleStats[$ruleId]['total_matches'] % 100 === 0) {
            $this->persistRuleStats($ruleId);
        }
    }

    /**
     * 持久化规则统计
     *
     * @param string $ruleId 规则ID
     * @return void
     */
    protected function persistRuleStats(string $ruleId): void
    {
        $stats = $this->ruleStats[$ruleId] ?? [];
        $avgConfidence = $stats['total_matches'] > 0
            ? $stats['total_confidence'] / $stats['total_matches']
            : 0;

        $stats['avg_confidence'] = $avgConfidence;
        $stats['updated_at'] = now()->toIso8601String();

        $cacheKey = self::CACHE_PREFIX . "stats:{$ruleId}";
        Cache::put($cacheKey, $stats, 86400); // 24小时

        if ($this->config->get('enable_debug_logging', false)) {
            Log::info("规则统计已持久化", [
                'rule_id' => $ruleId,
                'stats' => $stats,
            ]);
        }
    }

    /**
     * 规范化规则
     *
     * @param array $rule 原始规则
     * @return array 规范化后的规则
     */
    protected function normalizeRule(array $rule): array
    {
        return [
            'id' => $rule['id'] ?? md5(serialize($rule)),
            'name' => $rule['name'] ?? '未命名规则',
            'type' => $rule['type'] ?? self::TYPE_MEDIUM,
            'action' => $rule['action'] ?? self::ACTION_MONITOR,
            'score' => $rule['score'] ?? 50,
            'weight' => $rule['weight'] ?? 0.8,
            'enabled' => $rule['enabled'] ?? true,
            'conditions' => $rule['conditions'] ?? [],
            'description' => $rule['description'] ?? '',
        ];
    }

    /**
     * 添加自定义规则
     *
     * @param array $rule 规则
     * @return bool 是否成功
     */
    public function addRule(array $rule): bool
    {
        try {
            $normalizedRule = $this->normalizeRule($rule);
            $customRules = $this->config->get('custom_rules', []);
            $customRules[] = $normalizedRule;

            $this->config->set('custom_rules', $customRules);
            $this->clearCache();

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('规则已添加', [
                    'rule_id' => $normalizedRule['id'],
                    'rule_name' => $normalizedRule['name'],
                ]);
            }

            return true;
        } catch (Throwable $e) {
            Log::error('添加规则失败: ' . $e->getMessage(), [
                'rule' => $rule,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 删除规则
     *
     * @param string $ruleId 规则ID
     * @return bool 是否成功
     */
    public function removeRule(string $ruleId): bool
    {
        try {
            $customRules = $this->config->get('custom_rules', []);
            $customRules = array_filter($customRules, function ($rule) use ($ruleId) {
                return $rule['id'] !== $ruleId;
            });

            $this->config->set('custom_rules', array_values($customRules));
            $this->clearCache();

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('规则已删除', ['rule_id' => $ruleId]);
            }

            return true;
        } catch (Throwable $e) {
            Log::error('删除规则失败: ' . $e->getMessage(), [
                'rule_id' => $ruleId,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 更新规则
     *
     * @param string $ruleId 规则ID
     * @param array $updates 更新内容
     * @return bool 是否成功
     */
    public function updateRule(string $ruleId, array $updates): bool
    {
        try {
            $customRules = $this->config->get('custom_rules', []);
            $found = false;

            foreach ($customRules as &$rule) {
                if ($rule['id'] === $ruleId) {
                    $rule = array_merge($rule, $updates);
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                return false;
            }

            $this->config->set('custom_rules', $customRules);
            $this->clearCache();

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('规则已更新', [
                    'rule_id' => $ruleId,
                    'updates' => $updates,
                ]);
            }

            return true;
        } catch (Throwable $e) {
            Log::error('更新规则失败: ' . $e->getMessage(), [
                'rule_id' => $ruleId,
                'updates' => $updates,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 测试规则
     *
     * @param array $rule 规则
     * @param array $testCases 测试用例
     * @return array 测试结果
     */
    public function testRule(array $rule, array $testCases): array
    {
        $normalizedRule = $this->normalizeRule($rule);
        $results = [];

        foreach ($testCases as $testCase) {
            $mockRequest = $this->createMockRequest($testCase['request'] ?? []);
            $mockDetectionResults = $testCase['detection_results'] ?? [];

            $result = $this->evaluateRule($normalizedRule, $mockRequest, $mockDetectionResults);

            $results[] = [
                'test_case' => $testCase['name'] ?? '未命名',
                'expected' => $testCase['expected_matched'] ?? true,
                'actual_matched' => $result['matched'],
                'passed' => $result['matched'] === ($testCase['expected_matched'] ?? true),
                'confidence' => $result['confidence'] ?? 0,
            ];
        }

        $totalTests = count($results);
        $passedTests = count(array_filter($results, fn($r) => $r['passed']));

        return [
            'rule_id' => $normalizedRule['id'],
            'rule_name' => $normalizedRule['name'],
            'total_tests' => $totalTests,
            'passed_tests' => $passedTests,
            'failed_tests' => $totalTests - $passedTests,
            'success_rate' => $totalTests > 0 ? round(($passedTests / $totalTests) * 100, 2) : 0,
            'test_results' => $results,
        ];
    }

    /**
     * 创建模拟请求
     *
     * @param array $requestData 请求数据
     * @return Request 模拟请求对象
     */
    protected function createMockRequest(array $requestData): Request
    {
        return Request::create(
            $requestData['url'] ?? '/',
            $requestData['method'] ?? 'GET',
            $requestData['parameters'] ?? [],
            $requestData['cookies'] ?? [],
            $requestData['files'] ?? [],
            $requestData['server'] ?? [],
            $requestData['content'] ?? null
        );
    }

    /**
     * 获取规则统计信息
     *
     * @return array 统计信息
     */
    public function getRuleStats(): array
    {
        $rules = $this->getRules();

        $stats = [
            'total_rules' => count($rules),
            'enabled_rules' => 0,
            'by_type' => [],
            'by_action' => [],
            'rule_details' => [],
        ];

        foreach ($rules as $rule) {
            // 统计启用规则
            if ($this->isRuleEnabled($rule)) {
                $stats['enabled_rules']++;
            }

            // 按类型统计
            $type = $rule['type'];
            $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;

            // 按动作统计
            $action = $rule['action'];
            $stats['by_action'][$action] = ($stats['by_action'][$action] ?? 0) + 1;

            // 规则详情
            $stats['rule_details'][] = [
                'id' => $rule['id'],
                'name' => $rule['name'],
                'type' => $type,
                'action' => $action,
                'score' => $rule['score'],
                'weight' => $rule['weight'],
                'enabled' => $this->isRuleEnabled($rule),
            ];
        }

        return $stats;
    }

    /**
     * 清除规则缓存
     *
     * @return void
     */
    public function clearCache(): void
    {
        $this->ruleCache = [];
        Cache::forget(self::CACHE_PREFIX . 'all');
        Cache::forget(self::CACHE_PREFIX . 'learning_stats');
    }

    /**
     * 导出规则
     *
     * @return array 规则列表
     */
    public function exportRules(): array
    {
        return [
            'version' => '1.0',
            'exported_at' => now()->toIso8601String(),
            'rules' => $this->getRules(),
        ];
    }

    /**
     * 导入规则
     *
     * @param array $data 规则数据
     * @return bool 是否成功
     */
    public function importRules(array $data): bool
    {
        try {
            if (!isset($data['rules'])) {
                throw new Exception('无效的规则数据格式');
            }

            $this->config->set('custom_rules', $data['rules']);
            $this->clearCache();

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('规则已导入', [
                    'rule_count' => count($data['rules']),
                ]);
            }

            return true;
        } catch (Throwable $e) {
            Log::error('导入规则失败: ' . $e->getMessage(), [
                'data' => $data,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 获取服务统计信息
     *
     * @return array 统计信息
     */
    public function getServiceStats(): array
    {
        return [
            'rule_count' => count($this->getRules()),
            'enabled_rule_count' => count(array_filter($this->getRules(), [$this, 'isRuleEnabled'])),
            'cached_rules' => count($this->ruleCache),
            'stats_count' => count($this->ruleStats),
            'adaptive_learning_enabled' => $this->config->get('enable_adaptive_learning', false),
        ];
    }
}
