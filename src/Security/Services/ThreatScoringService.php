<?php

namespace zxf\Security\Services;

use Throwable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;

/**
 * 威胁评分服务 - 高级版
 *
 * 提供精准的威胁评估和风险分析功能：
 * 1. 多维度威胁评分机制
 * 2. 行为分析和模式识别
 * 3. 实时威胁情报更新
 * 4. 风险预测和预警
 * 5. 威胁评分历史追踪
 * 6. 自适应评分调整
 * 7. 威胁等级划分
 *
 * @package zxf\Security\Services
 */
class ThreatScoringService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 评分缓存
     */
    protected array $scoreCache = [];

    /**
     * 评分历史
     */
    protected array $scoreHistory = [];

    /**
     * 缓存前缀
     */
    protected const CACHE_PREFIX = 'security:threat:';

    /**
     * 缓存TTL
     */
    protected const CACHE_TTL = 600; // 10分钟

    /**
     * 威胁等级常量
     */
    public const LEVEL_SAFE = 'safe';
    public const LEVEL_LOW = 'low';
    public const LEVEL_MEDIUM = 'medium';
    public const LEVEL_HIGH = 'high';
    public const LEVEL_CRITICAL = 'critical';

    /**
     * 评分因子
     */
    protected const FACTOR_IP_REPUTATION = 'ip_reputation';
    protected const FACTOR_BEHAVIOR = 'behavior';
    protected const FACTOR_FREQUENCY = 'frequency';
    protected const FACTOR_CONTENT = 'content';
    protected const FACTOR_HEADERS = 'headers';
    protected const FACTOR_GEOLOCATION = 'geolocation';

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 计算威胁评分 - 主方法
     *
     * 综合多个维度计算威胁评分
     *
     * @param Request $request HTTP请求
     * @param array $detectionResults 检测结果
     * @param string $ip IP地址
     * @return array 评分结果
     */
    public function calculateThreatScore(Request $request, array $detectionResults, string $ip): array
    {
        // 检查缓存
        $cacheKey = $this->getCacheKey($ip, $request->path());
        if (isset($this->scoreCache[$cacheKey])) {
            return $this->scoreCache[$cacheKey];
        }

        // 计算各维度评分
        $factors = [
            self::FACTOR_IP_REPUTATION => $this->calculateIpReputationScore($ip),
            self::FACTOR_BEHAVIOR => $this->calculateBehaviorScore($request, $detectionResults),
            self::FACTOR_FREQUENCY => $this->calculateFrequencyScore($ip),
            self::FACTOR_CONTENT => $this->calculateContentScore($detectionResults),
            self::FACTOR_HEADERS => $this->calculateHeaderScore($request),
            self::FACTOR_GEOLOCATION => $this->calculateGeolocationScore($ip),
        ];

        // 获取因子权重
        $weights = $this->getFactorWeights();

        // 计算加权总分
        $totalScore = 0;
        $weightedScores = [];

        foreach ($factors as $factor => $score) {
            $weight = $weights[$factor] ?? 0.1;
            $weightedScore = $score * $weight;
            $weightedScores[$factor] = [
                'score' => $score,
                'weight' => $weight,
                'weighted_score' => $weightedScore,
            ];
            $totalScore += $weightedScore;
        }

        // 限制评分范围
        $totalScore = max(0, min($totalScore, 100));

        // 应用自适应调整
        if ($this->config->get('rule_engine.enable_adaptive_learning', false)) {
            $totalScore = $this->applyAdaptiveAdjustment($totalScore, $ip);
        }

        // 确定威胁等级
        $threatLevel = $this->determineThreatLevel($totalScore);

        // 构建结果
        $result = [
            'total_score' => round($totalScore, 2),
            'threat_level' => $threatLevel,
            'factors' => $weightedScores,
            'is_blocked' => $totalScore >= $this->getBlockThreshold(),
            'requires_review' => $totalScore >= $this->getReviewThreshold(),
            'recommendations' => $this->generateRecommendations($threatLevel, $factors),
        ];

        // 缓存结果
        $this->scoreCache[$cacheKey] = $result;
        Cache::put($cacheKey, $result, self::CACHE_TTL);

        // 记录评分历史
        $this->recordScoreHistory($ip, $result);

        return $result;
    }

    /**
     * 计算IP声誉评分
     *
     * 基于IP地址的历史行为评估声誉
     *
     * @param string $ip IP地址
     * @return float 评分（0-100）
     */
    protected function calculateIpReputationScore(string $ip): float
    {
        // 获取IP历史数据
        $ipStats = $this->getIpStats($ip);

        $score = 0;

        // 基础评分（根据历史威胁评分）
        $historicalScore = $ipStats['threat_score'] ?? 0;
        $score += $historicalScore * 0.4; // 历史评分占40%

        // 拦截率评分
        $totalCount = $ipStats['request_count'] ?? 1;
        $blockedCount = $ipStats['blocked_count'] ?? 0;
        $blockRate = $totalCount > 0 ? ($blockedCount / $totalCount) * 100 : 0;
        $score += $blockRate * 0.3; // 拦截率占30%

        // 触发次数评分
        $triggerCount = $ipStats['trigger_count'] ?? 0;
        $triggerScore = min($triggerCount * 5, 100); // 每次触发5分，最高100
        $score += $triggerScore * 0.2; // 触发次数占20%

        // IP类型评分
        $ipType = $ipStats['type'] ?? 'unknown';
        $typeScore = $this->getIpTypeScore($ipType);
        $score += $typeScore * 0.1; // IP类型占10%

        return min($score, 100);
    }

    /**
     * 计算行为评分
     *
     * 基于请求行为模式评估威胁
     *
     * @param Request $request HTTP请求
     * @param array $detectionResults 检测结果
     * @return float 评分（0-100）
     */
    protected function calculateBehaviorScore(Request $request, array $detectionResults): float
    {
        $score = 0;

        // 检测结果评分
        if (isset($detectionResults['detection_count'])) {
            $detectionCount = $detectionResults['detection_count'];
            $score += min($detectionCount * 15, 80); // 每次检测15分
        }

        // 攻击类型评分
        $attackTypes = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'file_inclusion'];
        foreach ($attackTypes as $type) {
            if (!empty($detectionResults[$type])) {
                $score += 20; // 每种攻击类型20分
            }
        }

        // 可疑行为评分
        if (!empty($detectionResults['suspicious_user_agent'])) {
            $score += 15;
        }
        if (!empty($detectionResults['suspicious_headers'])) {
            $score += 15;
        }
        if (!empty($detectionResults['anomalous_parameters'])) {
            $score += 10;
        }

        // HTTP方法评分
        $method = strtoupper($request->method());
        if (!in_array($method, ['GET', 'POST', 'HEAD', 'OPTIONS'])) {
            $score += 20;
        }

        return min($score, 100);
    }

    /**
     * 计算频率评分
     *
     * 基于请求频率评估威胁
     *
     * @param string $ip IP地址
     * @return float 评分（0-100）
     */
    protected function calculateFrequencyScore(string $ip): float
    {
        // 获取频率统计
        $frequencyStats = $this->getFrequencyStats($ip);

        $score = 0;

        // 请求频率评分
        $requestsPerMinute = $frequencyStats['requests_per_minute'] ?? 0;
        if ($requestsPerMinute > 60) {
            $score += 30;
        } elseif ($requestsPerMinute > 30) {
            $score += 20;
        } elseif ($requestsPerMinute > 10) {
            $score += 10;
        }

        // 峰值频率评分
        $peakRequests = $frequencyStats['peak_requests_per_minute'] ?? 0;
        if ($peakRequests > 120) {
            $score += 40;
        } elseif ($peakRequests > 60) {
            $score += 20;
        }

        // 持续高频评分
        $sustainedHigh = $frequencyStats['sustained_high_frequency'] ?? false;
        if ($sustainedHigh) {
            $score += 30;
        }

        return min($score, 100);
    }

    /**
     * 计算内容评分
     *
     * 基于请求内容评估威胁
     *
     * @param array $detectionResults 检测结果
     * @return float 评分（0-100）
     */
    protected function calculateContentScore(array $detectionResults): float
    {
        $score = 0;

        // SQL注入评分
        if (!empty($detectionResults['sql_injection'])) {
            $score += 90;
        }

        // XSS评分
        if (!empty($detectionResults['xss'])) {
            $score += 85;
        }

        // 命令注入评分
        if (!empty($detectionResults['command_injection'])) {
            $score += 95;
        }

        // 路径遍历评分
        if (!empty($detectionResults['path_traversal'])) {
            $score += 88;
        }

        // 文件包含评分
        if (!empty($detectionResults['file_inclusion'])) {
            $score += 92;
        }

        // 非法URL评分
        if (!empty($detectionResults['illegal_url'])) {
            $score += 75;
        }

        // 危险上传评分
        if (!empty($detectionResults['dangerous_upload'])) {
            $score += 80;
        }

        return min($score, 100);
    }

    /**
     * 计算请求头评分
     *
     * 基于请求头信息评估威胁
     *
     * @param Request $request HTTP请求
     * @return float 评分（0-100）
     */
    protected function calculateHeaderScore(Request $request): float
    {
        $score = 0;

        // User-Agent检查
        $userAgent = $request->userAgent();
        if (empty($userAgent)) {
            $score += 30;
        } elseif ($this->isSuspiciousUserAgent($userAgent)) {
            $score += 40;
        }

        // 请求头数量检查
        $headerCount = count($request->headers->all());
        if ($headerCount > 50) {
            $score += 25;
        }

        // 可疑请求头检查
        $suspiciousHeaders = ['X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL'];
        foreach ($suspiciousHeaders as $header) {
            if ($request->hasHeader($header)) {
                $score += 20;
            }
        }

        // Referer检查
        $referer = $request->header('Referer');
        if (empty($referer) && $request->method() === 'POST') {
            $score += 15;
        }

        return min($score, 100);
    }

    /**
     * 计算地理位置评分
     *
     * 基于IP地理位置评估威胁
     *
     * @param string $ip IP地址
     * @return float 评分（0-100）
     */
    protected function calculateGeolocationScore(string $ip): float
    {
        // 获取地理位置信息
        $geoInfo = $this->getGeolocation($ip);

        if (empty($geoInfo)) {
            return 20; // 未知地理位置，默认低风险
        }

        $score = 0;

        // 高风险国家评分
        $highRiskCountries = $this->config->get('high_risk_countries', []);
        if (in_array($geoInfo['country_code'] ?? '', $highRiskCountries)) {
            $score += 60;
        }

        // 代理/VPN评分
        if (!empty($geoInfo['is_proxy']) || !empty($geoInfo['is_vpn'])) {
            $score += 40;
        }

        // Tor节点评分
        if (!empty($geoInfo['is_tor'])) {
            $score += 80;
        }

        // 数据中心评分
        if (!empty($geoInfo['is_datacenter'])) {
            $score += 30;
        }

        return min($score, 100);
    }

    /**
     * 获取因子权重
     *
     * @return array 权重配置
     */
    protected function getFactorWeights(): array
    {
        return $this->config->get('threat_scoring.factor_weights', [
            self::FACTOR_IP_REPUTATION => 0.3,  // IP声誉占30%
            self::FACTOR_BEHAVIOR => 0.25,     // 行为分析占25%
            self::FACTOR_FREQUENCY => 0.15,     // 频率分析占15%
            self::FACTOR_CONTENT => 0.2,        // 内容分析占20%
            self::FACTOR_HEADERS => 0.05,       // 请求头分析占5%
            self::FACTOR_GEOLOCATION => 0.05,   // 地理位置占5%
        ]);
    }

    /**
     * 应用自适应调整
     *
     * @param float $score 原始评分
     * @param string $ip IP地址
     * @return float 调整后评分
     */
    protected function applyAdaptiveAdjustment(float $score, string $ip): float
    {
        // 获取历史评分趋势
        $history = $this->getScoreHistory($ip);

        if (count($history) < 3) {
            return $score;
        }

        // 计算评分趋势
        $recentScores = array_slice($history, -5);
        $avgRecentScore = array_sum($recentScores) / count($recentScores);

        // 如果评分持续上升，增加权重
        if ($avgRecentScore > $score * 1.2) {
            $score *= 1.1;
        }

        // 如果评分持续下降，降低权重
        if ($avgRecentScore < $score * 0.8) {
            $score *= 0.9;
        }

        return min($score, 100);
    }

    /**
     * 确定威胁等级
     *
     * @param float $score 威胁评分
     * @return string 威胁等级
     */
    protected function determineThreatLevel(float $score): string
    {
        $thresholds = $this->config->get('rule_engine.threat_thresholds', [
            'critical' => 80,
            'high' => 60,
            'medium' => 40,
            'low' => 20,
        ]);

        if ($score >= $thresholds['critical']) {
            return self::LEVEL_CRITICAL;
        } elseif ($score >= $thresholds['high']) {
            return self::LEVEL_HIGH;
        } elseif ($score >= $thresholds['medium']) {
            return self::LEVEL_MEDIUM;
        } elseif ($score >= $thresholds['low']) {
            return self::LEVEL_LOW;
        } else {
            return self::LEVEL_SAFE;
        }
    }

    /**
     * 获取拦截阈值
     *
     * @return float 阈值
     */
    protected function getBlockThreshold(): float
    {
        return $this->config->get('threat_scoring.block_threshold', 70);
    }

    /**
     * 获取人工审核阈值
     *
     * @return float 阈值
     */
    protected function getReviewThreshold(): float
    {
        return $this->config->get('threat_scoring.review_threshold', 50);
    }

    /**
     * 生成建议
     *
     * @param string $threatLevel 威胁等级
     * @param array $factors 因子评分
     * @return array 建议列表
     */
    protected function generateRecommendations(string $threatLevel, array $factors): array
    {
        $recommendations = [];

        // 基于威胁等级的建议
        switch ($threatLevel) {
            case self::LEVEL_CRITICAL:
                $recommendations[] = '立即拦截此IP';
                $recommendations[] = '通知安全团队';
                $recommendations[] = '收集详细证据';
                break;

            case self::LEVEL_HIGH:
                $recommendations[] = '考虑拦截此IP';
                $recommendations[] = '增加监控频率';
                break;

            case self::LEVEL_MEDIUM:
                $recommendations[] = '持续监控此IP';
                $recommendations[] = '记录详细日志';
                break;

            case self::LEVEL_LOW:
                $recommendations[] = '保持常规监控';
                break;
        }

        // 基于因子评分的建议
        if ($factors[self::FACTOR_IP_REPUTATION] > 60) {
            $recommendations[] = 'IP声誉较差，建议谨慎处理';
        }

        if ($factors[self::FACTOR_FREQUENCY] > 60) {
            $recommendations[] = '请求频率异常，建议实施限流';
        }

        if ($factors[self::FACTOR_CONTENT] > 60) {
            $recommendations[] = '检测到恶意内容，建议加强内容过滤';
        }

        return array_unique($recommendations);
    }

    /**
     * 获取IP统计数据
     *
     * @param string $ip IP地址
     * @return array 统计数据
     */
    protected function getIpStats(string $ip): array
    {
        $cacheKey = self::CACHE_PREFIX . 'ip_stats:' . md5($ip);
        $stats = Cache::get($cacheKey);

        if ($stats === null) {
            // 从数据库获取统计数据
            $stats = app(IpManagerService::class)->getIpStats($ip);
            Cache::put($cacheKey, $stats, 300); // 5分钟缓存
        }

        return $stats;
    }

    /**
     * 获取频率统计数据
     *
     * @param string $ip IP地址
     * @return array 频率统计
     */
    protected function getFrequencyStats(string $ip): array
    {
        $cacheKey = self::CACHE_PREFIX . 'frequency:' . md5($ip);
        $stats = Cache::get($cacheKey);

        if ($stats === null) {
            // 初始化统计数据
            $stats = [
                'requests_per_minute' => 0,
                'peak_requests_per_minute' => 0,
                'sustained_high_frequency' => false,
            ];
            Cache::put($cacheKey, $stats, 60); // 1分钟缓存
        }

        return $stats;
    }

    /**
     * 获取地理位置信息
     *
     * @param string $ip IP地址
     * @return array 地理位置信息
     */
    protected function getGeolocation(string $ip): array
    {
        // 实际实现可以集成第三方地理位置服务
        // 这里返回空数组表示未启用
        return [];
    }

    /**
     * 检查是否为可疑User-Agent
     *
     * @param string $userAgent User-Agent字符串
     * @return bool 是否可疑
     */
    protected function isSuspiciousUserAgent(string $userAgent): bool
    {
        $suspiciousPatterns = [
            '/bot/i',
            '/spider/i',
            '/crawler/i',
            '/scraper/i',
            '/curl/i',
            '/wget/i',
            '/python/i',
            '/perl/i',
            '/java/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取IP类型评分
     *
     * @param string $ipType IP类型
     * @return float 评分
     */
    protected function getIpTypeScore(string $ipType): float
    {
        $typeScores = [
            'whitelist' => 0,
            'blacklist' => 100,
            'suspicious' => 70,
            'monitoring' => 30,
            'unknown' => 20,
        ];

        return $typeScores[$ipType] ?? 20;
    }

    /**
     * 记录评分历史
     *
     * @param string $ip IP地址
     * @param array $result 评分结果
     * @return void
     */
    protected function recordScoreHistory(string $ip, array $result): void
    {
        $historyKey = self::CACHE_PREFIX . 'history:' . md5($ip);
        $history = Cache::get($historyKey, []);

        $history[] = [
            'score' => $result['total_score'],
            'level' => $result['threat_level'],
            'timestamp' => now()->toIso8601String(),
        ];

        // 只保留最近100条记录
        $history = array_slice($history, -100);

        Cache::put($historyKey, $history, 86400); // 24小时缓存
    }

    /**
     * 获取评分历史
     *
     * @param string $ip IP地址
     * @return array 历史记录
     */
    protected function getScoreHistory(string $ip): array
    {
        $historyKey = self::CACHE_PREFIX . 'history:' . md5($ip);
        $history = Cache::get($historyKey, []);

        return array_column($history, 'score');
    }

    /**
     * 获取缓存键
     *
     * @param string $ip IP地址
     * @param string $path URL路径
     * @return string 缓存键
     */
    protected function getCacheKey(string $ip, string $path): string
    {
        return self::CACHE_PREFIX . 'score:' . md5($ip . ':' . $path);
    }

    /**
     * 清除评分缓存
     *
     * @param string|null $ip IP地址（为null时清除所有）
     * @return void
     */
    public function clearScoreCache(?string $ip = null): void
    {
        if ($ip === null) {
            $this->scoreCache = [];
            Cache::forget(self::CACHE_PREFIX . 'all');
        } else {
            $pattern = self::CACHE_PREFIX . 'score:' . md5($ip . ':*');
            Cache::forget($pattern);
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
            'cached_scores' => count($this->scoreCache),
            'history_entries' => count($this->scoreHistory),
            'adaptive_learning_enabled' => $this->config->get('rule_engine.enable_adaptive_learning', false),
            'factor_weights' => $this->getFactorWeights(),
        ];
    }

    /**
     * 导出评分模型
     *
     * @return array 评分模型数据
     */
    public function exportModel(): array
    {
        return [
            'version' => '1.0',
            'exported_at' => now()->toIso8601String(),
            'factor_weights' => $this->getFactorWeights(),
            'thresholds' => [
                'block' => $this->getBlockThreshold(),
                'review' => $this->getReviewThreshold(),
                'threat_levels' => $this->config->get('rule_engine.threat_thresholds', []),
            ],
        ];
    }
}
