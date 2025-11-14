<?php

namespace zxf\Security\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use zxf\Security\Models\SecurityIp;
use Illuminate\Support\Facades\Log;

/**
 * IP管理服务
 *
 * 提供IP白名单、黑名单、封禁管理等功能
 * 支持动态IP列表和缓存优化
 */
class IpManagerService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 检查中间件是否忽略本地环境
     */
    protected function isIgnoreLocal(): bool
    {
        return $this->config->get('ignore_local', false);
    }

    /**
     * 检查IP是否在白名单
     */
    public function isWhitelisted(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);

        // 首先检查本地IP
        if ($this->isIgnoreLocal() && $this->isLocalIp($clientIp)) {
            return true;
        }

        // 检查数据库白名单
        return SecurityIp::isWhitelisted($clientIp);
    }

    /**
     * 检查IP是否在黑名单
     */
    public function isBlacklisted(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);

        // 本地IP不检查黑名单
        if ($this->isIgnoreLocal() && $this->isLocalIp($clientIp)) {
            return false;
        }

        // 检查数据库黑名单
        return SecurityIp::isBlacklisted($clientIp);
    }

    /**
     * 记录IP访问
     */
    public function recordAccess(Request $request, bool $blocked = false, ?string $rule = null): void
    {
        try {
            $clientIp = $this->getClientRealIp($request);

            Log::info("记录IP访问: {$clientIp}, 拦截: " . ($blocked ? '是' : '否') . ", 规则: " . ($rule ?? '无'));

            $result = SecurityIp::recordRequest($clientIp, $blocked, $rule);

            if ($result) {
                Log::info("IP访问记录成功: {$clientIp}, 记录ID: " . $result->id);
            } else {
                Log::error("IP访问记录失败: {$clientIp}");
            }

        } catch (\Exception $e) {
            Log::error("记录IP访问异常: " . $e->getMessage(), [
                'ip' => $clientIp ?? 'unknown',
                'blocked' => $blocked,
                'rule' => $rule,
                'exception' => $e
            ]);
        }
    }

    /**
     * 检查是否为本地请求
     */
    public function isLocalRequest(Request $request): bool
    {
        $clientIp = $this->getClientRealIp($request);
        return $this->isLocalIp($clientIp);
    }

    /**
     * 封禁IP
     */
    public function banIp(Request $request, string $type): void
    {
        $clientIp = $this->getClientRealIp($request);
        $duration = $this->getBanDuration($type);

        // 添加到数据库黑名单
        SecurityIp::addToBlacklist(
            $clientIp,
            "自动封禁: {$type}",
            now()->addSeconds($duration),
            true // 自动检测
        );

        \Illuminate\Support\Facades\Log::warning("IP封禁: {$clientIp} 类型: {$type} 时长: {$duration}秒");
    }

    /**
     * 获取客户端真实IP
     */
    public function getClientRealIp(Request $request): string
    {
        $ip = $request->ip();

        // 信任的代理头
        $trustedHeaders = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];

        foreach ($trustedHeaders as $header) {
            if ($request->headers->has($header)) {
                $ips = explode(',', $request->header($header));
                $candidate = trim($ips[0]);

                if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $ip = $candidate;
                    break;
                }
            }
        }

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    /**
     * 检查自定义黑名单逻辑
     */
    protected function checkCustomBlacklist(Request $request, string $ip): bool
    {
        $handler = $this->config->get('blacklist_handler', null, [$ip]);
        if (is_array($handler)) {
            app()->call($handler, [$ip]);
        }

        return true;
    }

    /**
     * 判断是否为本地IP
     */
    protected function isLocalIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false ||
            in_array($ip, ['127.0.0.1', '::1', 'localhost']);
    }

    /**
     * 获取封禁缓存键
     */
    protected function getBanCacheKey(string $ip): string
    {
        return "security:ip_banned:" . md5($ip);
    }

    /**
     * 获取封禁时长
     */
    protected function getBanDuration(string $type): int
    {
        $durations = [
            'Malicious' => 24 * 3600,
            'Anomalous' => 12 * 3600,
            'RateLimit' => 3600,
            'Blacklist' => 30 * 24 * 3600,
        ];

        return $durations[$type] ?? $this->config->get('ban_duration', 3600);
    }

    /**
     * 获取封禁原因
     */
    protected function getBanReason(string $type): string
    {
        $reasons = [
            'Malicious' => '恶意请求',
            'Anomalous' => '异常行为',
            'RateLimit' => '频率超限',
            'Blacklist' => '黑名单',
        ];

        return $reasons[$type] ?? '安全违规';
    }

    /**
     * 解析可调用对象
     */
    protected function resolveCallable($handler)
    {
        if (is_array($handler)) {
            return [app($handler[0]), $handler[1]];
        }

        if (is_string($handler) && str_contains($handler, '::')) {
            return $handler;
        }

        return $handler;
    }

    /**
     * 获取IP统计信息
     */
    public function getIpStats(string $ip): array
    {
        return SecurityIp::getIpStats($ip);
    }

    /**
     * 获取高威胁IP列表
     */
    public function getHighThreatIps(int $limit = 100): array
    {
        return SecurityIp::getHighThreatIps($limit)->toArray();
    }

    /**
     * 获取被封禁的IP数量
     */
    public function getBannedIpsCount(): int
    {
        return SecurityIp::activeBlacklistCount();
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        // 清除IP相关缓存
        Cache::flush();
    }
}