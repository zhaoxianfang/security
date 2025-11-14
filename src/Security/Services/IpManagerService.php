<?php

namespace zxf\Security\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

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
     * 检查IP是否在白名单
     */
    public function isWhitelisted(Request $request): bool
    {
        if (!$this->config->get('enable_ip_whitelist', true)) {
            return false;
        }

        $clientIp = $this->getClientRealIp($request);
        $whitelist = $this->config->get('ip_whitelist', []);

        return in_array($clientIp, $whitelist);
    }

    /**
     * 检查IP是否在黑名单
     */
    public function isBlacklisted(Request $request): bool
    {
        if (!$this->config->get('enable_ip_blacklist', true)) {
            return false;
        }

        $clientIp = $this->getClientRealIp($request);

        // 检查静态黑名单
        $blacklist = $this->config->get('ip_blacklist', []);
        if (in_array($clientIp, $blacklist)) {
            return true;
        }

        // 检查动态黑名单（缓存）
        $banKey = $this->getBanCacheKey($clientIp);
        if (Cache::has($banKey)) {
            return true;
        }

        // 检查自定义黑名单逻辑
        return $this->checkCustomBlacklist($request, $clientIp);
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

        $banData = [
            'type' => $type,
            'ip' => $clientIp,
            'duration' => $duration,
            'banned_at' => now()->toISOString(),
            'expires_at' => now()->addSeconds($duration)->toISOString(),
            'reason' => $this->getBanReason($type),
        ];

        $banKey = $this->getBanCacheKey($clientIp);
        $banData['ban_key'] = $banKey;

        // 调用封禁IP配置操作
        $handler = $this->config->get('ban_id_handler', null, $banData);
        if (is_array($handler)) {
            app()->call($handler, $banData);
        }else{
            Cache::put($banKey, $banData, $duration);
        }
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
     * 获取被封禁的IP数量
     */
    public function getBannedIpsCount(): int
    {
        // 这里需要根据实际存储实现
        return 0;
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        // 实现IP相关缓存清理
    }
}