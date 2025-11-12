<?php

namespace zxf\Security\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * 速率限制服务
 *
 * 提供多层速率限制功能，防止暴力破解和DDoS攻击
 * 支持分钟、小时、天级别的限制
 */
class RateLimiterService
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
     * 检查速率限制
     */
    public function check(Request $request): array
    {
        if (!$this->config->get('enable_rate_limiting', true)) {
            return ['blocked' => false];
        }

        $fingerprint = $this->getRequestFingerprint($request);
        $limits = $this->config->get('rate_limits', [
            'minute' => 60,
            'hour' => 1000,
            'day' => 10000,
        ]);

        // 检查各时间窗口的限制
        foreach ($limits as $window => $limit) {
            $count = $this->getRequestCount($fingerprint, $window);

            if ($count >= $limit) {
                return [
                    'blocked' => true,
                    'type' => 'RateLimit',
                    'reason' => "{$window}速率超限",
                    'details' => [
                        'window' => $window,
                        'current' => $count,
                        'limit' => $limit,
                        'retry_after' => $this->getRetryAfter($window),
                    ],
                ];
            }
        }

        // 更新计数器
        $this->incrementCounters($fingerprint);

        return ['blocked' => false];
    }

    /**
     * 获取请求指纹
     */
    protected function getRequestFingerprint(Request $request): string
    {
        return md5(implode('|', [
            $request->ip(),
            $request->userAgent(),
            $request->path(),
        ]));
    }

    /**
     * 获取请求计数
     */
    protected function getRequestCount(string $fingerprint, string $window): int
    {
        $key = $this->getCacheKey($fingerprint, $window);
        return Cache::get($key, 0);
    }

    /**
     * 增加计数器
     */
    protected function incrementCounters(string $fingerprint): void
    {
        $windows = [
            'minute' => 60,
            'hour' => 3600,
            'day' => 86400,
        ];

        foreach ($windows as $window => $ttl) {
            $key = $this->getCacheKey($fingerprint, $window);
            Cache::put($key, $this->getRequestCount($fingerprint, $window) + 1, $ttl);
        }
    }

    /**
     * 获取缓存键
     */
    protected function getCacheKey(string $fingerprint, string $window): string
    {
        return "security:rate_limit:{$window}:{$fingerprint}";
    }

    /**
     * 获取重试时间
     */
    protected function getRetryAfter(string $window): int
    {
        return match ($window) {
            'minute' => 60,
            'hour' => 3600,
            'day' => 86400,
            default => 60,
        };
    }

    /**
     * 获取速率限制统计
     */
    public function getRateLimitStats(): array
    {
        // 这里可以实现统计逻辑
        return [
            'total_blocks' => 0,
            'current_active' => 0,
        ];
    }

    /**
     * 清除缓存
     */
    public function clearCache(): void
    {
        // 实现缓存清理逻辑
    }
}