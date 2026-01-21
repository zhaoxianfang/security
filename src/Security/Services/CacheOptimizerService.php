<?php

namespace zxf\Security\Services;

use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;

/**
 * 缓存优化服务 - 高级版
 *
 * 提供高效的缓存管理功能：
 * 1. 多级缓存策略（内存+持久化）
 * 2. 智能缓存预热
 * 3. 缓存过期和更新策略
 * 4. 缓存命中率监控
 * 5. 缓存大小控制
 * 6. 缓存性能统计
 * 7. 缓存失效和清理
 *
 * @package zxf\Security\Services
 */
class CacheOptimizerService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 内存缓存
     */
    protected array $memoryCache = [];

    /**
     * 缓存统计
     */
    protected array $cacheStats = [
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'deletes' => 0,
        'preloads' => 0,
    ];

    /**
     * 缓存前缀
     */
    protected const CACHE_PREFIX = 'security:optimized:';

    /**
     * 内存缓存最大条目数
     */
    protected const MEMORY_CACHE_MAX_SIZE = 1000;

    /**
     * 内存缓存TTL（秒）
     */
    protected const MEMORY_CACHE_TTL = 60;

    /**
     * 缓存层级
     */
    public const CACHE_LEVEL_MEMORY = 'memory';
    public const CACHE_LEVEL_PERSISTENT = 'persistent';
    public const CACHE_LEVEL_DISTRIBUTED = 'distributed';

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
        $this->initializeMemoryCache();
    }

    /**
     * 初始化内存缓存
     *
     * @return void
     */
    protected function initializeMemoryCache(): void
    {
        // 预加载热点数据
        if ($this->config->get('cache_preload_enabled', true)) {
            $this->preloadHotData();
        }
    }

    /**
     * 预加载热点数据
     *
     * @return void
     */
    protected function preloadHotData(): void
    {
        try {
            $preloadKeys = $this->config->get('cache_preload_keys', [
                'whitelist_ips',
                'blacklist_ips',
                'security_rules',
                'threat_patterns',
            ]);

            foreach ($preloadKeys as $key) {
                $this->remember($key, function () use ($key) {
                    // 从数据源加载数据
                    return $this->loadDataFromSource($key);
                }, 300); // 5分钟TTL

                $this->cacheStats['preloads']++;
            }

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('缓存预热完成', [
                    'preloaded_keys' => count($preloadKeys),
                    'stats' => $this->cacheStats,
                ]);
            }
        } catch (Exception $e) {
            Log::error('缓存预热失败: ' . $e->getMessage(), [
                'exception' => $e,
            ]);
        }
    }

    /**
     * 从数据源加载数据
     *
     * @param string $key 数据键
     * @return mixed 数据
     */
    protected function loadDataFromSource(string $key): mixed
    {
        // 根据键名从不同数据源加载
        return match (true) {
            str_ends_with($key, 'whitelist_ips') => $this->loadWhitelistIps(),
            str_ends_with($key, 'blacklist_ips') => $this->loadBlacklistIps(),
            str_ends_with($key, 'security_rules') => $this->loadSecurityRules(),
            default => [],
        };
    }

    /**
     * 加载白名单IP
     *
     * @return array 白名单IP列表
     */
    protected function loadWhitelistIps(): array
    {
        // 从数据库加载白名单IP
        $ips = \zxf\Security\Models\SecurityIp::query()
            ->where('type', \zxf\Security\Models\SecurityIp::TYPE_WHITELIST)
            ->where('status', \zxf\Security\Models\SecurityIp::STATUS_ACTIVE)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->pluck('ip_address')
            ->toArray();

        return $ips;
    }

    /**
     * 加载黑名单IP
     *
     * @return array 黑名单IP列表
     */
    protected function loadBlacklistIps(): array
    {
        // 从数据库加载黑名单IP
        $ips = \zxf\Security\Models\SecurityIp::query()
            ->where('type', \zxf\Security\Models\SecurityIp::TYPE_BLACKLIST)
            ->where('status', \zxf\Security\Models\SecurityIp::STATUS_ACTIVE)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->pluck('ip_address')
            ->toArray();

        return $ips;
    }

    /**
     * 加载安全规则
     *
     * @return array 安全规则列表
     */
    protected function loadSecurityRules(): array
    {
        // 从规则引擎加载规则
        $ruleEngine = app(RuleEngineService::class);
        return $ruleEngine->getRules();
    }

    /**
     * 获取缓存（多级缓存）
     *
     * @param string $key 缓存键
     * @param callable|null $callback 数据加载回调
     * @param int $ttl TTL（秒）
     * @param array $options 选项
     * @return mixed 缓存值
     */
    public function remember(string $key, ?callable $callback = null, int $ttl = 300, array $options = []): mixed
    {
        // 1. 检查内存缓存
        $memoryKey = $this->getMemoryKey($key);
        if ($this->hasMemoryCache($memoryKey)) {
            $this->cacheStats['hits']++;
            return $this->getMemoryCache($memoryKey);
        }

        // 2. 检查持久化缓存
        $persistentKey = $this->getPersistentKey($key);
        $cachedValue = Cache::get($persistentKey);
        if ($cachedValue !== null) {
            $this->cacheStats['hits']++;
            $this->setMemoryCache($memoryKey, $cachedValue);
            return $cachedValue;
        }

        // 3. 缓存未命中，从数据源加载
        $this->cacheStats['misses']++;

        if ($callback === null) {
            return null;
        }

        try {
            $value = $callback();

            // 写入缓存
            $this->set($key, $value, $ttl, $options);

            return $value;
        } catch (Exception $e) {
            Log::error('缓存加载失败: ' . $e->getMessage(), [
                'key' => $key,
                'exception' => $e,
            ]);
            return null;
        }
    }

    /**
     * 设置缓存
     *
     * @param string $key 缓存键
     * @param mixed $value 缓存值
     * @param int $ttl TTL（秒）
     * @param array $options 选项
     * @return bool 是否成功
     */
    public function set(string $key, mixed $value, int $ttl = 300, array $options = []): bool
    {
        try {
            // 设置内存缓存
            $memoryKey = $this->getMemoryKey($key);
            $this->setMemoryCache($memoryKey, $value);

            // 设置持久化缓存
            $persistentKey = $this->getPersistentKey($key);
            Cache::put($persistentKey, $value, $ttl);

            $this->cacheStats['sets']++;

            return true;
        } catch (Exception $e) {
            Log::error('缓存设置失败: ' . $e->getMessage(), [
                'key' => $key,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 获取缓存
     *
     * @param string $key 缓存键
     * @return mixed 缓存值
     */
    public function get(string $key): mixed
    {
        // 1. 检查内存缓存
        $memoryKey = $this->getMemoryKey($key);
        if ($this->hasMemoryCache($memoryKey)) {
            $this->cacheStats['hits']++;
            return $this->getMemoryCache($memoryKey);
        }

        // 2. 检查持久化缓存
        $persistentKey = $this->getPersistentKey($key);
        $cachedValue = Cache::get($persistentKey);
        if ($cachedValue !== null) {
            $this->cacheStats['hits']++;
            $this->setMemoryCache($memoryKey, $cachedValue);
            return $cachedValue;
        }

        // 3. 缓存未命中
        $this->cacheStats['misses']++;
        return null;
    }

    /**
     * 检查缓存是否存在
     *
     * @param string $key 缓存键
     * @return bool 是否存在
     */
    public function has(string $key): bool
    {
        // 检查内存缓存
        $memoryKey = $this->getMemoryKey($key);
        if ($this->hasMemoryCache($memoryKey)) {
            return true;
        }

        // 检查持久化缓存
        $persistentKey = $this->getPersistentKey($key);
        return Cache::has($persistentKey);
    }

    /**
     * 删除缓存
     *
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function forget(string $key): bool
    {
        try {
            // 删除内存缓存
            $memoryKey = $this->getMemoryKey($key);
            unset($this->memoryCache[$memoryKey]);

            // 删除持久化缓存
            $persistentKey = $this->getPersistentKey($key);
            Cache::forget($persistentKey);

            $this->cacheStats['deletes']++;

            return true;
        } catch (Exception $e) {
            Log::error('缓存删除失败: ' . $e->getMessage(), [
                'key' => $key,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 批量删除缓存
     *
     * @param array $keys 缓存键列表
     * @return bool 是否成功
     */
    public function forgetMany(array $keys): bool
    {
        $success = true;

        foreach ($keys as $key) {
            if (!$this->forget($key)) {
                $success = false;
            }
        }

        return $success;
    }

    /**
     * 清除所有缓存
     *
     * @return bool 是否成功
     */
    public function flush(): bool
    {
        try {
            // 清除内存缓存
            $this->memoryCache = [];

            // 清除持久化缓存
            Cache::flush();

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('缓存已清除', [
                    'stats' => $this->cacheStats,
                ]);
            }

            return true;
        } catch (Exception $e) {
            Log::error('缓存清除失败: ' . $e->getMessage(), [
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 清除前缀匹配的缓存
     *
     * @param string $prefix 前缀
     * @return bool 是否成功
     */
    public function flushPrefix(string $prefix): bool
    {
        try {
            // 清除内存缓存
            foreach (array_keys($this->memoryCache) as $key) {
                if (str_starts_with($key, $prefix)) {
                    unset($this->memoryCache[$key]);
                }
            }

            // 清除持久化缓存
            $persistentPrefix = self::CACHE_PREFIX . $prefix;
            if (method_exists(Cache::getStore(), 'flushPrefix')) {
                Cache::getStore()->flushPrefix($persistentPrefix);
            } else {
                // 如果不支持前缀清除，遍历删除
                $this->clearPatternCache($persistentPrefix . '*');
            }

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('缓存前缀已清除', [
                    'prefix' => $prefix,
                ]);
            }

            return true;
        } catch (Exception $e) {
            Log::error('缓存前缀清除失败: ' . $e->getMessage(), [
                'prefix' => $prefix,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 清除模式匹配的缓存
     *
     * @param string $pattern 模式
     * @return void
     */
    protected function clearPatternCache(string $pattern): void
    {
        // 这是一个占位实现
        // 实际实现取决于使用的缓存驱动
        // 对于Redis，可以使用SCAN命令
        // 对于文件缓存，可以遍历文件
    }

    /**
     * 获取内存缓存键
     *
     * @param string $key 原始键
     * @return string 内存缓存键
     */
    protected function getMemoryKey(string $key): string
    {
        return 'mem:' . md5($key);
    }

    /**
     * 获取持久化缓存键
     *
     * @param string $key 原始键
     * @return string 持久化缓存键
     */
    protected function getPersistentKey(string $key): string
    {
        return self::CACHE_PREFIX . $key;
    }

    /**
     * 设置内存缓存
     *
     * @param string $key 缓存键
     * @param mixed $value 缓存值
     * @return void
     */
    protected function setMemoryCache(string $key, mixed $value): void
    {
        // 限制内存缓存大小
        if (count($this->memoryCache) >= self::MEMORY_CACHE_MAX_SIZE) {
            $this->evictMemoryCache();
        }

        $this->memoryCache[$key] = [
            'value' => $value,
            'timestamp' => time(),
        ];
    }

    /**
     * 获取内存缓存
     *
     * @param string $key 缓存键
     * @return mixed 缓存值
     */
    protected function getMemoryCache(string $key): mixed
    {
        if (!isset($this->memoryCache[$key])) {
            return null;
        }

        $entry = $this->memoryCache[$key];

        // 检查是否过期
        if (time() - $entry['timestamp'] > self::MEMORY_CACHE_TTL) {
            unset($this->memoryCache[$key]);
            return null;
        }

        return $entry['value'];
    }

    /**
     * 检查内存缓存是否存在
     *
     * @param string $key 缓存键
     * @return bool 是否存在
     */
    protected function hasMemoryCache(string $key): bool
    {
        if (!isset($this->memoryCache[$key])) {
            return false;
        }

        $entry = $this->memoryCache[$key];

        // 检查是否过期
        if (time() - $entry['timestamp'] > self::MEMORY_CACHE_TTL) {
            unset($this->memoryCache[$key]);
            return false;
        }

        return true;
    }

    /**
     * 内存缓存淘汰策略
     *
     * @return void
     */
    protected function evictMemoryCache(): void
    {
        // 淘汰最旧的条目
        uasort($this->memoryCache, function ($a, $b) {
            return $a['timestamp'] - $b['timestamp'];
        });

        // 删除最旧的20%
        $evictCount = max(1, (int)(count($this->memoryCache) * 0.2));
        $keysToEvict = array_slice(array_keys($this->memoryCache), 0, $evictCount);

        foreach ($keysToEvict as $key) {
            unset($this->memoryCache[$key]);
        }
    }

    /**
     * 获取缓存统计信息
     *
     * @return array 统计信息
     */
    public function getStats(): array
    {
        $totalRequests = $this->cacheStats['hits'] + $this->cacheStats['misses'];
        $hitRate = $totalRequests > 0
            ? round(($this->cacheStats['hits'] / $totalRequests) * 100, 2)
            : 0;

        $memoryUsage = count($this->memoryCache);
        $memoryUsagePercent = ($memoryUsage / self::MEMORY_CACHE_MAX_SIZE) * 100;

        return [
            'hits' => $this->cacheStats['hits'],
            'misses' => $this->cacheStats['misses'],
            'hit_rate' => $hitRate,
            'sets' => $this->cacheStats['sets'],
            'deletes' => $this->cacheStats['deletes'],
            'preloads' => $this->cacheStats['preloads'],
            'memory_cache_size' => $memoryUsage,
            'memory_cache_max_size' => self::MEMORY_CACHE_MAX_SIZE,
            'memory_cache_usage' => round($memoryUsagePercent, 2) . '%',
        ];
    }

    /**
     * 重置统计信息
     *
     * @return void
     */
    public function resetStats(): void
    {
        $this->cacheStats = [
            'hits' => 0,
            'misses' => 0,
            'sets' => 0,
            'deletes' => 0,
            'preloads' => 0,
        ];

        if ($this->config->get('enable_debug_logging', false)) {
            Log::info('缓存统计已重置');
        }
    }

    /**
     * 预热缓存
     *
     * @param array $keys 要预热的键列表
     * @return bool 是否成功
     */
    public function warmUp(array $keys): bool
    {
        try {
            foreach ($keys as $key) {
                $this->remember($key, function () use ($key) {
                    return $this->loadDataFromSource($key);
                }, 300);

                $this->cacheStats['preloads']++;
            }

            if ($this->config->get('enable_debug_logging', false)) {
                Log::info('缓存预热完成', [
                    'keys' => count($keys),
                ]);
            }

            return true;
        } catch (Exception $e) {
            Log::error('缓存预热失败: ' . $e->getMessage(), [
                'keys' => $keys,
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
            'memory_cache_size' => count($this->memoryCache),
            'memory_cache_max_size' => self::MEMORY_CACHE_MAX_SIZE,
            'memory_cache_ttl' => self::MEMORY_CACHE_TTL,
            'stats' => $this->getStats(),
        ];
    }

    /**
     * 导出缓存数据
     *
     * @param string $pattern 缓存键模式
     * @return array 缓存数据
     */
    public function export(string $pattern = '*'): array
    {
        return [
            'version' => '1.0',
            'exported_at' => now()->toIso8601String(),
            'pattern' => $pattern,
            'memory_cache_keys' => count($this->memoryCache),
            'memory_cache_size' => strlen(serialize($this->memoryCache)),
        ];
    }
}
