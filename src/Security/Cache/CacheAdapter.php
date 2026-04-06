<?php

namespace zxf\Security\Cache;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 缓存适配器 - 支持多种缓存驱动
 *
 * 提供统一的缓存接口，支持以下驱动：
 * - file: 独立文件缓存（零外部依赖）
 * - laravel: Laravel Cache门面（使用配置中的缓存驱动）
 * - auto: 自动选择（优先使用Laravel配置，回退到文件缓存）
 *
 * @author  zxf
 * @version 1.0.0
 * @package zxf\Security\Cache
 */
class CacheAdapter
{
    /**
     * 缓存驱动实例
     */
    protected FileCacheDriver|LaravelCacheDriver $driver;

    /**
     * 驱动类型
     */
    protected string $driverType;

    /**
     * 缓存前缀
     */
    protected string $prefix = 'security:';

    /**
     * 默认缓存时间（秒）
     */
    protected int $defaultTtl = 300;

    /**
     * 缓存命中统计
     */
    private static array $stats = [
        'hits' => 0,
        'misses' => 0,
        'writes' => 0,
        'deletes' => 0,
    ];

    /**
     * 是否启用统计
     */
    protected bool $enableStats = false;

    /**
     * 构造函数
     *
     * @param string $driverType 驱动类型: file | laravel | auto
     * @param string|null $prefix 缓存前缀
     * @param int|null $defaultTtl 默认缓存时间
     */
    public function __construct(
        string $driverType = 'auto',
        ?string $prefix = null,
        ?int $defaultTtl = null
    ) {
        $this->driverType = $driverType;
        $this->prefix = $prefix ?? 'security:';
        $this->defaultTtl = $defaultTtl ?? 300;

        $this->initializeDriver();
    }

    /**
     * 初始化缓存驱动
     */
    protected function initializeDriver(): void
    {
        switch ($this->driverType) {
            case 'file':
                $this->driver = new FileCacheDriver();
                break;

            case 'laravel':
                $this->driver = new LaravelCacheDriver($this->prefix, $this->defaultTtl);
                break;

            case 'auto':
            default:
                // 自动选择：检查Laravel缓存配置
                try {
                    $laravelCache = Cache::store();
                    // 如果可以正常使用Laravel缓存
                    if ($this->isLaravelCacheAvailable()) {
                        $this->driver = new LaravelCacheDriver($this->prefix, $this->defaultTtl);
                        $this->driverType = 'laravel';
                    } else {
                        throw new \Exception('Laravel cache not available');
                    }
                } catch (\Exception $e) {
                    // 回退到文件缓存
                    $this->driver = new FileCacheDriver();
                    $this->driverType = 'file';
                    Log::info('安全缓存使用文件驱动（Laravel缓存不可用）');
                }
                break;
        }
    }

    /**
     * 检查Laravel缓存是否可用
     */
    protected function isLaravelCacheAvailable(): bool
    {
        try {
            $testKey = 'security:test:' . uniqid();
            Cache::put($testKey, 'test', 1);
            $value = Cache::get($testKey);
            Cache::forget($testKey);
            return $value === 'test';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * 获取缓存值
     *
     * @param string $key 缓存键
     * @param mixed $default 默认值
     * @return mixed 缓存值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $fullKey = $this->getFullKey($key);
        $value = $this->driver->get($fullKey, $default);

        if ($value !== $default) {
            $this->recordHit();
        } else {
            $this->recordMiss();
        }

        return $value;
    }

    /**
     * 设置缓存值
     *
     * @param string $key 缓存键
     * @param mixed $value 缓存值
     * @param int|null $ttl 过期时间（秒）
     * @return bool 是否成功
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        $fullKey = $this->getFullKey($key);
        $ttl = $ttl ?? $this->defaultTtl;

        $result = $this->driver->set($fullKey, $value, $ttl);

        if ($result) {
            $this->recordWrite();
        }

        return $result;
    }

    /**
     * 删除缓存
     *
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function delete(string $key): bool
    {
        $fullKey = $this->getFullKey($key);
        $result = $this->driver->delete($fullKey);

        if ($result) {
            $this->recordDelete();
        }

        return $result;
    }

    /**
     * 检查缓存是否存在
     *
     * @param string $key 缓存键
     * @return bool 是否存在
     */
    public function has(string $key): bool
    {
        $fullKey = $this->getFullKey($key);
        return $this->driver->has($fullKey);
    }

    /**
     * 缓存不存在时设置
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数
     * @param int|null $ttl 过期时间
     * @return mixed 缓存值
     */
    public function remember(string $key, callable $callback, ?int $ttl = null): mixed
    {
        $fullKey = $this->getFullKey($key);

        // 先尝试获取
        $value = $this->driver->get($fullKey);

        if ($value !== null) {
            $this->recordHit();
            return $value;
        }

        $this->recordMiss();

        // 执行回调获取值
        $value = $callback();

        // 设置缓存
        $this->driver->set($fullKey, $value, $ttl ?? $this->defaultTtl);
        $this->recordWrite();

        return $value;
    }

    /**
     * 增加计数器
     *
     * @param string $key 缓存键
     * @param int $value 增加值
     * @return int|false 新值或false
     */
    public function increment(string $key, int $value = 1): int|false
    {
        $fullKey = $this->getFullKey($key);
        return $this->driver->increment($fullKey, $value);
    }

    /**
     * 减少计数器
     *
     * @param string $key 缓存键
     * @param int $value 减少值
     * @return int|false 新值或false
     */
    public function decrement(string $key, int $value = 1): int|false
    {
        return $this->increment($key, -$value);
    }

    /**
     * 清除所有缓存
     *
     * @return bool 是否成功
     */
    public function clear(): bool
    {
        return $this->driver->clear($this->prefix);
    }

    /**
     * 获取缓存键列表
     *
     * @param string|null $prefix 前缀过滤
     * @return array 缓存键列表
     */
    public function keys(?string $prefix = null): array
    {
        $fullPrefix = $prefix !== null ? $this->getFullKey($prefix) : $this->prefix;
        $keys = $this->driver->keys($fullPrefix);

        // 移除前缀
        $prefixLength = strlen($this->prefix);
        return array_map(function ($key) use ($prefixLength) {
            if (str_starts_with($key, $this->prefix)) {
                return substr($key, $prefixLength);
            }
            return $key;
        }, $keys);
    }

    /**
     * 批量获取
     *
     * @param array $keys 缓存键数组
     * @return array 键值对
     */
    public function many(array $keys): array
    {
        $result = [];

        foreach ($keys as $key) {
            $result[$key] = $this->get($key);
        }

        return $result;
    }

    /**
     * 批量设置
     *
     * @param array $values 键值对数组
     * @param int|null $ttl 过期时间
     * @return bool 是否成功
     */
    public function setMany(array $values, ?int $ttl = null): bool
    {
        $success = true;

        foreach ($values as $key => $value) {
            if (!$this->set($key, $value, $ttl)) {
                $success = false;
            }
        }

        return $success;
    }

    /**
     * 批量删除
     *
     * @param array $keys 缓存键数组
     * @return bool 是否成功
     */
    public function deleteMany(array $keys): bool
    {
        $success = true;

        foreach ($keys as $key) {
            if (!$this->delete($key)) {
                $success = false;
            }
        }

        return $success;
    }

    /**
     * 获取缓存统计
     *
     * @return array 统计信息
     */
    public function getStats(): array
    {
        $driverStats = [];
        if (method_exists($this->driver, 'getStats')) {
            $driverStats = $this->driver->getStats();
        }

        $total = self::$stats['hits'] + self::$stats['misses'];
        $hitRate = $total > 0 ? round((self::$stats['hits'] / $total) * 100, 2) : 0;

        return array_merge([
            'driver' => $this->driverType,
            'prefix' => $this->prefix,
            'adapter_hits' => self::$stats['hits'],
            'adapter_misses' => self::$stats['misses'],
            'adapter_writes' => self::$stats['writes'],
            'adapter_deletes' => self::$stats['deletes'],
            'adapter_hit_rate' => $hitRate . '%',
        ], $driverStats);
    }

    /**
     * 获取驱动类型
     *
     * @return string 驱动类型
     */
    public function getDriverType(): string
    {
        return $this->driverType;
    }

    /**
     * 获取原始驱动
     *
     * @return FileCacheDriver|LaravelCacheDriver
     */
    public function getDriver(): FileCacheDriver|LaravelCacheDriver
    {
        return $this->driver;
    }

    /**
     * 获取完整缓存键
     */
    protected function getFullKey(string $key): string
    {
        return $this->prefix . $key;
    }

    /**
     * 记录缓存命中
     */
    protected function recordHit(): void
    {
        if ($this->enableStats) {
            self::$stats['hits']++;
        }
    }

    /**
     * 记录缓存未命中
     */
    protected function recordMiss(): void
    {
        if ($this->enableStats) {
            self::$stats['misses']++;
        }
    }

    /**
     * 记录缓存写入
     */
    protected function recordWrite(): void
    {
        if ($this->enableStats) {
            self::$stats['writes']++;
        }
    }

    /**
     * 记录缓存删除
     */
    protected function recordDelete(): void
    {
        if ($this->enableStats) {
            self::$stats['deletes']++;
        }
    }

    /**
     * 启用统计
     */
    public function enableStats(): void
    {
        $this->enableStats = true;
    }

    /**
     * 禁用统计
     */
    public function disableStats(): void
    {
        $this->enableStats = false;
    }

    /**
     * 重置统计
     */
    public function resetStats(): void
    {
        self::$stats = [
            'hits' => 0,
            'misses' => 0,
            'writes' => 0,
            'deletes' => 0,
        ];

        if (method_exists($this->driver, 'resetStats')) {
            $this->driver->resetStats();
        }
    }

    /**
     * 清理过期缓存
     *
     * @return int 清理数量
     */
    public function cleanupExpired(): int
    {
        if (method_exists($this->driver, 'cleanupExpired')) {
            return $this->driver->cleanupExpired();
        }

        return 0;
    }
}

/**
 * Laravel缓存驱动包装器
 */
class LaravelCacheDriver
{
    protected string $prefix;
    protected int $defaultTtl;

    public function __construct(string $prefix, int $defaultTtl)
    {
        $this->prefix = $prefix;
        $this->defaultTtl = $defaultTtl;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return Cache::get($key, $default);
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        return Cache::put($key, $value, $ttl ?? $this->defaultTtl);
    }

    public function delete(string $key): bool
    {
        return Cache::forget($key);
    }

    public function has(string $key): bool
    {
        return Cache::has($key);
    }

    public function increment(string $key, int $value = 1): int|false
    {
        try {
            return Cache::increment($key, $value);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function clear(?string $prefix = null): bool
    {
        // Laravel缓存不支持按前缀清除，这里返回true
        return true;
    }

    public function keys(?string $prefix = null): array
    {
        // Laravel缓存不支持获取所有键
        return [];
    }
}
