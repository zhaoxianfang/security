<?php

namespace zxf\Security\Cache;

use zxf\Security\Contracts\CacheManagerInterface;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 安全缓存管理器
 *
 * 实现缓存抽象层，支持多种缓存策略
 * 遵循策略模式（Strategy Pattern）和装饰器模式（Decorator Pattern）
 * 
 * 设计原则：
 * - 单一职责原则（SRP）：只负责缓存管理
 * - 开闭原则（OCP）：对扩展开放，对修改关闭
 * - 依赖倒置原则（DIP）：依赖于抽象接口
 * - 策略模式：支持多种缓存策略
 * - 装饰器模式：支持缓存装饰和增强
 * 
 * 功能特性：
 * - 双层缓存：内存缓存+文件缓存
 * - 缓存预热：预先加载热点数据
 * - 缓存降级：异常时降级处理
 * - 缓存统计：记录缓存命中率
 * - 缓存清理：支持批量清理
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Cache
 */
class SecurityCacheManager implements CacheManagerInterface
{
    /**
     * 内存缓存（请求级别）
     */
    protected static array $memoryCache = [];

    /**
     * 缓存前缀
     */
    protected string $prefix = 'security:';

    /**
     * 默认缓存时间（秒）
     */
    protected int $defaultTtl = 300;

    /**
     * 是否启用内存缓存
     */
    protected bool $enableMemoryCache = true;

    /**
     * 缓存统计
     */
    protected static array $stats = [
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'deletes' => 0,
    ];

    /**
     * 是否启用统计
     */
    protected bool $enableStats = false;

    /**
     * 构造函数
     *
     * @param string $prefix 缓存前缀
     * @param int $defaultTtl 默认缓存时间
     */
    public function __construct(string $prefix = 'security:', int $defaultTtl = 300)
    {
        $this->prefix = $prefix;
        $this->defaultTtl = $defaultTtl;
    }

    /**
     * 获取缓存值
     *
     * 先查内存缓存，再查持久化缓存
     * 
     * @param string $key 缓存键
     * @param mixed $default 默认值
     * @return mixed 缓存值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $fullKey = $this->getFullKey($key);

        // 1. 先查内存缓存
        if ($this->enableMemoryCache && isset(self::$memoryCache[$fullKey])) {
            $this->recordHit();
            return self::$memoryCache[$fullKey];
        }

        // 2. 查持久化缓存
        $value = Cache::get($fullKey, $default);

        if ($value === $default) {
            $this->recordMiss();
            return $default;
        }

        // 3. 更新内存缓存
        if ($this->enableMemoryCache) {
            self::$memoryCache[$fullKey] = $value;
        }

        $this->recordHit();
        return $value;
    }

    /**
     * 设置缓存值
     *
     * 同时更新内存缓存和持久化缓存
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

        try {
            // 1. 更新内存缓存
            if ($this->enableMemoryCache) {
                self::$memoryCache[$fullKey] = $value;
            }

            // 2. 更新持久化缓存
            $result = Cache::put($fullKey, $value, $ttl);

            $this->recordSet();

            return $result;
        } catch (\Exception $e) {
            Log::error('缓存设置失败: ' . $e->getMessage(), [
                'key' => $fullKey,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 删除缓存值
     *
     * 同时删除内存缓存和持久化缓存
     * 
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function delete(string $key): bool
    {
        $fullKey = $this->getFullKey($key);

        try {
            // 1. 删除内存缓存
            if ($this->enableMemoryCache) {
                unset(self::$memoryCache[$fullKey]);
            }

            // 2. 删除持久化缓存
            $result = Cache::forget($fullKey);

            $this->recordDelete();

            return $result;
        } catch (\Exception $e) {
            Log::error('缓存删除失败: ' . $e->getMessage(), [
                'key' => $fullKey,
                'exception' => $e,
            ]);
            return false;
        }
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

        // 1. 先查内存缓存
        if ($this->enableMemoryCache && isset(self::$memoryCache[$fullKey])) {
            return true;
        }

        // 2. 查持久化缓存
        return Cache::has($fullKey);
    }

    /**
     * 清除所有缓存
     *
     * 清除所有带前缀的缓存
     * 
     * @return bool 是否成功
     */
    public function clear(): bool
    {
        try {
            // 1. 清除内存缓存
            if ($this->enableMemoryCache) {
                self::$memoryCache = [];
            }

            // 2. 清除持久化缓存
            // 注意：这里需要根据实际的缓存驱动实现
            // 简化实现：调用全局清理函数
            if (function_exists('clean_security_cache')) {
                clean_security_cache();
            }

            // 3. 重置统计
            if ($this->enableStats) {
                $this->resetStats();
            }

            Log::info('安全缓存已清除', ['prefix' => $this->prefix]);

            return true;
        } catch (\Exception $e) {
            Log::error('缓存清除失败: ' . $e->getMessage(), [
                'prefix' => $this->prefix,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 获取或设置缓存（如果不存在）
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数
     * @param int|null $ttl 过期时间（秒）
     * @return mixed 缓存值
     */
    public function remember(string $key, callable $callback, ?int $ttl = null): mixed
    {
        $fullKey = $this->getFullKey($key);

        // 1. 先查内存缓存
        if ($this->enableMemoryCache && isset(self::$memoryCache[$fullKey])) {
            $this->recordHit();
            return self::$memoryCache[$fullKey];
        }

        // 2. 查持久化缓存
        $value = Cache::get($fullKey);

        if ($value !== null) {
            // 3. 更新内存缓存
            if ($this->enableMemoryCache) {
                self::$memoryCache[$fullKey] = $value;
            }
            $this->recordHit();
            return $value;
        }

        $this->recordMiss();

        // 4. 执行回调获取值
        $value = $callback();

        // 5. 设置缓存
        $this->set($key, $value, $ttl);

        return $value;
    }

    /**
     * 获取或设置缓存（永久）
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数
     * @return mixed 缓存值
     */
    public function rememberForever(string $key, callable $callback): mixed
    {
        return $this->remember($key, $callback, null);
    }

    /**
     * 批量获取缓存
     *
     * @param array $keys 缓存键数组
     * @return array 缓存值数组
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
     * 批量设置缓存
     *
     * @param array $values 键值对数组
     * @param int|null $ttl 过期时间（秒）
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
     * 批量删除缓存
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
     * 增加缓存值
     *
     * @param string $key 缓存键
     * @param int $value 增加值
     * @return int|false 新值或false
     */
    public function increment(string $key, int $value = 1): int|false
    {
        $fullKey = $this->getFullKey($key);

        try {
            // 1. 更新持久化缓存
            $newValue = Cache::increment($fullKey, $value);

            // 2. 更新内存缓存
            if ($this->enableMemoryCache && $newValue !== false) {
                self::$memoryCache[$fullKey] = $newValue;
            }

            return $newValue;
        } catch (\Exception $e) {
            Log::error('缓存增加失败: ' . $e->getMessage(), [
                'key' => $fullKey,
                'value' => $value,
                'exception' => $e,
            ]);
            return false;
        }
    }

    /**
     * 减少缓存值
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
     * 获取缓存前缀
     *
     * @return string 缓存前缀
     */
    public function getPrefix(): string
    {
        return $this->prefix;
    }

    /**
     * 设置缓存前缀
     *
     * @param string $prefix 缓存前缀
     * @return void
     */
    public function setPrefix(string $prefix): void
    {
        $this->prefix = $prefix;
    }

    /**
     * 获取默认缓存时间
     *
     * @return int 默认缓存时间（秒）
     */
    public function getDefaultTtl(): int
    {
        return $this->defaultTtl;
    }

    /**
     * 设置默认缓存时间
     *
     * @param int $ttl 默认缓存时间（秒）
     * @return void
     */
    public function setDefaultTtl(int $ttl): void
    {
        $this->defaultTtl = $ttl;
    }

    /**
     * 是否启用内存缓存
     *
     * @return bool 是否启用
     */
    public function isMemoryCacheEnabled(): bool
    {
        return $this->enableMemoryCache;
    }

    /**
     * 设置内存缓存状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setMemoryCacheEnabled(bool $enabled): void
    {
        $this->enableMemoryCache = $enabled;
    }

    /**
     * 清除内存缓存
     *
     * @return void
     */
    public function clearMemoryCache(): void
    {
        self::$memoryCache = [];
    }

    /**
     * 预热缓存
     *
     * @param array $items 缓存项数组 ['key' => value]
     * @param int|null $ttl 过期时间（秒）
     * @return int 成功数量
     */
    public function warmup(array $items, ?int $ttl = null): int
    {
        $successCount = 0;

        foreach ($items as $key => $value) {
            if ($this->set($key, $value, $ttl)) {
                $successCount++;
            }
        }

        Log::info('缓存预热完成', [
            'total' => count($items),
            'success' => $successCount,
            'failed' => count($items) - $successCount,
        ]);

        return $successCount;
    }

    /**
     * 获取缓存统计
     *
     * @return array 统计信息
     */
    public function getStats(): array
    {
        if (!$this->enableStats) {
            return [];
        }

        $total = self::$stats['hits'] + self::$stats['misses'];
        $hitRate = $total > 0 ? (self::$stats['hits'] / $total) * 100 : 0;

        return [
            'hits' => self::$stats['hits'],
            'misses' => self::$stats['misses'],
            'sets' => self::$stats['sets'],
            'deletes' => self::$stats['deletes'],
            'total' => $total,
            'hit_rate' => round($hitRate, 2),
        ];
    }

    /**
     * 重置缓存统计
     *
     * @return void
     */
    public function resetStats(): void
    {
        self::$stats = [
            'hits' => 0,
            'misses' => 0,
            'sets' => 0,
            'deletes' => 0,
        ];
    }

    /**
     * 是否启用统计
     *
     * @return bool 是否启用
     */
    public function isStatsEnabled(): bool
    {
        return $this->enableStats;
    }

    /**
     * 设置统计状态
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setStatsEnabled(bool $enabled): void
    {
        $this->enableStats = $enabled;
    }

    /**
     * 获取完整缓存键
     *
     * @param string $key 缓存键
     * @return string 完整缓存键
     */
    protected function getFullKey(string $key): string
    {
        return $this->prefix . $key;
    }

    /**
     * 记录缓存命中
     *
     * @return void
     */
    protected function recordHit(): void
    {
        if ($this->enableStats) {
            self::$stats['hits']++;
        }
    }

    /**
     * 记录缓存未命中
     *
     * @return void
     */
    protected function recordMiss(): void
    {
        if ($this->enableStats) {
            self::$stats['misses']++;
        }
    }

    /**
     * 记录缓存设置
     *
     * @return void
     */
    protected function recordSet(): void
    {
        if ($this->enableStats) {
            self::$stats['sets']++;
        }
    }

    /**
     * 记录缓存删除
     *
     * @return void
     */
    protected function recordDelete(): void
    {
        if ($this->enableStats) {
            self::$stats['deletes']++;
        }
    }
}
