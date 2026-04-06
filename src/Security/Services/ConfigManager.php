<?php

namespace zxf\Security\Services;

use Closure;
use Exception;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 配置管理服务 - 高性能预加载版本
 *
 * 提供灵活的配置获取功能，支持：
 * 1. 静态配置值
 * 2. 闭包/回调函数
 * 3. 类方法调用
 * 4. 多级缓存优化
 * 5. 智能类型识别
 * 6. 配置验证和回退
 * 7. 配置预加载，减少运行时开销
 */
class ConfigManager
{
    /**
     * @var object 对象实例
     */
    protected static $instance;

    /**
     * 配置缓存
     */
    protected array $configCache = [];

    /**
     * 预加载配置缓存
     */
    protected static array $preloadedConfig = [];

    /**
     * 是否已预加载
     */
    protected static bool $isPreloaded = false;

    /**
     * 缓存键前缀
     */
    protected const CACHE_PREFIX = 'security:config:';

    /**
     * 缓存时间（秒）
     */
    protected const CACHE_TTL = 3600;

    /**
     * 高频率访问的配置键（预加载）
     */
    protected const HIGH_FREQUENCY_KEYS = [
        'enabled',
        'ignore_local',
        'enable_debug_logging',
        'enable_rate_limiting',
        'rate_limits',
        'rate_limit_strategy',
        'defense_layers',
        'enable_ip_cache',
        'ip_auto_detection',
    ];

    /**
     * 不应该解析为可调用对象的配置键名
     */
    protected array $noCallableKeys = [
        'enabled_type',
        'error_view',
        'rate_limit_strategy',
        'ajax_response_format.code',
        'ajax_response_format.message',
        'ajax_response_format.data',
        'response_status_codes',
        'trusted_proxies',
        'trusted_headers',
    ];

    /**
     * 获取单例实例
     */
    public static function instance(bool $refresh = false): self
    {
        if (!isset(self::$instance) || $refresh) {
            self::$instance = new self();
            // 自动预加载高频率配置
            if (!self::$isPreloaded || $refresh) {
                self::$instance->preload();
            }
        }
        return self::$instance;
    }

    /**
     * 预加载高频率配置 - 减少运行时开销
     */
    public function preload(): void
    {
        if (self::$isPreloaded) {
            return;
        }

        foreach (self::HIGH_FREQUENCY_KEYS as $key) {
            $value = $this->getFromSource($key);
            self::$preloadedConfig[$key] = $value;
        }

        self::$isPreloaded = true;

        if (config('security.enable_debug_logging', false)) {
            Log::debug('配置预加载完成', ['keys' => self::HIGH_FREQUENCY_KEYS]);
        }
    }

    /**
     * 从源获取配置（不经过缓存）
     */
    protected function getFromSource(string $key): mixed
    {
        $rawValue = config("security.{$key}");

        if ($rawValue === null) {
            return $this->getDefaultValue($key);
        }

        return $this->shouldProcessAsCallable($key)
            ? $this->processDynamicValue($rawValue)
            : $rawValue;
    }

    /**
     * 获取默认值
     */
    protected function getDefaultValue(string $key): mixed
    {
        return match($key) {
            'enabled' => true,
            'enable_rate_limiting' => true,
            'rate_limits' => ['minute' => 60, 'hour' => 1000],
            'rate_limit_strategy' => 'ip_ua_path',
            'enable_ip_cache' => true,
            'enable_debug_logging' => false,
            'ignore_local' => false,
            'defense_layers' => [],
            'ip_auto_detection' => ['enabled' => true],
            default => null,
        };
    }

    /**
     * 获取配置值 - 支持热重载和高性能缓存
     */
    public function get(string $key, mixed $default = null, mixed $params = null): mixed
    {
        // 1. 检查预加载配置（最快路径）
        if ($params === null && isset(self::$preloadedConfig[$key])) {
            return self::$preloadedConfig[$key];
        }

        // 2. 检查是否应该实时读取
        if ($this->shouldReadRealtime($key)) {
            return $this->getRealtime($key, $default, $params);
        }

        // 3. 构建完整缓存键
        $cacheKey = $this->getCacheKey($key, $params);

        // 4. 检查实例内存缓存
        if (array_key_exists($cacheKey, $this->configCache)) {
            return $this->configCache[$cacheKey] ?? $default;
        }

        // 5. 检查持久化缓存
        if ($this->shouldCache($key)) {
            $cachedValue = Cache::get($cacheKey);
            if ($cachedValue !== null) {
                $this->configCache[$cacheKey] = $cachedValue;
                return $cachedValue;
            }
        }

        // 6. 从源获取配置
        $processedValue = $this->getFromSource($key);

        // 7. 处理动态配置参数
        if ($params !== null && $this->shouldProcessAsCallable($key)) {
            $processedValue = $this->processDynamicValue($processedValue, $params);
        }

        // 8. 使用默认值
        if ($processedValue === null) {
            $processedValue = $default;
        }

        // 9. 缓存处理结果
        $this->cacheValue($key, $cacheKey, $processedValue);

        return $processedValue;
    }

    /**
     * 实时读取配置（不使用缓存）
     */
    protected function getRealtime(string $key, mixed $default = null, mixed $params = null): mixed
    {
        // 直接从配置文件读取
        $rawValue = config("security.{$key}", $default);

        // 处理动态配置
        return $this->shouldProcessAsCallable($key)
            ? $this->processDynamicValue($rawValue, $params)
            : $rawValue;
    }

    /**
     * 检查配置项是否应实时读取
     *
     * 直接读取配置，避免通过热重载服务造成递归
     */
    protected function shouldReadRealtime(string $key): bool
    {
        try {
            // 直接从Laravel配置读取no_cache_keys，避免通过ConfigHotReloadService
            $noCacheKeys = config('security.hot_reload.no_cache_keys', []);

            foreach ($noCacheKeys as $pattern) {
                if (str_ends_with($pattern, '*')) {
                    $prefix = substr($pattern, 0, -1);
                    if (str_starts_with($key, $prefix)) {
                        return true;
                    }
                } elseif ($key === $pattern) {
                    return true;
                }
            }

            return false;

        } catch (\Exception $e) {
            // 忽略错误，返回false
            return false;
        }
    }

    /**
     * 判断配置键是否应该被处理为可调用对象
     */
    protected function shouldProcessAsCallable(string $key): bool
    {
        // 检查是否在不应该解析的列表中
        foreach ($this->noCallableKeys as $callableKey) {
            if ($key === $callableKey || str_starts_with($key, "{$callableKey}.")) {
                return false;
            }
        }

        return true;
    }

    /**
     * 处理动态配置值
     */
    protected function processDynamicValue(mixed $value, mixed $params = null): mixed
    {
        if ($value instanceof Closure) {
            try {
                return call_user_func($value, $params);
            } catch (Throwable $e) {
                Log::error('配置闭包执行失败: ' . $e->getMessage(), [
                    'value_type' => gettype($value),
                    'exception' => $e
                ]);
                return null;
            }
        }

        if (is_array($value) && $this->isCallableArray($value)) {
            return $this->callClassMethod($value, $params);
        }

        if (is_string($value) && $this->isCallableString($value)) {
            return $this->callClassMethodFromString($value, $params);
        }

        return $value;
    }

    /**
     * 检查是否为可调用数组
     */
    protected function isCallableArray(mixed $value): bool
    {
        return is_array($value) &&
            count($value) === 2 &&
            is_string($value[0]) &&
            is_string($value[1]) &&
            class_exists($value[0]) &&
            method_exists($value[0], $value[1]);
    }

    /**
     * 检查是否为可调用字符串
     */
    protected function isCallableString(string $value): bool
    {
        // 排除视图模板格式
        if (preg_match('/^[a-z0-9_-]+::[a-z0-9_-]+$/i', $value)) {
            return false;
        }

        // 检查是否为有效的类方法调用格式
        if (str_contains($value, '::')) {
            [$class, $method] = explode('::', $value, 2);
            return class_exists($class) && method_exists($class, $method);
        }

        return false;
    }

    /**
     * 调用类方法
     */
    protected function callClassMethod(array $callable, mixed $params = null): mixed
    {
        [$class, $method] = $callable;

        try {
            $instance = App::make($class);

            if ($params !== null) {
                return $instance->$method($params);
            }

            return $instance->$method();

        } catch (Throwable $e) {
            Log::error("配置方法调用失败: {$class}::{$method} - " . $e->getMessage(), [
                'class' => $class,
                'method' => $method,
                'params' => $params,
                'exception' => $e
            ]);
            return null;
        }
    }

    /**
     * 从字符串调用类方法
     */
    protected function callClassMethodFromString(string $callable, mixed $params = null): mixed
    {
        try {
            if (empty($callable) || !str_contains($callable, '::')) {
                Log::warning('无效的类方法调用格式', ['callable' => $callable]);
                return null;
            }

            [$class, $method] = explode('::', $callable, 2);

            if (empty($class) || empty($method)) {
                Log::warning('类名或方法名为空', ['callable' => $callable]);
                return null;
            }

            if (!class_exists($class)) {
                Log::warning('类不存在', ['class' => $class]);
                return null;
            }

            if (!method_exists($class, $method)) {
                Log::warning('方法不存在', ['class' => $class, 'method' => $method]);
                return null;
            }

            $instance = App::make($class);

            if ($params !== null) {
                return $instance->$method($params);
            }

            return $instance->$method();

        } catch (Throwable $e) {
            Log::error("配置方法调用失败: {$callable} - " . $e->getMessage(), [
                'callable' => $callable,
                'params' => $params,
                'exception' => $e
            ]);
            return null;
        }
    }

    /**
     * 获取缓存键
     */
    protected function getCacheKey(string $key, mixed $params = null): string
    {
        try {
            $paramsHash = $params ? md5(serialize($params)) : 'null';
            return self::CACHE_PREFIX . md5("{$key}:{$paramsHash}");
        } catch (Throwable $e) {
            Log::error('生成缓存键失败: ' . $e->getMessage(), [
                'key' => $key,
                'exception' => $e
            ]);
            // 返回一个简单的缓存键
            return self::CACHE_PREFIX . md5($key);
        }
    }

    /**
     * 判断是否应该缓存
     */
    protected function shouldCache(string $key): bool
    {
        // 某些配置不应该缓存
        $noCacheKeys = [
            'enabled',
            'enabled_type',
            'ignore_local',
            'enable_debug_logging',
            'log_level',
            'log_details',
            'block_on_exception',
        ];

        return !in_array($key, $noCacheKeys);
    }

    /**
     * 缓存值
     */
    protected function cacheValue(string $key, string $cacheKey, mixed $value): void
    {
        try {
            // 内存缓存
            $this->configCache[$cacheKey] = $value;

            // 持久化缓存
            if ($this->shouldCache($key)) {
                $cacheTtl = config('security.cache_ttl', self::CACHE_TTL);
                // 验证cacheTtl为正数
                if (!is_int($cacheTtl) || $cacheTtl <= 0) {
                    $cacheTtl = self::CACHE_TTL;
                }
                Cache::put($cacheKey, $value, $cacheTtl);
            }
        } catch (Throwable $e) {
            Log::error('缓存配置值失败: ' . $e->getMessage(), [
                'key' => $key,
                'cacheKey' => $cacheKey,
                'exception' => $e
            ]);
        }
    }

    /**
     * 设置配置值
     */
    public function set(string $key, mixed $value): void
    {
        // 清除缓存
        $this->clearKeyCache($key);

        // 设置配置
        config(["security.{$key}" => $value]);

        // 清除内存缓存
        $cacheKey = $this->getCacheKey($key);
        Arr::forget($this->configCache, $cacheKey);
    }

    /**
     * 检查配置是否存在
     */
    public function has(string $key): bool
    {
        return !is_null($this->get($key));
    }

    /**
     * 获取所有配置
     */
    public function all(): array
    {
        $cacheKey = self::CACHE_PREFIX . 'all';

        if (isset($this->configCache[$cacheKey])) {
            return $this->configCache[$cacheKey];
        }

        $allConfig = Cache::remember($cacheKey, self::CACHE_TTL, function () {
            $config = config('security', []);
            $processed = [];

            foreach ($config as $key => $value) {
                $processed[$key] = $this->get($key);
            }

            return $processed;
        });

        $this->configCache[$cacheKey] = $allConfig;
        return $allConfig;
    }

    /**
     * 清除配置缓存
     */
    public function clearCache(): void
    {
        $this->configCache = [];

        // 清除持久化缓存
        Cache::forget(self::CACHE_PREFIX . 'all');

        // 清除所有配置相关的缓存
        $pattern = self::CACHE_PREFIX . '*';
        $this->clearPatternCache($pattern);
    }

    /**
     * 清除指定键的缓存
     */
    public function clearKeyCache(string $key): void
    {
        // 清除所有可能的参数组合的缓存
        $pattern = self::CACHE_PREFIX . md5($key . ':*');
        $this->clearPatternCache($pattern);

        // 清除无参数的缓存
        $cacheKey = $this->getCacheKey($key);
        Cache::forget($cacheKey);

        // 清除内存缓存
        Arr::forget($this->configCache, $cacheKey);
    }

    /**
     * 清除模式匹配的缓存
     */
    protected function clearPatternCache(string $pattern): void
    {
        // 这是一个占位实现
        // 实际实现取决于使用的缓存驱动

        // 对于Redis，可以使用SCAN命令
        // 对于文件缓存，可以遍历文件
    }

    /**
     * 重新加载配置
     */
    public function reload(): void
    {
        $this->clearCache();
        self::$preloadedConfig = [];
        self::$isPreloaded = false;
        $this->preload();
    }

    /**
     * 获取预加载配置统计
     */
    public function getPreloadStats(): array
    {
        return [
            'is_preloaded' => self::$isPreloaded,
            'preloaded_keys' => array_keys(self::$preloadedConfig),
            'memory_cache_size' => count($this->configCache),
        ];
    }

    /**
     * 批量设置配置
     */
    public function setMany(array $config): void
    {
        foreach ($config as $key => $value) {
            $this->set($key, $value);
        }
    }

    /**
     * 获取配置类型
     */
    public function getType(string $key): string
    {
        $value = $this->get($key);

        if (is_array($value)) {
            return 'array';
        }

        if (is_bool($value)) {
            return 'boolean';
        }

        if (is_int($value)) {
            return 'integer';
        }

        if (is_float($value)) {
            return 'float';
        }

        if (is_string($value)) {
            return 'string';
        }

        if (is_callable($value)) {
            return 'callable';
        }

        if (is_null($value)) {
            return 'null';
        }

        return gettype($value);
    }

    /**
     * 验证配置有效性
     */
    public function validate(string $key): bool
    {
        $value = $this->get($key);

        if (is_null($value)) {
            return false;
        }

        // 根据键名进行特定验证
        return match(true) {
            str_contains($key, 'threshold') => $this->validateThreshold($value),
            str_contains($key, 'duration') => $this->validateDuration($value),
            str_contains($key, 'limit') => $this->validateLimit($value),
            str_contains($key, 'enabled') => is_bool($value),
            default => true,
        };
    }

    /**
     * 验证阈值
     */
    protected function validateThreshold(mixed $value): bool
    {
        if (!is_numeric($value)) {
            return false;
        }

        $floatValue = (float) $value;
        return $floatValue >= 0 && $floatValue <= 100;
    }

    /**
     * 验证时长
     */
    protected function validateDuration(mixed $value): bool
    {
        if (!is_numeric($value)) {
            return false;
        }

        $intValue = (int) $value;
        return $intValue >= 0;
    }

    /**
     * 验证限制
     */
    protected function validateLimit(mixed $value): bool
    {
        if (!is_numeric($value)) {
            return false;
        }

        $intValue = (int) $value;
        return $intValue >= 0;
    }

}
