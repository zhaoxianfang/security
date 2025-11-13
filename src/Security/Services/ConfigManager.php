<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Arr;

/**
 * 配置管理服务
 *
 * 提供灵活的配置获取功能，支持：
 * 1. 静态配置值
 * 2. 闭包/回调函数
 * 3. 类方法调用
 * 4. 缓存优化
 * 5. 智能类型识别
 */
class ConfigManager
{
    /**
     * 配置缓存
     */
    protected array $configCache = [];

    /**
     * 不应该解析为可调用对象的配置键名
     */
    protected array $noCallableKeys = [
        'enabled_type',
        'error_view',
    ];

    /**
     * 获取配置值
     * @param string $key 配置键名
     * @param mixed $default 默认值
     * @param mixed $params 闭包回调参数
     */
    public function get(string $key, mixed $default = null, mixed $params = null)
    {
        // 检查缓存
        if (Arr::has($this->configCache, $key)) {
            return Arr::get($this->configCache, $key, $default);
        }

        // 从配置文件获取
        $value = config("security.{$key}", $default);

        if($value instanceof \Closure){
            return call_user_func($value, $params);
        }
        // 处理动态配置（排除不应解析的键）
        $processedValue = $this->shouldProcessAsCallable($key) ?
            $this->processDynamicValue($value,$params) :
            $value;

        // 缓存结果
        Arr::set($this->configCache, $key, $processedValue);

        return $processedValue;
    }

    /**
     * 判断配置键是否应该被处理为可调用对象
     */
    protected function shouldProcessAsCallable(string $key): bool
    {
        // 检查是否在 不应该解析的列表中
        if (in_array($key, $this->noCallableKeys)) {
            return false;
        }

        // 检查是否为数组配置项的子键
        foreach ($this->noCallableKeys as $callableKey) {
            if (str_starts_with($key, "{$callableKey}.")) {
                return false;
            }
        }

        return true;
    }

    /**
     * 处理动态配置值
     */
    protected function processDynamicValue($value,mixed $params = null)
    {
        if (is_callable($value)) {
            return call_user_func($value,$params);
        }

        if (is_array($value) && $this->isCallableArray($value)) {
            return $this->callClassMethod($value, $params);
        }

        if (is_string($value) && $this->isCallableString($value)) {
            return $this->callClassMethodFromString($value);
        }

        return $value;
    }

    /**
     * 检查是否为可调用数组
     */
    protected function isCallableArray($value): bool
    {
        return count($value) === 2 &&
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
        // 排除视图模板格式 (包含 :: 但不是类方法调用)
        if (preg_match('/^[a-z0-9_-]+::[a-z0-9_-]+$/i', $value)) {
            return false;
        }

        // 检查是否为有效的类方法调用格式
        return preg_match('/^([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)(::)([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)$/', $value) &&
            class_exists(explode('::', $value)[0]);
    }

    /**
     * 调用类方法
     */
    protected function callClassMethod(array $callable,mixed $params = null)
    {
        [$class, $method] = $callable;

        try {
            $instance = App::make($class);
            return $instance->$method($params);
        } catch (\Exception $e) {
            // 记录错误并返回默认值
            \Illuminate\Support\Facades\Log::error("配置方法调用失败: {$class}::{$method} - " . $e->getMessage());
            return null;
        }
    }

    /**
     * 从字符串调用类方法
     */
    protected function callClassMethodFromString(string $callable)
    {
        [$class, $method] = explode('::', $callable, 2);

        try {
            $instance = App::make($class);
            return $instance->$method();
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::error("配置方法调用失败: {$callable} - " . $e->getMessage());
            return null;
        }
    }

    /**
     * 设置配置值
     */
    public function set(string $key, $value): void
    {
        Arr::set($this->configCache, $key, $value);
        config(["security.{$key}" => $value]);
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
        $config = config('security', []);
        $processed = [];

        foreach ($config as $key => $value) {
            $processed[$key] = $this->get($key);
        }

        return $processed;
    }

    /**
     * 清除配置缓存
     */
    public function clearCache(): void
    {
        $this->configCache = [];
    }

    /**
     * 重新加载配置
     */
    public function reload(): void
    {
        $this->clearCache();
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

        return gettype($value);
    }
}