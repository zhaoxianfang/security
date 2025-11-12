<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Arr;

/**
 * 配置管理服务
 *
 * 提供灵活的配置获取功能，支持：
 * 1. 静态配置值
 * 2. 闭包/回调函数
 * 3. 类方法调用
 * 4. 缓存优化
 */
class ConfigManager
{
    /**
     * 配置缓存
     */
    protected array $configCache = [];

    /**
     * 获取配置值
     */
    public function get(string $key, $default = null)
    {
        // 检查缓存
        if (Arr::has($this->configCache, $key)) {
            return Arr::get($this->configCache, $key, $default);
        }

        // 从配置文件获取
        $value = config("security.{$key}", $default);

        // 处理动态配置
        $processedValue = $this->processDynamicValue($value);

        // 缓存结果
        Arr::set($this->configCache, $key, $processedValue);

        return $processedValue;
    }

    /**
     * 处理动态配置值
     */
    protected function processDynamicValue($value)
    {
        if (is_callable($value)) {
            return call_user_func($value);
        }

        if (is_array($value) && $this->isCallableArray($value)) {
            return $this->callClassMethod($value);
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
        return str_contains($value, '::') &&
            preg_match('/^([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)(::)([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)$/', $value);
    }

    /**
     * 调用类方法
     */
    protected function callClassMethod(array $callable)
    {
        [$class, $method] = $callable;

        try {
            $instance = App::make($class);
            return $instance->$method();
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
}