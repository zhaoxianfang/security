<?php

namespace zxf\Security\Services;

/**
 * 配置解析服务
 *
 * 支持多种配置格式的统一解析：
 * 1. 静态数组 — 直接返回
 * 2. 闭包函数 — 调用后返回数组
 * 3. 类名字符串 — 实例化后调用 __invoke 或返回数组的方法
 * 4. 可调用数组 — [类名, 方法名]
 *
 * 应用场景：
 * - trusted_ips、whitelist、blacklist 的动态解析
 * - user_agent_blacklist 的动态扩展
 * - upload.allowed_extensions / blocked_extensions 的动态计算
 * - markdown.syntax_patterns 的动态定义
 *
 * @package zxf\Security\Services
 * @since 6.0.0
 */
class ConfigResolver
{
    /**
     * 解析配置项为数组
     *
     * @param mixed $config 配置值（数组、闭包、类名、可调用数组）
     * @return array 解析后的数组
     */
    public static function resolve(mixed $config): array
    {
        // 1. 闭包函数
        if ($config instanceof \Closure) {
            $result = $config();
            return is_array($result) ? $result : [];
        }

        // 2. 可调用数组 [类名/实例, 方法名] — 必须在普通数组之前检查
        if (is_array($config) && count($config) === 2 && is_callable($config)) {
            $result = $config();
            return is_array($result) ? $result : [];
        }

        // 3. 已经是普通数组，直接返回
        if (is_array($config)) {
            return $config;
        }

        // 4. 可调用对象（传入实例且实现了 __invoke）
        if (is_object($config) && is_callable($config)) {
            $result = $config();
            return is_array($result) ? $result : [];
        }

        // 5. 类名字符串
        if (is_string($config) && class_exists($config)) {
            $instance = app($config);

            // 5a. 优先尝试约定方法（getItems / getConfig / resolve / toArray / all）
            foreach (['getItems', 'getConfig', 'resolve', 'toArray', 'all'] as $method) {
                if (method_exists($instance, $method)) {
                    $result = $instance->{$method}();
                    return is_array($result) ? $result : [];
                }
            }

            // 5b. 若未实现约定方法，再尝试可调用对象
            if (is_callable($instance)) {
                $result = $instance();
                return is_array($result) ? $result : [];
            }

            return [];
        }

        return [];
    }

    /**
     * 批量解析多个配置项
     *
     * @param array<string, mixed> $configs 配置项数组
     * @return array<string, array> 解析后的数组
     */
    public static function resolveMany(array $configs): array
    {
        $resolved = [];

        foreach ($configs as $key => $config) {
            $resolved[$key] = self::resolve($config);
        }

        return $resolved;
    }
}
