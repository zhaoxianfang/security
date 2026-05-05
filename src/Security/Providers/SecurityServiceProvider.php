<?php

namespace zxf\Security\Providers;

use Throwable;
use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Console\AboutCommand;
use zxf\Security\Middleware\SecurityMiddleware;
use Composer\InstalledVersions;

/**
 * 安全服务提供者
 *
 * 负责将安全中间件注册到 Laravel 应用。
 * 遵循 Laravel 服务容器最佳实践，支持延迟加载和配置发布。
 *
 * 功能：
 * 1. 发布配置文件到 config/security.php
 * 2. 注册安全中间件别名
 * 3. 自动启用全局安全保护（可选）
 *
 * @package zxf\Security\Providers
 */
class SecurityServiceProvider extends ServiceProvider
{
    /**
     * 启动服务
     *
     * 在应用启动时调用，用于：
     * - 发布配置文件
     * - 注册中间件别名
     * - 加载视图/路由（如有需要）
     *
     * @return void
     */
    public function boot(): void
    {
        // 发布配置文件到应用的 config 目录
        // 用户可通过 --tag=security-config 选择性发布
        $this->publishes([
            __DIR__ . '/../../../config/security.php' => config_path('security.php'),
        ], ['security-config']);

        // 注册视图命名空间
        // 使用 security::error 访问安全拦截错误页面
        app('view')->addNamespace('security', __DIR__ . '/../../../resources/views');

        // 注册安全中间件
        $this->registerMiddleware();

        // 注册about命令信息
        $this->registerAboutCommand();
    }

    /**
     * 注册服务
     *
     * 在应用容器构建时调用，用于：
     * - 合并默认配置
     * - 绑定接口到实现
     * - 注册单例服务
     *
     * @return void
     */
    public function register(): void
    {
        // 合并默认配置
        // 确保即使用户未发布配置文件，也有默认配置可用
        $this->mergeConfigFrom(
            __DIR__ . '/../../../config/security.php',
            'security'
        );
    }

    /**
     * 注册安全中间件
     *
     * 将安全中间件注册到 Laravel 路由系统：
     * 1. 注册中间件别名 'security'，可在路由中使用
     * 2. 如配置启用，自动添加到全局中间件栈
     *
     * @return void
     */
    protected function registerMiddleware(): void
    {
        // 自动注册全局中间件
        // 仅当 security.enabled 为 true 时启用
        if (config('security.enabled', true)) {
            // 保证在
            $router = $this->app['router'];

            // 1. 注册唯一中间件别名（内部使用，不冲突）

            // 1. 注册唯一中间件别名（内部使用，不冲突）
            $middleware = SecurityMiddleware::class;
            $alias = 'zxf.security';
            $router->aliasMiddleware($alias, $middleware);

            // ==============================================
            // 🔥 终极保障 1：全局所有路由 强制附加中间件
            // 无论路由有没有组、有没有中间件，全部执行！
            // ==============================================
            $router->middleware([$alias]);

            // ==============================================
            // 🔥 终极保障 2：安全注入所有存在的中间件组
            // 自动判断组是否存在，不存在则跳过，绝对不报错
            // ==============================================

            // 系统默认核心组（全覆盖）
            $defaultGroups = [
                'web', 'api', 'auth', 'guest',
                'sanctum', 'auth:sanctum', 'verified'
            ];

            // 获取项目实际已注册的所有组
            $existsGroups = array_keys($router->getMiddlewareGroups());

            // 合并去重
            $allGroups = array_unique(array_merge($defaultGroups, $existsGroups));

            // 循环：组存在才注入，不存在直接跳过
            foreach ($allGroups as $group) {
                if ($router->hasMiddlewareGroup($group)) {
                    $router->pushMiddlewareToGroup($group, $alias);
                }
            }
        }
    }

    /**
     * 注册about命令信息
     */
    protected function registerAboutCommand(): void
    {
        AboutCommand::add('Security', [
            'zxf/security' => function () {
                try {
                    return InstalledVersions::getPrettyVersion('zxf/security') ?? 'unknown';
                } catch (Throwable $e) {
                    return 'unknown';
                }
            },
            'Enabled' => function () {
                return config('security.enabled', true) ? 'Yes' : 'No';
            },
            'Log Enabled' => function () {
                return config('security.log_enabled', true) ? 'Yes' : 'No';
            },
            'Rate Limiting' => function () {
                return config('security.detection_layers.rate_limit', true) ? 'Enabled' : 'Disabled';
            },
        ]);
    }
}
