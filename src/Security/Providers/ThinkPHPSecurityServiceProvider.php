<?php

namespace zxf\Security\Providers;

use think\App;
use zxf\Security\Bridge\FrameworkBridge;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Patterns\PatternService;

/**
 * ThinkPHP 8+ 安全服务注册类
 *
 * 由于 ThinkPHP 没有 Laravel 的 ServiceProvider 自动发现机制，
 * 本类提供手动注册入口，推荐在 app/AppService.php 的 init() 中调用：
 *
 * <code>
 * // app/AppService.php
 * public function init()
 * {
 *     \zxf\Security\Providers\ThinkPHPSecurityServiceProvider::register($this->app);
 * }
 * </code>
 *
 * 或者直接在 app/middleware.php 中注册中间件（推荐）：
 *
 * <code>
 * // app/middleware.php
 * return [
 *     // ... 其他中间件
 *     \zxf\Security\Middleware\SecurityMiddleware::class,
 * ];
 * </code>
 *
 * 使用本注册类的好处是自动合并默认配置，避免用户手动复制配置文件。
 *
 * @package zxf\Security\Providers
 * @since 6.1.0
 */
class ThinkPHPSecurityServiceProvider
{
    /**
     * 注册安全服务到 ThinkPHP 应用
     *
     * @param App $app ThinkPHP 应用实例
     * @return void
     */
    public static function register(App $app): void
    {
        // 1. 合并默认配置（确保即使未发布配置文件也有默认值）
        $defaultConfigPath = __DIR__ . '/../../../config/security.php';
        if (file_exists($defaultConfigPath)) {
            $defaultConfig = require $defaultConfigPath;
            $userConfig = $app->config->get('security', []);
            $merged = array_merge(
                is_array($defaultConfig) ? $defaultConfig : [],
                is_array($userConfig) ? $userConfig : []
            );
            // ThinkPHP Config::set() 单参数传入数组时按键值对设置
            $app->config->set(['security' => $merged]);
        }

        // 2. 注册模式服务到容器（单例）
        if (!$app->exists(PatternService::class)) {
            $app->bind(PatternService::class, function () {
                return new PatternService();
            });
        }

        // 3. 注册视图命名空间（ThinkPHP 下视图路径为项目目录）
        // 注意：ThinkPHP 的视图系统与 Laravel Blade 不同，
        // 建议将 resources/views/error.blade.php 复制到项目 view/security/error.html
        try {
            $viewPath = __DIR__ . '/../../../resources/views';
            if (is_dir($viewPath) && method_exists($app, 'getRootPath')) {
                // ThinkPHP Config::set(string $name, $value = null) 的批量设置需传入单层数组
                // 目标：设置 view.view_path，使用 ['view' => ['view_path' => $viewPath]] 形式
                $app->config->set(['view' => ['view_path' => $viewPath]]);
            }
        } catch (\Throwable) {
            // 视图注册失败不应阻断服务启动
        }
    }

    /**
     * 手动注册全局中间件（替代在 app/middleware.php 中配置）
     *
     * @param App $app ThinkPHP 应用实例
     * @return void
     */
    public static function registerMiddleware(App $app): void
    {
        try {
            if (method_exists($app, 'middleware')) {
                $app->middleware->add(SecurityMiddleware::class);
            }
        } catch (\Throwable $e) {
            FrameworkBridge::logWarning('[Security] ThinkPHP 中间件注册失败', [
                'exception' => $e->getMessage(),
            ]);
        }
    }
}
