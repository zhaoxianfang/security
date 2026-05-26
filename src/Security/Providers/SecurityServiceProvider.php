<?php

namespace zxf\Security\Providers;

use Throwable;
use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Console\AboutCommand;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Patterns\PatternService;
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
        // 防御：CLI 环境下视图服务可能尚未绑定或不可用（如部分 artisan 命令）
        try {
            if ($this->app->bound('view')) {
                $this->app['view']->addNamespace('security', __DIR__ . '/../../../resources/views');
            }
        } catch (\Throwable) {
            // 视图命名空间注册失败不应阻断应用启动（CLI 常见场景）
        }

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

        // 注册模式服务（单例，延迟加载）
        // PatternService 使用独立数据文件存储正则模式，
        // 不会在 php artisan optimize 时加载，有效解决内存溢出问题
        $this->app->singleton(PatternService::class, function () {
            return new PatternService();
        });
    }

    /**
     * 注册安全中间件
     *
     * 使用全局中间件栈确保 SecurityMiddleware 在所有路由上执行。
     * 不通过 middlewareGroup() 修改用户自定义组，避免与其他包冲突。
     *
     * ⚠️ 全局中间件在 Laravel Pipeline 中最先执行，早于任何路由组中间件。
     *    如果路由使用了 withoutMiddleware($alias)，该路由会跳过安全检查。
     *
     * ⚠️ Laravel 11+ 变更：$router->middleware() 返回 PendingMiddleware，
     *    不再修改全局中间件栈。本方法在 Laravel 11+ 下自动降级为组级注册，
     *    并记录日志提示用户在 bootstrap/app.php 中手动注册全局中间件。
     *
     * @return void
     */
    protected function registerMiddleware(): void
    {
        // 自动注册全局中间件
        // 仅当 security.enabled 为 true 时启用
        if (!config('security.enabled', true)) {
            return;
        }

        $router = $this->app['router'];
        $middleware = SecurityMiddleware::class;
        $alias = 'zxf.security';

        // 注册唯一中间件别名（内部使用，不冲突）
        $router->aliasMiddleware($alias, $middleware);

        // 检测 Laravel 版本
        $laravelVersion = $this->getLaravelVersion();
        $isLaravel11Plus = $laravelVersion !== null && version_compare($laravelVersion, '11.0.0', '>=');

        // ==============================================
        // 全局中间件：所有路由自动生效
        // ==============================================
        // 注意：getMiddleware() 返回的是已解析的类名字符串，不是别名。
        // 因此需同时检查别名和实际类名，防止重复注册。
        $globals = $router->getMiddleware();
        $globalAliases = array_keys($globals);
        $globalClasses = array_values($globals);
        $alreadyGlobal = in_array($alias, $globalAliases, true) || in_array($middleware, $globalClasses, true);

        if (!$alreadyGlobal) {
            if ($isLaravel11Plus) {
                // Laravel 11+：$router->middleware() 返回 PendingMiddleware，不修改全局栈。
                // 不在此处调用，避免静默无效。依赖下方组级兜底 + 用户手动注册。
                if ($this->app->bound('log') || class_exists('Illuminate\Support\Facades\Log')) {
                    \Illuminate\Support\Facades\Log::warning('[Security] Laravel 11+ 检测到。ServiceProvider 自动全局中间件注册已不可用。请在 bootstrap/app.php 中手动注册：->withMiddleware(function (\Illuminate\Foundation\Configuration\Middleware $middleware) { $middleware->append(' . SecurityMiddleware::class . '::class); })');
                }
            } else {
                // Laravel 10 及以下：$router->middleware() 可靠地添加全局中间件
                $router->middleware([$alias]);
            }
        }

        // ==============================================
        // 兜底：推送进 web / api / global 中间件组
        // Laravel 11+ 下这是 ServiceProvider 唯一能自动生效的注册方式
        // ==============================================
        foreach (['global', 'web', 'api'] as $group) {
            if ($router->hasMiddlewareGroup($group)) {
                $items = $router->getMiddlewareGroups()[$group] ?? [];
                $hasAlias = false;
                foreach ($items as $item) {
                    if ($item === $alias || $item === $middleware) {
                        $hasAlias = true;
                        break;
                    }
                }
                if (!$hasAlias) {
                    $router->pushMiddlewareToGroup($group, $alias);
                }
            }
        }
    }

    /**
     * 获取当前 Laravel 框架版本号
     *
     * @return string|null 版本号字符串，无法检测时返回 null
     */
    protected function getLaravelVersion(): ?string
    {
        try {
            if (class_exists('Illuminate\Foundation\Application')) {
                return \Illuminate\Foundation\Application::VERSION;
            }
        } catch (\Throwable) {
        }
        return null;
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
