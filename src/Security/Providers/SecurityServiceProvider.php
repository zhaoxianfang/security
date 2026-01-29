<?php

namespace zxf\Security\Providers;

use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\File;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Console\AboutCommand;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Services\ConfigManager;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\ThreatDetectionService;
use zxf\Security\Console\Commands\SecurityInstallCommand;
use zxf\Security\Console\Commands\SecurityCleanupCommand;
use Composer\InstalledVersions;


/**
 * 安全服务提供者 - 优化增强版
 *
 * 注册安全中间件和相关服务到Laravel容器
 * 提供完整的配置发布和路由注册功能
 */
class SecurityServiceProvider extends ServiceProvider
{
    /**
     * 服务提供者是否延迟加载
     */
    protected bool $defer = false;

    /**
     * 启动服务
     */
    public function boot(): void
    {
        // 发布配置文件
        $this->publishConfig();

        // 发布数据库迁移
        $this->publishMigrations();

        // 加载视图
        $this->loadViews();

        // 注册中间件
        $this->registerMiddleware();

        // 注册路由
        $this->registerRoutes();

        // 注册命令
        $this->registerCommands();

        // 注册about命令信息
        $this->registerAboutCommand();
    }

    /**
     * 注册服务
     */
    public function register(): void
    {
        // 合并配置文件
        $this->mergeConfig();

        // 注册服务到容器
        $this->registerServices();

        // 注册路由服务提供者
        $this->app->register(RouteServiceProvider::class);
    }

    /**
     * 发布配置文件
     */
    protected function publishConfig(): void
    {
        $this->publishes([
            __DIR__ . '/../../../config/security.php' => config_path('security.php'),
        ], ['security-config', 'security']);
    }

    /**
     * 发布数据库迁移
     */
    protected function publishMigrations(): void
    {
        $this->publishes([
            __DIR__ . '/../../Database/Migrations' => database_path('migrations'),
        ], ['security-migrations', 'security']);
    }

    /**
     * 加载视图
     */
    protected function loadViews(): void
    {
        $this->loadViewsFrom(__DIR__ . '/../../Resources/views', 'security');
    }

    /**
     * 注册中间件
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        // 注册中间件别名
        $router->aliasMiddleware('security', SecurityMiddleware::class);

        // 自动注册全局中间件（如果配置启用）
        $this->registerGlobalMiddleware();
    }

    /**
     * 注册全局中间件
     */
    protected function registerGlobalMiddleware(): void
    {
        // 检查配置是否已发布
        $configPath = config_path('security.php');
        $configExists = File::exists($configPath);

        if (!$configExists) {
            // 配置文件未发布，提示用户
            $this->showInstallPrompt();
            return;
        }

        // 检查是否启用全局中间件
        $enabled = config('security.enabled', true);
        $enabledType = config('security.enabled_type', 'global');

        // global：全局启用安全中间件
        if ($enabled && $enabledType === 'global') {
            $kernel = $this->app->make(Kernel::class);

            // 将安全中间件添加到全局中间件栈的最前面
            $kernel->prependMiddleware(SecurityMiddleware::class);

            if (config('security.enable_debug_logging', false)) {
                Log::debug('安全中间件已全局注册');
            }
        }
    }

    /**
     * 显示安装提示
     */
    protected function showInstallPrompt(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityInstallCommand::class,
            ]);

            $this->info(PHP_EOL . '==================================================================================');
            $this->info(' 提    示 | 检测到您已经安装了 zxf/security 安全中间件包，但是没有发布配置文件');
            $this->info(' 安装发布 | php artisan security:install');
            $this->info(' 发布配置 | php artisan vendor:publish --tag=security-config');
            $this->info(' 发布迁移 | php artisan vendor:publish --tag=security-migrations');
            $this->info(' 文档地址 | https://weisifang.com/docs/2');
            $this->info('==================================================================================' . PHP_EOL);
        }
    }

    /**
     * 输出信息（控制台）
     */
    protected function info(string $message): void
    {
        if ($this->app->runningInConsole()) {
            echo $message . PHP_EOL;
        }
    }

    /**
     * 注册路由
     */
    protected function registerRoutes(): void
    {
        // 路由已经在 RouteServiceProvider 中注册
        // 这里可以添加额外的路由注册逻辑
    }

    /**
     * 注册命令
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityInstallCommand::class,   // 一键安装命令
                SecurityCleanupCommand::class,   // 清理命令
            ]);
        }
    }

    /**
     * 注册about命令信息
     */
    protected function registerAboutCommand(): void
    {
        AboutCommand::add('Security Package', [
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
            'Middleware Type' => function () {
                return config('security.enabled_type', 'global');
            },
            'Rate Limiting' => function () {
                return config('security.enable_rate_limiting', true) ? 'Enabled' : 'Disabled';
            },
            'IP Auto Detection' => function () {
                return config('security.ip_auto_detection.enabled', true) ? 'Enabled' : 'Disabled';
            },
        ]);
    }

    /**
     * 合并配置文件
     */
    protected function mergeConfig(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../../config/security.php', 'security'
        );
    }

    /**
     * 注册服务到容器
     */
    protected function registerServices(): void
    {
        // 配置管理器（单例）
        $this->app->singleton(ConfigManager::class, function ($app) {
            return new ConfigManager();
        });

        // IP管理服务（单例）
        $this->app->singleton(IpManagerService::class, function ($app) {
            return new IpManagerService($app->make(ConfigManager::class));
        });

        // 速率限制服务（单例）
        $this->app->singleton(RateLimiterService::class, function ($app) {
            return new RateLimiterService($app->make(ConfigManager::class));
        });

        // 威胁检测服务（单例）
        $this->app->singleton(ThreatDetectionService::class, function ($app) {
            return new ThreatDetectionService($app->make(ConfigManager::class));
        });

        // 安全中间件（单例）
        $this->app->singleton(SecurityMiddleware::class, function ($app) {
            return new SecurityMiddleware(
                $app->make(RateLimiterService::class),
                $app->make(IpManagerService::class),
                $app->make(ThreatDetectionService::class)
            );
        });
    }

    /**
     * 获取服务提供者提供的服务
     */
    public function provides(): array
    {
        return [
            ConfigManager::class,
            IpManagerService::class,
            RateLimiterService::class,
            ThreatDetectionService::class,
            SecurityMiddleware::class,
        ];
    }
}
