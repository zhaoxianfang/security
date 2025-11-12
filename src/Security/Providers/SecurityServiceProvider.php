<?php

namespace Zxf\Security\Providers;

use Illuminate\Support\ServiceProvider;
use Zxf\Security\Middleware\SecurityMiddleware;
use Zxf\Security\Services\ConfigManager;
use Zxf\Security\Services\RateLimiterService;
use Zxf\Security\Services\IpManagerService;
use Zxf\Security\Services\ThreatDetectionService;

/**
 * 安全服务提供者 - 优化版
 *
 * 注册安全中间件和相关服务到Laravel容器
 * 取消发布视图和资源文件，改为路由访问
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
        $this->publishes([
            __DIR__ . '/../../../config/security.php' => config_path('security.php'),
        ], 'security-config');

        // 加载视图（不发布，直接从包内访问）
        $this->loadViewsFrom(__DIR__ . '/../../Resources/views', 'security');

        // 注册中间件
        $this->registerMiddleware();

        // 注册路由
        $this->registerRoutes();

        // 注册命令
        if ($this->app->runningInConsole()) {
            $this->registerCommands();
        }
    }

    /**
     * 注册服务
     */
    public function register(): void
    {
        // 合并配置文件
        $this->mergeConfigFrom(
            __DIR__ . '/../../../config/security.php', 'security'
        );

        // 注册服务到容器
        $this->registerServices();

        // 注册路由服务提供者
        $this->app->register(RouteServiceProvider::class);
    }

    /**
     * 注册服务到容器
     */
    protected function registerServices(): void
    {
        // 配置管理器
        $this->app->singleton(ConfigManager::class, function ($app) {
            return new ConfigManager();
        });

        // IP管理服务
        $this->app->singleton(IpManagerService::class, function ($app) {
            return new IpManagerService($app->make(ConfigManager::class));
        });

        // 速率限制服务
        $this->app->singleton(RateLimiterService::class, function ($app) {
            return new RateLimiterService($app->make(ConfigManager::class));
        });

        // 威胁检测服务
        $this->app->singleton(ThreatDetectionService::class, function ($app) {
            return new ThreatDetectionService($app->make(ConfigManager::class));
        });

        // 安全中间件
        $this->app->singleton(SecurityMiddleware::class, function ($app) {
            return new SecurityMiddleware(
                $app->make(RateLimiterService::class),
                $app->make(IpManagerService::class),
                $app->make(ThreatDetectionService::class)
            );
        });
    }

    /**
     * 注册中间件
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        // 注册中间件别名
        $router->aliasMiddleware('security', SecurityMiddleware::class);

        // 注册中间件组（可选，根据需要启用）
        // $router->pushMiddlewareToGroup('web', SecurityMiddleware::class);
        // $router->pushMiddlewareToGroup('api', SecurityMiddleware::class);
    }

    /**
     * 注册路由
     */
    protected function registerRoutes(): void
    {
        // 路由已经在 RouteServiceProvider 中注册
    }

    /**
     * 注册命令
     */
    protected function registerCommands(): void
    {
        $this->commands([
            // 可以在这里注册Artisan命令
        ]);
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