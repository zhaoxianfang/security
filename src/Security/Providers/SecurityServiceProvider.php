<?php

namespace zxf\Security\Providers;

use Illuminate\Support\ServiceProvider;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Services\ConfigManager;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\ThreatDetectionService;
use Illuminate\Foundation\Console\AboutCommand;
use Composer\InstalledVersions;
use Illuminate\Support\Facades\File;
use Illuminate\Contracts\Http\Kernel;

/**
 * 安全服务提供者
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

        // 把 zxf/security 添加到 about 命令中
        AboutCommand::add('zxf', [
            'zxf/security' => fn () => InstalledVersions::getPrettyVersion('zxf/security'),
        ]);
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

        // 判断是否发布配置
        $this->checkConfigPublished();

        // 注册中间件组（可选，根据需要启用）
        // $router->pushMiddlewareToGroup('web', SecurityMiddleware::class);
        // $router->pushMiddlewareToGroup('api', SecurityMiddleware::class);
    }

    // 判断是否发布配置,如果已经发布配置，则检测是否需要全局启用security中间件
    protected function checkConfigPublished(): void
    {
        // 判断配置文件是否已发布
        $configHasPublished = File::exists(config_path('security.php'));
        if ($configHasPublished) {
            // 配置文件已发布，判断是否需要全局启用security中间件
            $middlewareEnabledType = config('security.enabled_type','global');
            if ($middlewareEnabledType === 'global') {
                // 全局启用security中间件
                $kernel = $this->app->make(Kernel::class);
                // $kernel->pushMiddleware(SecurityMiddleware::class); // 追加在后面
                $kernel->prependMiddleware(SecurityMiddleware::class); // 放在最前面
            }
        } else {
            if ($this->app->runningInConsole() ) {
                // 没有发布配置文件且处于控制台下提示发布配置
                echo PHP_EOL;
                echo '=================================================================================='.PHP_EOL;
                echo ' 提    示 | 检查到您已经安装了 zxf/security 安全中间件包，但是没有发布配置文件'.PHP_EOL;
                echo ' 发布命令 | php artisan vendor:publish --tag=security-config '.PHP_EOL;
                echo ' 文档地址 | https://weisifang.com/docs/2 '.PHP_EOL;
                echo '=================================================================================='.PHP_EOL;
            }
        }
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