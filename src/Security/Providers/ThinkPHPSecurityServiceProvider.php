<?php

namespace zxf\Security\Providers;

use think\App;
use zxf\Security\Bridge\FrameworkBridge;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Patterns\PatternService;
use zxf\Security\Services\CliCommandProtector;

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
            $app->bind(PatternService::class, function () use ($app) {
                $patternService = new PatternService();

                // 注册自定义模式文件（从配置，一次性加载）
                $securityConfig = $app->config->get('security', []);
                $customPatternsConfig = $securityConfig['custom_patterns'] ?? [];
                if (!empty($customPatternsConfig)) {
                    PatternService::registerCustomPatternsFromConfig($customPatternsConfig);
                }

                return $patternService;
            });
        }

        // 3. 注册视图命名空间（ThinkPHP 下视图路径为项目目录）
        try {
            $viewPath = __DIR__ . '/../../../resources/views';
            if (is_dir($viewPath) && method_exists($app, 'getRootPath')) {
                $app->config->set(['view' => ['view_path' => $viewPath]]);
            }
        } catch (\Throwable) {
            // 视图注册失败不应阻断服务启动
        }

        // 4. 注册 Artisan CLI 命令保护（ThinkPHP 8+ CLI 支持）
        // ThinkPHP 的 CLI 模式通过 think\console\Command 体系运行，
        // 需要在应用启动时注册控制台事件监听
        self::registerConsoleProtection($app);
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

    // ============================================
    // CLI 命令保护（ThinkPHP 8+ 实现 — 委托给 CliCommandProtector）
    // ============================================

    /**
     * 注册 Artisan CLI 命令保护（ThinkPHP 版本）
     *
     * ThinkPHP 8+ 的命令系统基于 Symfony Console 实现，
     * 通过 CliCommandProtector 共享 Laravel 相同的危险命令检测逻辑。
     */
    protected static function registerConsoleProtection(App $app): void
    {
        if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
            return;
        }

        $securityConfig = $app->config->get('security', []);
        if (!CliCommandProtector::isCliProtectionEnabled($securityConfig)) {
            return;
        }

        try {
            if (class_exists('think\console\Input') && class_exists('think\console\Output')) {
                self::registerThinkPhpConsoleHook($app, $securityConfig);
            }
        } catch (\Throwable) {
        }
    }

    /**
     * 注册 ThinkPHP 控制台钩子
     */
    protected static function registerThinkPhpConsoleHook(App $app, array $securityConfig): void
    {
        if (!$app->exists('think\Console')) {
            return;
        }

        $console = $app->get('think\Console');
        if (!is_object($console) || !method_exists($console, 'add')) {
            return;
        }

        try {
            if (method_exists($console, 'getDispatcher')) {
                $dispatcher = $console->getDispatcher();
                if ($dispatcher && method_exists($dispatcher, 'addListener')) {
                    $protector = new CliCommandProtector($securityConfig);
                    $dispatcher->addListener('console.command', function ($event) use ($protector, $app) {
                        self::checkThinkPhpCommand($event, $protector, $app);
                    });
                }
            }
        } catch (\Throwable) {
        }
    }

    /**
     * 检查 ThinkPHP CLI 命令（委托给 CliCommandProtector）
     */
    protected static function checkThinkPhpCommand(object $event, CliCommandProtector $protector, App $app): void
    {
        $commandName = '';
        try {
            if (method_exists($event, 'getCommand')) {
                $command = $event->getCommand();
                if ($command && method_exists($command, 'getName')) {
                    $commandName = $command->getName() ?: '';
                }
            }
        } catch (\Throwable) {
            return;
        }

        if ($commandName === '') {
            return;
        }

        $appEnv = $app->config->get('app.env', 'local') ?: 'local';

        // 获取 Console I/O
        $input = null;
        $output = null;
        try {
            if (method_exists($event, 'getInput')) {
                $input = $event->getInput();
            }
            if (method_exists($event, 'getOutput')) {
                $output = $event->getOutput();
            }
        } catch (\Throwable) {
        }

        // 委托检查
        $result = $protector->check($commandName, $appEnv, $input, $output);

        if ($result->isPass()) {
            return;
        }

        if ($result->isBlocked()) {
            $protector->renderBlockBanner($commandName, $appEnv, $output);
            self::logCliDecision($app, $commandName, $appEnv, false);
            exit(1);
        }

        // confirm 模式
        $confirmed = $protector->confirm($commandName, $appEnv, $input, $output);

        self::logCliDecision($app, $commandName, $appEnv, $confirmed);

        if (!$confirmed) {
            exit(1);
        }
    }

    /**
     * 记录 ThinkPHP CLI 拦截决策日志
     */
    protected static function logCliDecision(App $app, string $commandName, string $appEnv, bool $confirmed): void
    {
        $securityConfig = $app->config->get('security', []);
        if (!($securityConfig['log_enabled'] ?? true)) {
            return;
        }

        try {
            $logLevel = $securityConfig['log_level'] ?? 'warning';
            $action = $confirmed ? 'confirmed' : 'cancelled';

            FrameworkBridge::{$logLevel}(
                "[Security] Database dangerous CLI command {$action}: {$commandName}",
                [
                    'command' => $commandName,
                    'env' => $appEnv,
                    'action' => $action,
                    'type' => 'database_table_destruction',
                    'channel' => 'cli',
                ]
            );
        } catch (\Throwable) {
            // 日志失败不应阻断拦截流程
        }
    }
}
