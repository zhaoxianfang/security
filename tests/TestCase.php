<?php

namespace zxf\Security\Tests;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase as BaseTestCase;
use zxf\Security\SecurityServiceProvider;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 运行数据库迁移
        $this->loadMigrationsFrom(__DIR__ . '/../src/Database/Migrations');

        // 发布配置文件
        Artisan::call('vendor:publish', [
            '--provider' => SecurityServiceProvider::class,
            '--force' => true
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [
            SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // 测试数据库配置
        $app['config']->set('database.default', 'testbench');
        $app['config']->set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // 安全配置
        $app['config']->set('security.enabled', true);
        $app['config']->set('security.log_level', 'debug');
        $app['config']->set('security.enable_debug_logging', true);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }
}
