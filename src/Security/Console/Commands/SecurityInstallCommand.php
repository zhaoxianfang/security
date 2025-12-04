<?php

namespace zxf\Security\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\DB;
use zxf\Security\Middleware\SecurityMiddleware;
use zxf\Security\Providers\SecurityServiceProvider;

/**
 * 安全包安装命令 - 优化增强版
 *
 * 功能说明：
 * 1. 一键发布配置文件
 * 2. 一键发布数据库迁移文件
 * 3. 自动运行数据库迁移
 * 4. 提供完整的安装反馈
 * 5. 验证安装结果
 */
class SecurityInstallCommand extends Command
{
    /**
     * 命令名称和签名
     */
    protected $signature = 'security:install 
                            {--force : 强制覆盖现有文件}
                            {--no-migrate : 不运行数据库迁移}
                            {--no-config : 不发布配置文件}
                            {--test : 测试安装结果}
                            {--silently : 安静模式，减少输出}';

    /**
     * 命令描述
     */
    protected $description = '一键安装安全包:发布配置、迁移文件并运行迁移';

    /**
     * 安装步骤计数器
     */
    protected int $step = 0;

    /**
     * 安装结果记录
     */
    protected array $installResults = [];

    /**
     * 执行命令
     */
    public function handle(): int
    {
        $this->showWelcomeMessage();

        // 检查确认
        if (!$this->option('silently') && !$this->confirm('确定要继续安装吗？', true)) {
            $this->info('安装已取消。');
            return self::SUCCESS;
        }

        try {
            $this->step = 1;

            // 步骤1: 发布配置文件（除非指定不发布）
            if (!$this->option('no-config')) {
                $this->stepPublishConfig();
            } else {
                $this->info('步骤 1/3: 跳过配置文件发布');
            }

            // 步骤2: 发布迁移文件
            $this->stepPublishMigrations();

            // 步骤3: 运行数据库迁移（除非指定不运行）
            if (!$this->option('no-migrate')) {
                $this->stepRunMigrations();
            } else {
                $this->info('步骤 3/3: 跳过数据库迁移');
            }

            // 验证安装
            $this->validateInstallation();

            // 显示安装结果
            $this->showInstallationResult();

            // 测试安装结果（如果指定）
            if ($this->option('test')) {
                $this->testInstallation();
            }

            $this->showCompletionMessage();

            return self::SUCCESS;

        } catch (Exception $e) {
            $this->error('安装过程中发生错误: ' . $e->getMessage());

            if (!$this->option('silently')) {
                $this->error('错误详情: ' . $e->getFile() . ':' . $e->getLine());
                $this->error('堆栈跟踪: ' . $e->getTraceAsString());
            }

            $this->showErrorRecoveryTips();

            return self::FAILURE;
        }
    }

    /**
     * 显示欢迎信息
     */
    protected function showWelcomeMessage(): void
    {
        if ($this->option('silently')) {
            return;
        }

        $this->info('🚀 开始安装 zxf security 安全包...');
        $this->line('');
        $this->info('📦 版本信息:');
        $this->line('  • 安全中间件包 v2.0');
        $this->line('  • 适用于 Laravel 10+');
        $this->line('  • MySQL 8.2+ 优化版本');
        $this->line('');
        $this->info('🔧 安装将执行以下操作:');
        $this->line('  1. 发布配置文件 (config/security.php)');
        $this->line('  2. 发布数据库迁移文件');
        $this->line('  3. 运行数据库迁移');
        $this->line('');
    }

    /**
     * 步骤1: 发布配置文件
     */
    protected function stepPublishConfig(): void
    {
        $this->stepStart('发布配置文件');

        $configPath = config_path('security.php');
        $configExists = File::exists($configPath);

        if ($configExists && !$this->option('force')) {
            if ($this->option('silently') || $this->confirm('security.php 配置文件已存在，是否覆盖？', false)) {
                $this->publishConfigFile();
            } else {
                $this->info('  已跳过配置文件发布');
                $this->installResults['config'] = 'skipped';
            }
        } else {
            $this->publishConfigFile();
        }

        $this->stepComplete();
    }

    /**
     * 发布配置文件
     */
    protected function publishConfigFile(): void
    {
        $params = [
            '--provider' => 'zxf\\Security\\Providers\\SecurityServiceProvider',
            '--tag' => 'security-config'
        ];

        if ($this->option('force')) {
            $params['--force'] = true;
        }

        if ($this->option('silently')) {
            $params['--silently'] = true;
        }

        $exitCode = Artisan::call('vendor:publish', $params);

        if ($exitCode === 0) {
            $output = Artisan::output();
            if (str_contains($output, 'Copied File') || str_contains($output, '已发布')) {
                $this->info('  ✅ 已发布配置文件: config/security.php');
                $this->installResults['config'] = 'published';
            } else {
                $this->info('  ℹ️  配置文件已是最新');
                $this->installResults['config'] = 'up_to_date';
            }
        } else {
            $this->warn('  ⚠️  配置文件发布可能有问题');
            $this->installResults['config'] = 'potential_issue';
        }
    }

    /**
     * 步骤2: 发布迁移文件
     */
    protected function stepPublishMigrations(): void
    {
        $this->stepStart('发布迁移文件');

        $migrationFiles = [
            '2025_01_01_000000_create_security_ips_table.php',
        ];

        $publishedCount = 0;
        $skippedCount = 0;

        foreach ($migrationFiles as $migrationFile) {
            $targetPath = database_path('migrations/' . $migrationFile);

            if (File::exists($targetPath) && !$this->option('force')) {
                if (!$this->option('silently')) {
                    $this->warn("  ⚠️  迁移文件已存在: {$migrationFile}");
                }
                $skippedCount++;
                continue;
            }

            $sourcePath = __DIR__ . '/../../../Database/Migrations/' . $migrationFile;

            if (File::exists($sourcePath)) {
                // 确保目标目录存在
                if (!File::exists(dirname($targetPath))) {
                    File::makeDirectory(dirname($targetPath), 0755, true);
                }

                File::copy($sourcePath, $targetPath);

                if (!$this->option('silently')) {
                    $this->info("  ✅ 已发布迁移文件: {$migrationFile}");
                }
                $publishedCount++;
            } else {
                $this->error("  ❌ 源文件不存在: {$sourcePath}");
            }
        }

        if ($publishedCount > 0) {
            $this->installResults['migrations'] = "published_{$publishedCount}";
        } elseif ($skippedCount > 0) {
            $this->installResults['migrations'] = "skipped_{$skippedCount}";
        } else {
            $this->installResults['migrations'] = 'none';
        }

        $this->stepComplete();
    }

    /**
     * 步骤3: 运行数据库迁移
     */
    protected function stepRunMigrations(): void
    {
        $this->stepStart('运行数据库迁移');

        try {
            // 检查是否有待运行的迁移
            Artisan::call('migrate:status');
            $output = Artisan::output();

            $hasPendingMigrations = preg_match('/\s+No\s+\|\s+Yes\s+/', $output);

            if (!$hasPendingMigrations && str_contains($output, 'Ran')) {
                $this->info('  ℹ️  所有迁移已是最新');
                $this->installResults['migrate'] = 'up_to_date';
                $this->stepComplete();
                return;
            }

            // 运行迁移
            $params = [];
            if ($this->option('force')) {
                $params['--force'] = true;
            }

            if ($this->option('silently')) {
                $params['--silently'] = true;
            }

            Artisan::call('migrate', $params);
            $migrateOutput = Artisan::output();

            // 解析迁移输出
            if (str_contains($migrateOutput, 'Migrating') || str_contains($migrateOutput, 'Migrated')) {
                $lines = explode("\n", $migrateOutput);
                $migrationCount = 0;

                foreach ($lines as $line) {
                    if (str_contains($line, 'Migrating')) {
                        $migrationCount++;
                        if (!$this->option('silently')) {
                            $this->line("    " . trim($line));
                        }
                    }
                }

                $this->info("  ✅ 成功运行 {$migrationCount} 个迁移");
                $this->installResults['migrate'] = "ran_{$migrationCount}";
            } else {
                $this->info('  ℹ️  没有需要运行的迁移');
                $this->installResults['migrate'] = 'none';
            }

        } catch (Exception $e) {
            $this->error('  ❌ 数据库迁移失败: ' . $e->getMessage());
            $this->installResults['migrate'] = 'failed';

            if (!$this->option('silently')) {
                $this->error('  迁移错误: ' . $e->getMessage());
            }

            throw $e;
        }

        $this->stepComplete();
    }

    /**
     * 验证安装
     */
    protected function validateInstallation(): void
    {
        $this->stepStart('验证安装结果');

        $checks = [
            'config_file' => config_path('security.php'),
            'migration_file' => database_path('migrations/2025_01_01_000000_create_security_ips_table.php'),
        ];

        $passed = 0;
        $total = count($checks);

        foreach ($checks as $name => $path) {
            if (File::exists($path)) {
                $this->info("  ✅ {$name}: 存在");
                $passed++;
            } else {
                $this->warn("  ⚠️  {$name}: 不存在");
            }
        }

        // 检查数据库表
        try {
            $tables = ['security_ips', 'security_ip_stats'];
            foreach ($tables as $table) {
                if (DB::getSchemaBuilder()->hasTable($table)) {
                    $this->info("  ✅ 数据库表 {$table}: 存在");
                    $passed++;
                } else {
                    $this->warn("  ⚠️  数据库表 {$table}: 不存在");
                }
                $total++;
            }
        } catch (Exception $e) {
            $this->warn("  ⚠️  数据库连接检查失败: " . $e->getMessage());
        }

        $this->installResults['validation'] = "{$passed}/{$total}";

        if ($passed === $total) {
            $this->info("  ✅ 所有验证通过 ({$passed}/{$total})");
        } else {
            $this->warn("  ⚠️  验证通过 {$passed}/{$total}");
        }

        $this->stepComplete();
    }

    /**
     * 测试安装结果
     */
    protected function testInstallation(): void
    {
        $this->stepStart('测试安装结果');

        $tests = [
            '配置读取' => fn() => $this->testConfig(),
            '服务提供者' => fn() => $this->testServiceProvider(),
            '中间件注册' => fn() => $this->testMiddleware(),
            '助手函数' => fn() => $this->testHelpers(),
        ];

        $passed = 0;
        $total = count($tests);

        foreach ($tests as $name => $test) {
            try {
                $result = $test();
                if ($result) {
                    $this->info("  ✅ {$name}: 通过");
                    $passed++;
                } else {
                    $this->warn("  ⚠️  {$name}: 失败");
                }
            } catch (Exception $e) {
                $this->warn("  ⚠️  {$name}: 异常 - " . $e->getMessage());
            }
        }

        $this->installResults['test'] = "{$passed}/{$total}";
        $this->stepComplete();
    }

    /**
     * 测试配置
     */
    protected function testConfig(): bool
    {
        return config('security.enabled', false) !== false;
    }

    /**
     * 测试服务提供者
     */
    protected function testServiceProvider(): bool
    {
        return class_exists(SecurityServiceProvider::class);
    }

    /**
     * 测试中间件
     */
    protected function testMiddleware(): bool
    {
        return class_exists(SecurityMiddleware::class);
    }

    /**
     * 测试助手函数
     */
    protected function testHelpers(): bool
    {
        return function_exists('security_config');
    }

    /**
     * 显示安装结果
     */
    protected function showInstallationResult(): void
    {
        if ($this->option('silently')) {
            return;
        }

        $this->line('');
        $this->info('📊 安装结果汇总:');

        $results = [
            '配置文件' => $this->installResults['config'] ?? '未执行',
            '迁移文件' => $this->installResults['migrations'] ?? '未执行',
            '数据库迁移' => $this->installResults['migrate'] ?? '未执行',
            '安装验证' => $this->installResults['validation'] ?? '未执行',
        ];

        if (isset($this->installResults['test'])) {
            $results['安装测试'] = $this->installResults['test'];
        }

        foreach ($results as $item => $result) {
            $icon = str_contains($result, 'failed') ? '❌' :
                (str_contains($result, 'skipped') ? '⚠️ ' : '✅');
            $this->line("  {$icon} {$item}: {$result}");
        }
    }

    /**
     * 显示完成信息
     */
    protected function showCompletionMessage(): void
    {
        if ($this->option('silently')) {
            return;
        }

        $this->line('');
        $this->info('🎉 安全包安装完成！');
        $this->line('');

        $this->info('📝 下一步建议:');
        $this->line('  1. 查看配置文件: config/security.php');
        $this->line('  2. 根据需求调整配置');
        $this->line('  3. 测试安全中间件功能');
        $this->line('  4. 配置定时清理任务');
        $this->line('');

        $this->info('🔧 常用命令:');
        $this->line('  php artisan security:cleanup      # 清理安全数据');
        $this->line('  php artisan security:stats        # 查看安全统计');
        $this->line('  php artisan route:list            # 查看路由中间件');
        $this->line('');

        $this->info('📚 文档地址:');
        $this->line('  https://weisifang.com/docs/2');
        $this->line('');
    }

    /**
     * 显示错误恢复提示
     */
    protected function showErrorRecoveryTips(): void
    {
        if ($this->option('silently')) {
            return;
        }

        $this->line('');
        $this->error('💡 错误恢复建议:');
        $this->line('  1. 检查数据库连接配置');
        $this->line('  2. 确保有足够的数据库权限');
        $this->line('  3. 手动运行迁移: php artisan migrate');
        $this->line('  4. 手动发布配置: php artisan vendor:publish --tag=security-config');
        $this->line('  5. 查看详细错误日志: storage/logs/laravel.log');
        $this->line('');
    }

    /**
     * 步骤开始
     */
    protected function stepStart(string $stepName): void
    {
        if (!$this->option('silently')) {
            $this->info("步骤 {$this->step}/3: {$stepName}...");
        }
        $this->step++;
    }

    /**
     * 步骤完成
     */
    protected function stepComplete(): void
    {
        if (!$this->option('silently')) {
            $this->line('');
        }
    }

    /**
     * 获取安装状态
     */
    public function getInstallStatus(): array
    {
        return $this->installResults;
    }

    /**
     * 检查是否已安装
     */
    public static function isInstalled(): bool
    {
        $configExists = File::exists(config_path('security.php'));
        $migrationExists = File::exists(
            database_path('migrations/2025_01_01_000000_create_security_ips_table.php')
        );

        try {
            $tableExists = DB::getSchemaBuilder()->hasTable('security_ips');
        } catch (Exception $e) {
            $tableExists = false;
        }

        return $configExists && $migrationExists && $tableExists;
    }

    /**
     * 获取安装信息
     */
    public static function getInstallInfo(): array
    {
        return [
            'config_exists' => File::exists(config_path('security.php')),
            'migration_exists' => File::exists(
                database_path('migrations/2025_01_01_000000_create_security_ips_table.php')
            ),
            'table_exists' => function() {
                try {
                    return DB::getSchemaBuilder()->hasTable('security_ips');
                } catch (Exception $e) {
                    return false;
                }
            },
            'config_enabled' => config('security.enabled', false),
            'config_version' => config('security.version', 'unknown'),
        ];
    }
}
