<?php

namespace zxf\Security\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\DB;

/**
 * 安全包安装命令
 *
 * 功能说明：
 * 1. 一键发布配置文件
 * 2. 一键发布数据库迁移文件
 * 3. 自动运行数据库迁移
 * 4. 提供完整的安装反馈
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
     * 执行命令
     */
    public function handle(): int
    {
        // 检查确认
        if (!$this->option('silently') && !$this->confirm('确定要安装 zxf/security 吗？', true)) {
            $this->info('安装已取消!');
            return self::SUCCESS;
        }

        $this->info('🚀 开始安装 zxf/security 安全包...');

        try {
            $this->step = 1;

            // 步骤1: 发布配置文件（除非指定不发布）
            if (!$this->option('no-config')) {
                $this->stepPublishConfig();
            }

            // 步骤2: 发布迁移文件
            $this->stepPublishMigrations();

            // 步骤3: 运行数据库迁移（除非指定不运行）
            if (!$this->option('no-migrate')) {
                $this->stepRunMigrations();
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
     * 步骤1: 发布配置文件
     */
    protected function stepPublishConfig(): void
    {
        $configPath = config_path('security.php');
        $configExists = File::exists($configPath);

        if ($configExists && !$this->option('force')) {
            if ($this->option('silently') || $this->confirm('security.php 配置文件已存在，是否覆盖？', false)) {
                $this->publishConfigFile();
            }
        } else {
            $this->publishConfigFile();
        }
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
                $this->info('  已发布配置文件: config/security.php');
            }
        } else {
            $this->warn('  ⚠️  配置文件发布可能有问题');
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
                    $this->warn("  迁移文件已存在: {$migrationFile}");
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
                    $this->info("  已发布迁移文件: {$migrationFile}");
                }
                $publishedCount++;
            } else {
                $this->error("  ❌ 源文件不存在: {$sourcePath}");
            }
        }

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

            // 使用换行分割$output后逐行读取 $output 里面 包含 security_ips_table 字符串的这一行中是否包含 Ran 字符串
            $lines = explode("\n", $output);
            foreach ($lines as $line) {
                if (str_contains($line, 'security_ips_table')) {
                    if (str_contains($line, 'Ran')) {
                        break;
                    }
                }
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

                foreach ($lines as $line) {
                    if (str_contains($line, 'Migrating')) {
                        if (!$this->option('silently')) {
                            $this->line("    " . trim($line));
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->error('  ❌ 数据库迁移失败: ' . $e->getMessage());

            if (!$this->option('silently')) {
                $this->error('  迁移错误: ' . $e->getMessage());
            }

            throw $e;
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
            $this->info("步骤 {$this->step}/2: {$stepName}...");
        }
        $this->step++;
    }
}
