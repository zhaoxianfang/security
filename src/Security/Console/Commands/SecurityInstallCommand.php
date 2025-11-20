<?php

namespace zxf\Security\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

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
                            {--no-migrate : 不运行数据库迁移}';

    /**
     * 命令描述
     */
    protected $description = '一键安装安全包:发布配置、迁移文件并运行迁移';

    /**
     * 执行命令
     */
    public function handle(): int
    {
        $this->info('🚀 开始安装 zxf security 包...');

        // 检查确认
        if (!$this->confirm('确定要继续安装吗？', true)) {
            $this->info('安装已取消。');
            return self::SUCCESS;
        }

        try {
            // 步骤1: 发布配置文件
            $this->stepPublishConfig();

            // 步骤2: 发布迁移文件
            $this->stepPublishMigrations();

            // 步骤3: 运行数据库迁移（除非指定不运行）
            if (!$this->option('no-migrate')) {
                $this->stepRunMigrations();
            }

            return self::SUCCESS;

        } catch (\Exception $e) {
            $this->error('安装过程中发生错误: ' . $e->getMessage());
            $this->error('错误详情: ' . $e->getFile() . ':' . $e->getLine());
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
            if ($this->confirm('security.php 配置文件已存在，是否覆盖？', false)) {
                $this->publishConfigFile();
            }
        } else {
            $this->publishConfigFile();
        }

        $this->info('步骤 1/3: 发布配置文件处理完成');
    }

    /**
     * 发布配置文件
     */
    protected function publishConfigFile(): void
    {
        $params = ['--provider' => 'zxf\\Security\\Providers\\SecurityServiceProvider', '--tag' => 'security-config'];

        if ($this->option('force')) {
            $params['--force'] = true;
        }

        Artisan::call('vendor:publish', $params);

        $output = Artisan::output();
        if (str_contains($output, 'Copied File')) {
            $this->line('  已发布配置文件: config/security.php');
        }
    }

    /**
     * 步骤2: 发布迁移文件
     */
    protected function stepPublishMigrations(): void
    {
        $migrationFiles = [
            '2025_01_01_000000_create_security_ips_table.php',
        ];

        $publishedCount = 0;
        foreach ($migrationFiles as $migrationFile) {
            $targetPath = database_path('migrations/' . $migrationFile);

            if (File::exists($targetPath)) {
                $this->warn("步骤 2/3: 迁移文件已存在: {$migrationFile}");
                continue;
            }

            $sourcePath = __DIR__ . '/../../../Database/Migrations/' . $migrationFile;
            if (File::exists($sourcePath)) {
                File::copy($sourcePath, $targetPath);
                $this->line("步骤 2/3: 已发布迁移文件: {$migrationFile}");
                $publishedCount++;
            }
        }

        // if ($publishedCount > 0) {
        //     $this->info("  ✅ 成功发布 {$publishedCount} 个迁移文件");
        // } else {
        //     $this->info("  ℹ️  所有迁移文件已存在，无需发布");
        // }
    }

    /**
     * 步骤3: 运行数据库迁移
     */
    protected function stepRunMigrations(): void
    {
        try {
            $output = Artisan::output();

            if (str_contains($output, 'No')) {
                $this->info('  步骤 3/3: 没有待运行的迁移');
                return;
            }

            // 运行迁移
            Artisan::call('migrate', ['--force' => true]);
            $migrateOutput = Artisan::output();

            if (str_contains($migrateOutput, 'Migrating')) {
                $this->info('  步骤 3/3: 数据库迁移完成');

                // 显示迁移的表格
                $lines = explode("\n", $migrateOutput);
                foreach ($lines as $line) {
                    if (str_contains($line, 'Migrating') || str_contains($line, 'Migrated')) {
                        $this->line("    " . trim($line));
                    }
                }
            } else {
                $this->warn('  步骤 3/3: 没有需要运行的迁移');
            }

        } catch (\Exception $e) {
            $this->error('  ❌ 数据库迁移失败: ' . $e->getMessage());
            throw $e;
        }
    }
}