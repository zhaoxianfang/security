<?php

namespace zxf\Security\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use zxf\Security\Models\SecurityIp;

/**
 * 安全数据清理命令
 *
 * 功能说明：
 * 1. 清理过期的IP记录
 * 2. 更新统计信息
 * 3. 清理缓存数据
 */
class SecurityCleanupCommand extends Command
{
    /**
     * 命令名称和签名
     */
    protected $signature = 'security:cleanup
                            {--only-expired : 仅清理过期记录}';

    /**
     * 命令描述
     */
    protected $description = '安全包：清理安全相关的过期数据和缓存';

    /**
     * 执行命令
     */
    public function handle(): int
    {
        $this->info('🧹 开始清理...');

        try {
            // 清理过期IP记录
            $this->cleanupExpiredIps();

            // 如果不是仅清理过期记录，执行完整清理
            if (!$this->option('only-expired')) {
                $this->clearCaches();
            }

            $this->showCompletion();

            return self::SUCCESS;

        } catch (Exception $e) {
            $this->error('清理过程中发生错误: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    /**
     * 清理过期IP记录
     */
    protected function cleanupExpiredIps(): void
    {
        $deleted = SecurityIp::cleanupExpired();

        if ($deleted > 0) {
            $this->info(" 清理了 {$deleted} 条过期IP记录");
        }
    }

    /**
     * 清理缓存数据
     */
    protected function clearCaches(): void
    {
        // 清理安全相关的缓存
        clean_security_cache();
        $this->info('🧼 已清理所有安全缓存');
    }

    /**
     * 显示清理完成信息
     */
    protected function showCompletion(): void
    {
        $this->info(' 数据清理完成！');
        $this->comment('💡 提示: 可以设置定时任务自动运行清理命令');
        $this->line('      例如: php artisan schedule:run 中添加');
        $this->line('      $schedule->command(\'security:cleanup\')->daily();');
    }
}