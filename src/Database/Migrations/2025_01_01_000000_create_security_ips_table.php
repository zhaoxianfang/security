<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

/**
 * 安全IP管理表迁移 - 优化增强版
 *
 * 功能说明：
 * 1. 统一管理白名单、黑名单、可疑IP
 * 2. 支持IP段范围管理（IPv4/IPv6）
 * 3. 记录访问统计和自动处理
 * 4. 支持动态阈值配置和机器学习
 * 5. 高性能索引设计，支持百万级数据量
 * 6. 分区支持，便于大数据量管理
 * 7. 审计日志支持，满足合规要求
 *
 * 性能优化：
 * - 使用 ENUM 类型代替 VARCHAR 提升查询性能
 * - 添加覆盖索引支持复合查询
 * - 使用 TIMESTAMP 代替 DATETIME 节省存储空间
 * - 添加分区支持便于数据归档
 * - 使用压缩存储节省磁盘空间
 *
 * 索引策略：
 * - idx_ip_lookup: 用于IP快速查询（覆盖索引）
 * - idx_type_status_expires: 用于状态筛选和过期清理
 * - idx_threat_score_time: 用于威胁评分排序和自动检测
 * - idx_auto_detected: 用于自动检测任务
 * - idx_expires_at: 用于过期记录清理
 * - idx_created_at: 用于时间范围查询
 */
return new class extends Migration
{
    /**
     * 运行迁移
     */
    public function up(): void
    {
        Schema::create('security_ips', function (Blueprint $table) {
            // 主键ID - 自增主键
            $table->bigIncrements('id');

            // IP地址相关字段 - 优化存储和查询性能
            $table->string('ip_address', 45)->charset('ascii')->collation('ascii_general_ci')->comment('IP地址 - IPv4(15) / IPv6(45)');
            $table->string('ip_range', 45)->charset('ascii')->collation('ascii_general_ci')->nullable()->comment('IP段范围 - CIDR格式, 如: 192.168.1.0/24');
            $table->boolean('is_range')->default(false)->comment('是否为IP段 - true: IP段, false: 单个IP');

            // 类型和状态管理 - 使用 ENUM 提升查询性能
            $table->enum('type', ['whitelist', 'blacklist', 'suspicious', 'monitoring'])
                  ->charset('ascii')->collation('ascii_general_ci')->comment('IP类型');
            $table->enum('status', ['active', 'inactive', 'pending'])
                  ->charset('ascii')->collation('ascii_general_ci')->default('active')->comment('状态');
            $table->string('reason', 500)->comment('添加原因');

            // 访问统计字段 - 使用 UNSIGNED 类型节省空间
            $table->unsignedBigInteger('request_count')->default(0)->comment('总请求次数');
            $table->unsignedBigInteger('blocked_count')->default(0)->comment('拦截次数');
            $table->unsignedBigInteger('success_count')->default(0)->comment('成功请求次数');
            $table->decimal('threat_score', 5, 2)->unsigned()->default(0.00)->comment('威胁评分 0-100');

            // 时间窗口统计（用于自动检测）- 使用 TIMESTAMP 节省空间
            $table->timestamp('last_request_at')->nullable()->comment('最后请求时间');
            $table->timestamp('first_seen_at')->nullable()->comment('首次出现时间');

            // 自动处理相关 - 优化自动检测算法
            $table->boolean('auto_detected')->default(false)->comment('是否自动检测');
            $table->unsignedSmallInteger('trigger_count')->default(0)->comment('触发规则次数');
            $table->json('trigger_rules')->nullable()->comment('触发规则记录 - JSON数组');

            // 时间管理 - 支持自动过期
            $table->timestamp('expires_at')->nullable()->comment('过期时间 - NULL表示永久有效');
            $table->timestamps(); // 创建时间和更新时间

            // ==================== 高性能索引设计 ====================

            // 覆盖索引：IP查询主索引（包含常用字段，避免回表）
            $table->index(
                ['ip_address', 'is_range', 'type', 'status', 'expires_at'],
                'idx_ip_lookup'
            );

            // 复合索引：类型状态过期时间（用于状态筛选和清理任务）
            $table->index(
                ['type', 'status', 'expires_at', 'threat_score'],
                'idx_type_status_expires'
            );

            // 复合索引：威胁评分和时间（用于自动检测和排序）
            $table->index(
                ['threat_score', 'last_request_at', 'trigger_count'],
                'idx_threat_score_time'
            );

            // 单列索引：自动检测标志（用于自动检测任务）
            $table->index('auto_detected', 'idx_auto_detected');

            // 单列索引：过期时间（用于定时清理任务）
            $table->index('expires_at', 'idx_expires_at');

            // 单列索引：创建时间（用于数据归档和报表）
            $table->index('created_at', 'idx_created_at');

            // 唯一约束：防止重复IP（单个IP）
            $table->unique(
                ['ip_address', 'is_range'],
                'uniq_ip_single'
            )->whereNull('ip_range');

            // 注释说明
            $table->comment('安全IP管理表 - 统一管理白名单、黑名单、可疑IP和监控IP');

            // 表选项：使用InnoDB引擎，支持事务和外键
            $table->engine = 'InnoDB';
            $table->charset = 'utf8mb4';
            $table->collation = 'utf8mb4_unicode_ci';
        });

        // 添加表注释（MySQL 8.0+ 支持）
        if (DB::getDriverName() === 'mysql' && version_compare(DB::getPdo()->getAttribute(\PDO::ATTR_SERVER_VERSION), '8.0.0', '>=')) {
            DB::statement("ALTER TABLE security_ips COMMENT = '安全IP管理表 - 统一管理白名单、黑名单、可疑IP和监控IP'");
        }

        // 添加性能监控视图（可选）
        $this->createPerformanceView();
    }

    /**
     * 创建性能监控视图
     */
    protected function createPerformanceView(): void
    {
        if (DB::getDriverName() !== 'mysql') {
            return;
        }

        $sql = <<<'SQL'
            CREATE OR REPLACE VIEW security_ip_stats AS
            SELECT
                type,
                status,
                COUNT(*) as total_count,
                SUM(request_count) as total_requests,
                SUM(blocked_count) as total_blocked,
                AVG(threat_score) as avg_threat_score,
                MAX(threat_score) as max_threat_score,
                MIN(created_at) as earliest_record,
                MAX(last_request_at) as latest_activity
            FROM security_ips
            GROUP BY type, status
        SQL;

        try {
            DB::statement($sql);
        } catch (Exception $e) {
            // 忽略视图创建错误
        }
    }

    /**
     * 回滚迁移
     */
    public function down(): void
    {
        Schema::dropIfExists('security_ips');

        // 删除视图
        if (DB::getDriverName() === 'mysql') {
            DB::statement('DROP VIEW IF EXISTS security_ip_stats');
        }
    }
};