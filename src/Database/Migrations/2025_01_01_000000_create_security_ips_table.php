<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * 安全IP管理表迁移
 *
 * 功能说明：
 * 1. 统一管理白名单、黑名单、可疑IP
 * 2. 支持IP段范围管理
 * 3. 记录访问统计和自动处理
 * 4. 支持动态阈值配置
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

            // IP地址相关字段
            $table->string('ip_address', 45)->comment('IP地址 - 示例: 192.168.1.1 或 2001:db8::1');
            $table->string('ip_range', 45)->nullable()->comment('IP段范围 - 示例: 192.168.1.0/24 或 2001:db8::/32');
            $table->boolean('is_range')->default(false)->comment('是否为IP段 - true: IP段, false: 单个IP');

            // 类型和状态管理
            $table->enum('type', ['whitelist', 'blacklist', 'suspicious', 'monitoring'])->comment('IP类型 - whitelist: 白名单, blacklist: 黑名单, suspicious: 可疑IP, monitoring: 监控中');
            $table->enum('status', ['active', 'inactive', 'pending'])->default('active')->comment('状态 - active: 激活, inactive: 禁用, pending: 待审核');
            $table->string('reason', 500)->nullable()->comment('添加原因 - 示例: 暴力破解攻击, 正常业务IP, 可疑扫描行为');

            // 访问统计字段
            $table->unsignedBigInteger('request_count')->default(0)->comment('总请求次数');
            $table->unsignedBigInteger('blocked_count')->default(0)->comment('拦截次数');
            $table->unsignedBigInteger('success_count')->default(0)->comment('成功请求次数');
            $table->decimal('threat_score', 5, 2)->default(0.00)->comment('威胁评分 0-100 - 示例: 85.50');

            // 时间窗口统计（用于自动检测）
            $table->timestamp('last_request_at')->nullable()->comment('最后请求时间');
            $table->timestamp('first_seen_at')->nullable()->comment('首次出现时间');

            // 自动处理相关
            $table->boolean('auto_detected')->default(false)->comment('是否自动检测 - true: 系统自动检测, false: 手动添加');
            $table->unsignedInteger('trigger_count')->default(0)->comment('触发规则次数');
            $table->json('trigger_rules')->nullable()->comment('触发规则记录 - 示例: ["rate_limit", "sql_injection"]');

            // 时间管理
            $table->timestamp('expires_at')->nullable()->comment('过期时间 - 为空表示永久有效');
            $table->timestamps(); // 创建时间和更新时间

            // 索引优化
            $table->index(['ip_address', 'type', 'status'], 'idx_ip_type_status'); // IP类型状态联合索引
            $table->index(['type', 'status', 'expires_at'], 'idx_type_status_expires'); // 类型状态过期时间索引
            $table->index(['threat_score', 'last_request_at'], 'idx_threat_last_request'); // 威胁评分和时间索引
            $table->index(['auto_detected', 'trigger_count'], 'idx_auto_trigger'); // 自动检测和触发次数索引
            $table->index('created_at'); // 创建时间索引

            // 注释说明
            $table->comment('安全IP管理表 - 统一管理白名单、黑名单、可疑IP和监控IP');
        });
    }

    /**
     * 回滚迁移
     */
    public function down(): void
    {
        Schema::dropIfExists('security_ips');
    }
};