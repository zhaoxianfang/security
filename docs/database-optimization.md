# 数据库优化指南

本文档提供了 `zxf/security` 包的数据库优化建议，帮助您在大数据量场景下保持高性能。

## 目录

- [索引优化](#索引优化)
- [分区表](#分区表)
- [定期维护](#定期维护)
- [性能监控](#性能监控)

---

## 索引优化

### 基础索引（必需）

以下索引是必需的，建议在安装后立即创建：

```sql
-- 主键索引（迁移时已创建）
-- ALTER TABLE security_ips ADD PRIMARY KEY (id);

-- IP地址索引（最常用的查询）
ALTER TABLE security_ips ADD INDEX idx_ip_address (ip_address);

-- 类型和状态组合索引
ALTER TABLE security_ips ADD INDEX idx_type_status (type, status);

-- 威胁评分索引（用于排序）
ALTER TABLE security_ips ADD INDEX idx_threat_score (threat_score DESC);

-- 最后请求时间索引
ALTER TABLE security_ips ADD INDEX idx_last_request (last_request_at);

-- 过期时间索引（用于清理）
ALTER TABLE security_ips ADD INDEX idx_expires (expires_at);
```

### 复合索引（推荐）

对于常见查询模式，创建复合索引：

```sql
-- 检查IP状态（最常用查询）
ALTER TABLE security_ips ADD INDEX idx_type_status_ip (type, status, ip_address);

-- 获取高威胁IP列表
ALTER TABLE security_ips ADD INDEX idx_type_threat (type, threat_score DESC);

-- 获取监控中的IP
ALTER TABLE security_ips ADD INDEX idx_monitoring (type, status, last_request_at DESC);

-- 自动检测的IP查询
ALTER TABLE security_ips ADD INDEX idx_auto_detected (auto_detected, type, created_at DESC);
```

### 覆盖索引（高级）

使用覆盖索引避免回表查询：

```sql
-- 覆盖索引示例：只查询IP地址和类型
ALTER TABLE security_ips ADD INDEX idx_cover_ip_type 
(ip_address, type, status, threat_score, request_count);
```

---

## 分区表

当数据量超过100万条时，建议使用分区表。

### MySQL 分区示例

```sql
-- 创建分区表（新表）
CREATE TABLE security_ips_partitioned (
    id BIGINT UNSIGNED AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    ip_range VARCHAR(100) DEFAULT NULL,
    is_range TINYINT(1) DEFAULT 0,
    type VARCHAR(20) NOT NULL DEFAULT 'monitoring',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    reason VARCHAR(255) DEFAULT NULL,
    request_count INT UNSIGNED DEFAULT 0,
    blocked_count INT UNSIGNED DEFAULT 0,
    success_count INT UNSIGNED DEFAULT 0,
    threat_score DECIMAL(5,2) DEFAULT 0.00,
    last_request_at TIMESTAMP NULL,
    first_seen_at TIMESTAMP NULL,
    auto_detected TINYINT(1) DEFAULT 0,
    trigger_count INT UNSIGNED DEFAULT 0,
    trigger_rules JSON DEFAULT NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at),
    INDEX idx_ip_address (ip_address),
    INDEX idx_type_status (type, status),
    INDEX idx_threat_score (threat_score DESC)
) PARTITION BY RANGE (YEARWEEK(created_at)) (
    PARTITION p202401 VALUES LESS THAN (202402),
    PARTITION p202402 VALUES LESS THAN (202403),
    PARTITION p202403 VALUES LESS THAN (202404),
    PARTITION p202404 VALUES LESS THAN (202405),
    PARTITION p202405 VALUES LESS THAN (202406),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- 迁移数据
INSERT INTO security_ips_partitioned 
SELECT * FROM security_ips;

-- 重命名表
RENAME TABLE security_ips TO security_ips_old;
RENAME TABLE security_ips_partitioned TO security_ips;
```

### PostgreSQL 分区示例

```sql
-- 创建分区表
CREATE TABLE security_ips_partitioned (
    id BIGSERIAL,
    ip_address VARCHAR(45) NOT NULL,
    ip_range VARCHAR(100) DEFAULT NULL,
    is_range BOOLEAN DEFAULT FALSE,
    type VARCHAR(20) NOT NULL DEFAULT 'monitoring',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    reason VARCHAR(255) DEFAULT NULL,
    request_count INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    threat_score DECIMAL(5,2) DEFAULT 0.00,
    last_request_at TIMESTAMP NULL,
    first_seen_at TIMESTAMP NULL,
    auto_detected BOOLEAN DEFAULT FALSE,
    trigger_count INTEGER DEFAULT 0,
    trigger_rules JSONB DEFAULT NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- 创建分区
CREATE TABLE security_ips_y2024m01 PARTITION OF security_ips_partitioned
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
    
CREATE TABLE security_ips_y2024m02 PARTITION OF security_ips_partitioned
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- 继续创建更多分区...
```

---

## 定期维护

### 自动清理任务

在 `App\Console\Kernel.php` 中添加：

```php
protected function schedule(Schedule $schedule): void
{
    // 每小时清理过期IP记录
    $schedule->call(function () {
        $count = \zxf\Security\Models\SecurityIp::cleanupExpired();
        \Log::info("清理了 {$count} 条过期IP记录");
    })->hourly();

    // 每天优化表
    $schedule->call(function () {
        DB::statement('OPTIMIZE TABLE security_ips');
    })->dailyAt('02:00');

    // 每周分析表统计信息
    $schedule->call(function () {
        DB::statement('ANALYZE TABLE security_ips');
    })->weekly();
}
```

### 数据归档策略

```php
// 归档旧数据到历史表
$schedule->call(function () {
    $archived = DB::transaction(function () {
        // 移动3个月前的监控记录到历史表
        $count = DB::insert('
            INSERT INTO security_ips_history 
            SELECT * FROM security_ips 
            WHERE type = "monitoring" 
            AND created_at < DATE_SUB(NOW(), INTERVAL 3 MONTH)
        ');

        // 删除已归档的数据
        DB::delete('
            DELETE FROM security_ips 
            WHERE type = "monitoring" 
            AND created_at < DATE_SUB(NOW(), INTERVAL 3 MONTH)
        ');

        return $count;
    });

    Log::info("归档了 {$archived} 条历史记录");
})->weekly();
```

---

## 性能监控

### 慢查询监控

```sql
-- MySQL: 开启慢查询日志
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';

-- 查看慢查询
SELECT * FROM mysql.slow_log 
WHERE db = 'your_database' 
AND sql_text LIKE '%security_ips%'
ORDER BY start_time DESC
LIMIT 10;
```

### 查询性能分析

```sql
-- 分析查询执行计划
EXPLAIN ANALYZE
SELECT * FROM security_ips 
WHERE ip_address = '192.168.1.1' 
AND is_range = false;

-- 应该看到: type=ref, key=idx_ip_address
```

### PHP监控代码

```php
// 监控数据库查询时间
DB::listen(function ($query) {
    if (str_contains($query->sql, 'security_ips')) {
        $time = $query->time; // 毫秒
        
        if ($time > 100) {
            Log::warning('安全表查询较慢', [
                'sql' => $query->sql,
                'time_ms' => $time,
                'bindings' => $query->bindings,
            ]);
        }
    }
});
```

---

## 性能指标参考

| 数据量 | 查询响应时间 | 建议措施 |
|-------|-------------|---------|
| < 10万 | < 10ms | 基础索引即可 |
| 10-100万 | 10-50ms | 添加复合索引 |
| 100-500万 | 50-200ms | 考虑分区表 |
| > 500万 | > 200ms | 必须分区+归档 |

---

## 故障排查

### 查询变慢

```sql
-- 1. 检查表碎片
SHOW TABLE STATUS LIKE 'security_ips';

-- 2. 检查索引使用情况
SHOW INDEX FROM security_ips;

-- 3. 重建表（MySQL）
ALTER TABLE security_ips ENGINE=InnoDB;

-- 4. 更新统计信息
ANALYZE TABLE security_ips;
```

### 磁盘空间不足

```sql
-- 查看表大小
SELECT 
    table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_size_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_size_mb,
    ROUND((data_length + index_length) / 1024 / 1024, 2) AS total_size_mb
FROM information_schema.tables
WHERE table_name = 'security_ips';

-- 清理策略
-- 1. 删除过期数据
DELETE FROM security_ips WHERE expires_at < NOW();

-- 2. 归档旧数据（见上文）

-- 3. 清理后优化
OPTIMIZE TABLE security_ips;
```
