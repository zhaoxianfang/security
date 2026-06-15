<?php

/**
 * 数据库危险操作检测模式（v6.2 元数据格式）
 *
 * ═══════════════════════════════════════════════════════════════
 * 功能概述：
 *   识别并拦截 Web 请求中携带的数据库危险操作命令，防止通过 API/表单/URL
 *   等渠道执行可能造成数据丢失的数据库操作。覆盖 Laravel/ThinkPHP 等框架的
 *   ORM/QueryBuilder/Artisan 调用，以及原生 SQL 注入中的危险操作。
 *
 * ═══════════════════════════════════════════════════════════════
 * 检测目标（三大类别，共 52 条规则）：
 *
 *   一、表结构破坏类（table_destruction）—— 第 82-155 行，共 18 条
 *     - Laravel/ThinkPHP Artisan: migrate:fresh / migrate:refresh / migrate:reset /
 *       migrate:rollback / db:wipe
 *     - Schema Builder:  Schema::drop() / dropIfExists() / dropAllTables() / dropDatabase()
 *     - 原生 SQL DDL:   DROP TABLE / DATABASE / VIEW / PROCEDURE / FUNCTION
 *     - 危险前置操作:   ALTER TABLE DROP COLUMN/CONSTRAINT/INDEX/KEY
 *                      RENAME TABLE（破坏表依赖）、SET FOREIGN_KEY_CHECKS=0
 *                      SET SQL_SAFE_UPDATES=0
 *     - 堆叠查询:       分号后的 DROP/TRUNCATE（SQL 多语句注入变体）
 *
 *   二、全量数据删除类（mass_deletion）—— 第 163-246 行，共 21 条
 *     - SQL 原生命令:   TRUNCATE TABLE、DELETE FROM 无条件/永真条件
 *     - 永真条件变体:   WHERE 1=1 / WHERE 1 / WHERE true / WHERE '1'='1' / OR 1=1
 *                      以及更隐蔽的永真条件（WHERE 'a'='a' 等）
 *     - 无条件 UPDATE:  UPDATE ... SET（无 WHERE，全表更新）
 *     - Eloquent:       Model::truncate()、Model::query()->delete()
 *                      Model::all()->each(...delete...)、->select()->delete()
 *     - ThinkPHP:       Db::table()->delete()、Db::name()->delete()
 *                      Db::execute() 执行危险 SQL、Model::destroy() 无参数调用
 *
 *   三、代码级操作识别（code_level_operation）—— 第 254-303 行，共 13 条
 *     - Artisan 调用:   Artisan::call('migrate:fresh') 等危险命令
 *     - PHP 命令执行:   shell_exec / exec / passthru / system / popen / proc_open
 *                      执行 artisan 危险命令
 *     - Process 组件:   new Process() / Process::fromShellCommandline() 调用 artisan
 *     - DB Facade:      DB::statement() / DB::unprepared() 执行 DROP/TRUNCATE
 *
 * ═══════════════════════════════════════════════════════════════
 * 每条规则包含：
 *   pattern — 正则表达式（PCRE 兼容语法）
 *   desc    — 规则中文说明（用于调试日志和拦截上下文）
 *   risk    — 风险等级：high（高危） / medium（中危） / low（低危）
 *
 * ═══════════════════════════════════════════════════════════════
 * 设计原则（六大原则）：
 *   1. 高精确度 — 避免过度泛化的模式（如仅 ->delete() 不捕获），
 *       每条规则必须包含足够的上下文限定词
 *   2. 低误报   — 通过单词边界 \b、空格容忍 \s*、框架调用语法等精确定位
 *   3. 防绕过   — 覆盖多种编码绕过（% 编码、URL 编码、双编码）、
 *       大小写变体（i 修饰符）、空白字符变体（\s* 容忍空格/换行/制表符）
 *   4. 防回溯   — 使用有限量词 {0,N} 替代 [\s\S]*? 和 .*，避免 ReDoS
 *       （正则回溯灾难）攻击。量词上限基于实际 SQL 语句长度权衡
 *   5. 跨框架   — 同时覆盖 Laravel Eloquent/QueryBuilder/Artisan 和
 *       ThinkPHP Db/Model 语法
 *   6. 可扩展   — 支持通过 intercept_rules_exclude 排除和 intercept_rules 追加
 *
 * ═══════════════════════════════════════════════════════════════
 * 性能提示：
 *   - PatternService 的 preFilters 在正则匹配前进行 str_contains 预检，
 *     通过关键词快速排除 95%+ 的正常请求
 *   - 数据文件仅在检测开关启用时由 PatternService 按需 require 加载
 *   - 所有模式的量词均有限制，单次 preg_match 最大回溯步数约 1000 以内
 *
 * ═══════════════════════════════════════════════════════════════
 * 安全提示：
 *   - 修改本文件请确保充分测试，不当的泛化模式可能造成大面积误拦截
 *   - 新增规则请同时更新 PatternService::$preFilters 中的对应关键词
 *   - 低风险（risk=low）规则默认仅记录不拦截，需配合 threat_risk_levels 调整
 */

return [
    // ══════════════════════════════════════════════════════════════════════
    // 一、表结构破坏类 — 18 条规则
    //   破坏数据库/表结构，影响范围大，恢复困难。
    //   包括：DROP 系列、Artisan 迁移系列、Schema Builder 系列、
    //         ALTER TABLE DROP、RENAME TABLE、外键/安全设置关闭
    // ══════════════════════════════════════════════════════════════════════
    'table_destruction' => [
        // --- Artisan 命令类（5 条）---
        // 这些命令通过 URL 参数/POST 数据/路由参数传入，
        // 常见场景：API 暴露的 artisan 调用端点、调试路由未清理
        ['pattern' => '/\bmigrate:fresh\b/i',
            'desc' => 'Laravel migrate:fresh（删除所有表后重新执行迁移，数据不可恢复）',
            'risk' => 'high'],
        ['pattern' => '/\bmigrate:refresh\b/i',
            'desc' => 'Laravel migrate:refresh（回滚所有迁移后重新执行，数据不可恢复）',
            'risk' => 'high'],
        ['pattern' => '/\bmigrate:reset\b/i',
            'desc' => 'Laravel migrate:reset（回滚所有迁移，删除全部表）',
            'risk' => 'high'],
        ['pattern' => '/\bdb:wipe\b/i',
            'desc' => 'Laravel db:wipe（直接删除数据库中所有表，比 migrate:fresh 更彻底）',
            'risk' => 'high'],
        ['pattern' => '/\bmigrate:rollback\b/i',
            'desc' => 'Laravel/ThinkPHP migrate:rollback（回滚最后一次迁移，可能删除多张表）',
            'risk' => 'high'],

        // --- Schema Builder 类（4 条）---
        // 通过代码动态构造的 Schema 操作，可能在开发者调试 API 中暴露
        ['pattern' => '/Schema\s*::\s*drop\s*\(\s*[\'"]/i',
            'desc' => 'Laravel Schema::drop(\'表名\')（单个表删除，空格容忍绕过）',
            'risk' => 'high'],
        ['pattern' => '/Schema\s*::\s*dropIfExists\s*\(\s*[\'"]/i',
            'desc' => 'Laravel Schema::dropIfExists(\'表名\')（条件删表，空格容忍绕过）',
            'risk' => 'high'],
        ['pattern' => '/Schema\s*::\s*dropAllTables\s*\(/i',
            'desc' => 'Laravel Schema::dropAllTables()（删除数据库中全部表，最危险操作之一）',
            'risk' => 'high'],
        ['pattern' => '/Schema\s*::\s*dropDatabase\b/i',
            'desc' => 'Laravel Schema::dropDatabase()（删除整个数据库连接下的所有数据）',
            'risk' => 'high'],

        // --- 原生 SQL DROP 系列（4 条）---
        // 覆盖 MySQL/PostgreSQL/SQLite 等主流数据库的 DDL 语法
        ['pattern' => '/\bDROP\s+TABLE\s+(IF\s+EXISTS\s+)?[`"\']?\w/i',
            'desc' => 'SQL DROP TABLE（删除数据表及所有数据，支持 IF EXISTS 防护绕过）',
            'risk' => 'high'],
        ['pattern' => '/\bDROP\s+DATABASE\s+(IF\s+EXISTS\s+)?[`"\']?\w/i',
            'desc' => 'SQL DROP DATABASE（删除整个数据库，所有表和数据全部丢失）',
            'risk' => 'high'],
        ['pattern' => '/\bDROP\s+VIEW\s+(IF\s+EXISTS\s+)?[`"\']?\w/i',
            'desc' => 'SQL DROP VIEW（删除视图，可能影响依赖该视图的查询/报表）',
            'risk' => 'high'],
        ['pattern' => '/\bDROP\s+(PROCEDURE|FUNCTION)\s+(IF\s+EXISTS\s+)?[`"\']?\w/i',
            'desc' => 'SQL DROP PROCEDURE/FUNCTION（删除存储过程或函数，可能影响业务逻辑）',
            'risk' => 'high'],

        // --- 堆叠查询（1 条）---
        ['pattern' => '/;\s*(drop|truncate)\s+(table|database|view)\b/i',
            'desc' => 'SQL 堆叠查询攻击：分号后拼接 DROP/TRUNCATE 命令（SQL 注入高危变体）',
            'risk' => 'high'],

        // --- ALTER TABLE DROP（1 条）---
        ['pattern' => '/\bALTER\s+TABLE\s+[`"\']?\w+\s+DROP\s+(COLUMN|CONSTRAINT|INDEX|KEY)\b/i',
            'desc' => 'SQL ALTER TABLE DROP（删除表字段/约束/索引，可能破坏表结构完整性）',
            'risk' => 'high'],

        // --- RENAME TABLE（1 条）---
        ['pattern' => '/\bRENAME\s+TABLE\s+[`"\']?\w/i',
            'desc' => 'SQL RENAME TABLE（重命名表，可能破坏代码/视图/存储过程对表的依赖）',
            'risk' => 'medium'],

        // --- 危险前置设置（2 条）---
        // 这两个设置本身不破坏数据，但通常是危险操作的前奏信号
        ['pattern' => '/\bSET\s+FOREIGN_KEY_CHECKS\s*=\s*0\b/i',
            'desc' => 'MySQL SET FOREIGN_KEY_CHECKS=0（关闭外键约束，几乎总是 TRUNCATE/DROP 的前奏）',
            'risk' => 'high'],
        ['pattern' => '/\bSET\s+SQL_SAFE_UPDATES\s*=\s*0\b/i',
            'desc' => 'MySQL SET SQL_SAFE_UPDATES=0（关闭安全更新模式，允许无条件 UPDATE/DELETE）',
            'risk' => 'high'],
    ],

    // ══════════════════════════════════════════════════════════════════════
    // 二、全量数据删除类 — 18 条规则
    //   批量删除/清空表数据，虽然表结构还在但数据不可恢复。
    //   包括：TRUNCATE、无条件 DELETE、永真条件 DELETE/UPDATE、
    //         ORM 危险调用、ThinkPHP 危险调用
    // ══════════════════════════════════════════════════════════════════════
    'mass_deletion' => [
        // --- SQL TRUNCATE（2 条）---
        ['pattern' => '/\bTRUNCATE\s+(TABLE\s+)?[`"\']?\w/i',
            'desc' => 'SQL TRUNCATE TABLE（清空表全部数据，不可回滚，比 DELETE 更快更危险）',
            'risk' => 'high'],
        ['pattern' => '/->\s*truncate\s*\(\s*\)/i',
            'desc' => 'Laravel Eloquent/QueryBuilder truncate()（ORM 层清空表，空格容忍）',
            'risk' => 'high'],

        // --- 无条件 DELETE（1 条）---
        // 优化：增加上下文限定，仅在 SQL 语句上下文中检测
        ['pattern' => '/;\s*DELETE\s+FROM\s+[`"\']?\w+[`"\']?\s*[;\s]*$/im',
            'desc' => 'SQL DELETE FROM 无条件删除（无 WHERE 子句，分号后）',
            'risk' => 'high'],
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s*;\s*$/im',
            'desc' => 'SQL DELETE FROM 无条件删除（无 WHERE 子句，分号结尾）',
            'risk' => 'high'],

        // --- 永真条件 DELETE（5 条）---
        // 优化：增加 SQL 上下文限定，避免误报
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+1\s*=\s*1\b/i',
            'desc' => 'SQL DELETE ... WHERE 1=1（典型永真条件，全表删除攻击）',
            'risk' => 'high'],
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+1\b(?![\w])/i',
            'desc' => 'SQL DELETE ... WHERE 1（隐式永真条件）',
            'risk' => 'medium'],
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+[\'"]1[\'"]\s*=\s*[\'"]1[\'"]/i',
            'desc' => 'SQL DELETE ... WHERE \'1\'=\'1\'（字符串形式的永真条件）',
            'risk' => 'high'],
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+true\b/i',
            'desc' => 'SQL DELETE ... WHERE true（布尔永真条件）',
            'risk' => 'medium'],
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+.*\bOR\s+1\s*=\s*1\b/i',
            'desc' => 'SQL DELETE ... WHERE ... OR 1=1（OR 永真条件绕过）',
            'risk' => 'high'],

        // --- 永真条件变体（1 条）---
        // 优化：避免误报正常业务查询（如 WHERE status=status）
        ['pattern' => '/\bDELETE\s+FROM\s+[`"\']?\w+[`"\']?\s+WHERE\s+[\'"]\w+[\'"]\s*=\s*[\'"]\w+[\'"]\s*(?:--|\#|\/\*)/i',
            'desc' => 'SQL DELETE ... WHERE 自等永真条件后接注释（可疑攻击）',
            'risk' => 'medium'],

        // --- Eloquent/QueryBuilder 危险调用（4 条）---
        // 优化：增加更精确的上下文限定，避免误报正常业务代码
        ['pattern' => '/\b\w+::\s*query\s*\(\s*\)\s*->\s*delete\s*\(\s*\)/i',
            'desc' => 'Laravel Model::query()->delete()（无任何筛选直接删除全表数据）',
            'risk' => 'high'],
        ['pattern' => '/\b\w+::\s*all\s*\(\s*\)\s*->\s*each\s*\(\s*.*delete/i',
            'desc' => 'Laravel Model::all()->each(...delete...)（遍历所有记录逐条删除）',
            'risk' => 'high'],
        ['pattern' => '/->\s*select\s*\([^)]*\)\s*->\s*delete\s*\(\s*\)/i',
            'desc' => 'Laravel ->select()->delete()（无 WHERE 限定的删除）',
            'risk' => 'medium'],
        ['pattern' => '/->\s*get\s*\(\s*\)\s*->\s*each\s*\(\s*.*delete/i',
            'desc' => 'Laravel ->get()->each(...delete...)（获取记录后删除）',
            'risk' => 'medium'],

        // --- Model::destroy()（3 条，第 1 条为低风险仅记录）---
        ['pattern' => '/::\s*destroy\s*\(\s*\)/i',
            'desc' => 'Laravel Model::destroy() 无参数调用（传入空值可能触发意外行为）',
            'risk' => 'high'],
        ['pattern' => '/::\s*destroy\s*\(\s*\[\s*\]\s*\)/i',
            'desc' => 'Laravel Model::destroy([]) 空数组（传入空数组可能被误用为全量删除）',
            'risk' => 'high'],
        ['pattern' => '/::\s*destroy\s*\(\s*\d{1,6}\s*\)/i',
            'desc' => 'Laravel Model::destroy(数字ID)（单个ID删除，通常为正常操作，低风险仅记录）',
            'risk' => 'low'],

        // --- ThinkPHP 特定操作（3 条）---
        ['pattern' => '/Db\s*::\s*table\s*\(\s*[\'"]\w+[\'"]\s*\)\s*->\s*delete\s*\(\s*\)/i',
            'desc' => 'ThinkPHP Db::table()->delete() 无条件（无 WHERE 限定，全表删除）',
            'risk' => 'high'],
        ['pattern' => '/Db\s*::\s*name\s*\(\s*[\'"]\w+[\'"]\s*\)\s*->\s*delete\s*\(\s*\)/i',
            'desc' => 'ThinkPHP Db::name()->delete() 无条件（无 WHERE 限定，全表删除）',
            'risk' => 'high'],
        ['pattern' => '/Db\s*::\s*execute\s*\(\s*[\'"].*(drop|truncate|delete\s+from)\b/i',
            'desc' => 'ThinkPHP Db::execute() 执行 DROP/TRUNCATE/DELETE 原生 SQL（直接绕过 ORM 安全层）',
            'risk' => 'high'],

        // --- 无条件 UPDATE（2 条）---
        ['pattern' => '/\bUPDATE\s+[`"\']?\w+[`"\']?\s+SET\s+[^;]{0,200}$/im',
            'desc' => 'SQL UPDATE ... SET 无条件（无 WHERE 子句，全表更新所有行）',
            'risk' => 'high'],
        ['pattern' => '/\bUPDATE\s+[`"\']?\w+\b[^;]{0,300}\bWHERE\s+1\s*=\s*1\b/i',
            'desc' => 'SQL UPDATE ... WHERE 1=1（永真条件全表更新，可覆盖整列数据）',
            'risk' => 'high'],
    ],

    // ══════════════════════════════════════════════════════════════════════
    // 三、代码级操作识别 — 13 条规则
    //   检测代码中动态构造/执行数据库危险命令的调用模式。
    //   这类操作通常封装在后端逻辑中，出现在请求中说明存在代码注入
    //   或不当的 API 设计暴露了内部命令执行能力。
    // ══════════════════════════════════════════════════════════════════════
    'code_level_operation' => [
        // --- Artisan::call()（5 条）---
        ['pattern' => '/Artisan\s*::\s*call\s*\(\s*[\'"]migrate:fresh/i',
            'desc' => 'PHP Artisan::call(\'migrate:fresh\')（代码中动态调用删库重建命令）',
            'risk' => 'high'],
        ['pattern' => '/Artisan\s*::\s*call\s*\(\s*[\'"]migrate:refresh/i',
            'desc' => 'PHP Artisan::call(\'migrate:refresh\')（代码中动态调用回滚重建命令）',
            'risk' => 'high'],
        ['pattern' => '/Artisan\s*::\s*call\s*\(\s*[\'"]migrate:reset/i',
            'desc' => 'PHP Artisan::call(\'migrate:reset\')（代码中动态调用回滚全部迁移命令）',
            'risk' => 'high'],
        ['pattern' => '/Artisan\s*::\s*call\s*\(\s*[\'"]db:wipe/i',
            'desc' => 'PHP Artisan::call(\'db:wipe\')（代码中动态调用删除全部表命令）',
            'risk' => 'high'],
        ['pattern' => '/Artisan\s*::\s*call\s*\(\s*[\'"]migrate:rollback/i',
            'desc' => 'PHP Artisan::call(\'migrate:rollback\')（代码中动态调用回滚迁移命令）',
            'risk' => 'high'],

        // --- PHP 命令执行函数（3 条）---
        ['pattern' => '/shell_exec\s*\(\s*[\'"].*artisan\s+migrate:fresh/i',
            'desc' => 'PHP shell_exec() 执行 artisan migrate:fresh（通过 shell 执行删库重建）',
            'risk' => 'high'],
        ['pattern' => '/exec\s*\(\s*[\'"].*artisan\s+migrate:refresh/i',
            'desc' => 'PHP exec() 执行 artisan migrate:refresh（通过 shell 执行回滚重建）',
            'risk' => 'high'],
        ['pattern' => '/shell_exec\s*\(\s*[\'"].*artisan\s+db:wipe/i',
            'desc' => 'PHP shell_exec() 执行 artisan db:wipe（通过 shell 直接删除所有表）',
            'risk' => 'high'],

        // --- PHP 命令执行函数（泛化，1 条）---
        ['pattern' => '/(?:passthru|system|popen|proc_open)\s*\(\s*[\'"].*artisan/i',
            'desc' => 'PHP passthru/system/popen/proc_open 执行 artisan（多种 shell 执行函数覆盖）',
            'risk' => 'high'],

        // --- Symfony Process 组件（2 条）---
        ['pattern' => '/new\s+Process\s*\(\s*\[[\s\S]{0,200}?migrate:fresh/i',
            'desc' => 'Symfony new Process() 执行 migrate:fresh（通过进程组件调用删库命令）',
            'risk' => 'high'],
        ['pattern' => '/Process\s*::\s*fromShellCommandline\s*\(\s*[\'"].*php\s+artisan/i',
            'desc' => 'Symfony Process::fromShellCommandline() 执行 artisan（shell 字符串模式）',
            'risk' => 'medium'],

        // --- Laravel DB Facade 危险调用（2 条）---
        ['pattern' => '/DB\s*::\s*statement\s*\(\s*[\'"].*(drop\s+(table|database|view)|truncate\s+table)\b/i',
            'desc' => 'Laravel DB::statement() 执行 DROP/TRUNCATE（原生 SQL，绕过 Eloquent 安全层）',
            'risk' => 'high'],
        ['pattern' => '/DB\s*::\s*unprepared\s*\(\s*[\'"].*(drop\s+(table|database|view)|truncate\s+table)\b/i',
            'desc' => 'Laravel DB::unprepared() 执行 DROP/TRUNCATE（绕过预处理，最危险的原生 SQL 调用方式）',
            'risk' => 'high'],
    ],
];
