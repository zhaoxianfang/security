<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;

/**
 * 数据库危险操作识别与拦截
 *
 * 作为 SecurityMiddleware 的第十四层安全防护，在请求即将放行前做最后一道数据库安全检测。
 * 与前面的 SQL 注入/XSS 等攻击检测不同，本模块检测的是"合法的工程操作语法"
 * （如 DROP TABLE 命令、artisan 命令行参数），这些操作如果通过 Web 请求触发，
 * 通常意味着调试/管理 API 暴露、代码命令注入漏洞或开发者误操作。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 三大检测类别（分阶段匹配，命中即返回）：
 *
 *   阶段一：表结构破坏类（破坏性最强，不可逆，恢复只能靠备份）
 *     Laravel:  migrate:fresh/refresh/reset、db:wipe、Schema::drop() 等
 *     ThinkPHP: migrate:rollback
 *     原生SQL:  DROP TABLE/DATABASE/VIEW/PROCEDURE/FUNCTION、ALTER TABLE DROP
 *              RENAME TABLE、SET FOREIGN_KEY_CHECKS=0、SQL_SAFE_UPDATES=0
 *
 *   阶段二：全量数据删除类（表结构在，数据不可恢复）
 *     Laravel:  Model::truncate()、Model::query()->delete()、::all()->each(...delete...)
 *     ThinkPHP: Model::destroy() 无条件、Db::table()->delete()、Db::execute(DROP/TRUNCATE)
 *     原生SQL:  TRUNCATE TABLE、DELETE FROM 无条件/永真条件、UPDATE 无条件/永真条件
 *
 *   阶段三：代码级操作识别（检测动态命令执行）
 *     Artisan::call() 调用危险迁移命令
 *     shell_exec/exec/passthru/system/Process 执行 artisan 危险命令
 *     DB::statement()/DB::unprepared() 执行 DROP/TRUNCATE 原生 SQL
 *
 * ══════════════════════════════════════════════════════════════════════
 * 环境控制：
 *   database_operation.environments 配置支持：
 *   - all         : 所有环境均拦截（适合高度敏感系统）
 *   - production  : 仅生产环境（推荐，防止线上误操作丢数据）
 *   - staging     : 仅预发布环境
 *   - testing     : 仅测试环境
 *   - local       : 仅本地开发环境
 *   - cli         : 仅命令行环境（防止 artisan 命令管道中误调用）
 *
 *   支持多环境组合，如 ['production', 'cli'] 可同时覆盖 Web 和 CLI 场景。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 性能优化：两级过滤体系
 *   第一级 — str_contains 预过滤（O(n)，~50-200μs/请求）
 *     合并三个类别的预过滤关键词，对 6 类输入源统一扫描，让 95%+ 正常请求
 *     在微秒级代价下安全通过，无需执行任何正则匹配
 *   第二级 — preg_match 正则精确匹配（仅对通过预过滤的 <5% 输入执行）
 *     52 条规则分三阶段执行，所有量词均有限制（{0,300}等），防止 ReDoS 回溯灾难
 *
 * ══════════════════════════════════════════════════════════════════════
 * 误拦截防护（三层排除机制）：
 *   1. 表名排除（exclude_tables） — \b 单词边界精确匹配
 *   2. 命令排除（exclude_commands） — str_contains 子串匹配
 *   3. 环境控制 — 仅在配置的环境中生效
 *
 * 跨框架兼容：支持 Laravel 11+ 和 ThinkPHP 8+。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - isCliMode(): bool         — 判断当前是否 CLI 模式
 *   - isDetectionEnabled(): bool — 检查检测层开关
 *   - getExcludeRules(): array  — 获取缓存排除规则（惰性解析）
 *   - getInterceptRules(): array — 获取缓存追加规则（惰性解析）
 *   - truncateInput(): string   — 截断输入防止正则回溯
 *   - safePregMatch(): bool     — 安全正则匹配
 *   - sanitizeMatchedContent(): string — 脱敏处理匹配内容
 *   - $this->config[][]: mixed  — 安全配置数组
 *   - $this->patternService: PatternService — 模式服务实例
 *   - $this->threats[]: array   — 检测到的威胁类型数组
 *   - $this->lastMatchedPattern: string — 最后匹配的模式
 *   - $this->lastMatchedContent: string — 最后匹配的内容
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.2.0
 */
trait HandlesDatabaseOperations
{
    /**
     * 数据库操作预过滤关键词缓存
     *
     * 三个类别共享一部分关键词，但全量数据删除类额外需要 truncate/delete 相关词。
     * 使用合并后的统一关键词列表进行一次 str_contains 扫描，比分三次扫描更高效。
     *
     * @var array<string>|null
     */
    private ?array $dbPreFilterKeywords = null;

    /**
     * 数据库危险操作检测入口（第十四层安全防护）
     *
     * ═══════════════════════════════════════════════════════════════
     * 检测流程（6 步，按顺序短路，未通过即返回 null）：
     *
     *   步骤 1 — 开关检查：检测层开关 database_operation 是否启用
     *   步骤 2 — 环境检查：当前环境是否在 environments 配置列表中
     *   步骤 3 — 子类型检查：block_table_destruction/mass_deletion/code_level_operation 至少启用一个
     *   步骤 4 — 模式加载：从 PatternService 加载数据库操作模式（含排除/追加规则）
     *   步骤 5 — 输入收集：collectDatabaseOperationInputs() 收集 6 类来源 + 多级解码变体
     *   步骤 6 — 两级过滤：① str_contains 预过滤 → ② 分阶段正则匹配
     *         阶段一 — 表结构破坏类（最高优先级）
     *         阶段二 — 全量数据删除类
     *         阶段三 — 代码级操作识别
     *
     * ═══════════════════════════════════════════════════════════════
     * 返回值的含义：
     *   - null：未检测到威胁，请求正常放行
     *   - 'database_table_destruction'：检测到表结构破坏操作
     *   - 'database_mass_deletion'：检测到全量数据删除操作
     *   - 'database_code_level_operation'：检测到代码级数据库危险操作
     *
     * @param object $request HTTP请求对象（Laravel Request / ThinkPHP Request）
     * @return string|null 检测到的威胁类型，null 表示安全
     */
    protected function detectDatabaseOperations(object $request): ?string
    {
        // 第一层：检查检测层开关（唯一入口开关）
        if (!$this->isDetectionEnabled('database_operation')) {
            return null;
        }

        // 第二层：检查当前环境是否允许拦截
        if (!$this->isDatabaseOperationAllowedInEnvironment()) {
            return null;
        }

        // 获取配置
        $dbConfig = $this->config['database_operation'] ?? [];
        $blockTableDestruction = $dbConfig['block_table_destruction'] ?? true;
        $blockMassDeletion = $dbConfig['block_mass_deletion'] ?? true;
        $blockCodeLevel = $dbConfig['block_code_level_operation'] ?? true;

        // 至少需要有一个子类型被启用
        if (!$blockTableDestruction && !$blockMassDeletion && !$blockCodeLevel) {
            return null;
        }

        // 获取数据库操作模式（使用缓存规则方法）
        $excludeRules = $this->getExcludeRules();
        $interceptRules = $this->getInterceptRules();

        $patterns = $this->patternService->getDatabaseOperationPatterns($excludeRules, $interceptRules);

        if (empty($patterns)) {
            return null;
        }

        // 收集待检查的输入来源
        $checkSources = $this->collectDatabaseOperationInputs($request);

        if (empty($checkSources)) {
            return null;
        }

        // 预过滤阶段：快速跳过不含任何数据库危险关键词的输入
        if (!$this->dbPreFilterPass($checkSources)) {
            return null;
        }

        // 获取排除表名和命令
        $excludeTables = $dbConfig['exclude_tables'] ?? [];
        $excludeCommands = $dbConfig['exclude_commands'] ?? [];

        // 正则匹配阶段：分阶段精确匹配
        // 阶段1：表结构破坏类（最高优先级，破坏性最强）
        if ($blockTableDestruction && isset($patterns['table_destruction'])) {
            $result = $this->matchDatabasePatterns(
                $patterns['table_destruction'],
                $checkSources,
                'database_table_destruction',
                $excludeTables,
                $excludeCommands
            );
            if ($result !== null) {
                return $result;
            }
        }

        // 阶段2：全量数据删除类
        if ($blockMassDeletion && isset($patterns['mass_deletion'])) {
            $result = $this->matchDatabasePatterns(
                $patterns['mass_deletion'],
                $checkSources,
                'database_mass_deletion',
                $excludeTables,
                $excludeCommands
            );
            if ($result !== null) {
                return $result;
            }
        }

        // 阶段3：代码级操作识别
        if ($blockCodeLevel && isset($patterns['code_level_operation'])) {
            $result = $this->matchDatabasePatterns(
                $patterns['code_level_operation'],
                $checkSources,
                'database_code_level_operation',
                $excludeTables,
                $excludeCommands
            );
            if ($result !== null) {
                return $result;
            }
        }

        return null;
    }

    /**
     * 检查当前环境是否允许拦截数据库危险操作
     *
     * 从 database_operation.environments 读取环境列表进行匹配。
     *
     * 环境判定逻辑（按优先级）：
     *   1. 配置为 ['all'] → 所有环境均拦截（直接返回 true）
     *   2. PHP_SAPI = 'cli' → 匹配 'cli' 环境
     *   3. APP_ENV 值 → 匹配具体环境名（如 'production'）
     *
     * 安全兜底：environments 为空数组时默认回退到 ['production']，
     * 确保生产环境始终受保护。
     *
     * @return bool true=当前环境允许拦截，false=跳过检测
     */
    protected function isDatabaseOperationAllowedInEnvironment(): bool
    {
        $config = $this->config['database_operation'] ?? [];
        $environments = $config['environments'] ?? ['all'];

        // 未配置则默认仅生产环境拦截
        if (empty($environments)) {
            $environments = ['production'];
        }

        // 'all' 在所有环境下都拦截
        if (in_array('all', $environments, true)) {
            return true;
        }

        // 获取当前环境标识
        $isCli = $this->isCliMode();

        // CLI 环境检查
        if ($isCli && in_array('cli', $environments, true)) {
            return true;
        }

        // 应用环境检查（APP_ENV）
        $appEnv = FrameworkBridge::config('app.env', 'local');
        $appEnv = is_string($appEnv) ? strtolower($appEnv) : 'local';

        foreach ($environments as $env) {
            if ($env === 'cli' || $env === 'all') {
                continue;
            }
            if ($env === $appEnv) {
                return true;
            }
        }

        return false;
    }

    /**
     * 收集数据库操作检测需要的所有输入来源
     *
     * 与高危攻击检测（DetectsAttackPatterns）不同，数据库操作检测需要
     * 更广泛地收集输入来源：
     *  - URL 完整路径和查询字符串（Artisan 命令常出现在 CLI 路由参数中）
     *  - POST 表单数据（管理面板命令提交）
     *  - 路由参数（如 /api/artisan/call/{command}）
     *  - JSON/XML 请求体（API 调用）
     *
     * 每个来源保留原始值 + 1级解码 + 2级双重解码变体，
     * 防止 %25%36%34 → %64 → d 这种双编码绕过。
     *
     * @param object $request HTTP请求对象
     * @return array<string, array<string>> 来源标识 => 待检测字符串列表
     */
    protected function collectDatabaseOperationInputs(object $request): array
    {
        $sources = [];

        // 1. URL 路径及完整 URL（框架返回值已知为 UTF-8，跳过验证）
        $fullUrl = FrameworkBridge::requestFullUrl($request);
        $path = FrameworkBridge::requestPath($request);

        if ($fullUrl !== '') {
            $truncated = $this->truncateInputKnown($fullUrl);
            $decoded = $this->truncateInputKnown($this->cachedUrldecode($fullUrl, 1));
            if ($decoded !== $truncated) {
                $sources['full_url'] = [$truncated, $decoded];
            } else {
                $sources['full_url'] = [$truncated];
            }
        }

        if ($path !== '' && $path !== $fullUrl) {
            $sources['url_path'] = [$path, $this->truncateInputKnown($this->cachedUrldecode($path, 1))];
        }

        // 2. 查询参数字符串（整体）
        $queryString = FrameworkBridge::requestGetQueryString($request);
        if ($queryString !== null && $queryString !== '') {
            $decoded = $this->cachedUrldecode($queryString, 1);
            if ($decoded !== $queryString) {
                $sources['query_string'] = [$queryString, $decoded];
            } else {
                $sources['query_string'] = [$queryString];
            }
        }

        // 3-5. 查询/POST/路由参数值 — 使用内联去重替代 array_unique
        foreach ([
            ['query', FrameworkBridge::requestQuery($request)],
            ['post', FrameworkBridge::requestPost($request)],
            ['route', FrameworkBridge::requestRouteParams($request)],
        ] as [$prefix, $params]) {
            foreach ($params as $key => $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }
                $c1 = $this->truncateInputKnown($value);
                $c2 = $this->truncateInputKnown($this->cachedUrldecode($value, 1));
                $c3 = $this->truncateInputKnown($this->cachedUrldecode($value, 2));

                $candidates = [$c1];
                if ($c2 !== $c1) $candidates[] = $c2;
                if ($c3 !== $c1 && $c3 !== $c2) $candidates[] = $c3;
                $sources["{$prefix}.{$key}"] = $candidates;
            }
        }

        // 6. 原始请求体内容（适用于 JSON/XML API 请求）
        $contentType = FrameworkBridge::requestGetHeader($request, 'Content-Type') ?? '';
        if (stripos($contentType, 'json') !== false || stripos($contentType, 'xml') !== false) {
            try {
                if (method_exists($request, 'getContent')) {
                    $rawBody = $request->getContent();
                    if (is_string($rawBody) && $rawBody !== '') {
                        $truncated = $this->truncateInputKnown($rawBody);
                        $decoded = $this->truncateInputKnown($this->cachedUrldecode($rawBody, 1));
                        if ($decoded !== $truncated) {
                            $sources['raw_body'] = [$truncated, $decoded];
                        } else {
                            $sources['raw_body'] = [$truncated];
                        }
                    }
                }
            } catch (\Throwable) {
                // 忽略获取请求体时的异常
            }
        }

        return $sources;
    }

    /**
     * 预过滤阶段：快速排除不含数据库危险关键词的输入
     *
     * str_contains 是 O(n) 级别，PHP 内部使用 memmem() C 函数实现，极快（~5-15μs/次）。
     * 正常 Web 请求几乎从不包含 "migrate:fresh"、"drop table" 等数据库关键词，
     * 预过滤可让 95%+ 请求在微秒级代价下安全通过，无需执行 52 条正则。
     *
     * 关键词按长度降序排列（长词先匹配，短路更快）。
     * 输入统一转小写后匹配（大小写不敏感）。
     *
     * 优化：合并所有输入源为单次 strtolower + str_contains 遍历，
     * 相比逐源遍历减少函数调用次数。
     *
     * @param array<string, array<string>> $checkSources 输入来源
     * @return bool true=至少一条输入含关键词需正则检查，false=安全跳过
     */
    protected function dbPreFilterPass(array $checkSources): bool
    {
        $keywords = $this->getDbPreFilterKeywords();

        if (empty($keywords)) {
            return true;
        }

        // 扁平化所有来源 → 一次 strtolower 一次遍历
        // 替代之前的嵌套 foreach（每源每字符串每关键词三层循环）
        foreach ($checkSources as $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || $checkString === '') {
                    continue;
                }

                $lowered = strtolower($checkString);
                foreach ($keywords as $keyword) {
                    if (str_contains($lowered, $keyword)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 获取数据库操作预过滤关键词（懒加载 + 进程级缓存）
     *
     * 从 PatternService 获取三个类别（table_destruction/mass_deletion/code_level_operation）
     * 的预过滤关键词，合并去重后按长度降序排列。
     *
     * 缓存机制：使用实例属性 $dbPreFilterKeywords，首次调用构建，后续命中缓存。
     * null = 未初始化，[] = 已初始化但无关键词。
     *
     * @return array<string> 合并去重并按长度降序排列的关键词列表
     */
    protected function getDbPreFilterKeywords(): array
    {
        if ($this->dbPreFilterKeywords !== null) {
            return $this->dbPreFilterKeywords;
        }

        // 从 PatternService 获取各类型预过滤关键词并合并去重
        $keywords = array_merge(
            $this->patternService->getPreFilterKeywords('table_destruction'),
            $this->patternService->getPreFilterKeywords('mass_deletion'),
            $this->patternService->getPreFilterKeywords('code_level_operation')
        );

        // 去重并按长度降序排列（长关键词概率更高，先匹配可更快命中）
        $keywords = array_unique($keywords);
        usort($keywords, fn(string $a, string $b) => strlen($b) - strlen($a));

        $this->dbPreFilterKeywords = $keywords;
        return $keywords;
    }

    /**
     * 对收集到的输入来源执行正则模式匹配
     *
     * ═══════════════════════════════════════════════════════════════
     * 三重循环结构（外层可控，整体开销小）：
     *   外层：遍历输入来源 key（如 full_url、query.command、post.action）
     *   中层：遍历每个来源的待检字符串（原始值 + URL 解码变体）
     *   内层：遍历正则模式列表（16-18 条规则/类别）
     *         → safePregMatch() → 匹配成功 → 表名排除检查 → 命令排除检查
     *         → 全部通过 → 记录威胁信息 + 立即返回威胁类型
     *
     * ═══════════════════════════════════════════════════════════════
     * 短路优化：
     *   - 第一条正则命中且未在排除列表 → 立即返回，不检查同类其他正则
     *   - 因为同类正则对应不同具体命令，一次请求通常只触发其中一条
     *
     * ═══════════════════════════════════════════════════════════════
     * 排除机制（两层）：
     *   1. 表名排除 — 从匹配文本中提取表名，\b 单词边界精确匹配
     *   2. 命令排除 — 在输入中 str_contains 子串匹配命令名
     *
     * ═══════════════════════════════════════════════════════════════
     * 副作用：
     *   匹配成功时设置 $this->threats[]、lastMatchedPattern、lastMatchedContent，
     *   供 BuildsInterceptionResponse 使用。
     *
     * @param array<int, array{pattern:string,desc?:string,risk:string}> $patterns 正则模式数组
     * @param array<string, array<string>> $checkSources 输入来源
     * @param string $threatType 威胁类型标识
     * @param array<string> $excludeTables 排除表名列表
     * @param array<string> $excludeCommands 排除命令列表
     * @return string|null 匹配到的威胁类型，null 表示该类别的所有正则均未命中
     */
    protected function matchDatabasePatterns(
        array $patterns,
        array $checkSources,
        string $threatType,
        array $excludeTables = [],
        array $excludeCommands = []
    ): ?string {
        if (empty($patterns)) {
            return null;
        }

        foreach ($checkSources as $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || $checkString === '') {
                    continue;
                }

                foreach ($patterns as $item) {
                    if (!isset($item['pattern']) || !is_string($item['pattern'])) {
                        continue;
                    }

                    $matches = [];
                    if ($this->safePregMatch($item['pattern'], $checkString, $matches)) {
                        // 检查是否是排除表（对包含表名的操作）
                        if ($this->isExcludedTableMatch($matches, $excludeTables)) {
                            continue; // 该表在排除列表中，跳过
                        }

                        // 检查是否是排除命令
                        if ($this->isExcludedCommandMatch($checkString, $excludeCommands)) {
                            continue;
                        }

                        $this->threats[] = $threatType;
                        $this->lastMatchedPattern = $item['pattern'];
                        $this->lastMatchedContent = $this->sanitizeMatchedContent(
                            $matches[0] ?? ''
                        );
                        return $threatType;
                    }
                }
            }
        }

        return null;
    }

    /**
     * 检查匹配结果是否针对排除列表中的表名
     *
     * ═══════════════════════════════════════════════════════════════
     * 匹配逻辑：
     *   1. 从 preg_match 返回的 $matches[0] 获取完整匹配文本
     *   2. 转为小写后与排除表名列表逐条比对
     *   3. 使用 \b 单词边界 + preg_quote 构造临时正则，确保精确匹配
     *
     * ═══════════════════════════════════════════════════════════════
     * 单词边界示例：
     *   exclude_tables = ['cache', 'log']
     *   "DROP TABLE cache"      → 命中 'cache'  ✓ （正确排除）
     *   "DROP TABLE caches"     → 不命中 'cache'   （不排除，caches ≠ cache）
     *   "TRUNCATE TABLE user_cache" → 不命中     （不排除，user_cache ≠ cache）
     *   "DELETE FROM logs"      → 不命中 'log'    （不排除，logs ≠ log）
     *
     * @param array $matches preg_match 匹配结果
     * @param array<string> $excludeTables 排除表名列表
     * @return bool true=该操作针对排除表，应跳过拦截
     */
    protected function isExcludedTableMatch(array $matches, array $excludeTables): bool
    {
        if (empty($excludeTables) || empty($matches)) {
            return false;
        }

        // 从匹配结果中提取可能的表名
        $matchText = $matches[0] ?? '';
        if ($matchText === '') {
            return false;
        }

        $lowerMatch = strtolower($matchText);

        foreach ($excludeTables as $excludedTable) {
            $excludedTable = strtolower(trim($excludedTable));
            if ($excludedTable === '') {
                continue;
            }

            // 检查匹配文本中是否包含该表名
            // 使用单词边界确保精确匹配（避免 'user' 匹配到 'users'）
            if ($this->safePregMatch('/\b' . preg_quote($excludedTable, '/') . '\b/i', $lowerMatch)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查匹配是否针对排除列表中的命令
     *
     * 使用 str_contains 子串匹配（比表名排除宽松）：
     *   命令名通常唯一性较高，如 "migrate:rollback" 不会与其他内容冲突，
     *   因此使用子串匹配即可，无需 \b 边界。
     *
     * @param string $checkString 被匹配的字符串
     * @param array<string> $excludeCommands 排除命令列表（如 ['migrate:rollback']）
     * @return bool true=该命令在排除列表中，应跳过拦截
     */
    protected function isExcludedCommandMatch(string $checkString, array $excludeCommands): bool
    {
        if (empty($excludeCommands)) {
            return false;
        }

        $lowerCheck = strtolower($checkString);

        foreach ($excludeCommands as $excludedCommand) {
            $excludedCommand = strtolower(trim($excludedCommand));
            if ($excludedCommand === '') {
                continue;
            }

            // 检查输入字符串中是否包含排除的命令名
            if (str_contains($lowerCheck, $excludedCommand)) {
                return true;
            }
        }

        return false;
    }
}
