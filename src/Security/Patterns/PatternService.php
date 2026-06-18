<?php

namespace zxf\Security\Patterns;

/**
 * 安全模式服务 - 延迟加载 + 风险分级 + 统一规则管理
 *
 * 核心设计理念：
 *  1. 延迟加载 — 模式数据文件仅在首次访问时加载
 *  2. 内存缓存 — 已加载的模式在进程内缓存
 *  3. 风险分级 — 每条规则标注 high / medium / low 风险等级
 *  4. 统一排除 — intercept_rules_exclude 全局生效，优先级最高
 *  5. 统一追加 — intercept_rules 按风险等级分组，优先级次之
 *  6. 预过滤支持 — 快速字符串预检，减少不必要的正则匹配
 *  7. 零缓存依赖 — 不依赖 Laravel config 缓存，独立数据文件
 *
 * 规则优先级（从高到低）：
 *  1. intercept_rules_exclude — 排除列表中的规则全部被忽略
 *  2. intercept_rules — 用户自定义追加规则
 *  3. built-in patterns — 内置默认规则
 *
 * @package zxf\Security\Patterns
 * @since 6.0.0
 */
class PatternService
{
    /**
     * 已加载的模式缓存（进程级）
     *
     * @var array<string, array|null>
     */
    private static array $loadedPatterns = [];

    /**
     * 模式数据文件路径映射
     *
     * @var array<string, string>
     */
    private static array $dataFiles = [
        'high_risk'             => __DIR__ . '/data/high_risk_patterns.php',
        'xss'                   => __DIR__ . '/data/xss_patterns.php',
        'url_path'              => __DIR__ . '/data/url_path_patterns.php',
        'database_operation'    => __DIR__ . '/data/database_operation_patterns.php',
    ];

    /**
     * 用户自定义模式数据文件（追加到内置模式之后）
     *
     * key = 模式类型（high_risk / xss / url_path / database_operation）
     * value = 文件路径数组
     *
     * @var array<string, array<string>>
     */
    private static array $customDataFiles = [];

    /**
     * 已编译的模式验证缓存
     * key = 模式 MD5，value = true（编译通过）
     *
     * @var array<string, bool>
     */
    private static array $validatedPatterns = [];

    /**
     * 请求级预过滤结果缓存（避免同一输入对同一类型反复 str_contains）
     * key = "type::input_hash"，value = true/false
     * 可选启用，通过 PatternService::enableRequestCache() 控制
     *
     * @var array<string, bool>
     */
    private static array $preFilterRequestCache = [];

    /**
     * 是否启用请求级预过滤缓存
     */
    private static bool $requestCacheEnabled = false;

    /**
     * 快速预过滤关键词映射
     * 用于通过 str_contains 快速跳过不可能匹配的输入
     *
     * 关键词按长度降序排列（长词优先短路），在首次访问时自动排序。
     *
     * @var array<string, array<string>>
     */
    private static array $preFilters = [
        'sql'              => [
            'union select', 'union', 'sleep(', 'benchmark(', 'load_file', 'drop table', 'truncate table',
            'xp_', 'sp_oa', '%27', 'extractvalue', 'updatexml', 'floor(rand',
            '@@', 'group_concat', 'concat_ws', 'waitfor delay', 'unhex(', '/*', '/**/', '%df', '%bf',
            "' or ", "' and ", 'case when', 'if(',
            'substr(', 'substring(', 'json_extract', 'json_value', 'json_query',
            'regexp', 'procedure analyse', 'into outfile', 'into dumpfile',
        ],
        'command'          => [
            'system(', 'exec(', 'passthru(', 'shell_exec(', 'proc_open(', 'popen(', 'pcntl_exec(',
            'rm -', 'wget ', 'curl ', 'nc -', 'netcat -', '|', '`', '$(',
            'powershell -', 'cmd /c', 'bash -c', 'sh -c', 'python -c', 'perl -e', 'php -r',
            '${IFS}', 'whoami', 'id ', 'nslookup',
        ],
        'path'             => [
            '../', '..\\', '%2e%2e', '%252e', '/.env', '/.git', 'etc/', 'proc/',
            '.php', '.jsp', '.asp', '.aspx', '.sh', '.py', '.exe', '.dll', '.bat',
            'passwd', '.svn', '.hg', '.bzr', 'htaccess', 'htpasswd', 'web.config',
            'composer.json', 'package.json', 'docker', 'wp-', 'phpmyadmin', 'adminer',
            '%c0', '%ef', '%e0', '%00', 'windows', 'system32',
        ],
        'ldap'             => [')(', '|(', '&(', '*(', '(|', '(&'],
        'xml'              => ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'PUBLIC'],
        'nosql'            => ['$eq', '$ne', '$gt', '$lt', '$gte', '$lte', '$where', '$regex', '$exists', '$type', '$or', '$and', '$mod', '$size', '$all', '$in', '$nin'],
        'ssti'             => ['{{', '}}', '{%', '%}', 'eval(', 'exec('],
        'ssrf'             => [
            '127.0.0.1', '169.254', 'gopher://', 'metadata', 'nip.io', 'latest/', 'instance-',
            'rebind', 'dnsrebind', 'xip.io', 'sslip.io', 'burpcollaborator',
        ],
        'encoding'         => ['%25', '%00', '%c0', '%e0', '&#x', '&#', '%u', '%0d', '%0a'],
        'header_injection' => ['%0d', '%0a', '\r\n', 'content-type:', 'set-cookie:', 'location:', 'transfer-encoding:'],
        'redirect'         => [
            'redirect_uri=', 'redirect=', 'redirect:', 'callback=', 'return_url=', '//', 'goto=',
            'url=', 'next=', 'dest=', 'forward=',
        ],
        'file_include'     => [
            'include(', 'require(', 'php://', 'file_get_contents(', '/proc/self/',
            'data://', 'expect://', 'readfile(', 'fopen(', 'show_source(',
            'phar://', 'compress.zlib://', 'compress.bzip2://',
        ],
        'deserialization' => [
            'unserialize(', 'O:', 'C:', '__wakeup', '__destruct', '__toString',
            '__call', '__get', '__set', 'phar://',             'GuzzleHttp', 'Monolog',
        ],
        'prototype_pollution' => [
            '__proto__', 'constructor', 'prototype', 'Object.assign',
            'Object.create', 'defineProperty',
        ],
        'jndi' => [
            'jndi:', 'ldap://', 'rmi://', '${jndi', '${lower:',
            '${upper:', '${env:', '${::-j}', '${::-n}',
        ],
        'http_smuggling' => [
            'transfer-encoding', 'content-length:', 'chunked',
        ],
        'graphql' => [
            '__schema', '__type', '__typename', 'fragment',
            'mutation', 'subscription',
        ],
        'webshell' => [
            '$_GET', '$_POST', '$_REQUEST', 'base64_decode(', 'str_rot13(',
            'gzuncompress(', 'assert(', 'preg_replace(', 'create_function(',
            'call_user_func(', 'chr(', '\\x',
        ],
        'xss_script'       => ['<script', 'javascript:', 'eval('],
        'xss_dom'          => ['onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouse', 'innerHTML=', 'outerHTML='],
        'xss_event'        => ['onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouseover=', 'onblur=', 'onchange=', 'onsubmit='],
        'xss_tag'          => ['<iframe', '<object', '<embed', '<svg', '<img', '<input'],
        'xss_encoding'     => ['\\u', '&#x', 'base64,', 'data:'],
        'xss_framework'    => ['jQuery.fn', 'constructor', 'prototype', 'v-html'],
        'table_destruction'     => [
            'migrate:fresh', 'migrate:refresh', 'migrate:reset', 'migrate:rollback',
            'db:wipe', 'schema::drop', 'drop table', 'drop database', 'dropifexists',
            'dropalltables', 'alter table', 'drop view', 'drop procedure', 'drop function',
            'rename table', 'foreign_key_checks', 'sql_safe_updates',
            'database.connections', 'db_database', 'db_host',
            'module:migrate-refresh', 'module:migrate-fresh', 'module:migrate-reset',
            'module:migrate-rollback', 'module:delete',
        ],
        'mass_deletion'         => [
            'truncate table', 'delete from', '->delete(', '::destroy(', 'where 1=1',
            'where 1', 'where true', 'db::table', 'db::name', 'db::execute',
            '::all()->', '::query()->', '->each(', '->chunk(', '->cursor(',
            'db::raw', 'schema:dump',
        ],
        'code_level_operation'  => [
            'artisan::call', 'shell_exec(', 'migrate:fresh', 'migrate:refresh',
            'migrate:rollback', 'db:wipe', 'php artisan', 'db::statement(',
            'db::unprepared(', 'passthru(', 'proc_open(', 'system(',
            'new process(', 'fromshellcommandline',
            'db::raw(', 'config::set', 'db::connect',
            'module:delete', 'module:migrate-refresh', 'module:migrate-fresh',
            'module:migrate-reset', 'module:migrate-rollback',
        ],
    ];

    /**
     * 获取高危攻击模式
     *
     * @param array $excludeRules 排除规则列表（精确字符串匹配）
     * @param array $interceptRules 追加规则 ['high' => [], 'medium' => [], 'low' => []]
     * @return array<string, array<int, array{pattern:string,risk:string}>>
     */
    public function getHighRiskPatterns(array $excludeRules = [], array $interceptRules = []): array
    {
        $defaults = $this->loadDataFile('high_risk');

        // 应用排除规则（优先级最高）
        $defaults = $this->applyExclusions($defaults, $excludeRules);

        // 应用追加规则（优先级次之）
        return $this->applyInterceptions($defaults, $interceptRules);
    }

    /**
     * 获取XSS攻击模式
     *
     * @param array $excludeRules 排除规则列表
     * @param array $interceptRules 追加规则
     * @return array<string, array<int, array{pattern:string,risk:string}>>
     */
    public function getXssPatterns(array $excludeRules = [], array $interceptRules = []): array
    {
        $defaults = $this->loadDataFile('xss');

        $defaults = $this->applyExclusions($defaults, $excludeRules);

        return $this->applyInterceptions($defaults, $interceptRules);
    }

    /**
     * 获取URL路径攻击模式
     *
     * @param array $excludeRules 排除规则列表
     * @param array $interceptRules 追加规则
     * @return array<int, array{pattern:string,risk:string}>
     */
    public function getUrlPathPatterns(array $excludeRules = [], array $interceptRules = []): array
    {
        $defaults = $this->loadDataFile('url_path');

        // URL路径模式是扁平数组
        $defaults = $this->applyFlatExclusions($defaults, $excludeRules);

        return $this->applyFlatInterceptions($defaults, $interceptRules);
    }

    /**
     * 获取数据库危险操作模式
     *
     * 返回按类型分组的模式数组：
     *   - table_destruction ：表结构破坏类
     *   - mass_deletion     ：全量数据删除类
     *   - code_level_operation：代码级操作识别
     *
     * @param array $excludeRules 排除规则列表（精确字符串匹配）
     * @param array $interceptRules 追加规则 ['high' => [], 'medium' => [], 'low' => []]
     * @return array<string, array<int, array{pattern:string,risk:string}>>
     */
    public function getDatabaseOperationPatterns(array $excludeRules = [], array $interceptRules = []): array
    {
        $defaults = $this->loadDataFile('database_operation');

        // 应用排除规则（优先级最高）
        $defaults = $this->applyExclusions($defaults, $excludeRules);

        // 应用追加规则（优先级次之）
        return $this->applyInterceptions($defaults, $interceptRules);
    }

    /**
     * 解析配置中的规则（支持callable）
     *
     * @param mixed $config 配置值（数组、闭包、类名、可调用数组）
     * @return array 解析后的数组
     */
    public static function resolveRules(mixed $config): array
    {
        return \zxf\Security\Services\ConfigResolver::resolve($config);
    }

    /**
     * 应用排除规则到类型分组模式
     *
     * @param array<string, array<int, array{pattern:string,risk:string}>> $patterns
     * @param array<string> $excludeRules
     * @return array<string, array<int, array{pattern:string,risk:string}>>
     */
    protected function applyExclusions(array $patterns, array $excludeRules): array
    {
        if (empty($excludeRules)) {
            return $patterns;
        }

        // 防御：过滤非字符串值，防止 array_flip 抛出 TypeError
        $excludeRules = array_values(array_filter($excludeRules, 'is_string'));
        if (empty($excludeRules)) {
            return $patterns;
        }

        $excludeSet = array_flip($excludeRules);

        foreach ($patterns as $type => $typePatterns) {
            $patterns[$type] = array_values(array_filter(
                $typePatterns,
                // 保留 ?? '' 防御数据文件被篡改后缺少 pattern 键的情况
                /** @phpstan-ignore-next-line */
                fn(mixed $item) => is_array($item) && !isset($excludeSet[$item['pattern'] ?? ''])
            ));

            if (empty($patterns[$type])) {
                unset($patterns[$type]);
            }
        }

        return $patterns;
    }

    /**
     * 应用追加规则到类型分组模式
     *
     * 追加规则不区分类型，统一追加到独立类型 'custom_high' / 'custom_medium' / 'custom_low' 中。
     * 类型键与 DefaultConfig::RESPONSE_MESSAGES / ThreatData 保持一致（无下划线前缀）。
     *
     * @param array<string, array<int, array{pattern:string,risk:string}>> $patterns
     * @param array{high?:array<string>,medium?:array<string>,low?:array<string>} $interceptRules
     * @return array<string, array<int, array{pattern:string,risk:string}>>
     */
    protected function applyInterceptions(array $patterns, array $interceptRules): array
    {
        foreach (['high', 'medium', 'low'] as $risk) {
            $rules = $interceptRules[$risk] ?? [];
            if (empty($rules)) {
                continue;
            }

            $typeKey = 'custom_' . $risk;
            $customPatterns = [];

            foreach ($rules as $rule) {
                if (is_string($rule) && !empty($rule)) {
                    $customPatterns[] = ['pattern' => $rule, 'risk' => $risk];
                }
            }

            if (!empty($customPatterns)) {
                if (isset($patterns[$typeKey])) {
                    $patterns[$typeKey] = array_merge($patterns[$typeKey], $customPatterns);
                } else {
                    $patterns[$typeKey] = $customPatterns;
                }
            }
        }

        return $patterns;
    }

    /**
     * 应用排除规则到扁平模式数组
     *
     * @param array<int, array{pattern:string,risk:string}> $patterns
     * @param array<string> $excludeRules
     * @return array<int, array{pattern:string,risk:string}>
     */
    protected function applyFlatExclusions(array $patterns, array $excludeRules): array
    {
        if (empty($excludeRules)) {
            return $patterns;
        }

        // 防御：过滤非字符串值，防止 array_flip 抛出 TypeError
        $excludeRules = array_values(array_filter($excludeRules, 'is_string'));
        if (empty($excludeRules)) {
            return $patterns;
        }

        $excludeSet = array_flip($excludeRules);

        return array_values(array_filter(
            $patterns,
            // 保留 ?? '' 防御数据文件被篡改后缺少 pattern 键的情况
            /** @phpstan-ignore-next-line */
            fn(mixed $item) => is_array($item) && !isset($excludeSet[$item['pattern'] ?? ''])
        ));
    }

    /**
     * 应用追加规则到扁平模式数组
     *
     * @param array<int, array{pattern:string,risk:string}> $patterns
     * @param array{high?:array<string>,medium?:array<string>,low?:array<string>} $interceptRules
     * @return array<int, array{pattern:string,risk:string}>
     */
    protected function applyFlatInterceptions(array $patterns, array $interceptRules): array
    {
        foreach (['high', 'medium', 'low'] as $risk) {
            $rules = $interceptRules[$risk] ?? [];
            foreach ($rules as $rule) {
                if (is_string($rule) && !empty($rule)) {
                    $patterns[] = ['pattern' => $rule, 'risk' => $risk];
                }
            }
        }

        return $patterns;
    }

    /**
     * 获取预过滤关键词（首次访问时按长度降序排列）
     *
     * 关键词越长，命中概率越高（长词包含短词特征），
     * 按长度降序排列可使 str_contains 更快短路。
     *
     * @param string $type 模式类型
     * @return array<string>
     */
    public function getPreFilterKeywords(string $type): array
    {
        $type = $this->normalizeType($type);

        if (!isset(self::$preFilters[$type])) {
            return [];
        }

        // 懒排序：首次访问时排序，后续直接返回
        $keywords = self::$preFilters[$type];
        $firstKey = array_key_first($keywords);
        // 通过检查第一个关键词是否为最长来判定是否已排序
        $firstLen = strlen((string) $keywords[$firstKey] ?? '');
        $maxLen = 0;
        foreach ($keywords as $k) {
            $l = strlen($k);
            if ($l > $maxLen) $maxLen = $l;
        }

        if ($firstLen < $maxLen) {
            // 需要排序
            usort(self::$preFilters[$type], fn(string $a, string $b) => strlen($b) - strlen($a));
        }

        return self::$preFilters[$type];
    }

    /**
     * 快速预过滤检查
     *
     * 检查输入字符串是否包含指定类型的关键词特征。
     * 返回 false 表示可以安全跳过该类型的正则检查。
     *
     * @param string $type 模式类型
     * @param string $input 输入字符串（调用方应已转为小写以复用）
     * @param bool $isLowered 输入是否已转为小写（默认 false，内部转换）
     * @return bool true=可能包含特征需进一步检查，false=安全跳过
     */
    public function preFilter(string $type, string $input, bool $isLowered = false): bool
    {
        $keywords = $this->getPreFilterKeywords($type);

        if (empty($keywords)) {
            return true;
        }

        // 请求级缓存：同一输入+类型组合跳过重复检查
        $useCache = self::$requestCacheEnabled;
        $cacheKey = $useCache ? ($type . '::' . crc32($input)) : '';

        if ($useCache && isset(self::$preFilterRequestCache[$cacheKey])) {
            return self::$preFilterRequestCache[$cacheKey];
        }

        $lowerInput = $isLowered ? $input : strtolower($input);

        foreach ($keywords as $keyword) {
            if (str_contains($lowerInput, $keyword)) {
                if ($useCache) {
                    self::$preFilterRequestCache[$cacheKey] = true;
                }
                return true;
            }
        }

        if ($useCache && count(self::$preFilterRequestCache) < 500) {
            self::$preFilterRequestCache[$cacheKey] = false;
        }

        return false;
    }

    /**
     * 批量预过滤（单次遍历多类型）
     *
     * 一次性检查输入字符串对多种类型的预过滤结果，
     * 仅执行一次 strtolower()，避免多类型重复检查。
     *
     * @param string $input 输入字符串
     * @param array<string> $types 要检查的类型列表
     * @return array<string> 通过预过滤的类型列表（需进一步正则检查）
     */
    public function preFilterBatch(string $input, array $types): array
    {
        if (empty($types)) {
            return [];
        }

        $lowerInput = strtolower($input);
        $activeTypes = [];

        foreach ($types as $type) {
            if ($this->preFilter($type, $lowerInput, true)) {
                $activeTypes[] = $type;
            }
        }

        return $activeTypes;
    }

    /**
     * 预验证正则模式（在加载时调用一次）
     *
     * 对指定类型的模式进行预编译验证，缓存验证结果。
     * 已验证通过的模式在运行时无需 @ 错误抑制开销。
     *
     * @param string $type 模式类型
     * @return int 通过验证的模式数量
     */
    public function validatePatterns(string $type): int
    {
        $patterns = $this->loadDataFile($type);
        $count = 0;

        // 扁平化：按类型分组或扁平数组
        $flatPatterns = [];
        if (!empty($patterns)) {
            $firstValue = reset($patterns);
            if (is_array($firstValue) && isset($firstValue['pattern'])) {
                // 扁平数组
                $flatPatterns = $patterns;
            } elseif (is_array($firstValue)) {
                // 类型分组
                foreach ($patterns as $groupPatterns) {
                    if (is_array($groupPatterns)) {
                        foreach ($groupPatterns as $item) {
                            if (isset($item['pattern'])) {
                                $flatPatterns[] = $item;
                            }
                        }
                    }
                }
            }
        }

        foreach ($flatPatterns as $item) {
            $pattern = $item['pattern'] ?? null;
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            $hash = md5($pattern);
            if (isset(self::$validatedPatterns[$hash])) {
                $count++;
                continue;
            }

            // 用空字符串测试编译（不会实际匹配，仅验证模式语法）
            $result = @preg_match($pattern, '');
            self::$validatedPatterns[$hash] = $result !== false;
            if ($result !== false) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * 检查模式是否已通过编译验证
     *
     * @param string $pattern 正则模式
     * @return bool true=已验证通过/无需验证，false=未验证
     */
    public function isPatternValidated(string $pattern): bool
    {
        return isset(self::$validatedPatterns[md5($pattern)]);
    }

    /**
     * 启用请求级预过滤缓存
     *
     * 当同一请求中对同一输入多次执行 preFilter 时可显著减少 strtolower + str_contains 开销。
     * 需在请求开始时调用 enableRequestCache()，结束时调用 clearRequestCache()。
     */
    public static function enableRequestCache(): void
    {
        self::$requestCacheEnabled = true;
    }

    /**
     * 清除请求级预过滤缓存
     */
    public static function clearRequestCache(): void
    {
        self::$preFilterRequestCache = [];
    }

    /**
     * 加载模式数据文件
     *
     * 使用静态缓存，同一进程中多次访问仅加载一次。
     * 数据文件是纯 PHP 返回数组，不经过 config 缓存机制。
     *
     * 数据格式：
     *   类型分组：['type' => [['pattern' => '/.../', 'desc' => '说明', 'risk' => 'high'], ...]]
     *   扁平数组：[['pattern' => '/.../', 'desc' => '说明', 'risk' => 'high'], ...]
     *
     * @param string $name 数据文件名（不含路径和扩展名）
     * @return array
     */
    private function loadDataFile(string $name): array
    {
        // 命中进程级缓存，直接返回
        if (isset(self::$loadedPatterns[$name])) {
            return self::$loadedPatterns[$name];
        }

        $file = self::$dataFiles[$name] ?? null;

        $patterns = [];

        // 加载内置模式文件
        if ($file !== null && file_exists($file)) {
            $patterns = require $file;
            if (!is_array($patterns)) {
                $patterns = [];
            }
        }

        // 加载用户自定义模式文件（追加到内置规则后面）
        $customFiles = self::$customDataFiles[$name] ?? [];
        foreach ($customFiles as $customFile) {
            if (file_exists($customFile) && is_readable($customFile)) {
                try {
                    $customPatterns = require $customFile;
                    if (is_array($customPatterns) && !empty($customPatterns)) {
                        $patterns = $this->mergePatterns($patterns, $customPatterns);
                    }
                } catch (\Throwable) {
                    // 自定义模式文件加载失败不阻断内置规则加载
                }
            }
        }

        self::$loadedPatterns[$name] = $patterns;

        return $patterns;
    }

    /**
     * 合并自定义模式到内置模式数组
     *
     * 支持类型分组数组和扁平数组两种格式。
     *
     * @param array $builtin 内置模式
     * @param array $custom 自定义模式
     * @return array 合并后的模式数组
     */
    private function mergePatterns(array $builtin, array $custom): array
    {
        if (empty($custom)) {
            return $builtin;
        }

        if (empty($builtin)) {
            return $custom;
        }

        // 检测是否为类型分组数组（第一个元素有 'pattern' 键 → 扁平数组）
        $firstBuiltin = reset($builtin);
        $firstCustom = reset($custom);

        $builtinIsFlat = is_array($firstBuiltin) && isset($firstBuiltin['pattern']);
        $customIsFlat = is_array($firstCustom) && isset($firstCustom['pattern']);

        if ($builtinIsFlat && $customIsFlat) {
            // 两个都是扁平数组，直接合并
            return array_merge($builtin, $custom);
        }

        if (!$builtinIsFlat && !$customIsFlat) {
            // 两个都是类型分组，按类型合并
            foreach ($custom as $type => $typePatterns) {
                if (is_array($typePatterns) && !empty($typePatterns)) {
                    if (isset($builtin[$type])) {
                        $builtin[$type] = array_merge($builtin[$type], $typePatterns);
                    } else {
                        $builtin[$type] = $typePatterns;
                    }
                }
            }
            return $builtin;
        }

        // 格式不一致，将自定义追加到内置
        if ($builtinIsFlat) {
            foreach ($custom as $item) {
                if (is_array($item) && isset($item['pattern'])) {
                    $builtin[] = $item;
                }
            }
        } else {
            // 内置是类型分组，自定义是扁平数组 → 追加到所有类型
            foreach ($builtin as $type => &$typePatterns) {
                foreach ($custom as $item) {
                    if (is_array($item) && isset($item['pattern'])) {
                        $typePatterns[] = $item;
                    }
                }
            }
            unset($typePatterns);
        }

        return $builtin;
    }

    /**
     * 标准化类型名称
     */
    private function normalizeType(string $type): string
    {
        // 保留 xss_* 前缀的类型
        if (str_starts_with($type, 'xss_')) {
            return $type;
        }

        // 保留 custom_* 前缀的类型
        if (str_starts_with($type, 'custom_')) {
            return $type;
        }

        return $type;
    }

    /**
     * 注册自定义模式文件
     *
     * 开发者可通过此方法添加额外的模式文件，追加到内置规则后面。
     * 文件格式需与内置模式文件一致（PHP 文件 return 数组）。
     *
     * @param string $type 模式类型：'high_risk' | 'xss' | 'url_path' | 'database_operation'
     * @param string $filePath 模式文件绝对路径
     */
    public static function registerCustomPattern(string $type, string $filePath): void
    {
        if (file_exists($filePath) && is_readable($filePath)) {
            self::$customDataFiles[$type][] = $filePath;
        }
    }

    /**
     * 批量注册自定义模式文件（从配置）
     *
     * @param array<string, array<string>> $customPatterns 类型 => 文件路径数组
     */
    public static function registerCustomPatternsFromConfig(array $customPatterns): void
    {
        foreach ($customPatterns as $type => $files) {
            if (!is_array($files) || empty($files)) {
                continue;
            }
            foreach ($files as $filePath) {
                if (is_string($filePath) && $filePath !== '') {
                    self::registerCustomPattern($type, $filePath);
                }
            }
        }
    }

    /**
     * 清除已加载的模式缓存（用于测试）
     */
    public static function clearCache(): void
    {
        self::$loadedPatterns = [];
        self::$customDataFiles = [];
        self::$validatedPatterns = [];
        self::$preFilterRequestCache = [];
    }

    /**
     * 获取缓存状态信息（用于调试）
     *
     * @return array
     */
    public function getCacheInfo(): array
    {
        return [
            'loaded_files' => array_keys(self::$loadedPatterns),
            'total_loaded' => count(self::$loadedPatterns),
            'available_files' => array_keys(self::$dataFiles),
            'prefilter_types' => array_keys(self::$preFilters),
        ];
    }
}
