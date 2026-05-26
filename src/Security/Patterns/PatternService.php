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
        'high_risk' => __DIR__ . '/data/high_risk_patterns.php',
        'xss'       => __DIR__ . '/data/xss_patterns.php',
        'url_path'  => __DIR__ . '/data/url_path_patterns.php',
    ];

    /**
     * 快速预过滤关键词映射
     * 用于通过 str_contains 快速跳过不可能匹配的输入
     *
     * @var array<string, array<string>>
     */
    private static array $preFilters = [
        'sql'              => [
            'select', 'union', 'sleep', 'benchmark', 'load_file', 'drop', 'truncate',
            'xp_', 'sp_oa', '%27', '1=1', 'extractvalue', 'updatexml', 'floor(rand',
            '@@', 'database(', 'user(', 'system_user', 'current_user', 'group_concat',
            'concat_ws', 'waitfor', 'unhex', 'charset', '/*', '/**/', '%df', '%bf',
            "' or ", "' and ", 'case when', 'if(',
        ],
        'command'          => [
            'system', 'exec', 'passthru', 'shell_exec', 'proc_open', 'popen', 'pcntl_exec',
            'rm ', 'wget', 'curl', 'nc ', 'netcat', 'whoami', '|', '`', '$(',
            'powershell', 'cmd ', ';id', 'bash', 'sh ', 'python', 'perl', 'php ', 'ruby', 'lua', 'node',
        ],
        'path'             => [
            '../', '..\\', '%2e%2e', '%252e', '.env', '.git', 'etc/', 'proc/',
            '.php', '.jsp', '.asp', '.aspx', '.sh', '.py', '.exe', '.dll', '.bat',
            'passwd', '.svn', '.hg', '.bzr', 'htaccess', 'htpasswd', 'web.config',
            'composer', 'package', 'docker', 'wp-', 'phpmyadmin', 'adminer',
            '%c0', '%ef', '%e0', '%00', 'windows', 'system32',
        ],
        'ldap'             => [')(', '|(', '&(', '*(', '(|', '(&'],
        'xml'              => ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'PUBLIC'],
        'nosql'            => ['$eq', '$ne', '$gt', '$lt', '$gte', '$lte', '$where', '$regex', '$exists', '$type', '$or', '$and', '$mod', '$size', '$all', '$in', '$nin'],
        'ssti'             => ['{{', '}}', '{%', '%}', 'eval(', 'exec('],
        'ssrf'             => [
            '127.0.0.1', '169.254', 'gopher', 'metadata', 'nip.io', '//', 'redirect_uri',
            'callback', 'latest/', 'instance-', 'rebind', 'dnsrebind', 'port=',
        ],
        'encoding'         => ['%25', '%00', '%c0', '%e0', '&#x', '&#', '%u', '%0', '%1', '%2', '%3', '%4', '%5', '%6', '%7', '%8', '%9', '%a', '%b', '%c', '%d', '%e', '%f'],
        'header_injection' => ['%0d', '%0a', '\r\n', 'content-type:', 'set-cookie:', 'location:', 'transfer-encoding:'],
        'redirect'         => [
            'redirect_uri', 'redirect=', 'redirect:', 'callback', 'return_url', '//', 'goto=',
            'url=', 'target=', 'link=', 'next=', 'dest=', 'return=', 'forward=',
        ],
        'file_include'     => [
            'include(', 'require(', 'php://', 'file_get_contents', '/proc/self/',
            'data://', 'expect://', 'readfile', 'fopen', 'show_source',
        ],
        'xss_script'       => ['<script', 'javascript:', 'eval('],
        'xss_dom'          => ['onerror', 'onload', 'onclick', 'onfocus', 'onmouse', 'innerHTML', 'outerHTML'],
        'xss_tag'          => ['<iframe', '<object', '<embed', '<svg', '<img', '<input'],
        'xss_encoding'     => ['\\u', '&#x', 'base64,', 'data:'],
        'xss_framework'    => ['jQuery.fn', 'constructor', 'prototype', 'v-html'],
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
     * 追加规则不区分类型，统一追加到所有类型中作为通配检测。
     * 实际检测时，intercept_rules 作为独立类型 '_custom_high' / '_custom_medium' / '_custom_low' 处理。
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

            $typeKey = '_custom_' . $risk;
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
     * 获取预过滤关键词
     *
     * @param string $type 模式类型
     * @return array<string>
     */
    public function getPreFilterKeywords(string $type): array
    {
        $type = $this->normalizeType($type);

        return self::$preFilters[$type] ?? [];
    }

    /**
     * 快速预过滤检查
     *
     * 检查输入字符串是否包含指定类型的关键词特征。
     * 返回 false 表示可以安全跳过该类型的正则检查。
     *
     * @param string $type 模式类型
     * @param string $input 输入字符串
     * @return bool true=可能包含特征需进一步检查，false=安全跳过
     */
    public function preFilter(string $type, string $input): bool
    {
        $keywords = $this->getPreFilterKeywords($type);

        if (empty($keywords)) {
            return true; // 无预过滤规则，必须检查
        }

        $lowerInput = strtolower($input);

        foreach ($keywords as $keyword) {
            if (str_contains($lowerInput, $keyword)) {
                return true;
            }
        }

        return false;
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

        if ($file === null || !file_exists($file)) {
            self::$loadedPatterns[$name] = [];
            return [];
        }

        // 从独立数据文件加载（不会触发 config 缓存）
        $patterns = require $file;

        if (!is_array($patterns)) {
            $patterns = [];
        }

        self::$loadedPatterns[$name] = $patterns;

        return $patterns;
    }

    /**
     * 标准化类型名称
     */
    private function normalizeType(string $type): string
    {
        // 处理 xss_* 前缀的类型
        if (str_starts_with($type, 'xss_')) {
            return $type;
        }

        // 处理自定义规则类型
        if (str_starts_with($type, '_custom_')) {
            return $type;
        }

        return $type;
    }

    /**
     * 清除已加载的模式缓存（用于测试）
     */
    public static function clearCache(): void
    {
        self::$loadedPatterns = [];
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
