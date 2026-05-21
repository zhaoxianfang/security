<?php

namespace zxf\Security\Patterns;

/**
 * 安全模式服务 - 延迟加载 + 编译缓存 + 三种场景支持
 *
 * 核心设计理念：
 * 1. 延迟加载 - 模式数据文件仅在首次访问时加载，避免 php artisan optimize 时内存暴涨
 * 2. 内存缓存 - 已加载的模式在进程内缓存，同一请求周期无需重复加载
 * 3. 模式合并 - 内置默认模式 + 用户自定义模式（来自轻量配置）
 * 4. 模式排除 - 支持从内置模式中排除特定正则（精确字符串匹配）
 * 5. 模式替换 - 支持完全使用自定义模式、忽略内置模式
 * 6. 预过滤支持 - 提供快速字符串预检方法，减少不必要的正则匹配
 *
 * 三种使用场景：
 * - 场景1（排除）：使用所有内置规则，但排除特定几条 → excludePatterns + merge 模式
 * - 场景2（追加）：使用所有内置规则，并追加自定义规则 → merge 模式（默认）
 * - 场景3（替换）：完全使用自定义规则，忽略内置规则 → replace 模式
 *
 * @package zxf\Security\Patterns
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
            "' or ", "' and ",
        ],
        'command'          => [
            'system', 'exec', 'passthru', 'shell_exec', 'rm ', 'wget', 'curl',
            'nc ', 'whoami', '|', '`', '$(', 'powershell', 'cmd ', ';id',
        ],
        'path'             => [
            '../', '..\\', '%2e%2e', '%252e', '.env', '.git', 'etc/', 'proc/',
            '.php', '.jsp', '.asp', '.aspx', '.sh', '.py', '.exe', '.dll', '.bat',
            'passwd', '.svn', '.hg', '.bzr', 'htaccess', 'htpasswd', 'web.config',
            'composer', 'package', 'docker', 'wp-', 'phpmyadmin', 'adminer',
            '%c0', '%ef', '%e0', '%00',
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
     * 处理逻辑：
     * 1. 加载内置默认模式
     * 2. 应用排除列表（精确字符串匹配移除）
     * 3. 根据 pattern_mode 决定是合并还是替换
     *
     * @param array $customPatterns 用户自定义模式（来自配置）
     * @param array $excludePatterns 要排除的模式（来自配置），格式：['type' => ['pattern1', ...]]
     * @param string $mode 模式策略：'merge'（合并）或 'replace'（替换）
     * @return array<string, string[]>
     */
    public function getHighRiskPatterns(array $customPatterns = [], array $excludePatterns = [], string $mode = 'merge'): array
    {
        // 加载内置默认模式
        $defaults = $this->loadDataFile('high_risk');

        // 应用排除列表（先从内置模式中移除指定规则）
        if (!empty($excludePatterns)) {
            $defaults = $this->excludePatternsFromDefaults($defaults, $excludePatterns);
        }

        // 根据模式策略处理
        if ($mode === 'replace') {
            // 完全替换模式：仅使用用户自定义模式，忽略内置模式
            return $customPatterns;
        }

        // 合并模式（默认）：内置 + 自定义
        if (empty($customPatterns)) {
            return $defaults;
        }

        return $this->mergePatterns($defaults, $customPatterns);
    }

    /**
     * 获取XSS攻击模式
     *
     * @param array $customPatterns 用户自定义模式（来自配置）
     * @param array $excludePatterns 要排除的模式（来自配置）
     * @param string $mode 模式策略：'merge' 或 'replace'
     * @return array<string, string[]>
     */
    public function getXssPatterns(array $customPatterns = [], array $excludePatterns = [], string $mode = 'merge'): array
    {
        $defaults = $this->loadDataFile('xss');

        if (!empty($excludePatterns)) {
            $defaults = $this->excludePatternsFromDefaults($defaults, $excludePatterns);
        }

        if ($mode === 'replace') {
            return $customPatterns;
        }

        if (empty($customPatterns)) {
            return $defaults;
        }

        return $this->mergePatterns($defaults, $customPatterns);
    }

    /**
     * 获取URL路径攻击模式
     *
     * @param array $customPatterns 用户自定义模式（来自配置）
     * @param array $excludePatterns 要排除的模式（来自配置）
     * @param string $mode 模式策略：'merge' 或 'replace'
     * @return array<string>
     */
    public function getUrlPathPatterns(array $customPatterns = [], array $excludePatterns = [], string $mode = 'merge'): array
    {
        if ($mode === 'replace') {
            return $customPatterns;
        }

        $defaults = $this->loadDataFile('url_path');

        if (!empty($excludePatterns)) {
            $defaults = $this->excludeFlatPatternsFromDefaults($defaults, $excludePatterns);
        }

        if (empty($customPatterns)) {
            return $defaults;
        }

        return array_merge($defaults, $customPatterns);
    }

    /**
     * 获取预过滤关键词
     *
     * 用于在正则匹配前快速判断输入是否可能包含攻击特征。
     * 如果输入不包含任何预过滤关键词，则可以直接跳过该类型的正则检查。
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
     * 合并内置模式与用户自定义模式
     *
     * 合并策略：
     * - 用户自定义的类型：追加到内置模式后
     * - 用户未定义的类型：使用内置模式
     * - 内置没有但用户定义的类型：使用用户定义
     *
     * @param array $defaults 内置默认模式
     * @param array $custom 用户自定义模式
     * @return array<string, string[]>
     */
    private function mergePatterns(array $defaults, array $custom): array
    {
        $merged = $defaults;

        foreach ($custom as $type => $patterns) {
            if (!is_array($patterns)) {
                continue;
            }

            if (isset($merged[$type])) {
                $merged[$type] = array_merge($merged[$type], $patterns);
            } else {
                $merged[$type] = $patterns;
            }
        }

        return $merged;
    }

    /**
     * 从内置默认模式中排除指定规则（分类型正则）
     *
     * 用于 high_risk_patterns 和 xss_patterns 等按类型分组的模式。
     * 排除匹配采用精确字符串比较，只有完全一致的规则才会被移除。
     *
     * @param array $defaults 内置默认模式 ['type' => ['pattern1', 'pattern2', ...]]
     * @param array $exclude 要排除的模式 ['type' => ['pattern1', ...]]
     * @return array
     */
    private function excludePatternsFromDefaults(array $defaults, array $exclude): array
    {
        foreach ($exclude as $type => $patterns) {
            if (!isset($defaults[$type]) || !is_array($patterns)) {
                continue;
            }

            // 构建排除集合（翻转数组为key，O(1)查找）
            $excludeSet = array_flip($patterns);

            // 过滤掉匹配的规则
            $defaults[$type] = array_values(array_filter(
                $defaults[$type],
                fn(string $pattern) => !isset($excludeSet[$pattern])
            ));

            // 如果该类型已无规则，移除空类型
            if (empty($defaults[$type])) {
                unset($defaults[$type]);
            }
        }

        return $defaults;
    }

    /**
     * 从内置默认模式中排除指定规则（扁平数组）
     *
     * 用于 url_path_patterns 等扁平数组格式的模式。
     *
     * @param array $defaults 内置默认模式 ['pattern1', 'pattern2', ...]
     * @param array $exclude 要排除的模式 ['pattern1', ...]
     * @return array
     */
    private function excludeFlatPatternsFromDefaults(array $defaults, array $exclude): array
    {
        if (empty($exclude)) {
            return $defaults;
        }

        $excludeSet = array_flip($exclude);

        return array_values(array_filter(
            $defaults,
            fn(string $pattern) => !isset($excludeSet[$pattern])
        ));
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
