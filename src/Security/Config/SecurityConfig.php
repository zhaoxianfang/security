<?php

namespace zxf\Security\Config;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use zxf\Security\Contracts\SecurityConfigInterface;

/**
 * 安全配置管理类
 *
 * 提供动态配置获取方法，支持从数据库、缓存等多种源获取配置
 * 所有方法都是静态方法，便于在配置文件中调用
 */
class SecurityConfig implements SecurityConfigInterface
{
    /**
     * 获取IP白名单列表
     *
     * 支持从多种源获取白名单IP：
     * 1. 环境变量
     * 2. 数据库
     * 3. 配置文件
     * 4. 缓存
     *
     * @return array IP白名单数组
     */
    public static function getWhitelistIps(): array
    {
        // 首先检查环境变量
        $envIps = env('SECURITY_IP_WHITELIST', '');
        if (!empty($envIps)) {
            return array_filter(explode(',', $envIps));
        }

        // 尝试从数据库获取（如果表存在）
        try {
            if (self::hasDatabaseConnection() && self::hasTable('security_whitelist_ips')) {
                return Cache::remember('security:whitelist_ips', 300, function () {
                    return DB::table('security_whitelist_ips')
                        ->where('is_active', true)
                        ->pluck('ip_address')
                        ->toArray();
                });
            }
        } catch (\Exception $e) {
            // 数据库操作失败，使用默认值
        }

        // 返回默认值
        return ['127.0.0.1', '::1', 'localhost'];
    }

    /**
     * 获取IP黑名单列表
     *
     * 支持从多种源获取黑名单IP：
     * 1. 环境变量
     * 2. 数据库
     * 3. 配置文件
     * 4. 缓存
     *
     * @return array IP黑名单数组
     */
    public static function getBlacklistIps(): array
    {
        // 首先检查环境变量
        $envIps = env('SECURITY_IP_BLACKLIST', '');
        if (!empty($envIps)) {
            return array_filter(explode(',', $envIps));
        }

        // 尝试从数据库获取（如果表存在）
        try {
            if (self::hasDatabaseConnection() && self::hasTable('security_blacklist_ips')) {
                return Cache::remember('security:blacklist_ips', 300, function () {
                    return DB::table('security_blacklist_ips')
                        ->where('is_active', true)
                        ->pluck('ip_address')
                        ->toArray();
                });
            }
        } catch (\Exception $e) {
            // 数据库操作失败，使用默认值
        }

        // 返回默认值
        return [];
    }

    /**
     * 获取恶意请求体检测模式
     *
     * @return array 正则表达式模式数组
     */
    public static function getMaliciousBodyPatterns(): array
    {
        return [
            // XSS攻击检测 - 优化分组
            '/(?:<script[^>]*>.*?<\/script>|javascript:\\s*|on\\w+\\s*=\\s*["\']?)/is',

            // SQL注入检测 - 关键操作符和函数
            '/(?:\\b(?:union\\s+select|select\\s+[\\w*]+\\s+from|insert\\s+into|update\\s+\\w+\\s+set|drop\\s+table|exec\\s*\\(|xp_cmdshell)\\b|--\\s|\\/\\*[\\s\\S]*?\\*\\/)/is',

            // 命令注入检测 - 系统命令和特殊字符
            '/(?:\\b(?:system|exec|shell_exec|passthru)\\s*\\(|`[^`]*`|\\$\\s*\\(|\\|\\s*\\w+|&\\s*\\w+)/i',

            // 目录遍历和文件包含
            '/(?:\\.\\.\\/|\\.\\.\\\\|\\/etc\\/passwd|\\/etc\\/shadow|\\/winnt\\/system32)/i',

            // PHP代码执行和危险函数
            '/(?:<\\?php|\\b(?:eval|assert|create_function)\\s*\\(|\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\\b(?:include|require)(?:_once)?\\s*\\()/i',

            // 反序列化攻击特征
            '/(?:O:\\d+:"[^"]*":\\d+:|__destruct|__wakeup|__toString)/i',

            // XXE攻击特征
            '/(?:<!ENTITY|<!DOCTYPE[^>]*SYSTEM|SYSTEM\\s+["\'])/i',

            // 表达式注入
            '/(?:\\$\\{.*\\}|\\(\\{.*\\}\\)|\\{\\{.*\\}\\})/',

            // 新的威胁模式可以在这里添加
        ];
    }

    /**
     * 获取非法URL路径模式
     *
     * @return array 正则表达式模式数组
     */
    public static function getIllegalUrlPatterns(): array
    {
        return [
            // 隐藏文件和目录（排除 .well-known）
            '~/(?:\\.(?!well-known)[^/]*)(?=/|$)~i',

            // 配置文件和敏感数据文件
            '/\\.(?:env|config|settings|configuration)(?:\\.\\w+)?$/i',
            '/(?:composer|package)(?:\\.(?:json|lock))?$/i',

            // 源代码和脚本文件
            '/\\.(?:php|phtml|jsp|asp|aspx|pl|py|rb|sh)(?:\\.\\w+)?$/i',

            // 数据库和备份文件
            '/\\.(?:sql|db|mdb|accdb|sqlite|bak|old|backup)$/i',

            // 日志和临时文件
            '/\\.(?:log|trace|debug|temp|tmp)$/i',

            // 敏感目录路径
            '/(?:^|\\/)(?:config|setup|install|backup|logs?|temp|node_modules|\\.git)(?:$|\\/)/i',
        ];
    }

    /**
     * 获取可疑User-Agent模式
     *
     * @return array 正则表达式模式数组
     */
    public static function getSuspiciousUserAgents(): array
    {
        return [
            // 安全扫描工具和渗透测试工具
            '/\\b(?:sqlmap|nikto|metasploit|nessus|wpscan|acunetix|burp|dirbuster|nmap|netsparker)\\b/i',

            // 自动化工具和爬虫框架
            '/\\b(?:curl|wget|python-urllib|java|httpclient|guzzle|scrapy|selenium)\\b/i',

            // 恶意软件和攻击工具
            '/\\b(?:masscan|zmeu|blackwidow|hydra|havij|zap|arachni)\\b/i',
        ];
    }

    /**
     * 获取白名单User-Agent模式
     *
     * @return array 正则表达式模式数组
     */
    public static function getWhitelistUserAgents(): array
    {
        return [
            '/googlebot/i',
            '/bingbot/i',
            '/slurp/i',
            '/duckduckbot/i',
            '/baiduspider/i',
            '/yandexbot/i',
            '/facebookexternalhit/i',
            '/twitterbot/i',
            '/applebot/i',
        ];
    }

    /**
     * 获取禁止上传的文件扩展名
     *
     * @return array 文件扩展名数组
     */
    public static function getDisallowedExtensions(): array
    {
        return [
            // 可执行文件
            'exe', 'bat', 'cmd', 'com', 'msi', 'dll', 'so', 'bin', 'run', 'app', 'apk',

            // 脚本文件
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar',
            'jsp', 'jspx', 'asp', 'aspx', 'pl', 'py', 'rb', 'sh', 'bash',
            'js', 'html', 'htm', 'xhtml',

            // 配置文件
            'env', 'config', 'ini', 'conf', 'cfg', 'properties',

            // 数据库文件
            'sql', 'db', 'mdb', 'accdb', 'sqlite',

            // 其他危险文件
            'swf', 'jar', 'war', 'reg', 'vbs', 'wsf', 'ps1',
        ];
    }

    /**
     * 获取禁止上传的MIME类型
     *
     * @return array MIME类型数组
     */
    public static function getDisallowedMimeTypes(): array
    {
        return [
            'application/x-php',
            'text/x-php',
            'application/x-httpd-php',
            'application/x-jsp',
            'application/x-asp',
            'application/x-sh',
            'application/x-bat',
            'application/x-msdownload',
            'application/x-dosexec',
        ];
    }

    /**
     * 检查数据库连接是否可用
     *
     * @return bool 是否可用
     */
    private static function hasDatabaseConnection(): bool
    {
        try {
            DB::connection()->getPdo();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * 检查表是否存在
     *
     * @param string $tableName 表名
     * @return bool 是否存在
     */
    private static function hasTable(string $tableName): bool
    {
        try {
            return DB::getSchemaBuilder()->hasTable($tableName);
        } catch (\Exception $e) {
            return false;
        }
    }
}