<?php

namespace zxf\Security\Config;

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

            // 文件操作
            '/\b(file_get_contents|fopen|fwrite)\s*\(/i',
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
            // 匹配所有点(.)开头的文件或文件夹
            '~/(\.+[^/]*)(?=/|$)~',

            // 隐藏文件和目录（排除 .well-known）
            '~/(?:\\.(?!well-known)[^/]*)(?=/|$)~i',

            // 配置文件和敏感数据文件
            '/\\.(?:env|config|settings|configuration)(?:\\.\\w+)?$/i',
            '/(?:composer|package)(?:\\.(?:json|lock))?$/i',

            // 源代码和脚本文件
            '/\\.(?:php|phtml|jsp|asp|aspx|pl|py|rb|sh|cgi|cfm|bash|c|cpp|java|cfm|yaml|yml|log)(?:\\.\\w+)?$/i',

            // 数据库和备份文件
            '/\\.(?:sql|db|mdb|accdb|sqlite|bak|old|backup)$/i',

            // 日志和临时文件
            '/\\.(?:log|trace|debug|temp|tmp)$/i',

            // 系统文件
            '/^(readme|license|changelog)\.(md|txt)$/i',

            // 敏感目录路径
            '/(backup|node_modules|temp|vendor|phpmyadmin|\\.git)/i', // 敏感目录
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
            'sh', 'bash', 'csh', 'ksh', 'zsh', 'cgi',

            // 配置文件
            'env', 'config', 'ini', 'conf', 'cfg', 'properties', 'yml', 'yaml',

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

}