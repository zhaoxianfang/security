<?php

namespace zxf\Security\Config;

use zxf\Security\Services\ConfigResolver;

/**
 * 安全配置默认值
 *
 * 集中管理所有内置默认配置，减少配置文件 security.php 的代码量。
 * 开发者可在配置文件中重新定义同名配置项来覆盖默认值。
 *
 * 设计原则：
 *  1. 单一数据源 — 所有默认值在此统一定义
 *  2. 可覆盖 — 配置文件中同名项优先级更高
 *  3. 零依赖 — 纯静态方法，无需容器（仅 ConfigResolver 用于解析callable）
 *
 * @package zxf\Security\Config
 * @since 6.0.0
 * @version 6.2.0
 */
class DefaultConfig
{
    /**
     * 默认拦截提示消息
     *
     * @var array<string, string>
     */
    public const RESPONSE_MESSAGES = [
        'blacklist' => '您的IP地址已被列入黑名单，禁止访问',
        'whitelist' => 'IP白名单检查通过',
        'rate_limit' => '请求过于频繁，请稍后再试',
        'body_too_large' => '请求体过大，超过服务器限制',
        'url_too_long' => '请求URL过长',
        'invalid_method' => '不支持的HTTP请求方法',
        'bad_user_agent' => '检测到恶意User-Agent',
        'invalid_headers' => '请求头信息不合法',
        'url_path_attack' => 'URL路径包含非法内容',
        'encoding_bypass' => '请求包含编码绕过特征',
        'sql' => '检测到SQL注入攻击，请求已被拦截',
        'command' => '检测到命令注入攻击，请求已被拦截',
        'path' => '检测到路径遍历攻击，请求已被拦截',
        'ldap' => '检测到LDAP注入攻击，请求已被拦截',
        'xml' => '检测到XML注入攻击，请求已被拦截',
        'nosql' => '检测到NoSQL注入攻击，请求已被拦截',
        'ssti' => '检测到模板注入攻击，请求已被拦截',
        'encoding' => '检测到编码绕过攻击，请求已被拦截',
        'redirect' => '检测到开放重定向攻击，请求已被拦截',
        'file_include' => '检测到文件包含攻击，请求已被拦截',
        'xss_script' => '检测到脚本注入攻击，请求已被拦截',
        'xss_dom' => '检测到DOM型XSS攻击，请求已被拦截',
        'xss_tag' => '检测到标签注入攻击，请求已被拦截',
        'xss_encoding' => '检测到XSS编码绕过攻击，请求已被拦截',
        'xss_framework' => '检测到框架特定XSS攻击，请求已被拦截',
        'xss_event' => '检测到事件处理器XSS攻击，请求已被拦截',
        'dangerous_upload' => '检测到危险文件上传，请求已被拦截',
        'unknown' => '请求包含潜在的安全威胁，已被拦截',
        'custom_high' => '检测到高危安全威胁，请求已被拦截',
        'custom_medium' => '检测到中等安全威胁，请求已被拦截',
        'custom_low' => '检测到低危安全威胁，请求已被拦截',
        'database_table_destruction' => '检测到数据库表结构破坏操作，请求已被拦截',
        'database_mass_deletion' => '检测到数据库全量数据删除操作，请求已被拦截',
        'database_code_level_operation' => '检测到代码级数据库危险操作，请求已被拦截',
    ];

    /**
     * 默认允许上传的文件扩展名
     *
     * @var array<string>
     */
    public const UPLOAD_ALLOWED_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'rtf', 'csv', 'md',
        'zip', 'rar', '7z', 'tar', 'gz',
        'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv',
    ];

    /**
     * 默认禁止上传的文件扩展名
     *
     * @var array<string>
     */
    public const UPLOAD_BLOCKED_EXTENSIONS = [
        // Web脚本
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
        'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd',
        'cfm', 'cfml', 'cfc', 'dbm',
        'pl', 'pm', 'cgi',
        'py', 'pyc', 'pyo',
        'rb', 'rhtml',
        // Shell/脚本
        'sh', 'bash', 'zsh', 'csh', 'tcsh',
        'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
        // 可执行文件
        'exe', 'dll', 'bin', 'so', 'dylib', 'msi', 'com', 'scr',
        // 配置/数据
        'htaccess', 'htpasswd', 'config', 'ini', 'log',
        'sql', 'sqlite', 'sqlite3', 'mdb', 'accdb',
        'xml', 'yaml', 'yml', 'toml',
    ];

    /**
     * 默认User-Agent黑名单
     *
     * 支持格式：
     *   - 字符串：不区分大小写的部分匹配（如 'sqlmap'）
     *   - 正则表达式（以 / 开头）：精确匹配（如 '/python-requests\\//i'）
     *   - 闭包函数：自定义匹配逻辑
     *
     * 注意：通过 str_contains 做字符串部分匹配时，过于通用的词（如 'curl'、'wget'、'python'）
     * 不建议使用，因为它们会误报正常的 HTTP 请求。如需匹配，请使用正则精确格式。
     *
     * @var array<mixed>
     */
    public const USER_AGENT_BLACKLIST = [
        'sqlmap',        // SQLMap 注入工具
        'nmap',          // Nmap 扫描器
        'nikto',         // Nikto Web扫描器
        'dirbuster',     // DirBuster 目录扫描
        'burp',          // Burp Suite 安全测试
        'wpscan',        // WPScan WordPress扫描
        'acunetix',      // Acunetix 漏洞扫描器
        'nessus',        // Nessus 漏洞扫描器
        'openvas',       // OpenVAS 漏洞扫描器
        'zgrab',         // ZGrab 扫描器
        'masscan',       // Masscan 端口扫描
        'censys',        // Censys 搜索引擎
        'shodan',        // Shodan 搜索引擎
    ];

    /**
     * 默认允许的HTTP方法
     *
     * @var array<string>
     */
    public const ALLOWED_HTTP_METHODS = [
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
    ];

    /**
     * 默认Markdown语法识别正则
     *
     * @var array<string>
     */
    public const MARKDOWN_SYNTAX_PATTERNS = [
        '/^#{1,6}\s+/m',          // 标题
        '/^[-*+]\s+/m',           // 无序列表
        '/\[.+?\]\(.+?\)/',        // 链接
        '/^\s*>\s+/m',            // 引用块
        '/^\s*\|\s*[-:]+\s*\|/m', // 表格
        '/!\[.*?\]\(.*?\)/',      // 图片
        '/\*\*.*?\*\*/',          // 粗体
        '/\*[^*]+\*/',            // 斜体
        '/^---\s*$/m',            // 水平线 / frontmatter
        '/^- \[[ x]\] /m',        // 任务列表
        '/\[\^.+?\]:?/m',         // 脚注
        '/\~\~.*?\~\~/',          // 删除线
        '/^`{3,}\s*\w*/m',        // 代码块开始
        '/<!--[\s\S]*?-->/',      // HTML 注释
        '/^\d+\.\s+/m',           // 有序列表
        '/^:{1,3}\s+\S/m',        // 定义列表
    ];

    /**
     * 默认编码检测可疑模式
     *
     * @var array<string>
     */
    public const ENCODING_SUSPICIOUS_PATTERNS = [
        '../', '..\\', '<script', 'javascript:',
        'onerror=', 'onload=', 'onfocus=',
    ];

    /**
     * 获取配置项，优先使用用户配置，回退到默认值
     *
     * @param array $config 用户完整配置数组
     * @param string $key 配置键名（支持点号分隔）
     * @param mixed $default 最终兜底默认值
     * @return mixed
     */
    public static function get(array $config, string $key, mixed $default = null): mixed
    {
        $keys = explode('.', $key);
        $value = $config;

        foreach ($keys as $k) {
            if (!is_array($value) || !array_key_exists($k, $value)) {
                return $default;
            }
            $value = $value[$k];
        }

        return $value;
    }

    /**
     * 获取响应消息，支持用户覆盖
     *
     * @param array $userConfig 用户配置
     * @return array<string, string>
     */
    public static function getResponseMessages(array $userConfig): array
    {
        $userMessages = self::get($userConfig, 'response.messages', []);

        return array_merge(self::RESPONSE_MESSAGES, $userMessages);
    }

    /**
     * 获取允许上传的扩展名，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<string>
     */
    public static function getAllowedExtensions(array $userConfig): array
    {
        $userList = self::get($userConfig, 'upload.allowed_extensions');

        if ($userList === null) {
            return self::UPLOAD_ALLOWED_EXTENSIONS;
        }

        return ConfigResolver::resolve($userList);
    }

    /**
     * 获取禁止上传的扩展名，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<string>
     */
    public static function getBlockedExtensions(array $userConfig): array
    {
        $userList = self::get($userConfig, 'upload.blocked_extensions');

        if ($userList === null) {
            return self::UPLOAD_BLOCKED_EXTENSIONS;
        }

        return ConfigResolver::resolve($userList);
    }

    /**
     * 获取User-Agent黑名单，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<mixed>
     */
    public static function getUserAgentBlacklist(array $userConfig): array
    {
        $userList = self::get($userConfig, 'user_agent_blacklist');

        if ($userList === null) {
            return self::USER_AGENT_BLACKLIST;
        }

        return ConfigResolver::resolve($userList);
    }

    /**
     * 获取Markdown语法识别正则，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<string>
     */
    public static function getMarkdownSyntaxPatterns(array $userConfig): array
    {
        $userList = self::get($userConfig, 'markdown.syntax_patterns');

        if ($userList === null) {
            return self::MARKDOWN_SYNTAX_PATTERNS;
        }

        return ConfigResolver::resolve($userList);
    }

    /**
     * 获取允许的HTTP方法，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<string>
     */
    public static function getAllowedHttpMethods(array $userConfig): array
    {
        $userList = self::get($userConfig, 'allowed_http_methods');

        if ($userList === null) {
            return self::ALLOWED_HTTP_METHODS;
        }

        return ConfigResolver::resolve($userList);
    }

    /**
     * 获取编码检测可疑模式，支持用户覆盖和callable配置
     *
     * @param array $userConfig 用户配置
     * @return array<string>
     */
    public static function getEncodingSuspiciousPatterns(array $userConfig): array
    {
        $userList = self::get($userConfig, 'encoding_detection.suspicious_patterns');

        if ($userList === null) {
            return self::ENCODING_SUSPICIOUS_PATTERNS;
        }

        return ConfigResolver::resolve($userList);
    }
}
