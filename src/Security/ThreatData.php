<?php

namespace zxf\Security;

/**
 * 安全威胁元数据中心
 *
 * 集中管理所有威胁相关的静态数据（描述、风险等级、分类、拦截消息等），
 * 消除 SecurityMiddleware 和 InterceptionContext 中的数据重复。
 *
 * 设计原则：
 *  1. 单一数据源 — 所有威胁元数据在此统一定义
 *  2. 支持用户覆盖 — 风险等级可通过 $overrides 参数自定义
 *  3. 零依赖 — 纯静态方法，无需容器
 *
 * ⚠️ 数据分层说明：
 *  BLOCK_MESSAGES 与 DefaultConfig::RESPONSE_MESSAGES 内容重复但语义不同：
 *  - DefaultConfig::RESPONSE_MESSAGES 是第一层默认值，优先被 BuildsInterceptionResponse 使用
 *  - ThreatData::BLOCK_MESSAGES 是第二层兜底，仅在 DefaultConfig 无匹配时生效
 *  保持两份数据独立可避免单向依赖，但修改时需同步更新两处。
 *
 * @package zxf\Security
 * @since 5.4.0
 * @version 6.2.0
 */
class ThreatData
{
    /**
     * 威胁类型 → 中文描述
     *
     * @var array<string, string>
     */
    public const DESCRIPTIONS = [
        // 高危攻击
        'sql' => '检测到SQL注入攻击，试图通过输入字段操纵数据库查询',
        'command' => '检测到命令注入攻击，试图执行系统命令',
        'path' => '检测到路径遍历攻击，试图访问受限文件系统路径',
        'lfi' => '检测到本地文件包含攻击',
        'rfi' => '检测到远程文件包含攻击',
        'xml' => '检测到XML/XXE外部实体攻击',
        'ldap' => '检测到LDAP注入攻击',
        'nosql' => '检测到NoSQL注入攻击',
        'ssti' => '检测到服务器端模板注入攻击',
        'ssrf' => '检测到服务器端请求伪造(SSRF)攻击',
        'encoding' => '检测到编码绕过攻击',
        'encoding_bypass' => '检测到编码绕过攻击',
        'null_byte' => '检测到空字节注入',
        'header_injection' => '检测到HTTP头注入攻击',
        'redirect' => '检测到开放重定向攻击，试图将用户跳转到恶意站点',
        'file_include' => '检测到文件包含攻击(LFI/RFI)',
        'high_risk_pattern' => '检测到高风险攻击模式',
        'deserialization' => '检测到PHP反序列化攻击，试图注入恶意对象',
        'prototype_pollution' => '检测到JavaScript原型污染攻击',
        'jndi' => '检测到JNDI注入攻击(Log4Shell类漏洞利用)',
        'http_smuggling' => '检测到HTTP请求走私攻击',
        'graphql' => '检测到GraphQL注入/滥用攻击',
        'webshell' => '检测到WebShell上传或执行攻击',

        // XSS攻击
        'xss' => '检测到跨站脚本攻击(XSS)，试图注入恶意脚本',
        'xss_script' => '检测到XSS脚本注入攻击',
        'xss_dom' => '检测到DOM型XSS攻击',
        'xss_tag' => '检测到XSS标签注入攻击',
        'xss_encoding' => '检测到XSS编码绕过攻击',
        'xss_framework' => '检测到框架特定XSS攻击',
        'xss_event' => '检测到事件处理器XSS攻击（onerror/onload等）',

        // IP/访问控制
        'blacklist' => 'IP地址在黑名单中，已被禁止访问',
        'bad_user_agent' => '检测到恶意用户代理(User-Agent)',
        'invalid_headers' => '检测到可疑的HTTP请求头',
        'dangerous_upload' => '检测到危险文件上传',

        // 请求限制
        'rate_limit' => '请求频率超过限制',
        'invalid_method' => '使用了不允许的HTTP方法',
        'url_too_long' => 'URL长度超过限制',
        'body_too_large' => '请求体大小超过限制',
        'url_path_attack' => 'URL路径包含攻击特征',
        'custom_high' => '检测到高危自定义安全威胁',
        'custom_medium' => '检测到中等自定义安全威胁',
        'custom_low' => '检测到低危自定义安全威胁',
        'database_table_destruction' => '检测到数据库表结构破坏操作（DROP TABLE/migrate:fresh等），已被拦截',
        'database_mass_deletion' => '检测到数据库全量数据删除操作（TRUNCATE/无条件DELETE），已被拦截',
        'database_code_level_operation' => '检测到代码级数据库危险操作（Artisan::call危险命令），已被拦截',
    ];

    /**
     * 威胁类型 → 风险等级
     *
     * @var array<string, string>
     */
    public const RISK_LEVELS = [
        // 高危 — 可能导致服务器被接管
        'sql' => 'high',
        'command' => 'high',
        'path' => 'high',
        'xml' => 'high',
        'ssti' => 'high',
        'ssrf' => 'high',
        'blacklist' => 'high',
        'encoding_bypass' => 'high',
        'encoding' => 'high',
        'dangerous_upload' => 'high',
        'header_injection' => 'high',
        'file_include' => 'high',
        'deserialization' => 'high',
        'prototype_pollution' => 'high',
        'jndi' => 'high',
        'http_smuggling' => 'high',
        'webshell' => 'high',

        // 中危 — 可能造成数据泄露或损坏
        'redirect' => 'medium',
        'nosql' => 'medium',
        'xss_script' => 'medium',
        'xss_dom' => 'medium',
        'xss_tag' => 'medium',
        'url_path_attack' => 'medium',
        'bad_user_agent' => 'medium',
        'graphql' => 'medium',

        // 低危 — 可能是误报或低风险行为
        'ldap' => 'low',
        'xss_encoding' => 'low',
        'xss_framework' => 'low',
        'xss_event' => 'low',
        'rate_limit' => 'low',
        'invalid_method' => 'low',
        'url_too_long' => 'low',
        'body_too_large' => 'low',
        'invalid_headers' => 'low',
        'custom_high' => 'high',
        'custom_medium' => 'medium',
        'custom_low' => 'low',
        'database_table_destruction' => 'high',
        'database_mass_deletion' => 'high',
        'database_code_level_operation' => 'high',
    ];

    /**
     * 威胁类型 → 分类
     *
     * @var array<string, string>
     */
    public const CATEGORIES = [
        'sql'             => 'injection',
        'command'         => 'injection',
        'path'            => 'path_attack',
        'lfi'             => 'path_attack',
        'rfi'             => 'path_attack',
        'xss'             => 'client_side',
        'xss_script'      => 'client_side',
        'xss_dom'         => 'client_side',
        'xss_tag'         => 'client_side',
        'xss_encoding'    => 'client_side',
        'xss_framework'   => 'client_side',
        'xss_event'      => 'client_side',
        'xxe'             => 'xml_attack',
        'ldap'            => 'injection',
        'xpath'           => 'injection',
        'nosql'           => 'injection',
        'ssti'            => 'template_attack',
        'ssrf'            => 'ssrf',
        'encoding'        => 'evasion',
        'encoding_bypass' => 'evasion',
        'null_byte'       => 'evasion',
        'header_injection' => 'header_attack',
        'redirect' => 'redirect_attack',
        'file_include' => 'path_attack',
        'high_risk_pattern' => 'pattern_match',
        'blacklist'       => 'access_control',
        'bad_user_agent'  => 'reconnaissance',
        'invalid_headers' => 'reconnaissance',
        'dangerous_upload' => 'upload',
        'rate_limit'      => 'rate_limit',
        'invalid_method'  => 'protocol_violation',
        'url_too_long'    => 'protocol_violation',
        'body_too_large'  => 'protocol_violation',
        'url_path_attack' => 'path_attack',
        'custom_high' => 'custom_rule',
        'custom_medium' => 'custom_rule',
        'custom_low' => 'custom_rule',
        'database_table_destruction' => 'database_operation',
        'database_mass_deletion' => 'database_operation',
        'database_code_level_operation' => 'database_operation',
        'deserialization' => 'injection',
        'prototype_pollution' => 'client_side',
        'jndi' => 'injection',
        'http_smuggling' => 'protocol_attack',
        'graphql' => 'api_abuse',
        'webshell' => 'backdoor',
    ];

    /**
     * 威胁类型 → 中文简短描述（用于拦截上下文）
     *
     * @var array<string, string>
     */
    public const THREAT_NAMES = [
        'sql' => 'SQL注入攻击',
        'command' => '命令注入攻击',
        'path' => '路径遍历攻击',
        'xml' => 'XML/XXE注入攻击',
        'ldap' => 'LDAP注入攻击',
        'nosql' => 'NoSQL注入攻击',
        'ssti' => '服务器端模板注入(SSTI)',
        'blacklist' => '黑名单IP访问',
        'dangerous_upload' => '危险文件上传',
        'encoding_bypass' => '编码绕过攻击',
        'encoding' => '编码绕过攻击',
        'ssrf' => '服务器端请求伪造(SSRF)',
        'xss' => '跨站脚本攻击(XSS)',
        'xss_script' => 'XSS脚本注入',
        'xss_dom' => 'DOM型XSS',
        'xss_tag' => 'XSS标签注入',
        'xss_encoding' => 'XSS编码绕过',
        'xss_framework' => '框架特定XSS',
        'xss_event' => '事件处理器XSS',
        'rate_limit' => '请求频率超限',
        'url_too_long' => 'URL长度超限',
        'body_too_large' => '请求体过大',
        'invalid_method' => '非法HTTP方法',
        'invalid_headers' => '请求头不合法',
        'header_injection' => 'HTTP头注入攻击',
        'bad_user_agent' => '恶意User-Agent',
        'url_path_attack' => 'URL路径攻击',
        'redirect' => '开放重定向攻击',
        'file_include' => '文件包含攻击(LFI/RFI)',
        'custom_high' => '高危自定义安全威胁',
        'custom_medium' => '中等自定义安全威胁',
        'custom_low' => '低危自定义安全威胁',
        'database_table_destruction' => '数据库表结构破坏操作',
        'database_mass_deletion' => '数据库全量数据删除操作',
        'database_code_level_operation' => '代码级数据库危险操作',
        'deserialization' => 'PHP反序列化攻击',
        'prototype_pollution' => '原型污染攻击',
        'jndi' => 'JNDI注入攻击',
        'http_smuggling' => 'HTTP请求走私攻击',
        'graphql' => 'GraphQL注入/滥用',
        'webshell' => 'WebShell攻击',
    ];

    /**
     * 威胁类型 → 拦截提示消息
     *
     * @var array<string, string>
     */
    public const BLOCK_MESSAGES = [
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
        'xss_script' => '检测到脚本注入攻击，请求已被拦截',
        'xss_dom' => '检测到DOM型XSS攻击，请求已被拦截',
        'xss_tag' => '检测到标签注入攻击，请求已被拦截',
        'xss_encoding' => '检测到XSS编码绕过攻击，请求已被拦截',
        'xss_framework' => '检测到框架特定XSS攻击，请求已被拦截',
        'xss_event' => '检测到事件处理器XSS攻击，请求已被拦截',
        'dangerous_upload' => '检测到危险文件上传，请求已被拦截',
        'redirect' => '检测到开放重定向攻击，请求已被拦截',
        'file_include' => '检测到文件包含攻击，请求已被拦截',
        'ssrf' => '检测到SSRF攻击，请求已被拦截',
        'header_injection' => '检测到HTTP头注入攻击，请求已被拦截',
        'unknown' => '请求包含潜在的安全威胁，已被拦截',
        'custom_high' => '检测到高危安全威胁，请求已被拦截',
        'custom_medium' => '检测到中等安全威胁，请求已被拦截',
        'custom_low' => '检测到低危安全威胁，请求已被拦截',
        'database_table_destruction' => '检测到数据库表结构破坏操作，请求已被拦截',
        'database_mass_deletion' => '检测到数据库全量数据删除操作，请求已被拦截',
        'database_code_level_operation' => '检测到代码级数据库危险操作，请求已被拦截',
        'deserialization' => '检测到PHP反序列化攻击，请求已被拦截',
        'prototype_pollution' => '检测到原型污染攻击，请求已被拦截',
        'jndi' => '检测到JNDI注入攻击，请求已被拦截',
        'http_smuggling' => '检测到HTTP请求走私攻击，请求已被拦截',
        'graphql' => '检测到GraphQL注入/滥用，请求已被拦截',
        'webshell' => '检测到WebShell攻击，请求已被拦截',
    ];

    /**
     * 安全响应头
     *
     * @var array<string, string>
     */
    public const RESPONSE_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        // X-XSS-Protection 在主流浏览器中已被弃用，但仍提供对旧浏览器的兼容
        'X-XSS-Protection' => '0',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma' => 'no-cache',
        'X-Permitted-Cross-Domain-Policies' => 'none',
        'Cross-Origin-Resource-Policy' => 'same-origin',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Cross-Origin-Embedder-Policy' => 'require-corp',
    ];

    /**
     * 默认 MIME magic bytes 映射表
     *
     * @var array<string, string|array<string>>
     */
    public const MIME_MAGIC_MAP = [
        // 图片类
        'jpg' => ['image/jpeg', 'image/jpg'],
        'jpeg' => ['image/jpeg', 'image/jpg'],
        'png' => 'image/png',
        'gif' => 'image/gif',
        'webp' => 'image/webp',
        'bmp' => 'image/bmp',

        // 文档类
        'pdf' => 'application/pdf',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls' => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'csv' => ['text/csv', 'text/plain'],
        'txt' => 'text/plain',
        'md' => ['text/markdown', 'text/plain'],

        // 压缩包
        'zip' => ['application/zip', 'application/x-zip-compressed'],
        'rar' => 'application/vnd.rar',
        'gz' => ['application/gzip', 'application/x-gzip'],

        // 音视频
        'mp3' => ['audio/mpeg', 'audio/mp3'],
        'mp4' => 'video/mp4',
    ];

    // ==================== 静态访问方法 ====================

    /**
     * 获取威胁类型的详细描述
     */
    public static function getDescription(string $threatType): string
    {
        return static::DESCRIPTIONS[$threatType] ?? '检测到未知的安全威胁';
    }

    /**
     * 获取威胁类型的简短中文名称
     */
    public static function getName(string $threatType): string
    {
        return static::THREAT_NAMES[$threatType] ?? '安全威胁';
    }

    /**
     * 获取威胁类型的风险等级
     *
     * @param string $threatType 威胁类型
     * @param array<string, string> $overrides 用户自定义覆盖（来自配置）
     * @return string high|medium|low|unknown
     */
    public static function getRiskLevel(string $threatType, array $overrides = []): string
    {
        if (isset($overrides[$threatType])) {
            return $overrides[$threatType];
        }

        return static::RISK_LEVELS[$threatType] ?? 'unknown';
    }

    /**
     * 获取威胁类型的安全分类
     */
    public static function getCategory(string $threatType): string
    {
        return static::CATEGORIES[$threatType] ?? 'unknown';
    }

    /**
     * 获取拦截提示消息
     */
    public static function getBlockMessage(string $threatType, string $default = ''): string
    {
        if (empty($threatType)) {
            return $default;
        }

        return static::BLOCK_MESSAGES[$threatType] ?? $default;
    }

    /**
     * 获取安全响应头
     *
     * @return array<string, string>
     */
    public static function getResponseHeaders(): array
    {
        return static::RESPONSE_HEADERS;
    }

    /**
     * 获取 MIME magic 映射表
     *
     * @return array<string, string|array<string>>
     */
    public static function getMimeMagicMap(): array
    {
        return static::MIME_MAGIC_MAP;
    }

    /**
     * 获取所有已知威胁类型列表
     *
     * @return array<string>
     */
    public static function getKnownThreatTypes(): array
    {
        return array_keys(static::RISK_LEVELS);
    }
}
