<?php

namespace zxf\Security\Constants;

/**
 * SecurityEvent
 * 安全事件名称和类型对照
 */
class SecurityEvent
{
    const WHITELIST = 'Whitelist';
    const BLACKLIST = 'Blacklist';
    const METHOD_CHECK = 'MethodCheck';
    const SUSPICIOUS_METHOD = 'SuspiciousMethod';
    const EMPTY_USER_AGENT = 'EmptyUserAgent';
    const USER_AGENT_TOO_LONG = 'UserAgentTooLong';
    const SUSPICIOUS_USER_AGENT = 'SuspiciousUserAgent';
    const TOO_MANY_HEADERS = 'TooManyHeaders';
    const SUSPICIOUS_HEADERS = 'SuspiciousHeaders';
    const URL_TOO_LONG = 'UrlTooLong';
    const ILLEGAL_URL = 'IllegalUrl';
    const DANGEROUS_UPLOAD = 'DangerousUpload';
    const MALICIOUS_REQUEST = 'MaliciousRequest';
    const ANOMALOUS_PARAMETERS = 'AnomalousParameters';
    const RATE_LIMIT = 'RateLimit';
    const SQL_INJECTION = 'SqlInjection';
    const XSS_ATTACK = 'XSSAttack';
    const COMMAND_INJECTION = 'CommandInjection';
    const CUSTOM_RULE = 'CustomRule';
    const ERROR = 'SecurityError';

    /**
     * @var array 自定义事件名称和类型对照
     */
    public static array $eventNameMap = [
        self::WHITELIST => 'IP白名单',
        self::BLACKLIST => 'IP黑名单拦截',
        self::METHOD_CHECK => '不允许的请求方法',
        self::SUSPICIOUS_METHOD => '可疑的请求方法',
        self::EMPTY_USER_AGENT => '请求的User-Agent为空',
        self::USER_AGENT_TOO_LONG => 'User-Agent过长',
        self::SUSPICIOUS_USER_AGENT => '可疑的User-Agent',
        self::TOO_MANY_HEADERS => '请求头过多',
        self::SUSPICIOUS_HEADERS => '可疑的请求头',
        self::URL_TOO_LONG => 'URL过长',
        self::ILLEGAL_URL => '非法的URL',
        self::DANGEROUS_UPLOAD => '危险的文件上传',
        self::MALICIOUS_REQUEST => '检测到恶意的请求内容',
        self::ANOMALOUS_PARAMETERS => '异常的请求参数',
        self::RATE_LIMIT => '请求频率过高',
        self::SQL_INJECTION => 'SQL注入拦截',
        self::XSS_ATTACK => 'XSS攻击',
        self::COMMAND_INJECTION => '命令注入',
        self::CUSTOM_RULE => '自定义规则拦截',
        self::ERROR => '安全拦截异常',
    ];

    /**
     * 获取事件名称
     *
     * @param string $eventType 事件类型
     * @param string $default   默认事件名称
     *
     * @return string
     */
    public static function getEventName(string $eventType, string $default = '自定义规则拦截'): string
    {
        return self::$eventNameMap[$eventType] ?? $default;
    }
}