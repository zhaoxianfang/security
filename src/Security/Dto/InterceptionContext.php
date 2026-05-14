<?php

namespace zxf\Security\Dto;

use Illuminate\Http\Request;

/**
 * 拦截上下文数据传输对象
 *
 * 封装拦截时的所有相关信息，传递给回调函数使用。
 * 开发者可通过此对象获取拦截详情，自定义处理逻辑。
 *
 * @package zxf\Security\Dto
 * @since 4.0.0
 */
readonly class InterceptionContext
{
    /**
     * 创建拦截上下文实例
     *
     * @param Request $request HTTP请求对象
     * @param string $threatType 威胁类型（如：sql, xss, command, blacklist等）
     * @param string $matchedPattern 匹配到的正则模式（如适用）
     * @param string $matchedContent 匹配到的内容片段（脱敏处理）
     * @param string $clientIp 客户端IP地址
     * @param string $method HTTP方法
     * @param string $url 请求URL
     * @param string $request_id 请求唯一id
     * @param array<string> $allThreats 所有检测到的威胁类型数组
     * @param array<string, mixed> $requestData 请求数据摘要（不包含敏感信息）
     * @param \DateTimeImmutable $timestamp 拦截时间戳
     */
    public function __construct(
        public Request $request,
        public string $threatType,
        public \DateTimeImmutable $timestamp,
        public string $matchedPattern = '',
        public string $matchedContent = '',
        public string $clientIp = '',
        public string $method = '',
        public string $url = '',
        public array $allThreats = [],
        public array $requestData = [],
        public string $request_id = '',
    ) {
    }

    /**
     * 威胁类型到描述的映射
     *
     * @var array<string, string>
     */
    protected const THREAT_DESCRIPTIONS = [
        // 高危攻击
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

        // XSS攻击
        'xss' => '跨站脚本攻击(XSS)',
        'xss_script' => 'XSS脚本注入',
        'xss_dom' => 'DOM型XSS',
        'xss_tag' => 'XSS标签注入',
        'xss_encoding' => 'XSS编码绕过',
        'xss_framework' => '框架特定XSS',

        // 请求限制
        'rate_limit' => '请求频率超限',
        'url_too_long' => 'URL长度超限',
        'body_too_large' => '请求体过大',
        'invalid_method' => '非法HTTP方法',
        'invalid_headers' => '请求头不合法',
        'header_injection' => 'HTTP头注入攻击',

        // 其他
        'bad_user_agent' => '恶意User-Agent',
        'url_path_attack' => 'URL路径攻击',
    ];

    /**
     * 威胁类型到风险等级的映射
     *
     * @var array<string, string>
     */
    protected const THREAT_RISK_LEVELS = [
        // 高危
        'sql' => 'high',
        'command' => 'high',
        'path' => 'high',
        'blacklist' => 'high',
        'dangerous_upload' => 'high',
        'encoding_bypass' => 'high',
        'encoding' => 'high',
        'xml' => 'high',
        'ssti' => 'high',
        'ssrf' => 'high',
        'header_injection' => 'high',

        // 中危
        'nosql' => 'medium',
        'xss' => 'medium',
        'xss_script' => 'medium',
        'xss_dom' => 'medium',
        'xss_tag' => 'medium',
        'url_path_attack' => 'medium',
        'bad_user_agent' => 'medium',

        // 低危
        'xss_encoding' => 'low',
        'xss_framework' => 'low',
        'rate_limit' => 'low',
        'url_too_long' => 'low',
        'body_too_large' => 'low',
        'invalid_method' => 'low',
        'invalid_headers' => 'low',
        'ldap' => 'low',
    ];

    /**
     * 获取威胁类型的中文描述
     *
     * @return string 威胁类型描述
     */
    public function getThreatTypeDescription(): string
    {
        return self::THREAT_DESCRIPTIONS[$this->threatType] ?? '安全威胁';
    }

    /**
     * 获取风险等级
     *
     * @return string high|medium|low
     */
    public function getRiskLevel(): string
    {
        return self::THREAT_RISK_LEVELS[$this->threatType] ?? 'unknown';
    }

    /**
     * 获取请求ID
     *
     * @return string
     */
    public function getRequestId(): string
    {
        return $this->request_id;
    }

    /**
     * 转换为数组格式
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'threat_type' => $this->threatType,
            'threat_description' => $this->getThreatTypeDescription(),
            'risk_level' => $this->getRiskLevel(),
            'matched_pattern' => $this->matchedPattern,
            'client_ip' => $this->clientIp,
            'method' => $this->method,
            'url' => $this->url,
            'request_id' => $this->request_id,
            'all_threats' => $this->allThreats,
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
        ];
    }
}
