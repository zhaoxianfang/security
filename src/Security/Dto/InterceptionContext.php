<?php

namespace zxf\Security\Dto;

/**
 * 拦截上下文数据传输对象
 *
 * 封装拦截时的所有相关信息，传递给回调函数使用。
 * 开发者可通过此对象获取拦截详情，自定义处理逻辑。
 *
 * 跨框架兼容：request 字段声明为 object，支持 Laravel Request 和 ThinkPHP Request。
 *
 * @package zxf\Security\Dto
 * @since 4.0.0
 * @version 6.2.0
 */
readonly class InterceptionContext
{
    /**
     * 创建拦截上下文实例
     *
     * @param object $request HTTP请求对象（Laravel Request 或 ThinkPHP Request）
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
        public object $request,
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
     * 获取威胁类型的中文描述
     *
     * 委托给 ThreatData 单一数据源，避免与中心数据重复。
     *
     * @return string 威胁类型描述
     */
    public function getThreatTypeDescription(): string
    {
        return \zxf\Security\ThreatData::getName($this->threatType);
    }

    /**
     * 获取风险等级
     *
     * 委托给 ThreatData 单一数据源，避免与中心数据重复。
     *
     * @return string high|medium|low|unknown
     */
    public function getRiskLevel(): string
    {
        return \zxf\Security\ThreatData::getRiskLevel($this->threatType);
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
