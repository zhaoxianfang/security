<?php

namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

/**
 * 威胁检测接口
 *
 * 定义威胁检测和防护的核心功能契约
 * 遵循开闭原则（OCP），对扩展开放，对修改关闭
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface ThreatDetectorInterface
{
    /**
     * 检测请求是否包含威胁
     *
     * @param Request $request HTTP请求对象
     * @return array 威胁列表
     */
    public function detectThreats(Request $request): array;

    /**
     * 检查是否有可疑User-Agent
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否可疑
     */
    public function hasSuspiciousUserAgent(Request $request): bool;

    /**
     * 检查是否有可疑HTTP头
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否可疑
     */
    public function hasSuspiciousHeaders(Request $request): bool;

    /**
     * 检查是否有危险文件上传
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否危险
     */
    public function hasDangerousUploads(Request $request): bool;

    /**
     * 检查URL是否安全
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否安全
     */
    public function isSafeUrl(Request $request): bool;

    /**
     * 检查是否为资源文件路径
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否为资源路径
     */
    public function isResourcePath(Request $request): bool;

    /**
     * 添加自定义检测规则
     *
     * @param array $rule 检测规则
     * @return void
     */
    public function addCustomRule(array $rule): void;

    /**
     * 移除自定义检测规则
     *
     * @param string $ruleName 规则名称
     * @return void
     */
    public function removeCustomRule(string $ruleName): void;

    /**
     * 获取所有威胁类型
     *
     * @return array 威胁类型列表
     */
    public function getThreatTypes(): array;

    /**
     * 检测SQL注入
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否包含SQL注入
     */
    public function detectSqlInjection(Request $request): bool;

    /**
     * 检测XSS攻击
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否包含XSS攻击
     */
    public function detectXssAttack(Request $request): bool;

    /**
     * 检测命令注入
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否包含命令注入
     */
    public function detectCommandInjection(Request $request): bool;

    /**
     * 检测路径遍历
     *
     * @param Request $request HTTP请求对象
     * @return bool 是否包含路径遍历
     */
    public function detectPathTraversal(Request $request): bool;

    /**
     * 计算威胁评分
     *
     * @param array $threats 威胁列表
     * @return float 威胁评分（0-100）
     */
    public function calculateThreatScore(array $threats): float;
}
