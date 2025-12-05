<?php

namespace zxf\Security\Contracts;

/**
 * 安全配置接口
 *
 * 定义安全配置类必须实现的方法
 * 便于扩展和自定义配置源
 */
interface SecurityConfigInterface
{
    /**
     * 获取恶意请求体检测模式
     *
     * 返回用于检测恶意请求内容的正则表达式数组
     * 应覆盖各种攻击类型：SQL注入、XSS、命令注入等
     *
     * @return array 正则表达式模式数组
     */
    public static function getMaliciousBodyPatterns(): array;

    /**
     * 获取非法URL路径模式
     *
     * 返回用于检测非法URL路径的正则表达式数组
     * 应覆盖敏感文件、配置目录、开发文件等
     *
     * @return array URL检测正则表达式数组
     */
    public static function getIllegalUrlPatterns(): array;

    /**
     * 获取可疑User-Agent模式
     *
     * 返回用于检测可疑User-Agent的正则表达式数组
     * 应覆盖安全扫描工具、恶意软件、自动化工具等
     *
     * @return array User-Agent检测正则表达式数组
     */
    public static function getSuspiciousUserAgents(): array;

    /**
     * 获取白名单User-Agent模式
     *
     * 返回合法的搜索引擎和爬虫User-Agent正则表达式数组
     * 应确保正常业务不受影响
     *
     * @return array 白名单User-Agent正则表达式数组
     */
    public static function getWhitelistUserAgents(): array;

    /**
     * 获取禁止上传的文件扩展名
     *
     * 返回禁止上传的文件扩展名数组
     * 应覆盖可执行文件、脚本文件、配置文件等危险类型
     *
     * @return array 禁止的文件扩展名数组
     */
    public static function getDisallowedExtensions(): array;

    /**
     * 获取禁止上传的MIME类型
     *
     * 返回禁止上传的MIME类型数组
     * 基于MIME类型真实分析，防止扩展名欺骗
     *
     * @return array 禁止的MIME类型数组
     */
    public static function getDisallowedMimeTypes(): array;

    /**
     * 获取SQL注入检测模式（可选）
     *
     * 返回专门针对SQL注入攻击的检测模式
     * 如果未实现，应返回空数组
     *
     * @return array SQL注入检测正则表达式数组
     */
    public static function getSQLInjectionPatterns(): array;

    /**
     * 获取XSS攻击检测模式（可选）
     *
     * 返回专门针对XSS攻击的检测模式
     * 如果未实现，应返回空数组
     *
     * @return array XSS攻击检测正则表达式数组
     */
    public static function getXSSAttackPatterns(): array;

    /**
     * 获取命令注入检测模式（可选）
     *
     * 返回专门针对命令注入攻击的检测模式
     * 如果未实现，应返回空数组
     *
     * @return array 命令注入检测正则表达式数组
     */
    public static function getCommandInjectionPatterns(): array;

    /**
     * 获取事件类型禁用时长（可选）
     *
     * 返回事件类型禁用时长的数组
     *
     * @return array 事件类型禁用时长数组
     */
    public static function getEventTypeBanDuration(): array;

    /**
     * 获取配置版本信息（可选）
     *
     * 返回配置的版本信息，用于兼容性检查
     *
     * @return array 版本信息数组
     */
    public static function getVersionInfo(): array;

    /**
     * 验证配置完整性（可选）
     *
     * 验证配置的完整性和正确性
     *
     * @return bool 配置是否完整有效
     */
    public static function validate(): bool;
}
