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
     * @return array
     */
    public static function getMaliciousBodyPatterns(): array;

    /**
     * 获取非法URL路径模式
     *
     * @return array
     */
    public static function getIllegalUrlPatterns(): array;

    /**
     * 获取可疑User-Agent模式
     *
     * @return array
     */
    public static function getSuspiciousUserAgents(): array;

    /**
     * 获取禁止上传的文件扩展名
     *
     * @return array
     */
    public static function getDisallowedExtensions(): array;
}