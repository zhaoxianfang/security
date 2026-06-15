<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;

/**
 * 文件上传安全检查
 *
 * 检查维度：
 *  1. 文件扩展名黑名单（可执行脚本/WebShell)
 *  2. 文件大小限制
 *  3. MIME magic bytes 深度验证（防止扩展名伪装）
 *
 * 跨框架兼容：通过 FrameworkBridge::requestAllFiles() 统一获取上传文件，
 * 支持 Laravel 11+ 和 ThinkPHP 8+。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - $this->config[][]: mixed              — 安全配置数组
 *   - $this->lastMatchedPattern: string     — 最后匹配的正则模式
 *   - $this->lastMatchedContent: string     — 最后匹配的内容片段
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.1.0
 * @version 6.2.0
 */
trait HandlesFileUploads
{
    /**
     * 检查文件上传是否包含危险文件
     *
     * @param object $request HTTP请求对象（跨框架兼容）
     * @return bool true=包含危险文件，false=文件安全或没有上传
     */
    protected function hasDangerousUpload(object $request): bool
    {
        $upload = $this->config['upload'] ?? [];

        $files = FrameworkBridge::requestAllFiles($request);

        if (empty($files)) {
            return false;
        }

        $blockedExtensions = \zxf\Security\Config\DefaultConfig::getBlockedExtensions($this->config);
        $maxSize = $upload['max_size'] ?? 10 * 1024 * 1024;
        $checkMimeMagic = $upload['check_mime_magic'] ?? false;

        foreach ($files as $file) {
            $fileList = is_array($file) ? $file : [$file];

            foreach ($fileList as $singleFile) {
                // 防御：跳过非对象项（极端情况下可能混入原生数组或其他类型）
                if (!is_object($singleFile)) {
                    continue;
                }

                // 1. 扩展名检查
                $extension = FrameworkBridge::fileGetClientOriginalExtension($singleFile);
                if (in_array($extension, $blockedExtensions, true)) {
                    return true;
                }

                // 2. 文件大小检查
                if (FrameworkBridge::fileGetSize($singleFile) > $maxSize) {
                    return true;
                }

                // 3. MIME magic bytes 深度验证（防止扩展名伪装）
                if ($checkMimeMagic && FrameworkBridge::fileIsValid($singleFile)) {
                    if ($this->detectMimeTypeMismatch($singleFile)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 检测文件MIME类型与实际内容不匹配（Magic Bytes检测）
     *
     * 通过读取文件头部魔数字节，验证文件扩展名是否与真实内容一致。
     * 防止攻击者将 .php 文件改名为 .jpg 上传。
     *
     * 跨框架兼容：不依赖 Laravel UploadedFile 强类型，支持 ThinkPHP 文件对象。
     *
     * @param object $file 上传文件对象
     * @return bool true=类型不匹配（危险），false=类型匹配或无法判断
     */
    protected function detectMimeTypeMismatch(object $file): bool
    {
        $claimExt = FrameworkBridge::fileGetClientOriginalExtension($file);

        if (empty($claimExt)) {
            return true; // 无扩展名，视为危险
        }

        // 从配置获取允许的MIME类型映射
        $allowedExtensions = \zxf\Security\Config\DefaultConfig::getAllowedExtensions($this->config);
        $mimeMap = $this->config['upload']['mime_magic_map'] ?? \zxf\Security\ThreatData::getMimeMagicMap();

        // 如果扩展名不在允许列表中，跳过 magic bytes 检查（扩展名检查会处理）
        if (!in_array($claimExt, $allowedExtensions, true)) {
            return false;
        }

        // 获取预期MIME类型
        $expectedMime = $mimeMap[$claimExt] ?? null;

        if ($expectedMime === null) {
            return false; // 无预期映射，不做判断
        }

        $detectedMime = FrameworkBridge::fileGetMimeType($file);

        // 如果声明的扩展名对应的MIME不匹配实际MIME，可能被伪装
        $expectedList = is_array($expectedMime) ? $expectedMime : [$expectedMime];

        if (!in_array($detectedMime, $expectedList, true)) {
            $this->lastMatchedPattern = 'mime_mismatch:' . $claimExt;
            $this->lastMatchedContent = sprintf(
                'Extension: %s → Expected: %s → Got: %s',
                $claimExt,
                implode('|', $expectedList),
                $detectedMime ?? 'unknown'
            );
            return true;
        }

        return false;
    }
}
