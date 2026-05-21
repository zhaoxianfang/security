<?php

namespace zxf\Security\Middleware\Concerns;

/**
 * 文件上传安全检查
 *
 * 检查维度：
 *  1. 文件扩展名黑名单（可执行脚本/WebShell)
 *  2. 文件大小限制
 *  3. MIME magic bytes 深度验证（防止扩展名伪装）
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 */
trait HandlesFileUploads
{
    /**
     * 检查文件上传是否包含危险文件
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=包含危险文件，false=文件安全或没有上传
     */
    protected function hasDangerousUpload(\Illuminate\Http\Request $request): bool
    {
        $upload = $this->config['upload'] ?? [];

        $files = $request->allFiles();

        if (empty($files)) {
            return false;
        }

        $blockedExtensions = $upload['blocked_extensions'] ?? [];
        $maxSize = $upload['max_size'] ?? 10 * 1024 * 1024;
        $checkMimeMagic = $upload['check_mime_magic'] ?? false;

        // 支持从黑名单中排除特定扩展名（精确字符串匹配）
        $excludeExtensions = array_flip($upload['blocked_extensions_exclude'] ?? []);
        if (!empty($excludeExtensions)) {
            $blockedExtensions = array_values(array_filter(
                $blockedExtensions,
                fn(string $ext) => !isset($excludeExtensions[$ext])
            ));
        }

        // 支持追加自定义黑名单扩展名
        $addExtensions = $upload['blocked_extensions_add'] ?? [];
        if (!empty($addExtensions)) {
            $blockedExtensions = array_merge($blockedExtensions, $addExtensions);
        }

        foreach ($files as $file) {
            $fileList = is_array($file) ? $file : [$file];

            foreach ($fileList as $singleFile) {
                // 1. 扩展名检查
                $extension = strtolower($singleFile->getClientOriginalExtension());
                if (in_array($extension, $blockedExtensions, true)) {
                    return true;
                }

                // 2. 文件大小检查
                if ($singleFile->getSize() > $maxSize) {
                    return true;
                }

                // 3. MIME magic bytes 深度验证（防止扩展名伪装）
                if ($checkMimeMagic && $singleFile->isValid()) {
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
     * @param \Illuminate\Http\UploadedFile $file 上传文件
     * @return bool true=类型不匹配（危险），false=类型匹配或无法判断
     */
    protected function detectMimeTypeMismatch(\Illuminate\Http\UploadedFile $file): bool
    {
        $claimExt = strtolower($file->getClientOriginalExtension());

        if (empty($claimExt)) {
            return true; // 无扩展名，视为危险
        }

        // 从配置获取允许的MIME类型映射
        $allowedExtensions = $this->config['upload']['allowed_extensions'] ?? [];
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

        $detectedMime = $file->getMimeType();

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
