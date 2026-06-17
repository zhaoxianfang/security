<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;

/**
 * 安全正则表达式与输入处理工具集
 *
 * 提供安全的 PCRE 正则匹配/替换、输入扁平化、截断、脱敏等功能。
 * 所有正则操作均捕获 PCRE 编译错误，防止运行时崩溃。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - $this->config[][]: mixed  — 安全配置数组（input_processing 等）
 *   - $this->requestId: string  — 唯一请求 ID
 *   - $this->normalizedInputCache: array  — 请求级规范化缓存
 *
 * 跨框架兼容：日志通过 FrameworkBridge 输出，支持 Laravel 11+ 和 ThinkPHP 8+。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.1.0
 * @version 6.3.0
 */
trait UsesSafeRegex
{
    /**
     * 获取最大输入长度（用于截断，防止正则回溯）
     */
    protected function getMaxInputLength(): int
    {
        $length = $this->config['input_processing']['max_input_length'] ?? 100000;

        return max(1, (int) $length);
    }

    /**
     * 安全执行 preg_match，捕获并处理 PCRE 编译错误
     *
     * @param string $pattern 正则表达式模式
     * @param string $subject 要匹配的字符串
     * @param array|null $matches 匹配结果数组（引用）
     * @param int $flags PCRE 标志（如 PREG_OFFSET_CAPTURE）
     * @param int $offset 匹配起始偏移
     * @return bool true=匹配成功，false=未匹配或正则错误
     */
    protected function safePregMatch(string $pattern, string $subject, ?array &$matches = null, int $flags = 0, int $offset = 0): bool
    {
        if (empty($pattern) || $subject === '') {
            return false;
        }

        static $limitSet = false;
        if (!$limitSet) {
            ini_set('pcre.backtrack_limit', '1000000');
            $limitSet = true;
        }

        $localMatches = [];
        $result = @preg_match($pattern, $subject, $localMatches, $flags, $offset);

        if ($result === false) {
            if ($this->config['log_enabled'] ?? true) {
                $errorMsg = preg_last_error_msg();
                FrameworkBridge::logWarning('[Security] 正则表达式编译失败，已跳过该规则', [
                    'pattern' => mb_substr($pattern, 0, 100),
                    'error' => $errorMsg,
                    'request_id' => $this->requestId ?? '',
                ]);
            }
            return false;
        }

        if (func_num_args() >= 3) {
            $matches = $localMatches;
        }

        return $result === 1;
    }

    /**
     * 快速安全正则匹配（跳过错误抑制，用于已验证编译通过的内置模式）
     *
     * 与 safePregMatch 的区别：
     *  - 不使用 @ 错误抑制（~5% 的微基准性能提升）
     *  - 不检查 $result === false（内置模式已知编译正确）
     *  - 仅用于内置模式数据文件中的正则，不可用于用户自定义模式
     *
     * @param string $pattern 已验证编译通过的正则模式（内置模式）
     * @param string $subject 要匹配的字符串
     * @param array|null $matches 匹配结果数组（引用）
     * @param int $flags PCRE 标志
     * @param int $offset 匹配起始偏移
     * @return bool true=匹配成功，false=未匹配
     */
    protected function safePregMatchFast(string $pattern, string $subject, ?array &$matches = null, int $flags = 0, int $offset = 0): bool
    {
        if ($subject === '') {
            return false;
        }

        static $limitSet = false;
        if (!$limitSet) {
            ini_set('pcre.backtrack_limit', '1000000');
            $limitSet = true;
        }

        $localMatches = [];
        $result = preg_match($pattern, $subject, $localMatches, $flags, $offset);

        if (func_num_args() >= 3) {
            $matches = $localMatches;
        }

        return $result === 1;
    }

    /**
     * 安全执行 preg_replace，捕获并处理 PCRE 编译错误
     *
     * @param string $pattern 正则表达式模式
     * @param string $replacement 替换字符串
     * @param string $subject 要处理的字符串
     * @return string 处理后的字符串，出错时返回原始字符串
     */
    protected function safePregReplace(string $pattern, string $replacement, string $subject): string
    {
        if (empty($pattern) || $subject === '') {
            return $subject;
        }

        static $limitSet = false;
        if (!$limitSet) {
            ini_set('pcre.backtrack_limit', '1000000');
            $limitSet = true;
        }

        $result = @preg_replace($pattern, $replacement, $subject);

        if ($result === null) {
            if ($this->config['log_enabled'] ?? true) {
                $errorMsg = preg_last_error_msg();
                FrameworkBridge::logWarning('[Security] 正则替换失败，保留原内容', [
                    'pattern' => mb_substr($pattern, 0, 100),
                    'error' => $errorMsg,
                    'request_id' => $this->requestId ?? '',
                ]);
            }
            return $subject;
        }

        return $result;
    }

    /**
     * 截断输入字符串，防止正则回溯
     *
     * @param string $input 原始输入
     * @return string 截断后的输入
     */
    protected function truncateInput(string $input): string
    {
        $maxLength = $this->getMaxInputLength();

        if (strlen($input) <= $maxLength) {
            return $input;
        }

        // 仅在需要截断时验证 UTF-8（防御无效字节绕过截断）
        if (!mb_check_encoding($input, 'UTF-8')) {
            $input = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
        }

        return mb_substr($input, 0, $maxLength);
    }

    /**
     * 快速截断（跳过 UTF-8 验证）
     *
     * 适用于已知来源为合法 UTF-8 的字符串（如框架内部方法返回值）。
     * 避免每次 truncateInput 都调用 mb_check_encoding（可节省 ~5-10μs/次）。
     *
     * @param string $input 原始输入（已知为合法 UTF-8）
     * @return string 截断后的输入
     */
    protected function truncateInputKnown(string $input): string
    {
        $maxLength = $this->getMaxInputLength();

        if (strlen($input) <= $maxLength) {
            return $input;
        }

        return mb_substr($input, 0, $maxLength);
    }

    /**
     * 获取请求的输入字符串
     *
     * 优化：避免跨参数拼接导致误报。每个参数独立检测，
     * 仅在需要合并检测时才合并（用于检测跨参数关联的攻击）。
     *
     * @param object $request HTTP请求对象（跨框架兼容）
     * @param bool $sanitizeMarkdown 是否移除Markdown代码块
     * @return string 合并后的输入字符串
     */
    protected function getInputString(object $request, bool $sanitizeMarkdown = false): string
    {
        // 扁平化拼接所有输入（用于检测跨参数关联的攻击）
        $result = '';
        foreach ([
            FrameworkBridge::requestQuery($request),
            FrameworkBridge::requestPost($request),
            FrameworkBridge::requestRouteParams($request),
        ] as $source) {
            $result .= $this->flattenInput($source);
        }

        if ($sanitizeMarkdown) {
            $result = $this->removeMarkdownCodeBlocks($result);
        }

        return $result;
    }

    /**
     * 扁平化多维数组为字符串
     *
     * 优化：为每个值添加边界空格，避免跨参数值拼接导致误报。
     * 例如：param1=abc 和 param2=123 拼接后为 " abc 123"，
     * 不会误报为 "abc123" 导致正则匹配错误。
     *
     * @param array $input 输入数组
     * @return string 连接后的字符串
     */
    protected function flattenInput(array $input): string
    {
        $result = '';

        array_walk_recursive($input, function ($value) use (&$result) {
            // 处理所有标量值（含 int/float），避免攻击载荷躲在数值字段中绕过检测
            if (is_scalar($value) && !is_bool($value)) {
                // 添加边界空格，避免跨参数值拼接导致误报
                $result .= ' ' . (string) $value . ' ';
            }
        });

        return $result;
    }

    /**
     * 获取独立的参数值数组（用于单独检测，避免跨参数误报）
     *
     * @param object $request HTTP请求对象
     * @return array<string> 所有参数值（含查询、POST、路由参数）
     */
    protected function getIndependentInputValues(object $request): array
    {
        $values = [];

        foreach ([
            FrameworkBridge::requestQuery($request),
            FrameworkBridge::requestPost($request),
            FrameworkBridge::requestRouteParams($request),
        ] as $source) {
            $this->extractStringValues($source, $values);
        }

        return $values;
    }

    /**
     * 递归提取数组中的所有字符串值
     *
     * @param array $input 输入数组
     * @param array $values 值数组（引用）
     */
    protected function extractStringValues(array $input, array &$values): void
    {
        array_walk_recursive($input, function ($value) use (&$values) {
            if (is_string($value) && $value !== '') {
                $values[] = $value;
            }
        });
    }

    /**
     * 脱敏处理匹配到的内容
     *
     * @param string $content 原始匹配内容
     * @return string 脱敏后的内容
     */
    protected function sanitizeMatchedContent(string $content): string
    {
        if (empty($content)) {
            return '';
        }

        $config = $this->config['input_processing'] ?? [];
        $maxLength = $config['max_match_content_length'] ?? 200;

        if (mb_strlen($content) > $maxLength) {
            $content = mb_substr($content, 0, $maxLength) . '...[截断]';
        }

        $sensitivePatterns = [
            '/(password|passwd|pwd|token|secret|key)=\S+/i' => '$1=***',
            '/(authorization|bearer)\s+\S+/i' => '$1 ***',
        ];

        foreach ($sensitivePatterns as $pattern => $replacement) {
            $content = $this->safePregReplace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * 请求级缓存的输入规范化
     *
     * 同一请求中多个检测层（URL路径、高危攻击、XSS）可能对同一字符串
     * 重复执行 urldecode() / strtolower()。通过请求级缓存避免重复计算。
     *
     * 缓存键格式：{操作}::{原始字符串}，值=操作结果
     * 注意：缓存仅在当前请求生命周期内有效（SecurityMiddleware 实例化一次处理一个请求）
     *
     * @param string $input 原始输入
     * @return string 规范化后的输入
     */
    protected function normalizeInput(string $input): string
    {
        if ($input === '') {
            return '';
        }

        $cacheKey = 'lower::' . $input;
        if (isset($this->normalizedInputCache[$cacheKey])) {
            return $this->normalizedInputCache[$cacheKey];
        }

        $this->normalizedInputCache[$cacheKey] = strtolower($input);
        return $this->normalizedInputCache[$cacheKey];
    }

    /**
     * 请求级缓存的 urldecode
     *
     * 同一参数值可能在 URL 路径检测、高危检测、XSS 检测中分别被 urldecode 多次。
     * 通过请求级缓存避免重复计算。
     *
     * @param string $input 原始输入
     * @param int $level 解码次数（1 或 2）
     * @return string 解码后的输入
     */
    protected function cachedUrldecode(string $input, int $level = 1): string
    {
        if ($input === '') {
            return '';
        }

        $cacheKey = "urldecode_{$level}::{$input}";
        if (isset($this->normalizedInputCache[$cacheKey])) {
            return $this->normalizedInputCache[$cacheKey];
        }

        $result = $input;
        for ($i = 0; $i < $level; $i++) {
            $result = urldecode($result);
        }

        // 如果解码结果与原始输入相同，避免无意义缓存
        if ($result === $input) {
            return $result;
        }

        $this->normalizedInputCache[$cacheKey] = $result;
        return $result;
    }
}
