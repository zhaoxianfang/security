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
 *
 * 跨框架兼容：日志通过 FrameworkBridge 输出，支持 Laravel 11+ 和 ThinkPHP 8+。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 6.1.0
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
     * PCRE2（PHP 7.3+）不支持 \F, \L, \l, \N{name}, \U, \u 等转义序列。
     * 如果用户配置的正则模式包含这些不支持的特性，preg_match 会返回 false 并产生警告。
     * 本方法封装了错误处理，防止正则编译失败导致运行时崩溃。
     *
     * 性能优化：使用静态变量缓存回溯限制，避免每次调用 ini_set 的 syscall 开销。
     *
     * @param string $pattern 正则表达式模式
     * @param string $subject 要匹配的字符串
     * @param array|null $matches 匹配结果数组（引用）
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

        // 使用局部变量接收匹配结果，避免 PHP 8.2 引用参数默认 null 弃用警告
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

        // 仅在调用方传入引用参数时写回结果
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

        // 防御：无效 UTF-8 序列会导致 mb_strlen/mb_substr 返回 false 并产生警告，
        // 攻击者可能利用此特性使截断失效。先清理无效字节。
        if (!mb_check_encoding($input, 'UTF-8')) {
            $input = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
        }

        if (mb_strlen($input) > $maxLength) {
            return mb_substr($input, 0, $maxLength);
        }

        return $input;
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
}
