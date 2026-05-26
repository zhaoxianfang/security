<?php

namespace zxf\Security\Middleware\Concerns;

/**
 * Markdown 内容智能识别与安全旁路管理
 *
 * 核心功能：
 *  1. Markdown 文档识别（评分机制 + 多特征检测）
 *  2. 代码块内匹配定位（围栏式 + 缩进式）
 *  3. 危险代码旁路策略（双层控制模型）
 *  4. 代码块清理（移除 Markdown 标记后检测）
 *
 * 双层控制模型：
 *  - 第一层：allow_script_in_markdown → 控制 XSS 脚本标签检测
 *  - 第二层：allow_dangerous_code_in_markdown → 控制高危代码/命令检测
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 */
trait ManagesMarkdownSafety
{
    /**
     * 判断内容是否为 Markdown 文档（增强评分版）
     *
     * 采用评分机制，综合判断以下特征：
     *  - 围栏式代码块（```/~~~）— 强信号（+5分）
     *  - 行内代码 `backticks` — 中信号（+2分）
     *  - Markdown 语法模式（标题/列表/链接/表格等）— 基础分（+1分/个）
     *  - YAML frontmatter / HTML 注释 — 文档特征
     *
     * @param string $content 原始内容
     * @return bool true=是 Markdown 文档，false=不是
     */
    protected function isMarkdownContent(string $content): bool
    {
        $markdownConfig = $this->config['markdown'] ?? [];

        // 最小长度检查
        $minLength = $markdownConfig['min_length'] ?? 80;
        if (strlen($content) < $minLength) {
            return false;
        }

        $codeBlockMarkers = $markdownConfig['code_block_markers'] ?? ['```', '~~~'];
        $inlineCodeMarker = $markdownConfig['inline_code_marker'] ?? '`';

        // 围栏式代码块检测
        $hasCodeBlock = false;
        foreach ($codeBlockMarkers as $marker) {
            if (substr_count($content, $marker) >= 2) {
                $hasCodeBlock = true;
                break;
            }
        }

        // 行内代码检测
        $inlineCodeCount = substr_count($content, $inlineCodeMarker);
        $hasInlineCode = $inlineCodeCount >= 4;

        // Markdown 语法模式匹配
        $markdownPatterns = \zxf\Security\Config\DefaultConfig::getMarkdownSyntaxPatterns($this->config);

        $syntaxScore = 0;
        foreach ($markdownPatterns as $pattern) {
            if ($this->safePregMatch($pattern, $content)) {
                $syntaxScore++;
            }
        }

        // 代码块是强信号，大幅加分（表明这是技术文档）
        if ($hasCodeBlock) {
            $syntaxScore += 5;
        }

        // 行内代码也有一定加分
        if ($hasInlineCode) {
            $syntaxScore += 2;
        }

        $minScore = $markdownConfig['min_syntax_score'] ?? 2;

        // 综合判定：代码块存在 或 语法特征足够
        return $hasCodeBlock || $syntaxScore >= $minScore;
    }

    /**
     * 判断 XSS 匹配是否应因 Markdown 内容而忽略（误报判定）
     *
     * 仅用于 XSS 检测旁路。结合 Markdown 文档识别 + 代码块定位，
     * 判断匹配到的 XSS 模式是否位于 Markdown 代码块内（教学示例）。
     *
     * @param string $content 原始内容
     * @param string $matchedPattern 匹配到的正则模式
     * @return bool true=可能是Markdown内容中的代码示例，应跳过
     */
    protected function isLikelyMarkdownContent(string $content, string $matchedPattern): bool
    {
        // 基础 Markdown 检测
        if (!$this->isMarkdownContent($content)) {
            return false;
        }

        $markdownConfig = $this->config['markdown'] ?? [];
        $codeBlockMarkers = $markdownConfig['code_block_markers'] ?? ['```', '~~~'];

        // 检查是否包含围栏式代码块
        $hasCodeBlock = false;
        foreach ($codeBlockMarkers as $marker) {
            if (substr_count($content, $marker) >= 2) {
                $hasCodeBlock = true;
                break;
            }
        }

        // 有代码块 → 验证匹配行是否在代码块内
        if ($hasCodeBlock) {
            return $this->isPatternInCodeBlock($content, $matchedPattern);
        }

        // 无代码块但有行内代码 → 仍可能是 Markdown
        $inlineCodeMarker = $markdownConfig['inline_code_marker'] ?? '`';
        $inlineCodeCount = substr_count($content, $inlineCodeMarker);

        return $inlineCodeCount >= 4;
    }

    /**
     * 检查是否应对输入启用 Markdown 危险代码旁路
     *
     * 条件同时满足：
     *  1. markdown.smart_detection = true
     *  2. markdown.allow_dangerous_code_in_markdown = true
     *  3. 输入被识别为 Markdown 文档
     *
     * @param string $input 原始输入
     * @return bool true=启用旁路，false=正常检测
     */
    protected function shouldBypassMarkdownDangerousCode(string $input): bool
    {
        $markdownConfig = $this->config['markdown'] ?? [];

        $smartDetection = $markdownConfig['smart_detection'] ?? true;
        $allowDangerousCode = $markdownConfig['allow_dangerous_code_in_markdown'] ?? false;

        if (!$smartDetection || !$allowDangerousCode) {
            return false;
        }

        return $this->isMarkdownContent($input);
    }

    /**
     * 获取 Markdown 旁路的高危类型列表
     *
     * 仅对"在教学/文档中有合法出现场景"的攻击类型启用旁路。
     * SSRF、编码绕过、Header注入等不应旁路（即使出现在文档中也危险）。
     *
     * @return array<string>
     */
    protected function getMarkdownBypassTypes(): array
    {
        $markdownConfig = $this->config['markdown'] ?? [];

        $configured = $markdownConfig['dangerous_code_types'] ?? [];

        // 默认旁路类型（仅在代码示例中常见的攻击类型）
        $defaults = ['sql', 'command', 'path', 'nosql', 'ldap'];

        // 用户配置优先，空数组使用默认值
        if (empty($configured)) {
            return $defaults;
        }

        return $configured;
    }

    /**
     * 检查匹配的XSS/高危模式是否位于Markdown代码块内
     *
     * 扫描内容直到匹配行，跟踪代码块的开关状态。
     * 支持围栏式代码块（``` 和 ~~~）以及缩进式代码块（4空格/Tab）。
     *
     * @param string $content 原始内容
     * @param string $pattern 匹配的正则模式
     * @return bool true=在代码块内（教学示例，应放行），false=不在代码块内
     */
    protected function isPatternInCodeBlock(string $content, string $pattern): bool
    {
        $lines = explode("\n", $content);
        $inFencedBlock = false;
        $fenceMarker = '';

        // 先找到匹配的行号
        $matchedLineIndex = -1;
        foreach ($lines as $index => $line) {
            if ($this->safePregMatch($pattern, $line)) {
                $matchedLineIndex = $index;
                break;
            }
        }

        if ($matchedLineIndex === -1) {
            return false;
        }

        // 从第一行扫描到匹配行，跟踪代码块状态
        for ($i = 0; $i <= $matchedLineIndex; $i++) {
            $line = $lines[$i];
            $trimmed = trim($line);

            // 围栏式代码块检测
            if (str_starts_with($trimmed, '```') || str_starts_with($trimmed, '~~~')) {
                if (!$inFencedBlock) {
                    // 进入代码块
                    $inFencedBlock = true;
                    $fenceMarker = str_starts_with($trimmed, '```') ? '```' : '~~~';
                } else {
                    // 检查是否匹配结束标记（同类型围栏）
                    $currentMarker = str_starts_with($trimmed, '```') ? '```' : '~~~';
                    if ($currentMarker === $fenceMarker) {
                        $inFencedBlock = false;
                    }
                }
                continue;
            }
        }

        // 如果在围栏式代码块内，直接返回
        if ($inFencedBlock) {
            return true;
        }

        // 缩进式代码块检测（4空格或1Tab开头，且非空行）
        // 缩进式代码块需要连续3行以上才视为代码块，避免误判
        $line = $lines[$matchedLineIndex];
        if ((str_starts_with($line, '    ') || str_starts_with($line, "\t")) && trim($line) !== '') {
            $indentedCount = 1;
            // 向前检查
            for ($j = $matchedLineIndex - 1; $j >= max(0, $matchedLineIndex - 3); $j--) {
                $prevLine = $lines[$j];
                if ((str_starts_with($prevLine, '    ') || str_starts_with($prevLine, "\t")) && trim($prevLine) !== '') {
                    $indentedCount++;
                } elseif (trim($prevLine) === '') {
                    continue; // 空行不计
                } else {
                    break;
                }
            }
            // 向后检查
            for ($j = $matchedLineIndex + 1; $j < min(count($lines), $matchedLineIndex + 4); $j++) {
                $nextLine = $lines[$j];
                if ((str_starts_with($nextLine, '    ') || str_starts_with($nextLine, "\t")) && trim($nextLine) !== '') {
                    $indentedCount++;
                } elseif (trim($nextLine) === '') {
                    continue;
                } else {
                    break;
                }
            }

            return $indentedCount >= 3;
        }

        return false;
    }

    /**
     * 移除Markdown代码块
     *
     * 将围栏式代码块和行内代码替换为空格，
     * 用于在旁路模式下剥离代码示例后再检测其他内容。
     *
     * @param string $content 原始内容
     * @return string 移除代码块后的内容
     */
    protected function removeMarkdownCodeBlocks(string $content): string
    {
        $content = $this->safePregReplace('/```[\s\S]*?```/', ' ', $content);
        $content = $this->safePregReplace('/~~~[\s\S]*?~~~/', ' ', $content);
        $content = $this->safePregReplace('/`[^`]+`/', ' ', $content);

        return $content;
    }
}
