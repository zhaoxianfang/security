<?php

namespace zxf\Security\Middleware\Concerns;

/**
 * Markdown 内容智能识别与安全旁路管理
 *
 * 核心功能：
 *  1. Markdown 文档识别（多维评分机制 + YAML frontmatter + GFM 特性检测）
 *  2. 代码块内匹配定位（围栏式 + 缩进式 + 嵌套检测）
 *  3. 危险代码旁路策略（双层控制模型）
 *  4. 代码块清理（移除 Markdown 标记后检测）
 *  5. 多行注释/文档结构识别（避免误报教学/文档型内容）
 *
 * 双层控制模型：
 *  - 第一层：allow_script_in_markdown → 控制 XSS 脚本标签检测
 *  - 第二层：allow_dangerous_code_in_markdown → 控制高危代码/命令检测
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware + UsesSafeRegex trait 提供）：
 *   - $this->config[][]: mixed              — 安全配置数组
 *   - safePregMatch(): bool                 — 安全正则匹配（UsesSafeRegex）
 *   - safePregReplace(): string             — 安全正则替换（UsesSafeRegex）
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 * @version 6.4.0
 */
trait ManagesMarkdownSafety
{
    /**
     * 请求级 Markdown 检测结果缓存
     *
     * isMarkdownContent() 含 16 条正则匹配，一个请求中可能被多次调用
     * （shouldBypassMarkdownDangerousCode + isLikelyMarkdownContent）。
     * 通过 crc32b 哈希缓存结果，避免重复计算。
     *
     * @var array<int, bool>
     */
    private array $mdContentCache = [];

    /**
     * 判断内容是否为 Markdown 文档（增强多维评分版 + 请求级缓存）
     *
     * 采用多维度评分机制，综合判断以下特征：
     *  - 围栏式代码块（```/~~~）— 强信号（+6分）
     *  - YAML frontmatter（开头 --- 闭合）— 强文档信号（+5分）
     *  - 行内代码 `backticks` — 中信号（+3分）
     *  - HTML 注释块 — 文档特征（+3分）
     *  - Markdown 语法模式（标题/列表/链接/表格等）— 基础分（+1分/个）
     *  - GFM 特性（任务列表/删除线/脚注）— 额外分（+1分/个）
     *
     * @param string $content 原始内容
     * @return bool true=是 Markdown 文档，false=不是
     */
    protected function isMarkdownContent(string $content): bool
    {
        // 请求级缓存：同一请求中对同一内容多次调用不重复计算
        $cacheKey = crc32($content);
        if (isset($this->mdContentCache[$cacheKey])) {
            return $this->mdContentCache[$cacheKey];
        }

        $markdownConfig = $this->config['markdown'] ?? [];

        // 最小长度检查
        $minLength = $markdownConfig['min_length'] ?? 80;
        if (strlen($content) < $minLength) {
            $this->mdContentCache[$cacheKey] = false;
            return false;
        }

        $codeBlockMarkers = $markdownConfig['code_block_markers'] ?? ['```', '~~~'];
        $inlineCodeMarker = $markdownConfig['inline_code_marker'] ?? '`';

        // YAML frontmatter 检测（开头 --- 后内容，再遇到 --- 闭合）
        $hasFrontmatter = false;
        if (str_starts_with(ltrim($content), '---')) {
            $lines = explode("\n", $content);
            $firstLine = trim($lines[0] ?? '');
            if ($firstLine === '---') {
                for ($i = 1, $len = min(count($lines), 30); $i < $len; $i++) {
                    if (trim($lines[$i]) === '---') {
                        $hasFrontmatter = true;
                        break;
                    }
                }
            }
        }

        // 围栏式代码块检测（双标签配对）
        $hasCodeBlock = false;
        foreach ($codeBlockMarkers as $marker) {
            if (substr_count($content, $marker) >= 2) {
                $hasCodeBlock = true;
                break;
            }
        }

        // 行内代码检测（至少 2 对反引号 = 4 次出现）
        $inlineCodeCount = substr_count($content, $inlineCodeMarker);
        $hasInlineCode = $inlineCodeCount >= 4;

        // HTML 注释块检测（文档/博客常见）
        $hasHtmlComment = str_contains($content, '<!--') && str_contains($content, '-->');

        // Markdown 语法模式匹配
        $markdownPatterns = \zxf\Security\Config\DefaultConfig::getMarkdownSyntaxPatterns($this->config);

        $syntaxScore = 0;
        foreach ($markdownPatterns as $pattern) {
            if ($this->safePregMatch($pattern, $content)) {
                $syntaxScore++;
            }
        }

        // 代码块是强信号，大幅加分
        if ($hasCodeBlock) {
            $syntaxScore += 6;
        }

        // YAML frontmatter 是明确 Markdown 文档标志
        if ($hasFrontmatter) {
            $syntaxScore += 5;
        }

        // 行内代码也有一定加分
        if ($hasInlineCode) {
            $syntaxScore += 3;
        }

        // HTML 注释在文档/博客中也算一个信号
        if ($hasHtmlComment) {
            $syntaxScore += 3;
        }

        $minScore = $markdownConfig['min_syntax_score'] ?? 3;

        // 综合判定：代码块存在、frontmatter 存在、或语法特征足够
        $result = $hasCodeBlock || $hasFrontmatter || $syntaxScore >= $minScore;
        $this->mdContentCache[$cacheKey] = $result;
        return $result;
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

        // 逻辑优化：当 smart_detection 关闭时，不启用旁路
        // 当 smart_detection 开启但 allow_dangerous_code_in_markdown 关闭时，也不启用旁路
        // 只有当两者都开启时才启用旁路
        if (!$smartDetection) {
            return false;
        }

        if (!$allowDangerousCode) {
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
     * 通过 PREG_OFFSET_CAPTURE 定位匹配位置，避免逐行执行正则。
     * 支持围栏式代码块（``` 和 ~~~）、缩进式代码块（4空格/Tab）、
     * 以及嵌套围栏（外层~~~内层```等）。
     *
     * @param string $content 原始内容
     * @param string $pattern 匹配的正则模式
     * @return bool true=在代码块内（教学示例，应放行），false=不在代码块内
     */
    protected function isPatternInCodeBlock(string $content, string $pattern): bool
    {
        // 定位匹配偏移（仅需一次正则调用，替代逐行匹配）
        $matches = [];
        if (!$this->safePregMatch($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            return false;
        }

        $matchOffset = $matches[0][1];

        // ═══ 单次 explode，同时用于围栏状态解析和缩进检测 ═══
        // 之前代码两次调用 explode("\n", ...)，对大内容 Markdown 开销翻倍
        $allLines = explode("\n", $content);

        // 首次遍历：解析围栏式代码块状态，同时定位匹配行索引
        $inFencedBlock = false;
        $fenceMarker = '';
        $matchedLineIdx = 0;
        $charPos = 0;

        foreach ($allLines as $idx => $line) {
            $trimmed = trim($line);

            // 围栏切换
            if (str_starts_with($trimmed, '```') || str_starts_with($trimmed, '~~~')) {
                $currentMarker = str_starts_with($trimmed, '```') ? '```' : '~~~';
                if (!$inFencedBlock) {
                    $inFencedBlock = true;
                    $fenceMarker = $currentMarker;
                } elseif ($currentMarker === $fenceMarker) {
                    $inFencedBlock = false;
                }
            }

            // 通过字符偏移定位匹配所在行
            if ($matchedLineIdx === 0 && $matchOffset <= $charPos + strlen($line)) {
                $matchedLineIdx = $idx;
                if ($inFencedBlock) {
                    return true; // 匹配在围栏代码块内 → 尽快返回
                }
            }

            $charPos += strlen($line) + 1; // +1 for \n
        }

        // 缩进式代码块检测
        $matchedLine = $allLines[$matchedLineIdx] ?? '';

        if ((str_starts_with($matchedLine, '    ') || str_starts_with($matchedLine, "\t")) && trim($matchedLine) !== '') {
            $indentedCount = 1;

            // 向前检查（最多前 5 行）
            for ($j = $matchedLineIdx - 1; $j >= max(0, $matchedLineIdx - 5); $j--) {
                $prevLine = $allLines[$j] ?? '';
                if ((str_starts_with($prevLine, '    ') || str_starts_with($prevLine, "\t")) && trim($prevLine) !== '') {
                    $indentedCount++;
                } elseif (trim($prevLine) === '') {
                    continue;
                } else {
                    break;
                }
            }
            // 向后检查（最多后 5 行）
            for ($j = $matchedLineIdx + 1; $j < min(count($allLines), $matchedLineIdx + 6); $j++) {
                $nextLine = $allLines[$j] ?? '';
                if ((str_starts_with($nextLine, '    ') || str_starts_with($nextLine, "\t")) && trim($nextLine) !== '') {
                    $indentedCount++;
                } elseif (trim($nextLine) === '') {
                    continue;
                } else {
                    break;
                }
            }

            if ($indentedCount >= 2) {
                return true;
            }

            if ($indentedCount === 1) {
                $codeClues = [';', '=>', '->', 'function', 'class ', 'SELECT', 'DROP ',
                    'preg_', 'public ', 'private ', 'protected ', 'echo ', 'return '];
                foreach ($codeClues as $clue) {
                    if (str_contains($matchedLine, $clue)) {
                        return true;
                    }
                }
            }
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
        // 快速预检：无围栏标记则跳过正则替换
        if (str_contains($content, '```')) {
            $content = $this->safePregReplace('/```[\s\S]*?```/', ' ', $content);
        }
        if (str_contains($content, '~~~')) {
            $content = $this->safePregReplace('/~~~[\s\S]*?~~~/', ' ', $content);
        }
        if (str_contains($content, '`')) {
            $content = $this->safePregReplace('/`[^`]+`/', ' ', $content);
        }

        return $content;
    }
}
