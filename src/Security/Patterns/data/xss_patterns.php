<?php

/**
 * XSS 攻击检测模式定义（v6.2 元数据格式）
 *
 * ═══════════════════════════════════════════════════════════════
 * 功能概述：
 *   识别并拦截 Web 请求中的跨站脚本攻击（XSS）模式，覆盖脚本注入、DOM 型、
 *   标签注入、编码绕过及框架特定 XSS 共 5 个子类型，共 20 条规则。
 *
 * ═══════════════════════════════════════════════════════════════
 * 检测类别（5 类，共 20 条规则）：
 *
 *   一、脚本注入（script）    —— 第 11-14 行，共 3 条
 *   二、DOM 型（dom）          —— 第 16-19 行，共 2 条
 *   三、标签注入（tag）        —— 第 20-27 行，共 6 条
 *   四、编码绕过（encoding）   —— 第 28-34 行，共 5 条
 *   五、框架特定（framework）  —— 第 35-40 行，共 4 条
 *
 * ═══════════════════════════════════════════════════════════════
 * 每条规则包含：
 *   pattern — 正则表达式
 *   desc    — 规则说明（用于注释和调试）
 *   risk    — 风险等级：high / medium / low
 *
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 * 仅在实际执行安全检查时由 PatternService 按需加载
 */

return [
    'script' => [
        ['pattern' => '/<script\b[^>]*>[^<]*(alert|confirm|prompt|eval)\s*\(/i', 'desc' => 'script标签内执行alert/confirm/prompt/eval', 'risk' => 'high'],
        ['pattern' => '/<script\b[^>]*>[^<]*document\.(write|cookie|location)\s*=/i', 'desc' => 'script标签内操作DOM或窃取cookie', 'risk' => 'high'],
        ['pattern' => '/javascript:\s*(alert|confirm|prompt|eval)\s*\(/i', 'desc' => 'javascript:伪协议执行弹窗或eval', 'risk' => 'high'],
    ],
    'dom' => [
        // 优化：onXxx事件属性限定必须出现在HTML标签上下文中，避免在JSON数据或普通文本中误报
        ['pattern' => '/<[a-z]+\s[^>]*\bon(error|load|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mousemove|mouseout|unload)\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(/i', 'desc' => 'HTML标签中的DOM事件处理器绑定恶意函数', 'risk' => 'high'],
        ['pattern' => '/\.?(innerHTML|outerHTML)\s*=\s*[\'"]?\s*<\s*(script|img|iframe|svg)/i', 'desc' => 'innerHTML/outerHTML赋值为危险标签', 'risk' => 'medium'],
    ],
    // 通用事件处理器检测（低风险，仅在无HTML标签上下文时作为后备）
    // 注意：此规则需配合 checkXssPatterns 中的预过滤使用，仅当输入包含 onerror=、onload= 等关键词时才执行正则
    'event' => [
        ['pattern' => '/\b(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onchange|onsubmit)\s*=\s*[\'"]?(?:\s*alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\()/i', 'desc' => '通用事件处理器绑定恶意函数（低风险）', 'risk' => 'low'],
    ],
    'tag' => [
        ['pattern' => '/<iframe\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i', 'desc' => 'iframe src使用javascript:伪协议', 'risk' => 'high'],
        ['pattern' => '/<object\b[^>]*data\s*=\s*[\'"]?\s*javascript:/i', 'desc' => 'object data使用javascript:伪协议', 'risk' => 'high'],
        ['pattern' => '/<embed\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i', 'desc' => 'embed src使用javascript:伪协议', 'risk' => 'high'],
        ['pattern' => '/<svg\b[^>]*onload\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i', 'desc' => 'SVG onload事件执行恶意代码', 'risk' => 'high'],
        ['pattern' => '/<img\b[^>]*onerror\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i', 'desc' => 'img onerror事件执行恶意代码', 'risk' => 'high'],
        ['pattern' => '/<input\b[^>]*onfocus\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i', 'desc' => 'input onfocus事件执行恶意代码', 'risk' => 'medium'],
    ],
    'encoding' => [
        ['pattern' => '/\\\\u[0-9a-f]{4}/i', 'desc' => 'Unicode转义序列（\\u0041 = A，常用于绕过过滤）', 'risk' => 'medium'],
        ['pattern' => '/&(#x?)?(0*4|0*1|0*105|0*97|0*108|0*101|0*114|0*116)/i', 'desc' => 'HTML实体编码alert相关字符（&#97=l）', 'risk' => 'medium'],
        ['pattern' => '/(?:%6[aA]|%4[aA])(?:%61|%41)(?:%76|%56)(?:%61|%41)(?:%73|%53)(?:%63|%43)(?:%72|%52)(?:%69|%49)(?:%70|%50)(?:%74|%54)/i', 'desc' => 'URL编码的javascript字符串片段', 'risk' => 'low'],
        ['pattern' => '/data:text\/html;base64,/i', 'desc' => 'data:text/html;base64伪协议嵌入HTML', 'risk' => 'high'],
        ['pattern' => '/data:image\/svg\+xml;base64,/i', 'desc' => 'SVG图片内嵌Base64编码（可包含XSS）', 'risk' => 'medium'],
    ],
    'framework' => [
        ['pattern' => '/jQuery\.fn\.(init|extend)\s*\(\s*["\']\s*<script/i', 'desc' => 'jQuery.fn.init/extend传入script标签', 'risk' => 'medium'],
        ['pattern' => '/\{\{\s*.*constructor\s*\./i', 'desc' => 'Vue/Angular模板constructor属性访问（沙箱逃逸）', 'risk' => 'high'],
        ['pattern' => '/\[\s*constructor\s*\]\s*\[\s*"prototype"\s*\]/i', 'desc' => 'constructor[prototype]原型链污染攻击', 'risk' => 'high'],
        ['pattern' => '/v-html\s*=\s*["\']\s*</i', 'desc' => 'Vue v-html指令绑定原始HTML（XSS风险）', 'risk' => 'medium'],
    ],
];
