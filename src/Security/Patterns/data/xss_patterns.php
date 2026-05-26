<?php

/**
 * XSS攻击检测模式定义（v6.0 元数据格式）
 *
 * 每条规则包含：pattern, desc, risk
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 */

return [
    'script' => [
        ['pattern' => '/<script\b[^>]*>[^<]*(alert|confirm|prompt|eval)\s*\(/i', 'desc' => 'script标签内执行alert/confirm/prompt/eval', 'risk' => 'high'],
        ['pattern' => '/<script\b[^>]*>[^<]*document\.(write|cookie|location)\s*=/i', 'desc' => 'script标签内操作DOM或窃取cookie', 'risk' => 'high'],
        ['pattern' => '/javascript:\s*(alert|confirm|prompt|eval)\s*\(/i', 'desc' => 'javascript:伪协议执行弹窗或eval', 'risk' => 'high'],
    ],
    'dom' => [
        ['pattern' => '/\b(on(error|load|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mousemove|mouseout|unload))\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(/i', 'desc' => 'DOM事件处理器绑定恶意函数（onerror=alert()等）', 'risk' => 'high'],
        ['pattern' => '/\.?(innerHTML|outerHTML)\s*=\s*[\'"]?\s*<\s*(script|img|iframe|svg)/i', 'desc' => 'innerHTML/outerHTML赋值为危险标签', 'risk' => 'medium'],
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
