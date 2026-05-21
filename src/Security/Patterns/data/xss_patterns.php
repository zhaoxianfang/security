<?php

/**
 * XSS攻击检测模式定义
 *
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 * 仅在实际执行 XSS 安全检查时由 PatternService 按需加载
 *
 * 分类：script, dom, tag, encoding, framework
 */

return [
    // ========== 反射型/存储型XSS ==========
    'script' => [
        '/<script\b[^>]*>[^<]*(alert|confirm|prompt|eval)\s*\(/i',
        '/<script\b[^>]*>[^<]*document\.(write|cookie|location)\s*=/i',
        '/javascript:\s*(alert|confirm|prompt|eval)\s*\(/i',
    ],

    // ========== DOM型XSS ==========
    'dom' => [
        '/\b(on(error|load|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mousemove|mouseout|unload))\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(/i',
        '/\.(innerHTML|outerHTML)\s*=\s*[\'"]?\s*<\s*(script|img|iframe|svg)/i',
    ],

    // ========== 标签注入 ==========
    'tag' => [
        '/<iframe\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i',
        '/<object\b[^>]*data\s*=\s*[\'"]?\s*javascript:/i',
        '/<embed\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i',
        '/<svg\b[^>]*onload\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',
        '/<img\b[^>]*onerror\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',
        '/<input\b[^>]*onfocus\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',
    ],

    // ========== 编码绕过 ==========
    'encoding' => [
        '/\\\\u[0-9a-f]{4}/i',
        '/&(#x?)?(0*4|0*1|0*105|0*97|0*108|0*101|0*114|0*116)/i',
        '/(?:%6[aA]|%4[aA])(?:%61|%41)(?:%76|%56)(?:%61|%41)(?:%73|%53)(?:%63|%43)(?:%72|%52)(?:%69|%49)(?:%70|%50)(?:%74|%54)/i',
        '/data:text\/html;base64,/i',
        '/data:image\/svg\+xml;base64,/i',
    ],

    // ========== 框架/库特定XSS ==========
    'framework' => [
        '/jQuery\.fn\.(init|extend)\s*\(\s*["\']\s*<script/i',
        '/\{\{\s*.*constructor\s*\./i',
        '/\[\s*constructor\s*\]\s*\[\s*"prototype"\s*\]/i',
        '/v-html\s*=\s*["\']\s*</i',
    ],
];
