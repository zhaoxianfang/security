<?php

/**
 * URL 路径攻击检测模式定义（v6.2 元数据格式）
 *
 * ═══════════════════════════════════════════════════════════════
 * 功能概述：
 *   检测 URL 路径和查询参数中的路径遍历、敏感文件泄露、WebShell 特征等攻击。
 *   采用扁平数组格式（非分组），共 26 条规则，涵盖 Linux/Windows 路径穿越、
 *   编码绕过、系统文件探测、框架敏感路径等场景。
 *
 * ═══════════════════════════════════════════════════════════════
 * 检测类别（单类，共 26 条规则）：
 *
 *   路径穿越（第 11-18 行，8 条）      — ../、..\\、URL 编码、过度编码
 *   敏感文件（第 19-27 行，10 条）     — 系统文件、配置、依赖、Docker
 *   WebShell / 扩展名（第 28-37 行，8 条）— 脚本扩展名、敏感路径探测
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
    ['pattern' => '/(\.\.\/){2,}/', 'desc' => 'Linux多级目录穿越（../../..）', 'risk' => 'high'],
    ['pattern' => '/(\.\.\\\\)+/', 'desc' => 'Windows多级目录穿越（..\\..\\）', 'risk' => 'high'],
    ['pattern' => '/\.\.(\/|\\\\)\.\.(\/|\\\\)/', 'desc' => '混合路径遍历（../..或..\\..）', 'risk' => 'high'],
    ['pattern' => '/%2e%2e(%2f|%5c)/i', 'desc' => 'URL编码../或..\\路径穿越', 'risk' => 'high'],
    ['pattern' => '/%252e%252e%252f/i', 'desc' => '双重URL编码路径穿越', 'risk' => 'high'],
    ['pattern' => '/%c0%af/i', 'desc' => 'UTF-8过度编码路径穿越（%c0%af = /）', 'risk' => 'high'],
    ['pattern' => '/%ef%bc%8f/i', 'desc' => '全角斜杠编码绕过（U+FF0F）', 'risk' => 'high'],
    ['pattern' => '/%e0%80%af/i', 'desc' => 'UTF-8三字节过度编码路径穿越', 'risk' => 'high'],
    ['pattern' => '/%00|\\x00/i', 'desc' => '空字节注入（截断文件名）', 'risk' => 'high'],
    ['pattern' => '/\/(etc|proc|sys|var|root|home|usr\/local|usr\/share|usr\/bin|boot|opt|tmp)\/(passwd|shadow|hosts|id_rsa|id_dsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php|sudoers|group|crontab|fstab|resolv\.conf)\b/i', 'desc' => '敏感系统文件路径访问', 'risk' => 'high'],
    // 优化：.env/.git 限定在路径开头或斜杠后，避免在普通文本中被误报
    ['pattern' => '/\/(\.env|\.git\/|\.git\/config)(\/|\s|$)/i', 'desc' => 'URL路径中的.env或.git目录访问', 'risk' => 'medium'],
    ['pattern' => '/^(\.env|\.git\/|\.git\/config)(\/|\s|$)/i', 'desc' => 'URL路径开头的.env或.git目录访问', 'risk' => 'medium'],
    ['pattern' => '/(?<!\w)(\.svn|\.hg|\.bzr)/i', 'desc' => '版本控制目录泄露', 'risk' => 'medium'],
    ['pattern' => '/(?<!\w)(\.htaccess|\.htpasswd|web\.config)/i', 'desc' => 'Web服务器配置文件泄露', 'risk' => 'medium'],
    ['pattern' => '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock)\b/i', 'desc' => '项目依赖文件泄露', 'risk' => 'low'],
    ['pattern' => '/\b(Dockerfile|docker-compose\.yml)\b/i', 'desc' => 'Docker配置文件泄露', 'risk' => 'low'],
    ['pattern' => '/(?<!\w)(\.dockerignore)/i', 'desc' => '.dockerignore文件泄露', 'risk' => 'low'],
    ['pattern' => '/(?<!\w)(\.DS_Store|\.editorconfig|\.eslintrc|\.prettierrc)/i', 'desc' => 'IDE/编辑器配置文件泄露', 'risk' => 'low'],
    ['pattern' => '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i', 'desc' => 'Windows系统目录穿越', 'risk' => 'high'],
    ['pattern' => '/\.(?:php\d*|phtml|phar|shtml|jsp|jspx|asp|aspx|ashx|asmx|ascx|sh|bash|py|pyc|pl|pm|rb|exe|dll|bat|cmd|cgi|vbs|ps1)\b/i', 'desc' => 'URL路径中出现危险脚本/可执行扩展名', 'risk' => 'medium'],
    ['pattern' => '/\b(assert|eval|execute|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', 'desc' => 'URL中暴露WebShell执行特征', 'risk' => 'high'],
    ['pattern' => '/[?&](?:file|path|dir|download|include|src|document|page|template|view|load|read|style|img)\s*=\s*[^&]*\.(?:\w+)\.(?:php|asp|jsp|sh|py|pl|rb|cgi)/i', 'desc' => '文件参数指向脚本扩展名（二次扩展名攻击）', 'risk' => 'high'],
    ['pattern' => '/\b(wp-admin|wp-content|wp-includes|wp-config|xmlrpc\.php)\b/i', 'desc' => 'WordPress敏感路径探测', 'risk' => 'low'],
    ['pattern' => '/\b(phpinfo|php_info|test\.php|info\.php|debug|\.env\.backup|\.env\.example|\.env\.local|\.env\.production)\b/i', 'desc' => 'PHP信息泄露路径探测', 'risk' => 'low'],
    ['pattern' => '/\b(phpmyadmin|phpMyAdmin|adminer|sqlite|\.sql|\.sq3|\.db|\.mdb)\b/i', 'desc' => '数据库管理工具暴露探测', 'risk' => 'medium'],
    ['pattern' => '/\.(?:bak|backup|swp|orig|old|save|tar\.gz|zip|7z|rar)\b/i', 'desc' => '备份文件访问', 'risk' => 'medium'],
    ['pattern' => '/\b(error_log|access_log|debug\.log|laravel\.log|storage\/logs)\b/i', 'desc' => '日志文件泄露访问', 'risk' => 'low'],
];
