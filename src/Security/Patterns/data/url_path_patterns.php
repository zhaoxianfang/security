<?php

/**
 * URL路径攻击检测模式定义
 *
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 * 仅在实际执行 URL 路径安全检查时由 PatternService 按需加载
 */

return [
    // 路径遍历（至少两个 ../）
    '/(\.\.\/){2,}/',
    // Windows 路径遍历
    '/(\.\.\\\\){2,}/',
    // 混合路径遍历
    '/\.\.(\/|\\\\)\.\.(\/|\\\\)/',
    // URL 编码（兼容 Windows） ../ 或 ..\
    '/%2e%2e(%2f|%5c)/i',
    // 双重URL编码
    '/%252e%252e%252f/i',
    // Unicode 编码绕过
    '/%c0%af/i',
    '/%ef%bc%8f/i',
    '/%e0%80%af/i',
    // 空字节注入
    '/%00|\\x00/i',
    // 敏感文件访问
    '/\/(etc|proc|sys|var|root|home|usr\/local|usr\/share|usr\/bin|boot|opt|tmp)\/(passwd|shadow|hosts|id_rsa|id_dsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php|sudoers|group|crontab|fstab|resolv\.conf)\b/i',
    // 版本控制/配置文件
    // 注意: 使用 (?<!\w) 代替 \b, 因为 .(dot) 是非单词字符,
    // \b 在 /.git 这类 URL 路径上下文中不会触发
    '/(?<!\w)(\.env|\.git\/|\.git\/config)\b/i',
    '/(?<!\w)(\.svn|\.hg|\.bzr)\b/i',
    '/(?<!\w)(\.htaccess|\.htpasswd|web\.config)\b/i',
    '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock)\b/i',
    '/\b(Dockerfile|docker-compose\.yml)\b/i',
    '/(?<!\w)(\.dockerignore)\b/i',
    '/(?<!\w)(\.DS_Store|\.editorconfig|\.eslintrc|\.prettierrc)\b/i',
    // Windows 系统目录穿越
    '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i',
    // 脚本扩展名（增强：支持在路径任意位置）
    '/\.(?:php\d*|phtml|phar|shtml|jsp|jspx|asp|aspx|ashx|asmx|ascx|sh|bash|py|pyc|pl|pm|rb|exe|dll|bat|cmd|cgi|vbs|ps1|js|env|bak|swp|orig|inc|conf|ini|sql|log|tmp|old)(?=\b|[?#&]|$)/i',
    // WebShell 特征
    '/\b(assert|eval|execute|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i',
    // 文件下载/包含文件名参数 — 脚本扩展名
    '/[?&](?:file|path|dir|download|include|src|document|page|template|view|load|read|style|img)\s*=\s*[^&]*\.(?:\w+)\.(?:php|asp|jsp|sh|py|pl|rb|cgi)/i',
    // WordPress 常见漏洞路径
    '/\b(wp-admin|wp-content|wp-includes|wp-config|xmlrpc\.php)\b/i',
    // PHP 调试/信息泄露
    '/\b(phpinfo|php_info|test\.php|info\.php|debug|\.env\.backup|\.env\.example|\.env\.local|\.env\.production)\b/i',
    // 数据库管理工具暴露
    '/\b(phpmyadmin|phpMyAdmin|adminer|sqlite|\.sql|\.sq3|\.db|\.mdb)\b/i',
    // 备份文件
    '/\.(?:bak|backup|swp|orig|old|save|tar\.gz|zip|7z|rar)\b/i',
    // 日志文件泄露
    '/\b(error_log|access_log|debug\.log|laravel\.log|storage\/logs)\b/i',
];
