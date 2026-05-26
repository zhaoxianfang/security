<?php

/**
 * URL路径攻击检测模式定义（v6.0 元数据格式）
 *
 * 扁平数组格式，每条规则包含：pattern, desc, risk
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 */

return [
    ['pattern' => '/(\.\.\/){2,}/', 'desc' => 'Linux多级目录穿越（../../..）', 'risk' => 'high'],
    ['pattern' => '/(\.\\\\){2,}/', 'desc' => 'Windows多级目录穿越（..\\..\\）', 'risk' => 'high'],
    ['pattern' => '/\.\.(\/|\\\\)\.\.(\/|\\\\)/', 'desc' => '混合路径遍历（../..或..\\..）', 'risk' => 'high'],
    ['pattern' => '/%2e%2e(%2f|%5c)/i', 'desc' => 'URL编码../或..\\路径穿越', 'risk' => 'high'],
    ['pattern' => '/%252e%252e%252f/i', 'desc' => '双重URL编码路径穿越', 'risk' => 'high'],
    ['pattern' => '/%c0%af/i', 'desc' => 'UTF-8过度编码路径穿越（%c0%af = /）', 'risk' => 'high'],
    ['pattern' => '/%ef%bc%8f/i', 'desc' => '全角斜杠编码绕过（U+FF0F）', 'risk' => 'high'],
    ['pattern' => '/%e0%80%af/i', 'desc' => 'UTF-8三字节过度编码路径穿越', 'risk' => 'high'],
    ['pattern' => '/%00|\\x00/i', 'desc' => '空字节注入（截断文件名）', 'risk' => 'high'],
    ['pattern' => '/\/(etc|proc|sys|var|root|home|usr\/local|usr\/share|usr\/bin|boot|opt|tmp)\/(passwd|shadow|hosts|id_rsa|id_dsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php|sudoers|group|crontab|fstab|resolv\.conf)\b/i', 'desc' => '敏感系统文件路径访问', 'risk' => 'high'],
    ['pattern' => '/(?<!\w)(\.env|\.git\/|\.git\/config)\b/i', 'desc' => '.env或.git目录访问', 'risk' => 'medium'],
    ['pattern' => '/(?<!\w)(\.svn|\.hg|\.bzr)\b/i', 'desc' => '版本控制目录泄露', 'risk' => 'medium'],
    ['pattern' => '/(?<!\w)(\.htaccess|\.htpasswd|web\.config)\b/i', 'desc' => 'Web服务器配置文件泄露', 'risk' => 'medium'],
    ['pattern' => '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock)\b/i', 'desc' => '项目依赖文件泄露', 'risk' => 'low'],
    ['pattern' => '/\b(Dockerfile|docker-compose\.yml)\b/i', 'desc' => 'Docker配置文件泄露', 'risk' => 'low'],
    ['pattern' => '/(?<!\w)(\.dockerignore)\b/i', 'desc' => '.dockerignore文件泄露', 'risk' => 'low'],
    ['pattern' => '/(?<!\w)(\.DS_Store|\.editorconfig|\.eslintrc|\.prettierrc)\b/i', 'desc' => 'IDE/编辑器配置文件泄露', 'risk' => 'low'],
    ['pattern' => '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i', 'desc' => 'Windows系统目录穿越', 'risk' => 'high'],
    ['pattern' => '/\.(?:php\d*|phtml|phar|shtml|jsp|jspx|asp|aspx|ashx|asmx|ascx|sh|bash|py|pyc|pl|pm|rb|exe|dll|bat|cmd|cgi|vbs|ps1|js|env|bak|swp|orig|inc|conf|ini|sql|log|tmp|old)(?=\b|[?#&]|$)/i', 'desc' => 'URL路径中出现危险扩展名', 'risk' => 'medium'],
    ['pattern' => '/\b(assert|eval|execute|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', 'desc' => 'URL中暴露WebShell执行特征', 'risk' => 'high'],
    ['pattern' => '/[?&](?:file|path|dir|download|include|src|document|page|template|view|load|read|style|img)\s*=\s*[^&]*\.(?:\w+)\.(?:php|asp|jsp|sh|py|pl|rb|cgi)/i', 'desc' => '文件参数指向脚本扩展名（二次扩展名攻击）', 'risk' => 'high'],
    ['pattern' => '/\b(wp-admin|wp-content|wp-includes|wp-config|xmlrpc\.php)\b/i', 'desc' => 'WordPress敏感路径探测', 'risk' => 'low'],
    ['pattern' => '/\b(phpinfo|php_info|test\.php|info\.php|debug|\.env\.backup|\.env\.example|\.env\.local|\.env\.production)\b/i', 'desc' => 'PHP信息泄露路径探测', 'risk' => 'low'],
    ['pattern' => '/\b(phpmyadmin|phpMyAdmin|adminer|sqlite|\.sql|\.sq3|\.db|\.mdb)\b/i', 'desc' => '数据库管理工具暴露探测', 'risk' => 'medium'],
    ['pattern' => '/\.(?:bak|backup|swp|orig|old|save|tar\.gz|zip|7z|rar)\b/i', 'desc' => '备份文件访问', 'risk' => 'medium'],
    ['pattern' => '/\b(error_log|access_log|debug\.log|laravel\.log|storage\/logs)\b/i', 'desc' => '日志文件泄露访问', 'risk' => 'low'],
];
