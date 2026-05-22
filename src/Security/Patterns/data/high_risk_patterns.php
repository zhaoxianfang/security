<?php

/**
 * 高危攻击检测模式定义
 *
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 * 仅在实际执行安全检查时由 PatternService 按需加载
 *
 * 分类：sql, command, path, ldap, xml, nosql, ssti, ssrf, encoding, header_injection
 */

return [
    // ========== SQL注入检测 ==========
    'sql' => [
        // UNION注入
        '/\bunion\s+(all\s+)?select\s+(null|\d+|0x[0-9a-f]+|\$\d+|\?)/i',
        // 堆叠查询 - DROP/TRUNCATE
        '/;\s*(drop|truncate)\s+(table|database)\b/i',
        // SQL Server xp_cmdshell
        '/xp_cmdshell\s*\(/i',
        '/sp_oamethod\s*/i',
        '/sp_oacreate\s*/i',
        // MySQL 文件操作
        '/load_file\s*\(\s*[\'"]?\s*\//i',
        '/into\s+(outfile|dumpfile)\s+[\'"]?\s*\//i',
        // 时间盲注
        '/sleep\s*\(\s*[\'"]?\d{2,}/i',
        '/benchmark\s*\(\s*\d{5,}/i',
        '/pg_sleep\s*\(\s*[\'"]?\d{2,}/i',
        '/waitfor\s+delay\s*[\'"]\d{2,}/i',
        // 错误注入
        '/extractvalue\s*\(\s*[^,]+,\s*concat/i',
        '/updatexml\s*\(\s*[^,]+,\s*concat/i',
        '/floor\s*\(\s*rand\s*\(/i',
        // 布尔盲注
        '/\bcase\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)/i',
        '/\bif\s*\(\s*.*,\s*(sleep|benchmark|pg_sleep)/i',
        // 注释绕过
        '/\/\*!?\d{5,}\*\/\s*(union|select)\b/i',
        '/\/\*!?\d{5,}(?:union|select|drop|insert|update|delete|alter)\b/i',
        '/\/\*[^*]*\*\/\s*(and|or)\s+[\'"\d]/i',
        // 编码绕过
        '/(charset|character\s+set)\s*=\s*utf8/i',
        '/unhex\s*\(/i',
        '/hex\s*\(\s*[0-9a-f]+\s*\)/i',
        // 信息获取
        '/@@(version|datadir|basedir|hostname)/i',
        '/database\s*\(\s*\)/i',
        '/user\s*\(\s*\)/i',
        '/system_user\s*\(/i',
        '/current_user\s*\(/i',
        '/group_concat\s*\(/i',
        '/concat_ws\s*\(/i',
        // 宽字节注入
        '/%df%27/i',
        '/%bf%27/i',
        // 经典注入模式
        '/\b1\s*=\s*1\b/i',
        '/\'\s*(?:or|and)\s+\d+\s*=\s*\d+/i',
        '/[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i',
        // 常见注释绕过 + 数字（或仅注释符单独出现）
        '/--\s+\d+\s*$/im',
        '/--\s*$/im',
        // SQL 内联注释绕过（MySQL /**/ 等效于空白）
        '/\/\*\*\/\s*(select|union|insert|update|delete|drop)\b/i',
        // UNION DISTINCT / UNION 变体
        '/\bunion\s*\([^)]*\)\s*select\b/i',
    ],

    // ========== 命令注入检测 ==========
    'command' => [
        '/\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(\s*[\'"`\s]*(rm\s+-|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|cmd\s|powershell\s|python\s|perl\s|php\s|ruby\s|lua\s)/i',
        '/`\s*(rm\s|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|python\s|perl\s|whoami|id\s|cat\s|ls\s)/i',
        '/(;|\|\||&&|\|)\s*(rm\s+-|wget\s|curl\s|nc\s|bash\s|sh\s|python\s|perl\s|cmd\s|powershell\s|whoami|id(?:\s|[;&|]|$)|cat\s)/i',
        '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(php|data|expect|input|glob|phar):/i',
        // 管道/换行符/反引号/$() 注入
        '/\|(\s*\/?\w+\/)*(sh|bash|python|perl|ruby|node|nc)\b/i',
        '/`[^`]{1,50}`/i',
        '/\$\(\s*(id|whoami|cat|ls|wget|curl|nslookup|ping)(?:\s|\))/i',
        '/%0[aA].*(?:id|whoami|cat|ls|wget|curl)/i',
    ],

    // ========== 路径遍历检测 ==========
    'path' => [
        '/(\.\.\/){2,}/',
        '/(\.\.\\\\){2,}/',
        '/\.\.(\/|\\\\)\.\.(\/|\\\\)/',
        '/%2e%2e%2f/i',
        '/%252e%252e%252f/i',
        '/%2e%2e(%2f|%5c)/i',
        '/%c0%af/i',
        '/%ef%bc%8f/i',
        '/%e0%80%af/i',
        // 空字节 / 截断攻击
        '/%00|\\x00|\.%00/i',
        '/\/(etc|proc|sys|var|home|root|usr\/local)\/(passwd|shadow|hosts|id_rsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i',
        // 注意: 使用 (?<!\w) 代替 \b, 因为 .(dot) 是非单词字符, \b 在 URL 路径中不会触发
        '/(?<!\w)(\.env|\.git\/)\b/i',
        '/(?<!\w)(\.svn|\.hg|\.bzr)\b/i',
        '/(?<!\w)(\.htaccess|\.htpasswd|web\.config)\b/i',
        '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json)\b/i',
        '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i',
        '/\.\.(\/|\\\\).*\.(exe|dll|bat|cmd|sh|php|py|pl|rb|jsp|asp|aspx)$/i',
        // 危险脚本/可执行文件扩展名（防御纵深：即使 url_path 检测层被关闭，高危检测层也能拦截）
        '/\.(?:php\d*|phtml|phar|shtml|jsp|jspx|asp|aspx|ashx|asmx|ascx|sh|bash|py|pyc|pl|pm|rb|exe|dll|bat|cmd|cgi|vbs|ps1)(?=\b|[?#&]|$)/i',
    ],

    // ========== LDAP注入检测 ==========
    'ldap' => [
        '/\*\s*\)\s*\(\s*\*/i',
        '/\)\s*\(\s*\|\s*\(/i',
        '/\)\s*\(\s*&\s*\(/i',
    ],

    // ========== XML/XXE检测 ==========
    'xml' => [
        '/<!ENTITY\s+\w+\s+SYSTEM\s+[\'"]/i',
        '/<!ENTITY\s+\w+\s+PUBLIC\s+[\'"]/i',
        '/<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\'"]/i',
        '/<!DOCTYPE\s+\w+\s+SYSTEM\s+[\'"]/i',
    ],

    // ========== NoSQL注入检测 ==========
    'nosql' => [
        // MongoDB 操作符支持两种格式: {"$eq":value} 和 $eq:value
        '/\$\s*(eq|ne|gt|gte|lt|lte|in|nin|regex|where|or|and)\s*["\s]*:/i',
        '/\$where\s*:\s*[\'"]\s*function\s*\(/i',
        '/\$\s*(exists|type|mod|all|size)\s*["\s]*:/i',
    ],

    // ========== 模板注入(SSTI)检测 ==========
    'ssti' => [
        '/\{\{\s*.*\|.*(raw|escape|filter)\s*\}\}/i',
        '/\{\{\s*\$\w+\s*->\s*\w+\s*\([^)]*\)\s*\}\}/i',
        '/\{\{.*(eval|exec|system|shell_exec|passthru).*\}\}/i',
    ],

    // ========== SSRF检测 ==========
    'ssrf' => [
        // 内网 IP 地址
        '/\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b/',
        // 云元数据服务
        '/\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/i',
        '/\blatest\/(meta-data|user-data|dynamic)\b/i',
        '/\b(instance-identity|instance-id|hostname|public-keys|security-credentials)\b/i',
        // 危险协议
        '/\b(gopher|dict|file|ftp|ldap|tftp|netdoc|jar):\/\//i',
        // URL参数 + 内网目标
        '/\b(?:url|redirect_uri|callback|webhook|target|link)\s*=\s*[\'"]?\s*(?:https?:)?\/\/(?:127\.|10\.|172\.1[6-9]|172\.2\d|172\.3[01]|192\.168\.|0\.0\.0\.0|localhost)/i',
        // DNS rebind 服务
        '/\b(rebind|dnsrebind|nip\.io|xip\.io|sslip\.io|burpcollaborator)\b/i',
        // 端口探测
        '/\b(port\s*[=:]\s*)\d{1,5}\b/i',
        // //evil.com 无协议重定向
        // '/\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}(?:\/|$|\?|&)/i',
    ],

    // ========== 编码绕过检测 ==========
    'encoding' => [
        '/%25(?:25)+[0-9a-f]{2}/i',
        '/%25(?:25)+/i',
        '/%(?:c0[\x80-\xbf]|e0%80[\x80-\xbf])/i',
        '/%00|\x00|%00;/i',
        '/&#[xX]?[0-9a-f]+;/i',
        '/%[0-9a-f]{2}.*&#x[0-9a-f]+;/i',
        '/%00%[0-9a-f]{2}/i',
        // IIS / ASP.NET %u Unicode 编码绕过
        '/%u[0-9a-f]{4}/i',
    ],

    // ========== CRLF/HTTP头注入检测 ==========
    'header_injection' => [
        '/(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|%0[dD]|%0[aA])/i',
        '/(?:content-type|content-length|set-cookie|location|transfer-encoding)\s*:\s*[\'"]?\s*[^\'"]*\r?\n/i',
        '/(?:<br\s*\/?>|\r\n|\n|\r)\s*(?:content-type|set-cookie):\s*/i',
    ],

    // ========== 开放重定向检测 ==========
    'redirect' => [
        // 策略 1：常见重定向参数名 + 外部URL（针对完整查询串）
        '/(?:redirect_uri|redirect_url|redirect|callback|return_url|return|goto|next|target|link|dest|destination|webhook|notify_url)\s*=\s*(?:https?:\/\/|%3[aA]%2[fF]%2[fF]|%2[fF]%2[fF])[^\s&]+/i',
        // 策略 2：独立参数值 — 任意外部URL（http/https/ftp协议开头）
        // 用于 checkUrlParamsForSsrRedirect 对单个参数值的检查
        '/^(?:https?|ftp):\/\/(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?\.[a-z]{2,})/i',
        // 策略 3：协议绕过 — //evil.com（攻击者常去掉 http: 前缀）
        '/^\/\/[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?\.[a-z]{2,}/i',
        // 策略 4：URL编码的外部域名 — %2f%2f 开头的重定向
        '/%2[fF]%2[fF][a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?\.[a-z]{2,}/i',
        // 策略 5：data: 或 javascript: 伪协议重定向
        '/(?:redirect|url|goto|target|link)\s*[=:]\s*(?:data\s*:\s*text\/html|javascript\s*:|vbscript\s*:)/i',
        // 策略 6：CRLF + Location 响应头注入（HTTP响应拆分 + 重定向）
        '/%0[dD]%0[aA].*(?:location|content-type|set-cookie)\s*:/i',
        // 策略 7：单斜杠重定向绕过 — /evil.com（某些框架会将相对路径重定向到外部）
        '/^\/[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.[a-z]{2,}\//i',
    ],

    // ========== 文件包含(LFI/RFI)检测 ==========
    'file_include' => [
        '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(http|ftp|https|php|data|expect|input|glob|phar):/i',
        '/\b(file_get_contents|readfile|fopen|file|show_source|highlight_file)\s*\(\s*[\'"]?\s*(http|ftp|https|php):/i',
        '/\/proc\/self\/(environ|cmdline|fd)\b/i',
        '/php:\/\/filter\/((?:convert|read|write|resource)[^\/]*\/)/i',
        '/php:\/\/input\b/i',
        '/data:\/\/text\/plain;base64,/i',
        '/expect:\/\/\w+/i',
    ],
];
