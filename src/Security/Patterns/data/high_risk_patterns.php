<?php

/**
 * 高危攻击检测模式定义（v6.0 元数据格式）
 *
 * 每条规则包含：
 *   pattern — 正则表达式
 *   desc    — 规则说明（用于注释和调试）
 *   risk    — 风险等级：high / medium / low
 *
 * ⚠️ 此文件不会在 php artisan optimize 时加载
 * 仅在实际执行安全检查时由 PatternService 按需加载
 */

return [
    // ========== SQL注入检测 ==========
    'sql' => [
        ['pattern' => '/\bunion\s+(all\s+)?select\s+(null|\d+|0x[0-9a-f]+|\$\d+|\?)/i', 'desc' => 'UNION联合查询注入（如 union select null）', 'risk' => 'high'],
        ['pattern' => '/;\s*(drop|truncate)\s+(table|database)\b/i', 'desc' => '堆叠查询：DROP/TRUNCATE 删表/删库', 'risk' => 'high'],
        ['pattern' => '/xp_cmdshell\s*\(/i', 'desc' => 'SQL Server xp_cmdshell 系统命令执行', 'risk' => 'high'],
        ['pattern' => '/sp_oamethod\s*/i', 'desc' => 'SQL Server sp_oamethod OLE自动化攻击', 'risk' => 'high'],
        ['pattern' => '/sp_oacreate\s*/i', 'desc' => 'SQL Server sp_oacreate OLE对象创建攻击', 'risk' => 'high'],
        ['pattern' => '/load_file\s*\(\s*[\'"]?\s*\//i', 'desc' => 'MySQL load_file() 读取服务器文件', 'risk' => 'high'],
        ['pattern' => '/into\s+(outfile|dumpfile)\s+[\'"]?\s*\//i', 'desc' => 'MySQL INTO OUTFILE/DUMPFILE 写文件', 'risk' => 'high'],
        ['pattern' => '/sleep\s*\(\s*[\'"]?\d{2,}/i', 'desc' => 'MySQL SLEEP() 时间盲注（延时≥2秒）', 'risk' => 'high'],
        ['pattern' => '/benchmark\s*\(\s*\d{5,}/i', 'desc' => 'MySQL BENCHMARK() 时间盲注（次数≥5万）', 'risk' => 'high'],
        ['pattern' => '/pg_sleep\s*\(\s*[\'"]?\d{2,}/i', 'desc' => 'PostgreSQL pg_sleep() 时间盲注', 'risk' => 'high'],
        ['pattern' => '/waitfor\s+delay\s*[\'"]\d{2,}/i', 'desc' => 'SQL Server WAITFOR DELAY 时间盲注', 'risk' => 'high'],
        ['pattern' => '/extractvalue\s*\(\s*[^,]+,\s*concat/i', 'desc' => 'MySQL extractvalue() 报错注入', 'risk' => 'high'],
        ['pattern' => '/updatexml\s*\(\s*[^,]+,\s*concat/i', 'desc' => 'MySQL updatexml() 报错注入', 'risk' => 'high'],
        ['pattern' => '/floor\s*\(\s*rand\s*\(/i', 'desc' => 'MySQL floor(rand()) 报错注入（经典双查询）', 'risk' => 'high'],
        ['pattern' => '/\bcase\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)/i', 'desc' => 'CASE WHEN 条件分支盲注', 'risk' => 'high'],
        ['pattern' => '/\bif\s*\(\s*.*,\s*(sleep|benchmark|pg_sleep)/i', 'desc' => 'IF() 条件分支盲注', 'risk' => 'high'],
        ['pattern' => '/\/\*!?\d{5,}\*\/\s*(union|select)\b/i', 'desc' => 'MySQL 注释版版本号绕过（如 /*!50000 select */）', 'risk' => 'medium'],
        ['pattern' => '/\/\*!?\d{5,}(?:union|select|drop|insert|update|delete|alter)\b/i', 'desc' => 'MySQL 注释版关键字绕过', 'risk' => 'medium'],
        ['pattern' => '/\/\*[^*]*\*\/\s*(and|or)\s+[\'"\d]/i', 'desc' => '注释分隔后的 AND/OR 条件拼接', 'risk' => 'medium'],
        ['pattern' => '/(charset|character\s+set)\s*=\s*utf8/i', 'desc' => '利用 charset 设置进行编码绕过注入', 'risk' => 'low'],
        ['pattern' => '/unhex\s*\(/i', 'desc' => 'MySQL UNHEX() 解码注入载荷', 'risk' => 'medium'],
        ['pattern' => '/hex\s*\(\s*[\'"]?[a-z0-9_]+[\'"]?\s*\)/i', 'desc' => 'HEX() 编码注入载荷（常与UNHEX配合）', 'risk' => 'medium'],
        ['pattern' => '/@@(version|datadir|basedir|hostname)/i', 'desc' => '@@变量信息探测（版本/数据目录等）', 'risk' => 'medium'],
        ['pattern' => '/database\s*\(\s*\)/i', 'desc' => '探测当前数据库名', 'risk' => 'medium'],
        ['pattern' => '/user\s*\(\s*\)/i', 'desc' => '探测当前数据库用户名', 'risk' => 'medium'],
        ['pattern' => '/system_user\s*\(/i', 'desc' => '探测系统用户（MySQL system_user()）', 'risk' => 'medium'],
        ['pattern' => '/current_user\s*\(/i', 'desc' => '探测当前用户（current_user()）', 'risk' => 'medium'],
        ['pattern' => '/group_concat\s*\(/i', 'desc' => 'GROUP_CONCAT() 批量数据提取', 'risk' => 'medium'],
        ['pattern' => '/concat_ws\s*\(/i', 'desc' => 'CONCAT_WS() 字符串拼接提取数据', 'risk' => 'medium'],
        ['pattern' => '/%df%27/i', 'desc' => 'GBK宽字节注入（%df吃掉转义符）', 'risk' => 'high'],
        ['pattern' => '/%bf%27/i', 'desc' => 'GBK宽字节注入变体（%bf%27）', 'risk' => 'high'],
        ['pattern' => '/\b1\s*=\s*1\b/i', 'desc' => '经典永真条件（1=1）用于绕过认证', 'risk' => 'low'],
        ['pattern' => '/\'\s*(?:or|and)\s+\d+\s*=\s*\d+/i', 'desc' => '引号闭合后的 OR/AND 数字等式注入', 'risk' => 'low'],
        ['pattern' => '/[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i', 'desc' => '引号内 OR/AND 数字等式注入', 'risk' => 'low'],
        ['pattern' => '/--\s+\d+\s*$/im', 'desc' => 'SQL行尾注释（-- 数字）用于截断原SQL', 'risk' => 'medium'],
        ['pattern' => '/--\s*$/im', 'desc' => 'SQL行尾注释（--）截断原SQL', 'risk' => 'medium'],
        ['pattern' => '/\/\*\*\/\s*(select|union|insert|update|delete|drop)\b/i', 'desc' => '内联注释等效空白绕过（/**/select）', 'risk' => 'medium'],
        ['pattern' => '/\bunion\s*\([^)]*\)\s*select\b/i', 'desc' => 'UNION括号绕过（union (select ...) select）', 'risk' => 'high'],
    ],

    // ========== 命令注入检测 ==========
    'command' => [
        ['pattern' => '/\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(\s*[\'"`\s]*(rm\s+-|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|cmd\s|powershell\s|python\s|perl\s|php\s|ruby\s|lua\s)/i', 'desc' => 'PHP危险函数+危险命令组合执行', 'risk' => 'high'],
        ['pattern' => '/`\s*(rm\s|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|python\s|perl\s|whoami|id\s|cat\s|ls\s)/i', 'desc' => '反引号命令执行（`rm ...`）', 'risk' => 'high'],
        ['pattern' => '/(;|\|\||&&|\|)\s*(rm\s+-|wget\s|curl\s|nc\s|bash\s|sh\s|python\s|perl\s|cmd\s|powershell\s|whoami|id(?:\s|[;&|]|$)|cat\s)/i', 'desc' => '命令分隔符/管道后接危险命令', 'risk' => 'high'],
        ['pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(php|data|expect|input|glob|phar):/i', 'desc' => 'PHP伪协议文件包含导致命令执行', 'risk' => 'high'],
        ['pattern' => '/\|(\s*\/?\w+\/)*(sh|bash|python|perl|ruby|node|nc)\b/i', 'desc' => '管道符后接脚本解释器执行任意命令', 'risk' => 'high'],
        ['pattern' => '/`[^`]{1,50}`/i', 'desc' => '反引号内短命令执行（通用特征）', 'risk' => 'medium'],
        ['pattern' => '/\$\(\s*(id|whoami|cat|ls|wget|curl|nslookup|ping)(?:\s|\))/i', 'desc' => '$() 命令替换执行（如 $(id)）', 'risk' => 'high'],
        ['pattern' => '/%0[aA].*(?:id|whoami|cat|ls|wget|curl)/i', 'desc' => 'URL编码换行符后接命令执行（%0a命令）', 'risk' => 'high'],
    ],

    // ========== 路径遍历检测 ==========
    'path' => [
        ['pattern' => '/(\.\.\/){2,}/', 'desc' => 'Linux多级目录穿越（../../..）', 'risk' => 'high'],
        ['pattern' => '/(\.\.\\\\){2,}/', 'desc' => 'Windows多级目录穿越（..\\..\\）', 'risk' => 'high'],
        ['pattern' => '/\.\.(\/|\\\\)\.\.(\/|\\\\)/', 'desc' => '混合路径遍历（../..或..\\..）', 'risk' => 'high'],
        ['pattern' => '/%2e%2e%2f/i', 'desc' => 'URL编码路径穿越（%2e%2e%2f = ../）', 'risk' => 'high'],
        ['pattern' => '/%252e%252e%252f/i', 'desc' => '双重URL编码路径穿越', 'risk' => 'high'],
        ['pattern' => '/%2e%2e(%2f|%5c)/i', 'desc' => 'URL编码../或..\\路径穿越', 'risk' => 'high'],
        ['pattern' => '/%c0%af/i', 'desc' => 'UTF-8过度编码路径穿越（%c0%af = /）', 'risk' => 'high'],
        ['pattern' => '/%ef%bc%8f/i', 'desc' => '全角斜杠编码绕过（U+FF0F）', 'risk' => 'high'],
        ['pattern' => '/%e0%80%af/i', 'desc' => 'UTF-8三字节过度编码路径穿越', 'risk' => 'high'],
        ['pattern' => '/%00|\\x00|\.%00/i', 'desc' => '空字节截断攻击（绕过扩展名检查）', 'risk' => 'high'],
        ['pattern' => '/\/(etc|proc|sys|var|home|root|usr\/local)\/(passwd|shadow|hosts|id_rsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i', 'desc' => '敏感系统文件访问（passwd/shadow/id_rsa等）', 'risk' => 'high'],
        ['pattern' => '/(?<!\w)(\.env|\.git\/)\b/i', 'desc' => '.env配置文件或.git目录访问', 'risk' => 'medium'],
        ['pattern' => '/(?<!\w)(\.svn|\.hg|\.bzr)\b/i', 'desc' => '版本控制目录泄露（.svn/.hg/.bzr）', 'risk' => 'medium'],
        ['pattern' => '/(?<!\w)(\.htaccess|\.htpasswd|web\.config)\b/i', 'desc' => 'Web服务器配置文件访问', 'risk' => 'medium'],
        ['pattern' => '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json)\b/i', 'desc' => '项目依赖文件泄露（composer/package）', 'risk' => 'low'],
        ['pattern' => '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i', 'desc' => 'Windows系统目录穿越', 'risk' => 'high'],
        ['pattern' => '/\.\.(\/|\\\\).*\.(exe|dll|bat|cmd|sh|php|py|pl|rb|jsp|asp|aspx)$/i', 'desc' => '目录穿越后接可执行/脚本文件', 'risk' => 'high'],
        ['pattern' => '/\.(?:php\d*|phtml|phar|shtml|jsp|jspx|asp|aspx|ashx|asmx|ascx|sh|bash|py|pyc|pl|pm|rb|exe|dll|bat|cmd|cgi|vbs|ps1)(?=\b|[?#&]|$)/i', 'desc' => 'URL路径中出现危险脚本/可执行扩展名', 'risk' => 'medium'],
    ],

    // ========== LDAP注入检测 ==========
    'ldap' => [
        ['pattern' => '/\*\s*\)\s*\(\s*\*/i', 'desc' => 'LDAP通配符过滤器注入（*)(*）', 'risk' => 'high'],
        ['pattern' => '/\)\s*\(\s*\|\s*\(/i', 'desc' => 'LDAP OR过滤器注入（)(|(）', 'risk' => 'high'],
        ['pattern' => '/\)\s*\(\s*&\s*\(/i', 'desc' => 'LDAP AND过滤器注入（)(&()）', 'risk' => 'high'],
    ],

    // ========== XML/XXE检测 ==========
    'xml' => [
        ['pattern' => '/<!ENTITY\s+\w+\s+SYSTEM\s+[\'"]/i', 'desc' => 'XXE外部实体声明（SYSTEM）', 'risk' => 'high'],
        ['pattern' => '/<!ENTITY\s+\w+\s+PUBLIC\s+[\'"]/i', 'desc' => 'XXE公共实体声明（PUBLIC）', 'risk' => 'high'],
        ['pattern' => '/<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\'"]/i', 'desc' => 'XXE参数实体声明（% name SYSTEM）', 'risk' => 'high'],
        ['pattern' => '/<!DOCTYPE\s+\w+\s+SYSTEM\s+[\'"]/i', 'desc' => 'DOCTYPE SYSTEM 外部DTD引入', 'risk' => 'high'],
    ],

    // ========== NoSQL注入检测 ==========
    'nosql' => [
        ['pattern' => '/\$\s*(eq|ne|gt|gte|lt|lte|in|nin|regex|where|or|and)\s*["\s]*:/i', 'desc' => 'MongoDB操作符注入（$eq/$ne/$gt等）', 'risk' => 'high'],
        ['pattern' => '/\$where\s*:\s*[\'"]\s*function\s*\(/i', 'desc' => 'MongoDB $where JavaScript函数注入', 'risk' => 'high'],
        ['pattern' => '/\$\s*(exists|type|mod|all|size)\s*["\s]*:/i', 'desc' => 'MongoDB其他危险操作符注入', 'risk' => 'medium'],
    ],

    // ========== 模板注入(SSTI)检测 ==========
    'ssti' => [
        ['pattern' => '/\{\{\s*.*\|.*(raw|escape|filter)\s*\}\}/i', 'desc' => 'Twig/Jinja2 模板过滤器注入（|raw）', 'risk' => 'high'],
        ['pattern' => '/\{\{\s*\$\w+\s*->\s*\w+\s*\([^)]*\)\s*\}\}/i', 'desc' => 'PHP对象方法调用模板注入', 'risk' => 'high'],
        ['pattern' => '/\{\{.*(eval|exec|system|shell_exec|passthru).*\}\}/i', 'desc' => '模板内危险函数调用注入', 'risk' => 'high'],
    ],

    // ========== SSRF检测 ==========
    'ssrf' => [
        ['pattern' => '/\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b/', 'desc' => 'SSRF内网IPv4地址探测', 'risk' => 'high'],
        ['pattern' => '/\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/i', 'desc' => '云服务元数据服务地址探测', 'risk' => 'high'],
        ['pattern' => '/\blatest\/(meta-data|user-data|dynamic)\b/i', 'desc' => 'AWS/阿里云元数据API路径访问', 'risk' => 'high'],
        ['pattern' => '/\b(instance-identity|instance-id|hostname|public-keys|security-credentials)\b/i', 'desc' => '云实例敏感信息获取', 'risk' => 'high'],
        ['pattern' => '/\b(gopher|dict|file|ftp|ldap|tftp|netdoc|jar):\/\//i', 'desc' => 'SSRF危险协议访问（gopher/dict/file等）', 'risk' => 'high'],
        ['pattern' => '/\b(?:url|redirect_uri|callback|webhook|target|link)\s*=\s*[\'"]?\s*(?:https?:)?\/\/(?:127\.|10\.|172\.1[6-9]|172\.2\d|172\.3[01]|192\.168\.|0\.0\.0\.0|localhost)/i', 'desc' => 'URL参数指向内网地址', 'risk' => 'high'],
        ['pattern' => '/\b(rebind|dnsrebind|nip\.io|xip\.io|sslip\.io|burpcollaborator)\b/i', 'desc' => 'DNS重绑定攻击域名', 'risk' => 'high'],
        ['pattern' => '/\b(port\s*[=:]\s*)\d{1,5}\b/i', 'desc' => 'SSRF端口探测参数', 'risk' => 'medium'],
    ],

    // ========== 编码绕过检测 ==========
    'encoding' => [
        ['pattern' => '/%25(?:25)+[0-9a-f]{2}/i', 'desc' => '多重URL编码绕过（%2525...）', 'risk' => 'medium'],
        ['pattern' => '/%25(?:25)+/i', 'desc' => '多层%25编码序列', 'risk' => 'low'],
        ['pattern' => '/%(?:c0[\x80-\xbf]|e0%80[\x80-\xbf])/i', 'desc' => 'UTF-8过度编码绕过（单字符多字节）', 'risk' => 'high'],
        ['pattern' => '/%00|\x00|%00;/i', 'desc' => '空字节编码绕过', 'risk' => 'high'],
        ['pattern' => '/&#[xX]?[0-9a-f]+;/i', 'desc' => 'HTML实体编码绕过（&#x3c; = <）', 'risk' => 'medium'],
        ['pattern' => '/%[0-9a-f]{2}.*&#x[0-9a-f]+;/i', 'desc' => '混合URL编码+HTML实体绕过', 'risk' => 'medium'],
        ['pattern' => '/%00%[0-9a-f]{2}/i', 'desc' => '空字节后接编码序列', 'risk' => 'high'],
        ['pattern' => '/%u[0-9a-f]{4}/i', 'desc' => 'IIS/ASP.NET %uUnicode编码绕过', 'risk' => 'medium'],
    ],

    // ========== CRLF/HTTP头注入检测 ==========
    'header_injection' => [
        ['pattern' => '/(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|%0[dD]|%0[aA])/i', 'desc' => 'CRLF换行符序列（HTTP响应拆分）', 'risk' => 'high'],
        ['pattern' => '/(?:content-type|content-length|set-cookie|location|transfer-encoding)\s*:\s*[\'"]?\s*[^\'"]*\r?\n/i', 'desc' => 'HTTP头键值对后接换行（响应头注入）', 'risk' => 'high'],
        ['pattern' => '/(?:<br\s*\/?>|\r\n|\n|\r)\s*(?:content-type|set-cookie):\s*/i', 'desc' => '换行后接content-type/set-cookie伪头', 'risk' => 'high'],
    ],

    // ========== 开放重定向检测 ==========
    'redirect' => [
        ['pattern' => '/(?:redirect_uri|redirect_url|redirect|callback|return_url|return|goto|next|target|link|dest|destination|webhook|notify_url)\s*=\s*(?:https?:\/\/|%3[aA]%2[fF]%2[fF]|%2[fF]%2[fF])[^\s&]+/i', 'desc' => '重定向参数指向外部完整URL', 'risk' => 'medium'],
        ['pattern' => '/^(?:https?|ftp):\/\/(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?\.[a-z]{2,})/i', 'desc' => '参数值为独立外部URL（IP或域名）', 'risk' => 'medium'],
        ['pattern' => '/^\/[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.[a-z]{2,}\//i', 'desc' => '单斜杠后接域名（/evil.com/框架绕过）', 'risk' => 'medium'],
        ['pattern' => '/%2[fF]%2[fF][a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?\.[a-z]{2,}/i', 'desc' => 'URL编码双斜杠后接域名', 'risk' => 'medium'],
        ['pattern' => '/(?:redirect|url|goto|target|link)\s*[=:]\s*(?:data\s*:\s*text\/html|javascript\s*:|vbscript\s*:)/i', 'desc' => '重定向参数使用data:/javascript:伪协议', 'risk' => 'high'],
        ['pattern' => '/%0[dD]%0[aA].*(?:location|content-type|set-cookie)\s*:/i', 'desc' => 'CRLF后接location/content-type/set-cookie', 'risk' => 'high'],
    ],

    // ========== 文件包含(LFI/RFI)检测 ==========
    'file_include' => [
        ['pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(http|ftp|https|php|data|expect|input|glob|phar):/i', 'desc' => 'PHP文件包含伪协议（php:///data://等）', 'risk' => 'high'],
        ['pattern' => '/\b(file_get_contents|readfile|fopen|file|show_source|highlight_file)\s*\(\s*[\'"]?\s*(http|ftp|https|php):/i', 'desc' => 'PHP文件读取函数+伪协议', 'risk' => 'high'],
        ['pattern' => '/\/proc\/self\/(environ|cmdline|fd)\b/i', 'desc' => 'Linux /proc/self 信息读取', 'risk' => 'high'],
        ['pattern' => '/php:\/\/filter\/((?:convert|read|write|resource)[^\/]*\/)/i', 'desc' => 'php://filter 封装器读取任意文件', 'risk' => 'high'],
        ['pattern' => '/php:\/\/input\b/i', 'desc' => 'php://input 原始POST数据包含', 'risk' => 'high'],
        ['pattern' => '/data:\/\/text\/plain;base64,/i', 'desc' => 'data://协议Base64编码包含', 'risk' => 'high'],
        ['pattern' => '/expect:\/\/\w+/i', 'desc' => 'expect://协议执行系统命令', 'risk' => 'high'],
    ],
];
