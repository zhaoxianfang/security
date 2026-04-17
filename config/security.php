<?php

/**
 * Laravel 安全中间件配置文件
 *
 * 配置说明：
 * 1. 所有配置项均支持通过环境变量（.env文件）覆盖
 * 2. 高危模式正则经过精心调校，确保高拦截率、低误报率
 * 3. 支持Markdown内容智能识别，文档类请求不会被误拦截
 * 4. IP黑白名单支持CIDR格式（如 192.168.1.0/24）
 *
 * 快速配置建议：
 * - 开发环境：可关闭 rate_limit 避免调试时触发限流
 * - 生产环境：建议启用所有检测项，rate_limit 适当收紧
 * - 内网部署：将内网IP段加入 trusted_ips，提升性能
 *
 * @see \zxf\Security\Middleware\SecurityMiddleware
 */

return [

    /*
    |--------------------------------------------------------------------------
    | 基础开关配置
    |--------------------------------------------------------------------------
    |
    | 控制中间件的整体启用状态和日志记录功能。
    | 可通过 .env 文件中的 SECURITY_ENABLED 和 SECURITY_LOG_ENABLED 覆盖。
    |
    */

    // 主开关：是否启用安全中间件
    // 设为 false 将完全禁用所有安全检查，请求直接通过
    // 环境变量：SECURITY_ENABLED
    'enabled' => env('SECURITY_ENABLED', true),

    // 日志开关：是否记录安全威胁日志
    // 记录到 Laravel 默认日志通道（通常 storage/logs/laravel.log）
    // 环境变量：SECURITY_LOG_ENABLED
    'log_enabled' => env('SECURITY_LOG_ENABLED', true),

    // 日志级别：可选 'debug', 'info', 'warning', 'error', 'critical'
    // 开发环境建议使用 'debug'，生产环境建议使用 'warning'
    // 环境变量：SECURITY_LOG_LEVEL
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),

    // 是否记录完整请求数据（含POST数据）
    // 注意：生产环境开启可能记录敏感信息，请谨慎使用
    // 环境变量：SECURITY_LOG_FULL_REQUEST
    'log_full_request' => env('SECURITY_LOG_FULL_REQUEST', false),

    /*
    |--------------------------------------------------------------------------
    | 检测层级开关配置
    |--------------------------------------------------------------------------
    |
    | 允许单独启用/禁用特定的安全检测层级。
    | 所有检测默认启用，可以按需关闭某些检测以减少误报或提升性能。
    |
    | 注意：
    | - IP白名单和黑名单不受这些开关控制（始终启用）
    | - 建议生产环境保持所有检测启用
    |
    */

    'detection_layers' => [
        // URL路径攻击检测（路径遍历等）
        'url_path' => env('SECURITY_DETECT_URL_PATH', true),

        // 多重编码检测（编码绕过攻击）
        'encoding' => env('SECURITY_DETECT_ENCODING', true),

        // User-Agent检查
        'user_agent' => env('SECURITY_DETECT_USER_AGENT', true),

        // HTTP头检查
        'headers' => env('SECURITY_DETECT_HEADERS', true),

        // 请求体大小检查
        'body_size' => env('SECURITY_DETECT_BODY_SIZE', true),

        // 速率限制
        'rate_limit' => env('SECURITY_DETECT_RATE_LIMIT', true),

        // HTTP方法检查
        'http_method' => env('SECURITY_DETECT_HTTP_METHOD', true),

        // URL长度检查
        'url_length' => env('SECURITY_DETECT_URL_LENGTH', true),

        // 高危攻击检测（SQL注入、命令注入等）
        'high_risk' => env('SECURITY_DETECT_HIGH_RISK', true),

        // XSS攻击检测
        'xss' => env('SECURITY_DETECT_XSS', true),

        // 文件上传检查
        'upload' => env('SECURITY_DETECT_UPLOAD', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | 信任IP配置
    |--------------------------------------------------------------------------
    |
    | trusted_ips 中的IP地址会跳过所有安全检查，直接放行。
    | 适用于：内网环境、负载均衡器、监控探针、可信合作伙伴。
    |
    | 支持格式：
    | - 单个IP：'192.168.1.100'
    | - CIDR网段：'192.168.0.0/16'（整个B类私网）
    |
    | 警告：谨慎添加公网IP到白名单，这会让该IP绕过所有防护！
    |
    */

    'trusted_ips' => [
        // IPv4 本地回环
        '127.0.0.1',

        // IPv6 本地回环
        '::1',

        // RFC1918 私有地址段 - A类（大型网络）
        '10.0.0.0/8',

        // RFC1918 私有地址段 - B类（中型网络）
        '172.16.0.0/12',

        // RFC1918 私有地址段 - C类（小型网络）
        '192.168.0.0/16',
    ],

    /*
    |--------------------------------------------------------------------------
    | 速率限制配置
    |--------------------------------------------------------------------------
    |
    | 防止暴力破解、CC攻击、API滥用。
    | 使用 Laravel 原生的 RateLimiter，支持多种缓存后端。
    |
    | 触发限流后的行为：
    | - 返回 HTTP 429 Too Many Requests
    | - 客户端需等待 decay_minutes 时间后恢复
    |
    | 阈值建议：
    | - 普通网站：60次/分钟
    | - API服务：300次/分钟
    | - 后台管理：20次/分钟（更严格）
    |
    */

    'rate_limit' => [
        // 是否启用速率限制
        // 环境变量：SECURITY_RATE_LIMIT_ENABLED
        'enabled' => env('SECURITY_RATE_LIMIT_ENABLED', true),

        // 每 decay_minutes 分钟内允许的最大请求数
        // 超过此数量将触发限流
        // 环境变量：SECURITY_RATE_LIMIT_ATTEMPTS
        'max_attempts' => env('SECURITY_RATE_LIMIT_ATTEMPTS', 60),

        // 限流时间窗口（分钟）
        // 例如设为1表示每分钟限制 max_attempts 次
        // 环境变量：SECURITY_RATE_LIMIT_DECAY
        'decay_minutes' => env('SECURITY_RATE_LIMIT_DECAY', 1),
    ],

    /*
    |--------------------------------------------------------------------------
    | IP 黑名单
    |--------------------------------------------------------------------------
    |
    | 已知的恶意IP地址列表，这些IP会被立即拦截（HTTP 403）。
    |
    | 支持格式：
    | - 字符串IP：'192.168.1.100'
    | - CIDR网段：'10.0.0.0/24'
    | - 闭包函数：function($ip, $request) { return $ip === '1.1.1.1'; }
    | - 类名（实现 IpCheckerInterface）：'App\Security\CustomIpChecker'
    | - 可调用数组：['App\Security\IpChecker', 'isBlocked']
    |
    | 适用场景：
    | - 封禁已确认的攻击者IP
    | - 阻止已知的恶意爬虫、扫描器
    | - 配合日志分析自动封禁暴力破解源
    | - 从数据库/Redis动态获取黑名单
    |
    */

    'blacklist' => [
        // 示例：封禁单个IP
        // '192.168.1.100',

        // 示例：封禁整个网段
        // '10.0.0.0/24',

        // 示例：使用闭包动态判断
        // function($ip, $request) {
        //     return \App\Models\BlockedIp::where('ip', $ip)->exists();
        // },

        // 示例：使用自定义检查类
        // \App\Security\DynamicBlacklistChecker::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | IP 白名单
    |--------------------------------------------------------------------------
    |
    | 与 trusted_ips 类似，但语义上用于特定的业务场景。
    | 例如：合作伙伴API、支付回调IP、Webhook源等。
    |
    | 支持格式（同 blacklist）：
    | - 字符串IP、CIDR网段、闭包、类、可调用数组
    |
    | 注意：白名单IP也会跳过 rate_limit 检查！
    | 如果只想跳过攻击检测但保留限流，应使用 trusted_ips。
    |
    */

    'whitelist' => [
        // 示例：合作伙伴服务器
        // '203.0.113.50',

        // 示例：支付网关回调IP段
        // '198.51.100.0/24',

        // 示例：使用闭包动态判断
        // function($ip, $request) {
        //     return \App\Models\PartnerIp::where('ip', $ip)->exists();
        // },
    ],

    /*
    |--------------------------------------------------------------------------
    | 高危攻击模式检测
    |--------------------------------------------------------------------------
    |
    | 这些正则表达式用于检测直接威胁系统安全的攻击。
    | 模式经过精心挑选，确保：
    | 1. 高检出率 - 不漏过真实攻击
    | 2. 低误报率 - 不误拦截正常请求
    |
    | 分类说明：
    | - sql：SQL注入攻击（数据库安全）
    | - command：命令注入（服务器安全）
    | - path：路径遍历（文件系统安全）
    | - ldap：LDAP注入（目录服务安全）
    | - xml：XML注入/XXE（解析器安全）
    |
    */

    'high_risk_patterns' => [

        // ========== SQL注入检测 ==========
        // 检测可能导致数据泄露、数据篡改、服务器接管的SQL攻击
        // 核心原则：仅检测明确的攻击特征，避免正常SQL被误拦截
        'sql' => [
            // UNION注入 - 最常用的数据窃取技术
            // 严格匹配：union + select 组合，且select后跟数字/null/十六进制（注入特征）
            '/\bunion\s+(all\s+)?select\s+(null|\d+|0x[0-9a-f]+|\$\d+|\?)/i',

            // 堆叠查询 - 执行多条SQL语句（SQL Server/PostgreSQL）
            // 示例：'; DROP TABLE users;--
            // 要求分号后紧跟危险操作，减少正常SQL误报
            '/;\s*(drop|truncate)\s+(table|database)\b/i',

            // SQL Server 特有危险功能 - xp_cmdshell 可直接执行操作系统命令
            '/xp_cmdshell\s*\(/i',
            '/sp_oamethod\s*/i',
            '/sp_oacreate\s*/i',

            // MySQL 文件操作 - 可能导致服务器文件泄露
            // 示例：SELECT LOAD_FILE('/etc/passwd')
            '/load_file\s*\(\s*[\'"]?\s*\//i',
            '/into\s+(outfile|dumpfile)\s+[\'"]?\s*\//i',

            // 时间盲注函数 - 用于无回显的数据窃取
            // 必须跟具体数字参数才是攻击特征
            '/sleep\s*\(\s*[\'"]?\d{2,}/i',  // 2位以上数字（正常sleep(1)可能是业务需求）
            '/benchmark\s*\(\s*\d{5,}/i',     // 5位以上数字
            '/pg_sleep\s*\(\s*[\'"]?\d{2,}/i',
            '/waitfor\s+delay\s*[\'"]\d{2,}/i',  // SQL Server延时注入

            // 错误注入 - 通过报错获取数据库信息
            '/extractvalue\s*\(\s*[^,]+,\s*concat/i',
            '/updatexml\s*\(\s*[^,]+,\s*concat/i',
            '/floor\s*\(\s*rand\s*\(/i',

            // 布尔盲注特征 - 条件判断+延时或报错函数
            '/\bcase\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)/i',
            '/\bif\s*\(\s*.*,\s*(sleep|benchmark|pg_sleep)/i',

            // 注释绕过 - 攻击者常用技巧（仅匹配明确的攻击模式）
            '/\/\*!?\d{5,}\*\/\s*(union|select)\b/i',  // 长数字注释后跟SQL关键字
            '/\/\*[^*]*\*\/\s*(and|or)\s+[\'"\d]/i',  // 注释后接条件

            // 字符编码绕过
            '/(charset|character\s+set)\s*=\s*utf8/i',  // 可能的编码攻击
            '/unhex\s*\(/i',  // MySQL unhex函数常用于绕过

            // 信息获取函数
            '/@@(version|datadir|basedir|hostname)/i',
            '/database\s*\(\s*\)/i',
            '/user\s*\(\s*\)/i',
            '/system_user\s*\(/i',

            // 危险的SQL函数组合
            '/group_concat\s*\(/i',
            '/concat_ws\s*\(/i',
        ],

        // ========== 命令注入检测 ==========
        // 检测可能在服务器上执行任意系统命令的攻击
        // 核心原则：必须同时满足函数+危险命令才会触发
        'command' => [
            // PHP命令执行函数 + 危险命令组合
            // 严格匹配：函数名( + 可选空格/引号 + 危险命令
            '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*[\'"`\s]*(rm\s+-|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|cmd\s|powershell\s|python\s|perl\s)/i',

            // 反引号执行（PHP/Shell）+ 危险命令
            '/`\s*(rm\s|wget\s|curl\s|nc\s|netcat\s|bash\s|sh\s|python\s|perl\s)/i',

            // 命令连接符 + 危险命令
            // 示例：; rm -rf / 或 && wget http://evil.com/shell.sh
            '/(;|\|\||&&)\s*(rm\s+-|wget\s|curl\s|nc\s|bash\s|sh\s|python\s|perl\s|cmd\s|powershell\s)/i',

            // 文件包含导致的RCE（PHP）
            // 匹配危险协议封装器
            '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(php|data|expect|input):/i',
        ],

        // ========== 路径遍历检测 ==========
        // 检测试图访问Web根目录外文件的攻击
        // 注意：仅检测明确的攻击特征，避免正常相对路径被误拦截
        'path' => [
            // 经典路径遍历（至少两个../）
            // 示例：../../../etc/passwd
            '/(\.\.\/){2,}/',

            // Windows路径遍历（至少两个..\）
            '/(\.\.\\\\){2,}/',

            // 混合路径遍历（UNIX/Windows混合）
            '/\.\.(\/|\\\\)\.\.(\/|\\\\)/',

            // URL编码的遍历（双重编码）
            '/%2e%2e%2f/i',
            '/%252e%252e%252f/i',
            '/%2e%2e(%2f|%5c)/i',

            // Unicode规范化攻击（常见绕过技术）
            '/%c0%af/i',  // /的UTF-8过度编码
            '/%ef%bc%8f/i',  // 全角斜线
            '/%e0%80%af/i',  // 另一种UTF-8编码

            // 敏感文件访问尝试（仅限Linux系统文件）
            '/\/(etc|proc|sys|var|home|root|usr\/local)\/(passwd|shadow|hosts|id_rsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i',

            // 版本控制/配置文件泄露（更全面的检测）
            '/\b(\.env|\.git\/)\b/i',
            '/\b(\.svn|\.hg|\.bzr)\b/i',
            '/\b(\.htaccess|\.htpasswd|web\.config)\b/i',
            '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json)\b/i',

            // Windows系统目录穿越
            '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i',

            // 危险的文件扩展名访问
            '/\.\.(\/|\\\\).*\.(exe|dll|bat|cmd|sh|php|py|pl|rb|jsp|asp|aspx)$/i',
        ],

        // ========== LDAP注入检测 ==========
        // 检测针对LDAP目录服务的注入攻击
        'ldap' => [
            // LDAP过滤器注入
            '/\*\s*\)\s*\(\s*\*/i',
            '/\)\s*\(\s*\|\s*\(/i',
            '/\)\s*\(\s*&\s*\(/i',
        ],

        // ========== XML注入/XXE检测 ==========
        // 检测XML外部实体注入攻击
        'xml' => [
            // XXE声明
            '/<!ENTITY\s+\w+\s+SYSTEM\s+[\'"]/i',
            '/<!ENTITY\s+\w+\s+PUBLIC\s+[\'"]/i',

            // 参数实体（更危险的XXE变体）
            '/<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\'"]/i',

            // 外部DTD
            '/<!DOCTYPE\s+\w+\s+SYSTEM\s+[\'"]/i',
        ],

        // ========== 编码绕过检测 ==========
        // 检测使用各种编码技术绕过WAF的攻击
        'encoding' => [
            // 多重URL编码
            '/%25(?:25)*[0-9a-f]/i',

            // Unicode规范化攻击（更多变体）
            '/%(?:c0[\x80-\xbf]|e0%80[\x80-\xbf])/i',

            // 空字节注入（PHP/C风格字符串终止）
            '/%00|\x00|%00;/i',

            // HTML实体编码（潜在的XSS绕过）
            '/&#[xX]?[0-9a-f]+;/i',
        ],

        // ========== NoSQL注入检测 ==========
        // 检测MongoDB等NoSQL数据库注入攻击
        'nosql' => [
            // MongoDB操作符注入
            '/\$\s*(eq|ne|gt|gte|lt|lte|in|nin|regex|where|or|and)\s*:/i',

            // JavaScript执行
            '/\$where\s*:\s*[\'"]\s*function\s*\(/i',

            // 数组操作符注入
            '/\$\s*(exists|type|mod|all|size)\s*:/i',
        ],

        // ========== 模板注入(SSTI)检测 ==========
        // 检测服务器端模板注入攻击
        'ssti' => [
            // Twig/Laravel Blade 模板注入
            '/\{\{\s*.*\|.*(raw|escape|filter)\s*\}\}/i',

            // PHP代码执行
            '/\{\{\s*\$\w+\s*->\s*\w+\s*\([^)]*\)\s*\}\}/i',

            // 危险函数调用
            '/\{\{.*(eval|exec|system|shell_exec|passthru).*\}\}/i',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | XSS攻击模式检测
    |--------------------------------------------------------------------------
    |
    | 检测跨站脚本攻击，但智能识别Markdown文档中的合法代码示例。
    |
    | 核心区别：
    | - 执行性XSS（拦截）：<script>alert(1)</script>、<img onerror=alert(1)>
    | - 文档示例（放行）：```html <script>example</script> ```
    |
    | 实现原理：
    | 中间件会先移除Markdown代码块，再执行XSS检测。
    | 因此代码块内的标签不会触发拦截。
    |
    */

    'xss_patterns' => [

        // ========== 反射型/存储型XSS ==========
        // 检测可能在页面中执行的脚本注入
        'script' => [
            // 完整的script标签（包含执行性内容）
            // 严格匹配：script标签内包含执行函数调用（有括号）
            '/<script\b[^>]*>[^<]*(alert|confirm|prompt|eval)\s*\(/i',

            // document相关危险操作
            '/<script\b[^>]*>[^<]*document\.(write|cookie|location)\s*=/i',

            // JavaScript伪协议
            '/javascript:\s*(alert|confirm|prompt|eval)\s*\(/i',
        ],

        // ========== DOM型XSS ==========
        // 检测可能通过DOM操作触发的XSS
        'dom' => [
            // 危险属性 + 事件处理器 + 执行函数
            // 严格匹配：on事件=执行代码（必须有括号或敏感关键字）
            '/\b(on(error|load|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mousemove|mouseout|unload))\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(/i',

            // innerHTML/outerHTML赋值为HTML标签或脚本
            '/\.(innerHTML|outerHTML)\s*=\s*[\'"]?\s*<\s*(script|img|iframe|svg)/i',
        ],

        // ========== 标签注入 ==========
        // 检测通过HTML标签属性进行的XSS
        'tag' => [
            // iframe src=javascript:
            '/<iframe\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i',

            // object/data注入
            '/<object\b[^>]*data\s*=\s*[\'"]?\s*javascript:/i',

            // embed src注入
            '/<embed\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i',

            // SVG onload事件
            '/<svg\b[^>]*onload\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',

            // 图片错误事件
            '/<img\b[^>]*onerror\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',

            // 输入框焦点事件
            '/<input\b[^>]*onfocus\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i',
        ],

        // ========== 编码绕过 ==========
        // 检测常见的XSS编码绕过技术
        'encoding' => [
            // Unicode转义
            '/\\u[0-9a-f]{4}/i',

            // HTML实体（危险函数）
            '/&(#x?)?(0*4|0*1|0*105|0*97|0*108|0*101|0*114|0*116)/i',

            // URL编码的JavaScript伪协议
            '(%6a|%4a)(%61|%41)(%76|%56)(%61|%41)(%73|%53)(%63|%43)(%72|%52)(%69|%49)(%70|%50)(%74|%54)/i',

            // Base64数据URI（潜在的XSS载体）
            '/data:text\/html;base64,/i',
            '/data:image\/svg\+xml;base64,/i',
        ],

        // ========== 框架/库特定XSS ==========
        'framework' => [
            // jQuery原型污染相关
            '/jQuery\.fn\.(init|extend)\s*\(\s*["\']\s*<script/i',

            // Angular表达式注入
            '/\{\{\s*.*constructor\s*\./i',
            '/\[\s*constructor\s*\]\s*\[\s*"prototype"\s*\]/i',

            // Vue.js模板注入
            '/v-html\s*=\s*["\']\s*</i',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 文件上传安全
    |--------------------------------------------------------------------------
    |
    | 控制上传文件的安全检查规则。
    |
    | 检查维度：
    | 1. 文件扩展名 - 禁止可执行脚本
    | 2. 文件大小 - 防止DoS攻击
    | 3. MIME类型（可选）- 深度验证
    |
    | 安全建议：
    | - 上传目录不应具有执行权限
    | - 建议重命名上传文件（避免原始文件名）
    | - 图片文件应进行二次处理（压缩/转换），清除可能的恶意代码
    |
    */

    'upload' => [
        // 是否启用上传检查
        'enabled' => true,

        // 单个文件最大大小（字节）
        // 默认10MB，超过此大小会被拦截
        'max_size' => 10 * 1024 * 1024,

        // 允许的文件扩展名（白名单）
        // 注意：这不会覆盖 blocked_extensions，只是用于前端提示
        'allowed_extensions' => [
            // 图片
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp',

            // 文档
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'txt', 'rtf', 'csv', 'md',

            // 压缩包
            'zip', 'rar', '7z', 'tar', 'gz',

            // 音视频
            'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv',
        ],

        // 禁止的文件扩展名（黑名单）
        // 这些扩展名的文件会被直接拒绝
        'blocked_extensions' => [
            // Web脚本（高危）
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar',
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
            'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd',
            'cfm', 'cfml', 'cfc', 'dbm',

            // 其他脚本
            'pl', 'pm', 'cgi',
            'py', 'pyc', 'pyo',
            'rb', 'rhtml',
            'sh', 'bash', 'zsh', 'csh', 'tcsh',
            'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',

            // 可执行文件
            'exe', 'dll', 'bin', 'so', 'dylib', 'msi', 'com', 'scr',

            // 配置文件（可能泄露敏感信息）
            'htaccess', 'htpasswd', 'config', 'ini', 'log',

            // 数据库文件
            'sql', 'sqlite', 'sqlite3', 'mdb', 'accdb',

            // 序列化数据（可能包含恶意对象）
            'xml', 'yaml', 'yml', 'toml',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | URL长度限制
    |--------------------------------------------------------------------------
    |
    | 限制URL最大长度，防止：
    | 1. 缓冲区溢出攻击
    | 2. 日志注入攻击
    | 3. 绕过WAF规则（通过超长字符串分割关键字）
    |
    | 浏览器限制参考：
    | - IE: 2048字符
    | - Chrome: ~32K字符
    | - Firefox: ~64K字符
    |
    | 推荐值：2048（兼容所有浏览器，足够正常使用）
    |
    */

    'max_url_length' => 2048,

    /*
    |--------------------------------------------------------------------------
    | 请求体大小限制
    |--------------------------------------------------------------------------
    |
    | 限制请求体最大大小，防止：
    | 1. 内存溢出攻击
    | 2. 超大POST数据导致的DoS
    | 3. 文件上传绕过检查
    |
    | 注意：此限制应在Web服务器（Nginx/Apache）层首先设置
    | 这里的限制作为二次防护
    |
    */

    'max_body_size' => [
        // 是否启用检查
        'enabled' => true,

        // 最大请求体大小（字节）
        // 默认 10MB
        'limit' => 10 * 1024 * 1024,
    ],

    /*
    |--------------------------------------------------------------------------
    | User-Agent 黑名单
    |--------------------------------------------------------------------------
    |
    | 封禁已知的恶意User-Agent，如扫描器、爬虫工具等。
    |
    | 支持格式：
    | - 字符串：完全匹配或包含匹配
    | - 正则表达式：'/scann(er|ing)/i'
    | - 闭包：function($ua, $request) { return str_contains($ua, 'BadBot'); }
    |
    | 常见恶意UA示例：
    | - SQLMap、Nmap、Nikto、DirBuster
    | - 各种扫描器和爬虫
    |
    */

    'user_agent_blacklist' => [
        // 扫描工具
        'sqlmap',
        'nmap',
        'nikto',
        'dirbuster',
        'burp',
        'wpscan',
        'acunetix',
        'nessus',
        'openvas',
        'zgrab',
        'masscan',
        'censys',
        'shodan',

        // 爬虫（可选，视业务需求）
        // 'scrapy',
        // 'curl',
        // 'wget',

        // 自定义正则
        // '/(scanner|bot|crawler|spider)/i',

        // 自定义闭包
        // function($ua, $request) {
        //     return strlen($ua) < 10 || strlen($ua) > 500;
        // },
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP 头安全检查
    |--------------------------------------------------------------------------
    |
    | 检查HTTP请求头中的安全隐患。
    |
    */

    'headers' => [
        // 是否启用头检查
        'enabled' => true,

        // 必须包含的头（如特定API密钥头）
        // 'required' => ['X-API-Key'],

        // 禁止的头（可能用于攻击）
        'forbidden' => [
            // 代理相关（可能被用于绕过IP限制）
            // 'X-Forwarded-Host',  // 如需使用请根据环境配置
            // 'X-HTTP-Host-Override',

            // 调试头
            'X-Debug',
            'X-Debug-Token',
        ],

        // Host头检查（防止Host头攻击）
        'host_validation' => [
            'enabled' => false,  // 默认关闭，需配置允许的主机名
            'allowed_hosts' => [
                // 'example.com',
                // '*.example.com',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 路由排除配置
    |--------------------------------------------------------------------------
    |
    | 指定哪些路由跳过安全检查。
    |
    | 支持格式：
    | - 字符串：'webhook/*'（匹配模式）
    | - 正则：'/^webhook\//'
    | - 闭包：function($request) { return $request->is('webhook/*'); }
    |
    | 警告：谨慎使用，确保排除的路由有独立的安全措施！
    |
    */

    'excluded_routes' => [
        // 示例：排除webhook路由
        // 'webhook/*',
        // 'api/webhook/*',

        // 示例：使用闭包
        // function($request) {
        //     return $request->is('health-check') || $request->header('X-Internal-Request') === 'true';
        // },
    ],

    /*
    |--------------------------------------------------------------------------
    | 拦截前回调配置
    |--------------------------------------------------------------------------
    |
    | 在正式拦截请求前，会调用此回调函数，允许开发者自定义拦截决策。
    |
    | 配置格式支持：
    | - false/null：禁用回调，直接拦截
    | - 布尔值 true：启用默认处理（直接拦截）
    | - 类名字符串：'App\\Security\\CustomInterceptor'（需实现 __invoke 方法）
    | - 可调用数组：['App\\Security\\CustomInterceptor', 'handle']
    | - 闭包函数：function(InterceptionContext $context): ?bool { ... }
    |
    | 回调返回值：
    | - false：放行请求（不拦截），继续后续处理
    | - true/null：拦截请求，返回拦截响应给用户
    |
    | 回调参数 InterceptionContext 包含：
    | - threat_type: 威胁类型
    | - threat_description: 威胁描述
    | - risk_level: 风险等级 (high/medium/low)
    | - client_ip: 客户端IP
    | - method: HTTP方法
    | - url: 请求URL
    | - matched_pattern: 匹配的正则模式
    | - all_threats: 所有检测到的威胁
    |
    | 使用场景：
    | 1. 记录拦截日志到数据库或外部服务
    | 2. 对特定IP或用户进行例外处理
    | 3. 实现动态威胁评分，低危请求自动放行
    | 4. 发送安全告警通知（短信、邮件、钉钉等）
    |
    | 示例配置：
    |
    | 'before_block_callback' => function($context) {
    |     // 记录到数据库
    |     SecurityLog::create($context->toArray());
    |
    |     // 低风险请求放行
    |     if ($context->getRiskLevel() === 'low') {
    |         return false; // 放行
    |     }
    |
    |     // 发送告警（异步）
    |     SecurityAlertJob::dispatch($context);
    |
    |     return true; // 拦截
    | },
    |
    */

    'before_block_callback' => null,

    /*
    |--------------------------------------------------------------------------
    | HTTP响应配置
    |--------------------------------------------------------------------------
    |
    | 配置拦截请求时返回的HTTP状态码、消息和视图。
    |
    | 状态码说明：
    | - 403 Forbidden：请求被理解但拒绝执行（通用拦截）
    | - 429 Too Many Requests：速率限制触发
    |
    | 视图配置支持以下格式：
    | 1. 字符串视图名：'errors.security'（使用 resources/views/errors/security.blade.php）
    | 2. 闭包函数：function($data) { return view('errors.block', $data); }
    | 3. 类方法数组：['App\Http\Controllers\SecurityController', 'block']
    | 4. 可调用类：App\Security\CustomResponseHandler::class
    |
    | 视图接收的数据：
    | - message: 拦截提示消息
    | - blocked: true
    | - threats: 威胁类型数组
    | - matched_pattern: 匹配的正则模式
    | - matched_content: 匹配的内容片段
    |
    */

    'response' => [
        // 通用拦截状态码
        'blocked_status' => 403,

        // 速率限制状态码
        'rate_limit_status' => 429,

        // 默认拦截消息（Web请求）
        'message' => '请求被拒绝：检测到潜在的安全威胁',

        // 是否显示详细威胁信息（生产环境建议关闭）
        'show_threat_details' => env('SECURITY_SHOW_DETAILS', false),

        // 多语言支持：拦截消息配置
        // 支持根据威胁类型返回不同的拦截消息
        // 键名为威胁类型，键值为消息内容
        // 如果某个类型未配置，将使用上面的默认 message
        'messages' => [
            // IP相关
            'blacklist' => '您的IP地址已被列入黑名单，禁止访问',
            'whitelist' => 'IP白名单检查通过',

            // 请求限制
            'rate_limit' => '请求过于频繁，请稍后再试',
            'body_too_large' => '请求体过大，超过服务器限制',
            'url_too_long' => '请求URL过长',
            'invalid_method' => '不支持的HTTP请求方法',

            // 请求头相关
            'bad_user_agent' => '检测到恶意User-Agent',
            'invalid_headers' => '请求头信息不合法',

            // URL攻击
            'url_path_attack' => 'URL路径包含非法内容',
            'encoding_bypass' => '请求包含编码绕过特征',

            // 高危攻击
            'sql' => '检测到SQL注入攻击，请求已被拦截',
            'command' => '检测到命令注入攻击，请求已被拦截',
            'path' => '检测到路径遍历攻击，请求已被拦截',
            'ldap' => '检测到LDAP注入攻击，请求已被拦截',
            'xml' => '检测到XML注入攻击，请求已被拦截',
            'nosql' => '检测到NoSQL注入攻击，请求已被拦截',
            'ssti' => '检测到模板注入攻击，请求已被拦截',
            'encoding' => '检测到编码绕过攻击，请求已被拦截',

            // XSS攻击
            'xss_script' => '检测到脚本注入攻击，请求已被拦截',
            'xss_dom' => '检测到DOM型XSS攻击，请求已被拦截',
            'xss_tag' => '检测到标签注入攻击，请求已被拦截',
            'xss_encoding' => '检测到XSS编码绕过攻击，请求已被拦截',
            'xss_framework' => '检测到框架特定XSS攻击，请求已被拦截',

            // 文件上传
            'dangerous_upload' => '检测到危险文件上传，请求已被拦截',

            // 通用
            'unknown' => '请求包含潜在的安全威胁，已被拦截',
        ],

        // 自定义视图配置（可选）
        // 设为 null 或空字符串则使用默认文本响应
        // 支持格式：视图名、闭包、类方法数组、可调用类
        //
        // 示例1：使用 Blade 视图
        // 'view' => 'security::error',
        //
        // 示例2：使用闭包函数
        // 'view' => function($data) {
        //     return view('errors.blocked', [
        //         'message' => $data['message'],
        //         'threats' => $data['threats'],
        //     ]);
        // },
        //
        // 示例3：使用类方法
        // 'view' => ['App\Http\Controllers\SecurityController', 'renderBlockPage'],
        //
        // 示例4：使用可调用类, 需要实现  __invoke 方法
        // 'view' => \App\Security\BlockResponseHandler::class,
        'view' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | 高级配置：Markdown内容识别
    |--------------------------------------------------------------------------
    |
    | 控制中间件对Markdown格式内容的智能识别功能。
    |
    | 启用后，中间件会：
    | 1. 检测内容是否包含Markdown语法
    | 2. 识别代码块区域（``` 或 ~~~ 包裹的部分）
    | 3. 对代码块内的HTML标签放宽XSS检测
    |
    | 适用场景：
    | - 内容管理系统（CMS）
    | - 文档协作平台
    | - 开发者社区
    | - 知识库系统
    |
    */

    'markdown' => [
        // 是否启用Markdown智能识别
        // 设为 true 可减少文档类内容的误拦截
        'smart_detection' => true,

        // 代码块标记
        'code_block_markers' => ['```', '~~~'],

        // 行内代码标记
        'inline_code_marker' => '`',
    ],

    /*
    |--------------------------------------------------------------------------
    | URL路径攻击检测配置
    |--------------------------------------------------------------------------
    |
    | 配置URL路径和查询参数中的路径遍历攻击检测模式。
    |
    */

    'url_path_detection' => [
        'enabled' => env('SECURITY_URL_PATH_DETECTION', true),

        'path_patterns' => [
            // 路径遍历检测正则模式
            '/(\.\.\/){2,}/',
            '/(\.\.\\\\){2,}/',
            '/\.\.(\/|\\\\)\.\.(\/|\\\\)/',
            '/%2e%2e(%2f|%5c)/i', // URL 编码（兼容 Windows）	../ 或 ..\

            // 敏感文件访问检测模式
            '/\/(etc|proc|sys|var|root|home|usr\/local)\/(passwd|shadow|hosts|id_rsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i',
            '/\b(\.env|\.git\/)\b/i',
            '/\b(\.svn|\.hg|\.bzr)\b/i',
            '/\b(\.htaccess|\.htpasswd|web\.config)\b/i',
            '/\b(composer\.json|composer\.lock|package\.json|package-lock\.json)\b/i',
            '/\.\.(\/|\\\\)(windows|winnt|system32|system|program files|programdata|inetpub)/i',

            // 其他匹配规则
            // '/\.(php|jsp|sh)(?:[?#&\/]|$)/i', // 匹配 php、jsp、sh 等文件扩展名
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 编码绕过攻击检测配置
    |--------------------------------------------------------------------------
    |
    | 配置多重编码攻击的检测参数。
    |
    */

    'encoding_detection' => [
        'enabled' => env('SECURITY_ENCODING_DETECTION', true),

        // URL编码百分比阈值（0-1）
        'percent_threshold' => 0.30,

        // 解码后检查的可疑模式
        'suspicious_patterns' => [
            '../', '..\\', '<script', 'javascript:',
            'onerror=', 'onload=', 'onfocus=',
        ],

        'detect_null_bytes' => true,
        'detect_utf8_overlong' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP方法配置
    |--------------------------------------------------------------------------
    |
    | 配置允许的HTTP请求方法。
    |
    */

    'allowed_http_methods' => [
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
    ],

    /*
    |--------------------------------------------------------------------------
    | 输入处理配置
    |--------------------------------------------------------------------------
    |
    | 配置请求输入的处理参数。
    |
    */

    'input_processing' => [
        // 最大输入长度（字节），防止正则回溯
        'max_input_length' => 100 * 1024,

        // 匹配内容最大长度（用于日志）
        'max_match_content_length' => 200,

        // Markdown检测最小内容长度
        'markdown_min_length' => 100,

        // Markdown语法模式
        'markdown_patterns' => [
            '/^#{1,6}\s+/m',
            '/^[-*+]\s+/m',
            '/\[.+?\]\(.+?\)/',
            '/^\s*>\s+/m',
            '/^\s*\|\s*[-:]+\s*\|/m',
            '/!\[.*?\]\(.*?\)/',
            '/\*\*.*?\*\*/',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 威胁风险等级映射
    |--------------------------------------------------------------------------
    |
    | 配置每种威胁类型的风险等级（high, medium, low）
    | 不配置(空数组) 表示使用默认配置
    |
    */

    'threat_risk_levels' => [
        // 'sql' => 'high', // 高危
    ],

];
