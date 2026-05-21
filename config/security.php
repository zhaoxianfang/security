<?php

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║        Laravel 安全中间件 - 配置文件 (v5.2+)                                 ║
 * ║        🔐 14层纵深安全防护，覆盖 OWASP Top 10 核心攻击向量                     ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * 📦 支持的 PHP 版本：8.2 / 8.3 / 8.4 / 8.5； 支持的 Laravel 版本：11 / 12 / 13
 *
 * 📖 配置优先级（从高到低）：
 *    1. 环境变量（.env）       — 运行时覆盖，不同环境独立配置
 *    2. 直接修改本文件         — 发布后自定义
 *    3. 包内置默认值           — 零配置即可使用
 *
 * 🚀 快速配置建议：
 *    - 开发环境：关闭 rate_limit，log_level 设为 debug
 *    - 测试环境：保持默认，rate_limit 适当宽松
 *    - 生产环境：开启全部检测，rate_limit 收紧
 *    - 内网部署：将内网IP段加入 trusted_ips
 *
 */

return [

    /*
    |--------------------------------------------------------------------------
    | 基础开关                                                 【配置项】
    |--------------------------------------------------------------------------
    */

    // 主开关：是否启用安全中间件
    'enabled' => env('SECURITY_ENABLED', true),

    // 日志开关：是否记录安全威胁日志
    'log_enabled' => env('SECURITY_LOG_ENABLED', true),

    // 日志级别：可选 'debug', 'info', 'warning', 'error', 'critical'
    'log_level' => env('SECURITY_LOG_LEVEL', 'warning'),

    // 是否记录完整请求数据（含POST数据）
    'log_full_request' => env('SECURITY_LOG_FULL_REQUEST', false),

    /*
    |--------------------------------------------------------------------------
    | 🔍 检测层级开关                                           【配置项】
    |--------------------------------------------------------------------------
    |
    | 精细控制每一层安全检测的启用/禁用。
    | 使用场景：减少误报、性能优化、调试排查
    | ⚠️ IP黑白名单不受这些开关控制（始终生效）
    */

    'detection_layers' => [
        'url_path'     => env('SECURITY_DETECT_URL_PATH', true),     // 是否开启 URL 路径攻击检测（路径遍历、敏感文件等）
        'encoding'     => env('SECURITY_DETECT_ENCODING', true),     // 是否开启多重编码绕过检测（URL编码、空字节注入等）
        'user_agent'   => env('SECURITY_DETECT_USER_AGENT', true),   // 是否开启 User-Agent 黑名单检测（恶意扫描器识别）
        'headers'      => env('SECURITY_DETECT_HEADERS', true),      // 是否开启 HTTP 请求头安全检查（禁用头、CRLF注入等）
        'body_size'    => env('SECURITY_DETECT_BODY_SIZE', true),    // 是否开启请求体大小检查（防止超大请求OOM）
        'rate_limit'   => env('SECURITY_DETECT_RATE_LIMIT', true),   // 是否开启请求速率限制（防止暴力破解/CC攻击）
        'http_method'  => env('SECURITY_DETECT_HTTP_METHOD', true),  // 是否开启 HTTP 方法检查（仅允许 GET/POST 等合法方法）
        'url_length'   => env('SECURITY_DETECT_URL_LENGTH', true),   // 是否开启 URL 长度检查（防止缓冲区溢出攻击）
        'high_risk'    => env('SECURITY_DETECT_HIGH_RISK', true),    // 是否开启高危攻击检测（SQL注入/命令注入/SSTI/SSRF等）
        'xss'          => env('SECURITY_DETECT_XSS', true),          // 是否开启 XSS 跨站脚本攻击检测
        'upload'       => env('SECURITY_DETECT_UPLOAD', true),       // 是否开启文件上传安全检查（扩展名/MIME/大小）
        'redirect'     => env('SECURITY_DETECT_REDIRECT', false),    // 是否禁止重定向(true:禁止;false:允许)（默认运行，无重定向需求的业务易误报）
    ],

    /*
    |--------------------------------------------------------------------------
    | 🛡️ 信任 IP（安全关键）—— 跳过所有检测直接放行           【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 信任 IP 列表中的地址将跳过所有安全检查直接放行。适用于：本机服务间调用、CI/CD流水线等。
    |
    | ⚠️ 默认仅包含本机回环地址（127.0.0.1 / ::1）。
    |    生产环境中请根据需要添加特定的负载均衡器/反向代理 IP， 切勿将整个内网段（10.0.0.0/8 等）添加到信任列表，
    |    否则所有经由内网代理的请求都将跳过安全检查！
    |
    | 正确做法（按实际架构添加）：
    |   'trusted_ips' => [
    |       '127.0.0.1',       // 本机 IPv4
    |       '::1',             // 本机 IPv6
    |       '10.0.1.5',        // 仅添加 LB/Proxy 的具体 IP，不要加网段
    |       '172.17.0.0/16',   // Docker 网段（仅当确认容器到容器通信安全时）
    |   ],
    |
    | 支持 IPv4、IPv6 和 CIDR 网段。
    | ⚠️ 切勿将公网 IP 添加到信任列表！
    */

    'trusted_ips' => [
        // '10.0.0.0/8',         // RFC1918 私有地址段 - A类（大型网络）
        // '172.16.0.0/12',      // RFC1918 私有地址段 - B类（中型网络）
        // '192.168.0.0/16',     // RFC1918 私有地址段 - C类（小型网络）
        // '127.0.0.1',          // 本机 IPv4 - IPv4 本地回环
        // '::1',                // 本机 IPv6 - IPv6 本地回环
    ],

    /*
    |--------------------------------------------------------------------------
    | ⏱️ 速率限制                                               【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 基于 IP + 路由路径组合限流（key: {prefix}:{IP}:{路由MD5}），
    | 使用 Laravel 内置 RateLimiter，无需额外缓存驱动。
    |
    | 推荐值：普通网站 60次/分，API 300次/分，后台 20次/分
    */

    'rate_limit' => [
        'max_attempts' => env('SECURITY_RATE_LIMIT_ATTEMPTS', 60),         // 时间窗口内最大请求数
        'decay_minutes' => env('SECURITY_RATE_LIMIT_DECAY', 1),            // 时间窗口（分钟）
        'key_prefix' => env('SECURITY_RATE_LIMIT_KEY_PREFIX', 'security'), // 限流 key 前缀
    ],

    /*
    |--------------------------------------------------------------------------
    | 🚫 IP 黑名单 —— 直接拦截（HTTP 403）                       【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 黑名单中的 IP 将被直接拦截（HTTP 403），不进行其他检查。
    |
    | 支持 5 种格式（按需选择）：
    |   ① 静态 IP：'203.0.113.50'
    |   ② CIDR 网段：'103.21.244.0/24'
    |   ③ 闭包函数：function(string $ip, Request $request): bool { ... }
    |   ④ 类名（实现 IpCheckerInterface）：App\Security\Checkers\BlacklistChecker::class
    |   ⑤ 可调用数组：[App\Security\IpService::class, 'isBlocked']
    |
    | 配置示例：
    |   'blacklist' => [
    |       '203.0.113.50',                     // 静态 IP：单个攻击者 IP
    |       '198.51.100.0/24',                  // CIDR 网段：恶意 IP 段
    |       function(string $ip, Request $request) {   // 数据库动态查询
    |           return \App\Models\BannedIp::where('ip', $ip)->exists();
    |       },
    |   ],
    */

    'blacklist' => [],

    /*
    |--------------------------------------------------------------------------
    | ✅ IP 白名单 —— 业务层信任（合作方 API、支付回调）           【排除规则】
    |--------------------------------------------------------------------------
    |
    | 白名单语义上用于特定业务场景（合作伙伴API、支付回调等）。
    |
    | trusted_ips vs whitelist 的区别：
    |   - trusted_ips：系统层面信任（内网），跳过所有检查
    |   - whitelist：业务层面信任（合作方），可单独审计
    |
    | 支持格式与 blacklist 完全相同。
    |
    | 配置示例：
    |   'whitelist' => [
    |       '198.51.100.50',                     // 支付网关回调 IP
    |       '203.0.113.0/28',                    // 合作伙伴 IP 段
    |       function(string $ip, $request) {     // 按 API Key 动态判断
    |           return \App\Models\Partner::where('api_key',
    |               $request->header('X-Partner-Key'))->exists();
    |       },
    |   ],
    */

    'whitelist' => [],

    /*
    |--------------------------------------------------------------------------
    | 🎯 模式策略                                               【配置项】
    |--------------------------------------------------------------------------
    |
    | 'merge'（默认）— 自定义模式与内置模式合并，追加到内置模式之后
    | 'replace'      — 完全替换内置模式，仅使用自定义模式
    |
    | 三场景快速对照：
    | ┌──────────────────────┬──────────────────────────────────────┐
    | │ 叠加新规则             │ pattern_mode='merge'                 │
    | │ 排除个别内置规则        │ 在 *_patterns 中添加自定义正则          │
    | │                      │ 在 *_patterns_exclude 中列出排除项     │
    | ├──────────────────────┼──────────────────────────────────────┤
    | │ 完全自定义             │ pattern_mode='replace'               │
    | │                      │ 在 *_patterns 中定义完整规则集          │
    | └──────────────────────┴──────────────────────────────────────┘
    */
    'pattern_mode' => 'merge',

    /*
    |--------------------------------------------------------------------------
    | ☣️ 高危攻击模式 — 自定义正则                                【追加规则】
    |--------------------------------------------------------------------------
    |
    | ⚠️ 内置默认正则模式已迁移至独立数据文件（延迟加载）。
    |
    | 内置检测类型及覆盖的攻击向量：
    |   sql             — SQL注入（UNION/堆叠查询/时间盲注/报错注入/宽字节注入）
    |   command         — 命令注入（system/exec/passthru + 危险命令）
    |   path            — 路径遍历（../、URL编码、敏感文件泄露）
    |   ldap            — LDAP注入（过滤器注入）
    |   xml             — XML/XXE外部实体注入
    |   nosql           — NoSQL注入（MongoDB操作符注入）
    |   ssti            — 服务器端模板注入（{{}}/{% %}/<%= %>）
    |   ssrf            — SSRF（内网IP/云元数据/危险协议）
    |   encoding        — 编码绕过（多重URL编码/Unicode/HTML实体/NULL字节）
    |   header_injection — CRLF/HTTP头注入与响应拆分
    |   redirect        — 开放重定向（外部URL/协议绕过/CRLF+Location）
    |
    | 也支持自定义类型键名，将作为新类型追加到检测中。
    |
    | 配置示例：
    |   'high_risk_patterns' => [
    |       'sql' => ['/my_custom_sqli_regex/i'],          // 追加SQL规则
    |       'graphql' => ['/(__schema|__type)\s*\{/'],     // 自定义GraphQL注入检测
    |   ],
    */

    'high_risk_patterns' => [],

    /*
    |--------------------------------------------------------------------------
    | ❌ 高危模式 — 排除内置正则                                   【排除规则】
    |--------------------------------------------------------------------------
    |
    | 指定要从内置默认模式中移除的正则表达式（精确字符串匹配）。
    | 当业务正常使用某个敏感函数时，可排除对应规则避免误报。
    |
    | 格式：['类型键名' => ['要排除的正则1', '要排除的正则2']]
    |
    | 内置类型键名（对应 src/Security/Patterns/data/high_risk_patterns.php）：
    |   sql, command, path, ldap, xml, nosql, ssti, ssrf,
    |   encoding, header_injection, redirect, file_include
    |
    | 配置示例：
    |   'high_risk_patterns_exclude' => [
    |       // SQL注入：排除误报规则
    |       'sql' => [
    |           '/unhex\s*\(/i',           // 业务使用 unhex() 做密码哈希
    |           '/benchmark\s*\(/i',       // 业务使用 benchmark 做性能测试
    |       ],
    |       // 命令注入：排除合法命令
    |       'command' => [
    |           '/\b(wget\s|curl\s)/i',    // 业务使用 wget/curl 获取资源
    |       ],
    |       // 路径遍历：排除 Windows 特定规则误报
    |       'path' => [
    |           '/(\\.\\.\\\\\\){2,}/',    // Windows 路径遍历在企业内网正常
    |       ],
    |       'encoding' => [
    |           '/%25(?:25)+[0-9a-f]{2}/i',
    |           '/%(?:c0[\x80-\xbf]|e0%80[\x80-\xbf])/i',
    |       ],
    |       // SSRF：排除误报协议或内网地址
    |       'ssrf' => [
    |           '/\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}(?:\/|$|\?|&)/i', // 排除协议省略型
    |       ],
    |   ],
    |
    | ⚠️ 排除规则时务必评估安全风险！
    */
    'high_risk_patterns_exclude' => [],

    /*
    |--------------------------------------------------------------------------
    | 🏷️ XSS 攻击模式 — 自定义正则                                【追加规则】
    |--------------------------------------------------------------------------
    |
    | ⚠️ 内置默认正则模式已迁移至独立数据文件（延迟加载）。
    |
    | ⚡ 预过滤优化：每种 XSS 子类型都有预过滤关键词
    |    （如 script 预检 <script，tag 预检 <iframe），不包含则跳过正则匹配。
    |
    | 内置检测类型：
    |   script    — 脚本标签注入（<script>/javascript:/vbscript: 伪协议）
    |   dom       — DOM型XSS（onerror/onload/onfocus 等事件处理器）
    |   tag       — 标签注入（<iframe>/<object>/<embed>/<svg>/<img>等）
    |   encoding  — 编码绕过（Unicode转义/HTML实体/Base64 data URI）
    |   framework — 框架特定XSS（jQuery/Vue v-html/Angular沙箱逃逸）
    |
    | 配置示例：
    |   'xss_patterns' => [
    |       'script' => ['/custom_xss_regex/i'],
    |   ],
    */

    'xss_patterns' => [],

    /*
    |--------------------------------------------------------------------------
    | ❌ XSS 模式 — 排除内置正则                                   【排除规则】
    |--------------------------------------------------------------------------
    |
    | 格式与 high_risk_patterns_exclude 相同，精确字符串匹配。
    |
    | 内置类型键名（对应 src/Security/Patterns/data/xss_patterns.php）：
    |   script, dom, tag, encoding, framework
    |
    | 配置示例：
    |   'xss_patterns_exclude' => [
    |       'script' => [
    |           '/<script\b[^>]*>[^<]*(alert|confirm|prompt|eval)\s*\(/i', // 富文本编辑器
    |       ],
    |       'tag' => [
    |           '/<iframe\b[^>]*src\s*=\s*[\'"]?\s*javascript:/i',  // 内嵌合法视频
    |           '/<img\b[^>]*onerror\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval)/i', // 图片上传预览
    |       ],
    |       'dom' => [
    |           '/\b(on(error|load|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mousemove|mouseout|unload))\s*=\s*[\'"]?\s*(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(/i',
    |       ],
    |       'encoding' => [
    |           '/\\\\u[0-9a-f]{4}/i',     // Unicode 转义在 JSON API 中正常
    |       ],
    |   ],
    */
    'xss_patterns_exclude' => [],

    /*
    |--------------------------------------------------------------------------
    | 📁 文件上传安全                                            【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 四层防护：扩展名白名单 + 黑名单 + 大小限制 + MIME魔术字节验证
    |
    | 安全建议：上传目录无执行权限、文件改名、图片二次处理
    */

    'upload' => [
        'max_size' => 50 * 1024 * 1024,                              // 单文件最大 50MB
        'check_mime_magic' => env('SECURITY_UPLOAD_CHECK_MIME', false), // 深度MIME验证（防止扩展名伪装）
        'mime_magic_map' => [],                                      // 自定义MIME映射（留空使用内置）

        // 允许上传文件后缀
        'allowed_extensions' => [
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'txt', 'rtf', 'csv', 'md',
            'zip', 'rar', '7z', 'tar', 'gz',
            'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv',
        ],

        // 禁止上传文件后缀
        'blocked_extensions' => [
            // Web脚本
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar',
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
            'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd',
            'cfm', 'cfml', 'cfc', 'dbm',
            'pl', 'pm', 'cgi',
            'py', 'pyc', 'pyo',
            'rb', 'rhtml',
            // Shell/脚本
            'sh', 'bash', 'zsh', 'csh', 'tcsh',
            'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
            // 可执行文件
            'exe', 'dll', 'bin', 'so', 'dylib', 'msi', 'com', 'scr',
            // 配置/数据
            'htaccess', 'htpasswd', 'config', 'ini', 'log',
            'sql', 'sqlite', 'sqlite3', 'mdb', 'accdb',
            'xml', 'yaml', 'yml', 'toml',
        ],

        /*
        | 从黑名单中排除特定扩展名（精确字符串匹配）                   【排除规则】
        | ====================================================
        |
        | 示例：
        |   'blocked_extensions_exclude' => [
        |       'yml',      // 配置管理工具需上传 .yml
        |       'xml',      // 业务需要 XML 数据导入
        |       'log',      // 运维需上传日志
        |   ],
        |
        | ⚠️ 仔细评估安全风险后再排除！
        */
        'blocked_extensions_exclude' => [],

        /*
        | 追加自定义禁止上传的扩展名                                   【追加规则】
        | ====================================================
        |
        | 示例：
        |   'blocked_extensions_add' => [
        |       'war',      // Tomcat WAR 部署包
        |       'ear',      // Java EE EAR 包
        |       'jar',      // Java JAR 包
        |       'swf',      // Flash SWF
        |   ],
        */
        'blocked_extensions_add' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | 📏 URL 长度限制                                           【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 超过此长度的 URL 将被拦截（防缓冲区溢出/DoS 攻击）。
    */

    'max_url_length' => [
        'limit' => 2048,                                            // 最大字符数
    ],

    /*
    |--------------------------------------------------------------------------
    | 📦 请求体大小限制                                          【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 防止超大请求体导致内存耗尽，通过 Content-Length 头部判断。
    */

    'max_body_size' => [
        'limit' => 50 * 1024 * 1024,       // 默认 50MB
    ],

    /*
    |--------------------------------------------------------------------------
    | 🤖 User-Agent 黑名单                                      【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 已知恶意扫描器/攻击工具的 User-Agent 特征串（不区分大小写部分匹配）。
    | 支持字符串、正则（以/开头）、闭包三种格式。
    |
    | 自定义追加示例：
    |   'user_agent_blacklist' => [
    |       '/python-requests/i',              // 正则：Python 脚本
    |       '/Go-http-client/i',               // 正则：Go HTTP 客户端
    |       function($ua, $request) {          // 闭包：空UA且POST请求视为可疑
    |           return empty($ua) && $request->isMethod('POST');
    |       },
    |   ],
    */

    'user_agent_blacklist' => [
        'sqlmap',        // SQLMap 注入工具
        'nmap',          // Nmap 扫描器
        'nikto',         // Nikto Web扫描器
        'dirbuster',     // DirBuster 目录扫描
        'burp',          // Burp Suite 安全测试
        'wpscan',        // WPScan WordPress扫描
        'acunetix',      // Acunetix 漏洞扫描器
        'nessus',        // Nessus 漏洞扫描器
        'openvas',       // OpenVAS 漏洞扫描器
        'zgrab',         // ZGrab 扫描器
        'masscan',       // Masscan 端口扫描
        'censys',        // Censys 搜索引擎
        'shodan',        // Shodan 搜索引擎
    ],

    /*
    |--------------------------------------------------------------------------
    | ❌ UA 黑名单 — 排除内置条目                                   【排除规则】
    |--------------------------------------------------------------------------
    |
    | 精确字符串匹配，从内置 UA 黑名单中排除特定工具。
    | 适用于：公司内部使用某款安全扫描器做自动化测试。
    |
    | 配置示例：
    |   'user_agent_blacklist_exclude' => [
    |       'burp',        // 企业内部安全团队使用 Burp Suite 做授权测试
    |       'nessus',      // Nessus 定期扫描
    |   ],
    |
    | ⚠️ 这里仅支持排除内置字符串条目，不支持排除正则/闭包条目。
    */
    'user_agent_blacklist_exclude' => [],


    /*
    |--------------------------------------------------------------------------
    | 🔒 HTTP 头安全检查                                         【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 检查维度：禁止的请求头、CRLF注入（HTTP响应拆分）、Host头验证
    |
    | Host 验证配置示例：
    |   'host_validation' => [
    |       'enabled' => true,
    |       'allowed_hosts' => [
    |           'example.com',
    |           'www.example.com',
    |           '*.cdn.example.com',   // 通配符子域名
    |       ],
    |   ],
    */

    'headers' => [
        'forbidden' => [
            'X-Debug',           // Symfony/Laravel 调试头
            'X-Debug-Token',     // Symfony 调试 Token
        ],
        'detect_crlf' => env('SECURITY_DETECT_CRLF', true),  // CRLF/HTTP响应拆注入检测
        'host_validation' => [
            'enabled' => false,             // 默认关闭，按需开启
            'allowed_hosts' => [],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 🚏 路由排除                                                  【排除规则】
    |--------------------------------------------------------------------------
    |
    | 排除列表中的路径将跳过所有安全检查直接放行。
    | 适用于：健康检查、Webhook回调、管理后台等。
    |
    | 支持格式：
    |   ① 字符串（支持 * 通配符）：'api/health*'、'webhook/*'
    |   ② 正则（以 / 开头）：'/^api\/v1\/health$/'
    |   ③ 闭包函数：function(Request $request): bool { ... }
    |
    | ⚠️ 不要将整个 /api/* 排除，风险过高！
    |
    | 配置示例：
    |   'excluded_routes' => [
    |       'api/health',            // 健康检查
    |       'api/healthz',           // Kubernetes 健康探测
    |       'webhook/stripe',        // Stripe 支付回调
    |       'webhook/github',        // GitHub Webhook
    |   ],
    */

    'excluded_routes' => [],

    /*
    |--------------------------------------------------------------------------
    | 🎛️ 拦截前回调                                              【配置项】
    |--------------------------------------------------------------------------
    |
    | 在正式拦截前执行的自定义回调，支持灵活拦截决策。
    |
    | 返回值含义：
    |   false  → 放行请求
    |   其他   → 拦截请求（true/null/无返回均视为拦截）
    |
    | 支持格式：
    |   null/false              → 禁用回调，直接拦截
    |   闭包函数                  → function(InterceptionContext $context): ?bool { ... }
    |   类名字符串                → 'App\\Security\\CustomInterceptor'（需实现 __invoke）
    |   可调用数组                → ['App\\Security\\CustomInterceptor', 'handle']
    |
    | 配置示例：
    |   // 仅拦截高危威胁，中低风险放行
    |   'before_block_callback' => function($context) {
    |       return $context->getRiskLevel() === 'high';
    |       // 低风险请求放行
    |       if ($context->getRiskLevel() === 'low') {
    |           return false; // 放行
    |       }
    |   },
    |
    |   // 内网IP放行 + 记录到数据库
    |   'before_block_callback' => function($context) {
    |       \App\Models\SecurityLog::create($context->toArray());
    |       if (str_starts_with($context->clientIp, '192.168.')) {
    |           return false;
    |       }
    |       return true;
    |   },
    */

    'before_block_callback' => null,

    /*
    |--------------------------------------------------------------------------
    | 📤 HTTP 响应配置                                           【配置项】
    |--------------------------------------------------------------------------
    |
    | 拦截时的自定义响应消息和状态码。
    | view 配置支持：字符串视图名、闭包、类方法数组、可调用类。
    */

    'response' => [
        'blocked_status' => 403,                                     // 通用拦截 HTTP 状态码
        'rate_limit_status' => 429,                                  // 速率限制状态码
        'message' => '请求被拒绝：检测到潜在的安全威胁',                // 默认拦截提示
        'show_threat_details' => env('SECURITY_SHOW_DETAILS', false), // 生产环境切勿开启

        'messages' => [
            'blacklist' => '您的IP地址已被列入黑名单，禁止访问',
            'whitelist' => 'IP白名单检查通过',
            'rate_limit' => '请求过于频繁，请稍后再试',
            'body_too_large' => '请求体过大，超过服务器限制',
            'url_too_long' => '请求URL过长',
            'invalid_method' => '不支持的HTTP请求方法',
            'bad_user_agent' => '检测到恶意User-Agent',
            'invalid_headers' => '请求头信息不合法',
            'url_path_attack' => 'URL路径包含非法内容',
            'encoding_bypass' => '请求包含编码绕过特征',
            'sql' => '检测到SQL注入攻击，请求已被拦截',
            'command' => '检测到命令注入攻击，请求已被拦截',
            'path' => '检测到路径遍历攻击，请求已被拦截',
            'ldap' => '检测到LDAP注入攻击，请求已被拦截',
            'xml' => '检测到XML注入攻击，请求已被拦截',
            'nosql' => '检测到NoSQL注入攻击，请求已被拦截',
            'ssti' => '检测到模板注入攻击，请求已被拦截',
            'encoding' => '检测到编码绕过攻击，请求已被拦截',
            'redirect' => '检测到开放重定向攻击，请求已被拦截',
            'file_include' => '检测到文件包含攻击，请求已被拦截',
            'xss_script' => '检测到脚本注入攻击，请求已被拦截',
            'xss_dom' => '检测到DOM型XSS攻击，请求已被拦截',
            'xss_tag' => '检测到标签注入攻击，请求已被拦截',
            'xss_encoding' => '检测到XSS编码绕过攻击，请求已被拦截',
            'xss_framework' => '检测到框架特定XSS攻击，请求已被拦截',
            'dangerous_upload' => '检测到危险文件上传，请求已被拦截',
            'unknown' => '请求包含潜在的安全威胁，已被拦截',
        ],

        'view' => null,  // 自定义拦截视图：'errors.security' 或闭包
    ],

    /*
    |--------------------------------------------------------------------------
    | 📝 Markdown 内容智能识别                                   【排除规则】
    |--------------------------------------------------------------------------
    |
    | 智能识别 Markdown 文档，避免代码示例被误判为攻击。
    | 适用于：文档系统、Wiki、博客、论坛等。
    |
    | 双层控制：
    |   allow_script_in_markdown         — XSS 脚本标签旁路
    |   allow_dangerous_code_in_markdown — 高危代码旁路（SQL/命令等）
    |
    | ⚠️ 仅文档提交场景开启，开放评论/留言场景建议保持 false。
    */

    'markdown' => [
        'smart_detection' => env('SECURITY_MARKDOWN_SMART_DETECT', true),
        'allow_script_in_markdown' => env('SECURITY_MARKDOWN_ALLOW_SCRIPT', false),
        'allow_dangerous_code_in_markdown' => env('SECURITY_MARKDOWN_ALLOW_DANGEROUS_CODE', false),

        // 高危代码旁路适用的攻击类型
        'dangerous_code_types' => [
            'sql', 'command', 'path', 'nosql', 'ldap', 'file_include',
        ],

        // 围栏式代码块标记
        'code_block_markers' => ['```', '~~~'],

        // 行内代码标记
        'inline_code_marker' => '`',

        // Markdown 识别最小内容长度
        'min_length' => 80,

        // Markdown 语法特征最低匹配分数
        'min_syntax_score' => 2,

        // Markdown 语法识别正则                                       【拦截规则】
        'syntax_patterns' => [
            '/^#{1,6}\s+/m',          // 标题
            '/^[-*+]\s+/m',           // 无序列表
            '/\[.+?\]\(.+?\)/',        // 链接
            '/^\s*>\s+/m',            // 引用块
            '/^\s*\|\s*[-:]+\s*\|/m', // 表格
            '/!\[.*?\]\(.*?\)/',      // 图片
            '/\*\*.*?\*\*/',          // 粗体
            '/\*[^*]+\*/',            // 斜体
            '/^---\s*$/m',            // 水平线 / frontmatter
            '/^- \[[ x]\] /m',        // 任务列表
            '/\[\^.+?\]:?/m',         // 脚注
            '/\~\~.*?\~\~/',          // 删除线
            '/^`{3,}\s*\w*/m',        // 代码块开始
            '/<!--[\s\S]*?-->/',      // HTML 注释
            '/^\d+\.\s+/m',           // 有序列表
            '/^:{1,3}\s+\S/m',        // 定义列表
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 🔗 URL 路径攻击检测                                         【拦截规则】
    |--------------------------------------------------------------------------
    |
    | ⚠️ 默认正则模式已迁移至独立数据文件（延迟加载）。
    | 内置检测覆盖：经典路径遍历、Windows路径遍历、URL编码绕过、
    | Unicode绕过、敏感文件（.env/.git等）、版本控制文件泄露、
    | WebShell特征、数据库管理工具暴露、备份/日志文件泄露等。
    |
    | path_patterns：追加自定义正则（格式：扁平数组）
    | path_patterns_exclude：排除内置正则（精确字符串匹配）
    |
    | 自定义追加示例：
    |   'path_patterns' => ['/my_custom_regex/i'],
    |
    | 排除示例（对应 url_path_patterns.php 中的具体规则）：
    |   'path_patterns_exclude' => [
    |       '/(\.\.\/){2,}/',                                        // 业务接口正常使用多级路径
    |       '/\b(\.env|\.git\/|\.git\/config)\b/i',                  // 镜像了 .git 仓库的文档站
    |       '/\.(?:php\d*|phtml|phar|shtml|jsp|...)/i',             // 排除脚本扩展名检测
    |   ],
    */

    'url_path_detection' => [
        'path_patterns' => [],                                       // 自定义追加的路径检测正则
        'path_patterns_exclude' => [],                               // 排除的内置路径检测正则
    ],

    /*
    |--------------------------------------------------------------------------
    | 🔐 编码绕过攻击检测（Layer 4 — 请求级编码异常）               【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 与 Layer 11 high_risk_patterns.encoding 互补（Layer 4 请求级 / Layer 11 内容级）。
    */

    'encoding_detection' => [
        'percent_threshold' => 0.30,                                 // %占比阈值

        // 解码后检查的可疑模式                                          【拦截规则】
        'suspicious_patterns' => [
            '../', '..\\', '<script', 'javascript:',
            'onerror=', 'onload=', 'onfocus=',
        ],

        // 编码检测正则                                                 【拦截规则】
        'encoding_patterns' => [],

        // 排除检测维度 或 排除特定正则（精确字符串匹配）                  【排除规则】
        // 维度名：'null_byte' / 'percent_threshold' / 'multi_encoding' / 'utf8_overlong'
        // 正则串：从 encoding_patterns 中排除特定正则
        //
        // 示例（排除整组）：'encoding_patterns_exclude' => ['multi_encoding'],
        // 示例（排除单条）：'encoding_patterns_exclude' => ['/regex/here/i'],
        //
        // ⚠️ 不影响 Layer 11，需同时配置 high_risk_patterns_exclude['encoding']
        'encoding_patterns_exclude' => [
            '/%25(?:25)+[0-9a-f]{2}/i', // 第三方回调时把回调地址URL使用 urlencode($url) 处理可能会使用到，需要排除此规则
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 🔧 HTTP 方法限制                                          【拦截规则】
    |--------------------------------------------------------------------------
    |
    | 不在列表中的 HTTP 方法将被拦截。
    | 如需禁用某个方法，直接从数组中移除即可。
    |
    | 示例（禁用 DELETE 和 PATCH）：
    |   'allowed_http_methods' => ['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS'],
    */

    'allowed_http_methods' => [
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
    ],

    /*
    |--------------------------------------------------------------------------
    | ⚙️ 输入处理                                                【配置项】
    |--------------------------------------------------------------------------
    |
    | 控制输入截断与日志脱敏。
    */

    'input_processing' => [
        'max_input_length' => 100 * 1024,                     // 最大输入长度（防止正则回溯）
        'max_match_content_length' => 200,                    // 日志中匹配内容最大长度（脱敏）
    ],

    /*
    |--------------------------------------------------------------------------
    | 📊 威胁风险等级映射                                         【配置项】
    |--------------------------------------------------------------------------
    |
    | 自定义每种威胁类型的风险等级：high / medium / low
    | 空数组 = 使用内置默认等级。
    |
    | 配置示例：
    |   'threat_risk_levels' => [
    |       'sql' => 'high',           // SQL注入 → 高危
    |       'xss_script' => 'medium',  // XSS脚本 → 中危
    |       'rate_limit' => 'low',     // 速率限制 → 低危
    |   ],
    */

    'threat_risk_levels' => [],
];
