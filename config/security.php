<?php

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║        Laravel / ThinkPHP 安全中间件 - 配置文件 (v6.2)                       ║
 * ║        🔐 15层纵深安全防护，覆盖 OWASP Top 10 核心攻击向量                     ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * 📦 支持的 PHP 版本：8.2 / 8.3 / 8.4 / 8.5
 * 📦 支持的框架版本：Laravel 11 / 12 / 13，ThinkPHP 8+
 *
 * 📖 配置优先级（从高到低）：
 *    1. 环境变量（.env）       — 运行时覆盖
 *    2. 直接修改本文件         — 发布后自定义
 *    3. 包内置默认值           — 零配置即可使用（位于 @see DefaultConfig 类中）
 *
 * 🚀 快速配置建议：
 *    - 开发环境：关闭 rate_limit，log_level 设为 debug
 *    - 测试环境：保持默认，rate_limit 适当宽松
 *    - 生产环境：开启全部检测，rate_limit 收紧
 *    - 内网部署：将内网IP段加入 trusted_ips
 */

use zxf\Security\Config\DefaultConfig;

return [

    /*
    |--------------------------------------------------------------------------
    | 基础开关
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
    | 🔍 检测层级开关
    |--------------------------------------------------------------------------
    |
    | 精细控制每一层安全检测的启用/禁用。
    | ⚠️ IP黑白名单不受这些开关控制（始终生效）
    */

    'detection_layers' => [
        'url_path'     => env('SECURITY_DETECT_URL_PATH', true),     // URL路径攻击检测（路径遍历、敏感文件）
        'encoding'     => env('SECURITY_DETECT_ENCODING', true),     // 多重编码绕过检测
        'user_agent'   => env('SECURITY_DETECT_USER_AGENT', true),   // User-Agent黑名单检测
        'headers'      => env('SECURITY_DETECT_HEADERS', true),      // HTTP请求头安全检查
        'body_size'    => env('SECURITY_DETECT_BODY_SIZE', true),    // 请求体大小检查
        'rate_limit'   => env('SECURITY_DETECT_RATE_LIMIT', true),   // 请求速率限制
        'http_method'  => env('SECURITY_DETECT_HTTP_METHOD', true),  // HTTP方法检查
        'url_length'   => env('SECURITY_DETECT_URL_LENGTH', true),   // URL长度检查
        'high_risk'    => env('SECURITY_DETECT_HIGH_RISK', true),    // 高危攻击检测（SQL/命令/SSTI/SSRF等）
        'xss'          => env('SECURITY_DETECT_XSS', true),          // XSS攻击检测
        'upload'       => env('SECURITY_DETECT_UPLOAD', true),       // 文件上传安全检查
        'redirect'     => env('SECURITY_DETECT_REDIRECT', false),    // 开放重定向检测（默认关闭，易误报）
        'database_operation' => env('SECURITY_DETECT_DB_OPERATION', false), // 数据库危险操作检测（默认关闭）
    ],

    /*
    |--------------------------------------------------------------------------
    | 📩 联系我们链接地址
    |--------------------------------------------------------------------------
    |
    | 如果配置此参数，在错误页面的操作按钮区域（"返回首页"右侧）会显示"联系我们"按钮。
    | 用户点击后跳转到配置的 URL 地址。
    |
    | 支持任意合法 URL 格式：
    |   - 站内路径：'/contact'、'/support/form'
    |   - 外部链接：'https://example.com/contact'
    |   - 邮件链接：'mailto:support@example.com'
    |   - 电话链接：'tel:+861234567890'
    |
    | 默认: '' (空字符串表示不显示)
    */
    'contact_url' => env('SECURITY_CONTACT_URL', ''),

    /*
    |--------------------------------------------------------------------------
    | 🛡️ 信任 IP — 跳过所有检测直接放行
    |--------------------------------------------------------------------------
    |
    | 适用场景：本机服务间调用、CI/CD流水线、负载均衡器/反向代理。
    |
    | ⚠️ 默认空数组，由开发者按需配置。
    |    切勿将整个内网段（10.0.0.0/8 等）添加，否则所有内网代理请求都将跳过检查！
    |
    | 支持格式：
    |   ① 静态IP/CIDR：'127.0.0.1', '10.0.1.0/24'
    |   ② 闭包函数：function(string $ip, object $request): bool { ... }
    |   ③ 类名字符串：App\Security\IpChecker::class
    |   ④ 可调用数组：[App\Security\IpService::class, 'isTrusted']
    |
    | 示例：
    |   'trusted_ips' => [
    |       '127.0.0.1',
    |       '::1',
    |       '10.0.1.5',
    |       '172.17.0.0/16',
    |   ],
    */
    'trusted_ips' => [],

    /*
    |--------------------------------------------------------------------------
    | ⏱️ 速率限制
    |--------------------------------------------------------------------------
    |
    | 基于 IP + 路由路径组合限流（key: {prefix}:{IP}:{路由MD5}）
    | 推荐值：普通网站 60次/分，API 300次/分，后台 20次/分
    */
    'rate_limit' => [
        'max_attempts' => env('SECURITY_RATE_LIMIT_ATTEMPTS', 300),
        'decay_minutes' => env('SECURITY_RATE_LIMIT_DECAY', 1),
        'key_prefix' => env('SECURITY_RATE_LIMIT_KEY_PREFIX', 'security'),
    ],

    /*
    |--------------------------------------------------------------------------
    | 🚫 IP 黑名单 — 直接拦截（HTTP 403）
    |--------------------------------------------------------------------------
    |
    | 支持格式与 trusted_ips 完全相同。
    |
    | 示例：
    |   'blacklist' => [
    |       '203.0.113.50',
    |       '198.51.100.0/24',
    |       function(string $ip, object $request) {
    |           return \App\Models\BannedIp::where('ip', $ip)->exists();
    |       },
    |   ],
    */
    'blacklist' => [],

    /*
    |--------------------------------------------------------------------------
    | ✅ IP 白名单 — 业务层信任（合作方 API、支付回调）
    |--------------------------------------------------------------------------
    |
    | trusted_ips vs whitelist 的区别：
    |   - trusted_ips：系统层面信任，跳过所有检查
    |   - whitelist：业务层面信任，可单独审计
    |
    | 支持格式与 blacklist 完全相同。
    */
    'whitelist' => [],

    /*
    |--------------------------------------------------------------------------
    | ⚔️ 统一拦截规则管理（v6.0 核心特性）
    |--------------------------------------------------------------------------
    |
    | 规则优先级（从高到低）：
    |   1. intercept_rules_exclude — 排除列表（全局生效，精确字符串匹配）
    |   2. intercept_rules — 用户自定义追加规则（按风险等级分组）
    |   3. built-in patterns — 内置默认规则（src/Security/Patterns/data/）
    |
    | intercept_rules 说明：
    |   不区分攻击类型，仅按 high / medium / low 三种风险等级分组。
    |   追加的规则将作为独立类型 '_custom_high' / '_custom_medium' / '_custom_low' 参与检测。
    |
    | intercept_rules_exclude 说明：
    |   不管是哪种类型（内置sql/command/path/xss等）的拦截，只要添加在此处的正则字符串，
    |   就全部排除，不对其进行拦截。使用精确字符串匹配（与正则表达式完整字符串一致）。
    |
    | 配置示例：
    |   'intercept_rules' => [
    |       'high' => [
    |           '/my_custom_critical_regex/i',
    |       ],
    |       'medium' => [
    |           '/some_business_risk_pattern/i',
    |       ],
    |       'low' => [],
    |   ],
    |   'intercept_rules_exclude' => [
    |       '/unhex\s*\(/i',           // 业务使用 unhex() 做密码哈希
    |       '/benchmark\s*\(/i',       // 业务使用 benchmark 做性能测试
    |       '/\b1\s*=\s*1\b/i',        // 搜索场景常用"1=1"，误报率高
    |   ],
    |
    | ⚠️ 排除规则时务必评估安全风险！
    */

    // 【追加】拦截规则：按高危、中危、低危分组，不区分类型
    'intercept_rules' => [
        'high'   => [],
        'medium' => [],
        'low'    => [],
    ],

    // 【排除】拦截规则：全局排除，精确字符串匹配正则表达式
    'intercept_rules_exclude' => [
        // 允许URL编码绕过安全拦截: %25；如果不需要，直接删除或注释即可；
        '/%25(?:25)+[0-9a-f]{2}/i', // 多重URL编码绕过（%2525...）
        '/%25(?:25)+/i', // 多层%25编码序列

        // 默认排除：业务系统可能正常使用的模式（按需调整）
        // 示例：如业务使用 unhex() 做密码哈希，可取消注释排除
        // '/unhex\s*\(/i',
        // '/benchmark\s*\(/i',
        // '/\b1\s*=\s*1\b/i',        // 搜索场景常用"1=1"，误报率高
    ],

    /*
    |--------------------------------------------------------------------------
    | 📁 文件上传安全
    |--------------------------------------------------------------------------
    |
    | 四层防护：扩展名白名单 + 黑名单 + 大小限制 + MIME魔术字节验证
    |
    | allowed_extensions / blocked_extensions 支持多种格式：
    |   ① 静态数组：['jpg', 'png', 'pdf']
    |   ② 闭包函数：function(): array { return ['jpg', 'png']; }
    |   ③ 类名字符串：App\Security\UploadConfig::class
    |   ④ 可调用数组：[App\Security\UploadConfig::class, 'getAllowed']
    |
    | 安全建议：上传目录无执行权限、文件改名、图片二次处理
    */
    'upload' => [
        'max_size' => 50 * 1024 * 1024,                              // 单文件最大 50MB
        'check_mime_magic' => env('SECURITY_UPLOAD_CHECK_MIME', false), // 深度MIME验证
        'mime_magic_map' => [],                                      // 自定义MIME映射（留空使用内置）

        /** 允许上传的文件扩展名（默认列表在 @see DefaultConfig::UPLOAD_ALLOWED_EXTENSIONS 中定义，此处可覆盖）*/
        'allowed_extensions' => null,  // null = 使用内置默认值，数组 = 完全覆盖

        /** 禁止上传的文件扩展名（默认列表在 @see DefaultConfig::UPLOAD_BLOCKED_EXTENSIONS 中定义，此处可覆盖）*/
        'blocked_extensions' => null,  // null = 使用内置默认值，数组 = 完全覆盖
    ],

    /*
    |--------------------------------------------------------------------------
    | 📏 URL 长度限制
    |--------------------------------------------------------------------------
    */
    'max_url_length' => [
        'limit' => 2048,
    ],

    /*
    |--------------------------------------------------------------------------
    | 📦 请求体大小限制
    |--------------------------------------------------------------------------
    */
    'max_body_size' => [
        'limit' => 50 * 1024 * 1024,       // 默认 50MB
    ],

    /*
    |--------------------------------------------------------------------------
    | 🤖 User-Agent 黑名单
    |--------------------------------------------------------------------------
    |
    | 已知恶意扫描器/攻击工具的 User-Agent 特征串。
    |
    | 支持格式：
    |   ① 静态字符串：'sqlmap', 'nmap'
    |   ② 正则表达式（以/开头）：'/python-requests/i'
    |   ③ 闭包函数：function(string $ua, object $request): bool { ... }
    |   ④ 类名字符串 / 可调用数组（通过 ConfigResolver 解析）
    |
    | 默认列表在 @see DefaultConfig::USER_AGENT_BLACKLIST 中定义，此处可覆盖。
    */
    'user_agent_blacklist' => null,  // null = 使用内置默认值，数组 = 完全覆盖

    /*
    |--------------------------------------------------------------------------
    | 🔒 HTTP 头安全检查
    |--------------------------------------------------------------------------
    |
    | 检查维度：禁止的请求头、CRLF注入（HTTP响应拆分）、Host头验证
    */
    'headers' => [
        'forbidden' => [
            'X-Debug',
            'X-Debug-Token',
        ],
        'detect_crlf' => env('SECURITY_DETECT_CRLF', true),
        'host_validation' => [
            'enabled' => false,
            'allowed_hosts' => [],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 🚏 路由排除
    |--------------------------------------------------------------------------
    |
    | 排除列表中的路径将跳过所有安全检查直接放行。
    | 适用场景：健康检查、Webhook回调、管理后台等。
    |
    | 支持格式：
    |   ① 字符串（支持 * 通配符）：'api/health*'
    |   ② 正则（以 / 开头）：'/^api\/v1\/health$/'
    |   ③ 闭包函数：function(object $request): bool { ... }
    |
    | ⚠️ 不要将整个 /api/* 排除，风险过高！
    */
    'excluded_routes' => [],

    /*
    |--------------------------------------------------------------------------
    | 🎛️ 拦截前回调
    |--------------------------------------------------------------------------
    |
    | 在正式拦截前执行的自定义回调，支持灵活拦截决策。
    |
    | 返回值含义：
    |   false  → 放行请求
    |   其他   → 拦截请求
    |
    | 支持格式：
    |   null/false              → 禁用回调，直接拦截
    |   闭包函数                 → function(InterceptionContext $context): ?bool { ... }
    |   类名字符串               → 'App\Security\CustomInterceptor'（需实现 __invoke）
    |   可调用数组               → ['App\Security\CustomInterceptor', 'handle']
    |
    | 示例（仅拦截高危）：
    |   'before_block_callback' => function($context) {
    |       return $context->getRiskLevel() === 'high';
    |   },
    */
    'before_block_callback' => null,

    /*
    |--------------------------------------------------------------------------
    | 📤 HTTP 响应配置
    |--------------------------------------------------------------------------
    |
    | messages 默认列表在 @see DefaultConfig::RESPONSE_MESSAGES 中定义，此处可覆盖单个条目。
    | view 支持：字符串视图名、闭包、类方法数组、可调用类。
    */
    'response' => [
        'blocked_status' => 403,
        'rate_limit_status' => 429,
        'message' => '请求被拒绝：检测到潜在的安全威胁',
        'show_threat_details' => env('SECURITY_SHOW_DETAILS', false),

        // 自定义拦截消息（覆盖内置默认值，非覆盖则保持默认）
        'messages' => [],

        'view' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | 📝 Markdown 内容智能识别
    |--------------------------------------------------------------------------
    |
    | 智能识别 Markdown 文档，避免代码示例被误判为攻击。
    |
    | syntax_patterns 支持多种配置格式（数组、闭包、类名、可调用数组）。
    | 默认列表在 @see DefaultConfig::MARKDOWN_SYNTAX_PATTERNS 中定义，此处可覆盖。
    |
    | ⚠️ 仅文档提交场景开启，开放评论/留言场景建议保持 false。
    */
    'markdown' => [
        'smart_detection' => env('SECURITY_MARKDOWN_SMART_DETECT', true),
        'allow_script_in_markdown' => env('SECURITY_MARKDOWN_ALLOW_SCRIPT', false),
        'allow_dangerous_code_in_markdown' => env('SECURITY_MARKDOWN_ALLOW_DANGEROUS_CODE', false),

        'dangerous_code_types' => [
            'sql', 'command', 'path', 'nosql', 'ldap', 'file_include',
        ],

        'code_block_markers' => ['```', '~~~'],
        'inline_code_marker' => '`',
        'min_length' => 80,
        'min_syntax_score' => 2,

        // Markdown语法识别正则（null=使用内置默认值）
        'syntax_patterns' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | 🔐 编码绕过攻击检测
    |--------------------------------------------------------------------------
    |
    | 与 high_risk_patterns.encoding 互补（本层为请求级 / encoding为内容级）。
    |
    | 检测维度（通过 encoding_patterns_exclude 排除）：
    |   - null_byte：空字节注入
    |   - percent_threshold：URL中%字符占比异常
    |   - utf8_overlong：UTF-8过度编码
    |
    | suspicious_patterns 默认列表在 @see DefaultConfig 中定义。
    */
    'encoding_detection' => [
        'percent_threshold' => 0.30,

        // 解码后检查的可疑模式（null=使用内置默认值）
        'suspicious_patterns' => null,

        // 排除检测维度 或 排除特定正则（精确字符串匹配）
        // 维度名：'null_byte' / 'percent_threshold' / 'utf8_overlong'
        'encoding_patterns_exclude' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | 🔧 HTTP 方法限制
    |--------------------------------------------------------------------------
    |
    | 不在列表中的 HTTP 方法将被拦截。
    | 默认列表在 @see DefaultConfig::ALLOWED_HTTP_METHODS 中定义，此处可覆盖。
    */
    'allowed_http_methods' => null,  // null = 使用内置默认值，数组 = 完全覆盖

    /*
    |--------------------------------------------------------------------------
    | ⚙️ 输入处理
    |--------------------------------------------------------------------------
    */
    'input_processing' => [
        'max_input_length' => 100 * 1024,      // 最大输入长度（防止正则回溯）
        'max_match_content_length' => 200,     // 日志匹配内容最大长度（脱敏）
    ],

    /*
    |--------------------------------------------------------------------------
    | 📊 威胁风险等级映射
    |--------------------------------------------------------------------------
    |
    | 自定义每种威胁类型的风险等级：high / medium / low
    | 空数组 = 使用内置默认等级。
    |
    | 示例：
    |   'threat_risk_levels' => [
    |       'sql' => 'high',
    |       'xss_script' => 'medium',
    |       'rate_limit' => 'low',
    |   ],
    */
    'threat_risk_levels' => [],

    /*
    |--------------------------------------------------------------------------
    | 🗄️ 数据库危险操作检测与拦截（第十四层安全防护）
    |--------------------------------------------------------------------------
    |
    | 识别并拦截通过 Web 请求提交的数据库危险操作命令，防止通过 API/表单/URL
    | 等渠道执行可能造成数据丢失的操作。
    |
    | ══════════════════════════════════════════════════════════════════════
    | 三大检测类别（52 条规则，分阶段匹配）：
    |
    | 1. 表结构破坏类（18 条规则，破坏性最强，不可逆）：
    |    - Laravel Artisan: migrate:fresh、migrate:refresh、migrate:reset、db:wipe
    |    - ThinkPHP: migrate:rollback
    |    - Schema Builder: Schema::drop()、dropIfExists()、dropAllTables()、dropDatabase()
    |    - 原生 SQL DDL: DROP TABLE/DATABASE/VIEW/PROCEDURE/FUNCTION
    |    - 危险前置操作: ALTER TABLE DROP、RENAME TABLE、SET FOREIGN_KEY_CHECKS=0
    |                    SET SQL_SAFE_UPDATES=0
    |
    | 2. 全量数据删除类（21 条规则，数据不可恢复）：
    |    - SQL: TRUNCATE TABLE、DELETE FROM 无条件/永真条件（WHERE 1=1/OR 1=1等）
    |           UPDATE 无条件/永真条件
    |    - Laravel Eloquent: Model::truncate()、::query()->delete()
    |                        ::all()->each(...delete...)、->select()->delete()
    |    - ThinkPHP: Db::table()->delete()、Db::name()->delete()
    |                Db::execute(DROP/TRUNCATE)、Model::destroy() 无条件
    |
    | 3. 代码级操作识别（13 条规则）：
    |    - Artisan::call() 调用危险迁移命令
    |    - shell_exec/exec/passthru/system/popen/proc_open 执行 artisan
    |    - Symfony Process 组件执行 artisan
    |    - DB::statement()/DB::unprepared() 执行 DROP/TRUNCATE 原生 SQL
    |
    | ══════════════════════════════════════════════════════════════════════
    | 两级过滤性能优化：
    |   第一级 — str_contains 预过滤（~50μs）：合并关键词列表，排除 95%+ 安全请求
    |   第二级 — preg_match 正则匹配：仅对通过预过滤的 <5% 输入执行 52 条正则
    |
    | ══════════════════════════════════════════════════════════════════════
    | environments 支持的值及其含义：
    |   'all'        — 所有环境均拦截（适合高度敏感系统）
    |   'production' — 仅生产环境拦截（推荐配置，防止线上误操作丢数据）
    |   'staging'    — 预发布/灰度环境拦截
    |   'testing'    — 仅测试环境拦截
    |   'local'      — 仅本地开发环境拦截（调试用）
    |   'cli'        — 仅 CLI 命令行环境拦截（防止 artisan 命令管道误调用）
    |
    | 支持多环境组合：['production', 'staging', 'cli'] 可覆盖多个场景。
    |
    | ══════════════════════════════════════════════════════════════════════
    | 环境配置建议：
    |   - 开发环境：保持默认（environments 不含 'local'），或仅开启 CLI
    |   - 测试环境：设置为 ['testing']
    |   - 预发布环境：设置为 ['staging']
    |   - 生产环境：设置为 ['production', 'cli']（防止误操作丢数据）
    |   - 高敏系统：设置为 ['all']
    |
    | ══════════════════════════════════════════════════════════════════════
    | 误拦截排除：
    |   - exclude_tables: 排除对特定系统表的操作（如 cache/sessions/jobs）
    |   - exclude_commands: 排除特定 artisan 命令名（如 migrate:rollback）
    |*/
    'database_operation' => [
        // 拦截生效环境：指定在哪些环境下识别并拦截数据库危险操作
        // 注意：总开关由 detection_layers.database_operation 控制（见上方）
        // 环境选项：'all' | 'production' | 'staging' | 'testing' | 'local' | 'cli'
        // 例如：['production'] 仅生产环境拦截，['all'] 所有环境拦截
        'environments' => ['production'],

        // 是否拦截表结构破坏操作（DROP TABLE、migrate:fresh 等）
        'block_table_destruction' => env('SECURITY_DB_BLOCK_TABLE_DESTRUCTION', true),

        // 是否拦截全量数据删除操作（TRUNCATE、DELETE 无条件等）
        'block_mass_deletion' => env('SECURITY_DB_BLOCK_MASS_DELETION', true),

        // 是否拦截代码级数据库危险操作（Artisan::call 等）
        'block_code_level_operation' => env('SECURITY_DB_BLOCK_CODE_LEVEL', true),

        // 自定义排除表名/命令（不被拦截的表名或命令名称列表）
        // 例如：['cache', 'sessions', 'jobs'] 表示对 cache/sessions/jobs 表操作不拦截
        'exclude_tables' => [],

        // 自定义排除命令（不被拦截的 artisan 命令全名列表）
        // 例如：['migrate:rollback'] 允许 migrate:rollback 执行
        'exclude_commands' => [],
    ],
];
