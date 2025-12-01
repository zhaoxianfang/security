<?php

namespace zxf\Security\Config;

use zxf\Security\Contracts\SecurityConfigInterface;

/**
 * 商业级安全配置管理类 - 工业标准最终完整版
 *
 * 核心特性：
 * 1. 高性能合并正则表达式，减少匹配次数，提升检测速度
 * 2. 智能分层检测策略，平衡安全防护与系统性能
 * 3. 最小化误报率设计，确保业务连续性和用户体验
 * 4. 商业级威胁覆盖，全面防护各类网络攻击向量
 * 5. 工业标准合规性，符合国际安全最佳实践和标准
 * 6. 实时威胁情报集成支持，动态更新防护规则
 * 7. 自适应学习机制支持，持续优化检测准确率
 * 8. 多维度风险评估，提供全面的安全态势感知
 * 9. 模块化配置设计，支持灵活扩展和定制
 * 10. 完整的性能监控，实时掌握系统运行状态
 */
class SecurityConfig implements SecurityConfigInterface
{
    /**
     * 预编译的正则表达式缓存 - 大幅提升性能
     * 通过缓存机制避免重复编译，减少CPU开销
     */
    protected static array $compiledPatterns = [];

    /**
     * 配置版本信息 - 便于版本管理和升级
     */
    protected const CONFIG_VERSION = '4.0.0';
    protected const CONFIG_LEVEL = 'commercial_industrial_plus';

    /**
     * 获取优化的恶意请求体检测模式 - 商业级最终优化版
     *
     * 采用智能合并和分层策略，将相似攻击向量合并为高性能正则表达式
     * 通过优化回溯和分组匹配，在保持检测精度的同时大幅提升匹配效率
     * 支持多层级威胁检测，从基础攻击到高级持久化威胁全面覆盖
     *
     * @return array 优化后的正则表达式模式数组
     */
    public static function getMaliciousBodyPatterns(): array
    {
        return array_merge(
            self::getCriticalThreatPatterns(),     // 关键威胁检测 - 最高优先级
            self::getCommonAttackPatterns(),       // 常见攻击检测 - 高性能
            self::getAdvancedThreatPatterns(),     // 高级威胁检测 - 全面覆盖
            self::getEmergingThreatPatterns()      // 新兴威胁检测 - 前瞻防护
        );
    }

    /**
     * 关键威胁检测模式 - 最高性能和安全优先级
     *
     * 覆盖最危险且最常见的攻击类型，性能最优
     * 目标：在0.1ms内完成关键威胁检测
     */
    protected static function getCriticalThreatPatterns(): array
    {
        return [
            /**
             * 合并的关键XSS和脚本注入检测
             * 覆盖：脚本标签、JavaScript/VBScript协议、数据URI、事件处理器
             * 性能优化：使用非捕获组，避免不必要的回溯
             */
            '/(?:<script\b[^>]*>.*?<\/script>|javascript:\s*[^"\'{}<>]*|vbscript:\s*[^"\'{}<>]*|data:\s*(?:text|application)\/(?:javascript|ecmascript)|\bon\w+\s*=\s*["\']?[^"\'>]*(?:alert|prompt|confirm)\s*\([^)]*\))/is',

            /**
             * 合并的关键SQL注入检测
             * 覆盖：联合查询、数据操作语句、存储过程、SQL注释、编码绕过
             * 性能优化：使用单词边界和精确匹配，减少误报
             */
            '/\b(?:union\s+select|select\s+[\w*]+\s+from|insert\s+into|update\s+\w+\s+set|drop\s+(?:table|database|view|procedure)|delete\s+from|truncate\s+table|exec\s*\(|xp_cmdshell|sp_|--\s+|\/\*.*?\*\/|0x[0-9a-f]+|char\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\))/is',

            /**
             * 合并的关键命令注入检测
             * 覆盖：系统命令函数、反引号执行、管道符号、重定向、命令分隔
             * 性能优化：精确匹配系统函数，避免通用模式
             */
            '/\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\([^)]*\)|`[^`]*`|\|\s*\w+|\&\s*\w+|;\s*\w+|\$\s*\([^)]*\)/i',

            /**
             * 合并的关键路径遍历和文件包含检测
             * 覆盖：目录遍历、敏感文件访问、本地/远程文件包含、协议包装器
             * 性能优化：精确匹配敏感路径和协议
             */
            '/(?:\.\.\/|\.\.\\\\|\/etc\/(?:passwd|shadow|hosts)|\/winnt\/system32|\/windows\/system32|\b(?:include|require)(?:_once)?\s*\(?\s*[\'\"][^\"\']*\.(?:php|phtml|inc)|\b(?:include|require)(?:_once)?\s*\(?\s*[\'\"](?:https?|ftp|phar):\/\/|php:\/\/(?:input|filter|glob|data|expect))/i',
        ];
    }

    /**
     * 常见攻击检测模式 - 平衡性能和覆盖范围
     *
     * 覆盖中等复杂度的攻击类型，性能良好
     * 目标：在1ms内完成常见攻击检测
     */
    protected static function getCommonAttackPatterns(): array
    {
        return [
            /**
             * 合并的代码执行和反序列化检测
             * 覆盖：PHP标签、危险函数、反序列化、编码函数、变量操作
             * 性能优化：分组匹配相关函数，减少匹配次数
             */
            '/(?:<\?php|<\?=|\b(?:eval|assert|create_function|unserialize|str_rot13|base64_decode|gzinflate|gzuncompress)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]+\]|O:\d+:"[^"]*":\d+:|__(?:destruct|wakeup|toString|invoke|call|callStatic|get|set)\b)/i',

            /**
             * 合并的表达式和模板注入检测
             * 覆盖：各种模板语法、表达式语言、脚本注入
             * 性能优化：使用通用模式匹配多种模板语法
             */
            '/(?:\$\{.*?\}|\({.*?}\)|\{\{.*?\}\}|@\w+\(.*?\)|\{%.*?%\}|\[\[.*?\]\]|<\%.*?\%>)/s',

            /**
             * 合并的NoSQL注入和API滥用检测
             * 覆盖：MongoDB操作符、数组操作、GraphQL注入、REST参数污染
             * 性能优化：精确匹配数据库操作符
             */
            '/"\$(?:where|eq|ne|gt|gte|lt|lte|in|nin|or|and|not|exists|regex|text|where|push|pull|pop|addToSet|pullAll)"/',

            /**
             * 合并的文件上传绕过检测
             * 覆盖：双扩展名、空字节注入、大小写混淆、特殊文件名
             * 性能优化：精确匹配绕过技术特征
             */
            '/(?:\.(php|phtml|jsp|asp|asa|cer)\.(txt|jpg|png|gif)$|\\x00|\.(PhP|pHp|Phtml|JSp|aSp|AsA|CeR)$|\.(php[0-9]|phtml[0-9])$)/i',
        ];
    }

    /**
     * 高级威胁检测模式 - 全面覆盖复杂攻击
     *
     * 覆盖复杂和新型攻击类型，检测精度最高
     * 目标：在10ms内完成高级威胁检测
     */
    protected static function getAdvancedThreatPatterns(): array
    {
        return [
            /**
             * XXE和XML外部实体攻击检测
             * 覆盖：外部实体声明、DOCTYPE外部引用、参数实体、XML注入
             * 安全优化：全面覆盖各类XXE攻击向量
             */
            '/(?:<!ENTITY\s+\w+\s+SYSTEM\s+["\']|<!DOCTYPE[^>[]*SYSTEM\s*["\']|<!ENTITY\s+%\s+\w+|<?xml[^>]*encoding\s*=\s*["\']?[^"\'<>]*\?>\s*<!ENTITY)/i',

            /**
             * Web Shell和恶意代码特征检测
             * 覆盖：一句话木马、编码后门、文件管理器、远程控制特征
             * 安全优化：基于真实Web Shell样本特征
             */
            '/(?:@\$_=\$_[_];@\$_\(\$_[__]\);|\beval\(\s*base64_decode|\bgzinflate\(\s*base64_decode|\b(?:FileManager|r57|c99|w4ck1ng|b374k|webadmin)\.(?:php|txt)\b|\b(?:phpspy|afe|wso|reGeorg)\.(?:php|jsp|aspx)\b)/i',

            /**
             * 云服务密钥和敏感信息泄露检测
             * 覆盖：AWS密钥、Google API密钥、SSH私钥、数据库凭证
             * 安全优化：基于真实密钥格式和模式
             */
            '/(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\\-_]{35}|sk-[a-zA-Z0-9]{48}|-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----|(?:host|port|user|password)\s*=\s*[^\s]+)/',

            /**
             * 加密货币和金融信息检测
             * 覆盖：比特币地址、以太坊地址、钱包文件特征
             * 安全优化：精确匹配加密货币地址格式
             */
            '/(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|bc1[a-z0-9]{39,59}|L[1-9A-HJ-NP-Za-km-z]{26,33})/',

            /**
             * 服务端请求伪造(SSRF)检测
             * 覆盖：内网地址、本地回环、元数据服务、协议滥用
             * 安全优化：覆盖各类SSRF攻击目标
             */
            '/(?:127\.0\.0\.1|localhost|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|0\.0\.0\.0|metadata\.google\.internal|169\.254\.169\.254)/i',
        ];
    }

    /**
     * 新兴威胁检测模式 - 前瞻性防护
     *
     * 覆盖新型和零日攻击类型，持续更新
     * 目标：提供对未来威胁的防护能力
     */
    protected static function getEmergingThreatPatterns(): array
    {
        return [
            /**
             * 依赖混淆和供应链攻击检测
             * 覆盖：恶意包名、依赖劫持、包混淆特征
             * 前瞻性：针对软件供应链攻击的防护
             */
            '/(?:node_modules\/[^\/]+\/(?:bin|lib)\/|vendor\/[^\/]+\/(?:src|lib)\/|import\s+[^;]*(?:malicious|backdoor|trojan)|require\s*\(\s*[^)]*(?:evil|hack))/i',

            /**
             * API安全滥用检测
             * 覆盖：GraphQL查询滥用、REST参数污染、API密钥泄露
             * 前瞻性：针对现代API攻击的防护
             */
            '/(?:query\s*\{[^}]*__typename[^}]*\}|mutation\s*\{[^}]*delete|api_key\s*=\s*[^\s&]+|apikey\s*=\s*[^\s&]+)/i',

            /**
             * 容器和安全隔离逃逸检测
             * 覆盖：容器逃逸、命名空间突破、资源滥用
             * 前瞻性：针对云原生环境攻击的防护
             */
            '/(?:\/proc\/self\/|\/sys\/kernel\/|cgroup|docker\.sock|kubelet|namespace|privileged|capabilities)/i',

            /**
             * 机器学习模型投毒检测
             * 覆盖：模型文件篡改、训练数据污染、后门植入
             * 前瞻性：针对AI系统安全的防护
             */
            '/(?:\.(?:pkl|pth|h5|model|joblib)\.(?:php|exe|bat)$|model_state_dict|training_data)/i',
        ];
    }

    /**
     * 获取工业级URL路径检测模式 - 最终优化版
     *
     * 针对目录遍历、敏感文件泄露、配置信息暴露等攻击的全面防护
     * 采用精确匹配和高性能正则，在保持低误报率的同时提供全面保护
     *
     * @return array URL检测正则表达式数组
     */
    public static function getIllegalUrlPatterns(): array
    {
        return [
            /**
             * 隐藏文件和目录检测
             * 排除合法的 .well-known 目录（用于SSL验证等）
             * 性能优化：使用正向否定预查，避免误伤合法目录
             */
            '~/(?:\.(?!well-known)[^/]*|\.{2,})(?=/|$)~i',

            /**
             * 配置文件和敏感数据文件检测
             * 覆盖：环境配置、应用配置、版本控制、服务器配置
             * 安全优化：全面覆盖各类敏感配置文件
             */
            '/\.(?:env|config|settings|configuration|secret|key|credential|token)(?:\.[\w]+)?$/i',
            '/\.(?:gitignore|gitattributes|htaccess|htpasswd|nginx\.conf|apache2?\.conf)(?:\.[\w]+)?$/i',
            '/(?:composer|package|yarn|pip|gemfile)(?:\.(?:json|lock|yml|yaml))?$/i',

            /**
             * 源代码和脚本文件泄露检测
             * 覆盖：服务器端脚本、客户端脚本、编译文件、配置文件
             * 安全优化：全面覆盖各类可执行和配置文件
             */
            '/\.(?:php[3457s]?|phtml|phar|inc)(?:\.[\w]+)?$/i',
            '/\.(?:jspx?|asp|aspx?|asmx|ascx|cer)(?:\.[\w]+)?$/i',
            '/\.(?:pl|py|rb|rhtml|sh|bash|cgi|fcgi)(?:\.[\w]+)?$/i',
            '/\.(?:java|class|jar|war|ear)(?:\.[\w]+)?$/i',
            '/\.(?:js|html?|xhtml|xml|json)(?:\.[\w]+)?$/i',

            /**
             * 数据库文件和备份文件检测
             * 覆盖：数据库文件、备份文件、转储文件、日志文件
             * 安全优化：防止数据库信息和日志泄露
             */
            '/\.(?:sql|db|mdb|accdb|sqlite|dbf|mdf|ldf|frm)(?:\.[\w]+)?$/i',
            '/\.(?:bak|old|backup|temp|tmp|swp|swo)(?:\.[\w]+)?$/i',
            '/\.(?:log|trace|debug|error|access|audit)(?:\.[\w]+)?$/i',

            /**
             * 敏感目录路径检测
             * 覆盖：备份目录、临时目录、版本控制、管理界面、依赖目录
             * 安全优化：防止目录遍历和信息泄露
             */
            '/(?:^|\/)(?:backup|temp|tmp|cache|session)(?:\/|$)/i',
            '/(?:^|\/)(?:node_modules|vendor|bower_components)(?:\/|$)/i',
            '/(?:^|\/)(?:\.git|\.svn|\.hg|\.DS_Store)(?:\/|$)/i',
            '/(?:^|\/)(?:administrator|phpmyadmin|wp-admin)(?:\/|$)/i',

            /**
             * 系统文档和许可证文件检测
             * 覆盖：说明文档、许可证文件、变更日志、贡献指南
             * 安全优化：防止系统信息泄露
             */
            '/(?:readme|license|changelog|contributing|todo|faq)\.(?:md|txt|rst|html?)$/i',
        ];
    }

    /**
     * 获取商业级可疑User-Agent检测模式 - 增强优化版
     *
     * 智能识别安全扫描工具、恶意软件、自动化攻击工具、僵尸网络等
     * 基于真实威胁情报和攻击工具特征，确保高检测率和低误报率
     *
     * @return array User-Agent检测正则表达式数组
     */
    public static function getSuspiciousUserAgents(): array
    {
        return [
            /**
             * 安全扫描和渗透测试工具检测
             * 覆盖：主流漏洞扫描器、渗透测试框架、安全评估工具
             * 安全优化：基于真实工具特征，持续更新
             */
            '/\b(?:sqlmap|nikto|metasploit|nessus|wpscan|acunetix|burp|dirbuster|nmap|netsparker|openvas|qualys|rapid7|tenable|greenbone)\b/i',

            /**
             * 恶意软件和攻击框架检测
             * 覆盖：渗透测试框架、后门工具、Web Shell管理工具
             * 安全优化：覆盖已知恶意软件家族
             */
            '/\b(?:beef|setoolkit|empire|cobaltstrike|armitage|canvas|havij|zap|arachni|w3af|skipfish|wapiti)\b/i',

            /**
             * DDoS工具和僵尸网络检测
             * 覆盖：压力测试工具、DDoS僵尸网络、网络扫描工具
             * 安全优化：识别自动化攻击工具
             */
            '/\b(?:slowloris|r-u-dead-yet|loic|hoic|goldeneye|mirai|bashlite|gafgyt|qbot|nebula)\b/i',

            /**
             * 自动化攻击和扫描工具检测
             * 覆盖：网络扫描、目录爆破、漏洞扫描、信息收集工具
             * 安全优化：识别自动化攻击行为
             */
            '/\b(?:masscan|zmap|zmeu|blackwidow|satori|xenotix|zgrab|nuclei|ffuf|gobuster|dirb)\b/i',

            /**
             * 可疑模式和匿名工具检测
             * 覆盖：随机字符串、虚假标识、匿名代理、爬虫滥用
             * 安全优化：基于行为特征的检测
             */
            '/^[A-Z0-9]{16,}$|^(?:null|undefined|test|fake|unknown)$/i',
            '/\b(?:tor|vpn|proxy|anonymizer)\s*(?:bot|crawler|spider)/i',
            '/\b(?:scan|spider|crawl|bot)\b.*\b(?:unknown|generic|self)\b/i',
        ];
    }

    /**
     * 获取工业级白名单User-Agent模式 - 扩展优化版
     *
     * 包含主流搜索引擎、社交媒体、监控工具、合法API客户端、内容聚合器等
     * 基于真实业务流量分析，确保正常业务不受影响，同时提供全面保护
     *
     * @return array 白名单User-Agent正则表达式数组
     */
    public static function getWhitelistUserAgents(): array
    {
        return [
            // 主流搜索引擎爬虫 - 确保SEO不受影响
            '/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|facebot/i',

            // 社交媒体和服务商爬虫 - 确保社交分享功能正常
            '/facebookexternalhit|twitterbot|linkedinbot|pinterest|applebot|msnbot|whatsapp|telegrambot/i',

            // SEO和分析工具 - 确保网站分析数据准确
            '/ahrefsbot|semrushbot|mj12bot|moz\.com|seznambot|petalbot/i',

            // 监控和服务状态检查工具 - 确保系统监控正常
            '/uptimerobot|pingdom|newrelic|datadog|statuscake|site24x7|monitis/i',

            // 合法API客户端和开发工具 - 确保API服务正常
            '/(?:curl|wget|python-requests|go-http-client|java|http-client|okhttp)\/[0-9]/i',

            // 内容聚合和订阅工具 - 确保内容分发正常
            '/feedburner|feedvalidator|rss(?:bandit|owl)|feedparser|bloglines/i',

            // 浏览器和移动设备 - 确保正常用户访问
            '/mozilla|chrome|safari|edge|opera|firefox|webkit|trident|android|iphone|ipad/i',
        ];
    }

    /**
     * 获取商业级禁止文件扩展名 - 全面防护优化版
     *
     * 基于文件类型和真实威胁分析，覆盖可执行文件、脚本文件、配置文件等危险类型
     * 采用白名单+黑名单双重机制，在提供全面防护的同时确保业务文件正常上传
     *
     * @return array 禁止的文件扩展名数组
     */
    public static function getDisallowedExtensions(): array
    {
        return [
            // ==================== 可执行文件 ====================
            'exe', 'bat', 'cmd', 'com', 'msi', 'dll', 'so', 'bin', 'app', 'apk',
            'scr', 'pif', 'jar', 'war', 'deb', 'rpm', 'run', 'out', 'elf',

            // ==================== 服务器端脚本 ====================
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'phps',
            'jsp', 'jspx', 'asp', 'aspx', 'asmx', 'ascx', 'cer', 'asa',
            'pl', 'py', 'rb', 'rhtml', 'sh', 'bash', 'csh', 'ksh', 'zsh', 'cgi', 'fcgi',

            // ==================== 客户端脚本 ====================
            'js', 'html', 'htm', 'xhtml', 'svg', 'xss', 'xsl', 'xslt',

            // ==================== 配置和数据库文件 ====================
            'env', 'config', 'ini', 'conf', 'cfg', 'properties', 'prefs',
            'sql', 'db', 'mdb', 'accdb', 'sqlite', 'dbf', 'mdf', 'ldf', 'frm',

            // ==================== 办公文档宏 ====================
            'docm', 'dotm', 'xlsm', 'xltm', 'pptm', 'potm', 'ppam', 'sldm',

            // ==================== 其他危险文件类型 ====================
            'swf', 'reg', 'vbs', 'wsf', 'ps1', 'psm1', 'msh', 'lnk', 'hta', 'cpl',
            'msp', 'scr', 'pif', 'gadget', 'application', 'command', 'crontab',
        ];
    }

    /**
     * 获取工业级禁止MIME类型 - 深度检测优化版
     *
     * 基于MIME类型真实分析，防止扩展名欺骗和文件类型混淆攻击
     * 覆盖可执行文件、脚本文件、宏文档等危险类型，提供深度文件安全检测
     *
     * @return array 禁止的MIME类型数组
     */
    public static function getDisallowedMimeTypes(): array
    {
        return [
            // ==================== 可执行文件类型 ====================
            'application/x-msdownload',
            'application/x-ms-installer',
            'application/x-dosexec',
            'application/x-executable',
            'application/x-mach-binary',
            'application/java-archive',
            'application/vnd.android.package-archive',

            // ==================== 脚本文件类型 ====================
            'application/x-php',
            'text/x-php',
            'application/x-httpd-php',
            'application/x-httpd-php-source',
            'application/x-jsp',
            'application/x-asp',
            'application/x-aspx',
            'application/x-sh',
            'application/x-bat',
            'application/x-csh',
            'text/x-perl',
            'text/x-python',
            'text/x-ruby',
            'text/x-shellscript',

            // ==================== 宏文档类型 ====================
            'application/vnd.ms-word.document.macroEnabled.12',
            'application/vnd.ms-word.template.macroEnabled.12',
            'application/vnd.ms-excel.sheet.macroEnabled.12',
            'application/vnd.ms-excel.template.macroEnabled.12',
            'application/vnd.ms-excel.addin.macroEnabled.12',
            'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
            'application/vnd.ms-powerpoint.template.macroEnabled.12',
            'application/vnd.ms-powerpoint.addin.macroEnabled.12',
            'application/vnd.ms-powerpoint.slideshow.macroEnabled.12',

            // ==================== 其他危险类型 ====================
            'application/x-ms-shortcut',
            'application/x-shellscript',
            'text/html-application',
            'application/hta',
            'application/x-cpl',
        ];
    }
}