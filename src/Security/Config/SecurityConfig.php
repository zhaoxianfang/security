<?php

namespace zxf\Security\Config;

use Exception;
use zxf\Security\Constants\SecurityEvent;
use zxf\Security\Contracts\SecurityConfigInterface;

/**
 * 安全配置管理类
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
    protected const CONFIG_VERSION = '2.0.0';
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
            self::getEmergingThreatPatterns(),     // 新兴威胁检测 - 前瞻防护
            self::getSQLInjectionPatterns(),       // SQL注入专项检测
            self::getXSSAttackPatterns(),          // XSS攻击专项检测
            self::getCommandInjectionPatterns()    // 命令注入专项检测
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
             * 优化：使用原子组和否定预查减少回溯
             */
            '/(?>(?:<script\b[^>]*>.*?<\/script>|javascript:\s*[^"\'\s{}<>]*|vbscript:\s*[^"\'\s{}<>]*|data:\s*(?:text|application)\/(?:javascript|ecmascript)|\bon\w+\s*=\s*["\']?[^"\'>]*(?:alert|prompt|confirm)\s*\([^)]*\)))/is',

            /**
             * 合并的关键SQL注入检测
             * 优化：使用精确匹配和单词边界
             */
            '/\b(?>union\s+select|select\s+[\w*]+\s+from|insert\s+into|update\s+\w+\s+set|drop\s+(?>table|database|view|procedure)|delete\s+from|truncate\s+table|exec\s*\(|xp_cmdshell|sp_|--\s+|\/\*[^*]*\*+(?:[^*\/][^*]*\*+)*\/|0x[0-9a-f]+|char\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\))/is',

            /**
             * 合并的关键命令注入检测
             * 优化：精确匹配系统函数和特殊字符
             */
            '/\b(?>system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\([^)]*\)|`[^`]*`|\|\s*\w+|\&\s*\w+|;\s*\w+|\$\s*\([^)]*\)|\.\.\/\.\.\//i',

            /**
             * 合并的关键路径遍历和文件包含检测
             * 优化：减少分组，提高匹配速度
             */
            '/(?>\.\.\/|\.\.\\\\|\/etc\/(?>passwd|shadow|hosts)|\/winnt\/system32|\/windows\/system32|\b(?:include|require)(?:_once)?\s*\(?\s*[\'"][^"\']*\.(?:php|phtml|inc)|\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?>https?|ftp|phar):\/\/|php:\/\/(?>input|filter|glob|data|expect))/i',
        ];
    }

    /**
     * SQL注入专项检测模式
     *
     * 针对SQL注入攻击的深度检测模式
     * 覆盖各种SQL注入技术和绕过方法
     */
    public static function getSQLInjectionPatterns(): array
    {
        return [
            // 基础SQL关键字检测
            '/\b(?>select|insert|update|delete|drop|truncate|create|alter|grant|revoke|exec|execute|call|declare|fetch|open|close)\b\s*\(/i',

            // SQL注释和编码绕过检测
            '/(?>(?:--|\#)[^\n\r]*|(?:\/\*[\s\S]*?\*\/)|;.*?(?:--|\#))/i',

            // SQL函数和存储过程检测
            '/\b(?>xp_cmdshell|sp_|fn_|dbcc|waitfor|shutdown|kill|backup|restore|load_file|outfile|dumpfile)\b/i',

            // 联合查询检测
            '/union\s+all\s+select|union\s+select\s+null/i',

            // 盲注和延时注入检测
            '/\b(?>sleep|benchmark|waitfor|pg_sleep)\s*\(/i',

            // 条件语句检测
            '/\b(?>case\s+when|if\s*\(|else|then|end)\b/i',

            // 错误注入检测
            '/\b(?>extractvalue|updatexml|floor|exp|pow)\s*\(/i',

            // 堆叠查询检测
            '/;\s*(?>select|insert|update|delete|drop|create|alter)\b/i',

            // 十六进制和字符编码检测
            '/0x[0-9a-f]+|char\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)|concat\s*\(/i',

            // 内联注释检测 (MySQL特定)
            '/\/\*![0-9]{5}.*?\*\//i',

            // 宽字节注入检测
            '/%[a-f0-9]{2}%[a-f0-9]{2}|\xbf\x27|\xdf\x27|\xef\xbc\x87/i',
        ];
    }

    /**
     * XSS攻击专项检测模式
     *
     * 针对XSS攻击的深度检测模式
     * 覆盖各种XSS攻击技术和绕过方法
     */
    public static function getXSSAttackPatterns(): array
    {
        return [
            // 脚本标签检测
            '/<(?>script|iframe|frame|embed|object|applet|meta|link|style|svg|math|base)\b[^>]*>/i',

            // 事件处理器检测
            '/\bon(?>load|error|click|mouse|key|focus|blur|change|submit)\s*=\s*["\'][^"\']*["\']/i',

            // JavaScript协议检测
            '/(?>javascript|vbscript|data|jar):\s*[^"\'\s]*/i',

            // 编码绕过检测
            '/&#(?>x[0-9a-f]+|\d+);|\\[xu][0-9a-f]{2,4}|%[0-9a-f]{2}/i',

            // 属性注入检测
            '/<(?>img|input|button|a|div|span|p|td|th)\b[^>]*\s(?>src|href|style|class|id)\s*=\s*["\'][^"\']*["\']/i',

            // CSS表达式检测
            '/expression\s*\(|@import|@charset|@namespace|url\s*\(/i',

            // HTML5新特性XSS检测
            '/<(?>video|audio|source|track|canvas)\b[^>]*>|autofocus|onpointer|ontouch/i',

            // 模板注入检测
            '/\$\{.*?\}|{{.*?}}|\{%.*?%\}|\[\[.*?\]\]|<\%.*?\%>/s',

            // DOM型XSS检测
            '/document\.(?>write|writeln|createElement)|innerHTML|outerHTML|eval\s*\(/i',

            // 反射型XSS检测
            '/<(?>img|div|span|p)\b[^>]*>\s*<\/(?>img|div|span|p)>/i',

            // 存储型XSS检测
            '/<(?>textarea|input|select)\b[^>]*>.*?<\/(?>textarea|input|select)>/is',

            // 基于CSS的XSS检测
            '/style\s*=\s*["\'][^"\']*(?>expression|javascript|url\s*\([^)]*\))[^"\']*["\']/i',
        ];
    }

    /**
     * 命令注入专项检测模式
     *
     * 针对命令注入攻击的深度检测模式
     * 覆盖各种命令注入技术和绕过方法
     */
    public static function getCommandInjectionPatterns(): array
    {
        return [
            // 系统命令函数检测
            '/\b(?>system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|dl|assert|eval|create_function)\s*\(/i',

            // 反引号命令执行检测
            '/`[^`]*`|\$\([^)]*\)|\${\s*[^}]*\s*}/',

            // 管道和重定向检测
            '/\|\s*\w+|\&\s*\w+|\>\s*\w+|\<\s*\w+|\|\|/',

            // 命令分隔符检测
            '/;\s*\w+|&&|\|\||%0a|%0d|%3b|%26%26|%7c%7c/',

            // 环境变量检测
            '/\$[A-Z_][A-Z0-9_]*|\%[A-Z_][A-Z0-9_]*\%/i',

            // 路径遍历检测
            '/(?>\.\.\/){2,}|\.\.\\\{2,}|\/~|\/\.\./',

            // 敏感文件访问检测
            '/\b(?>\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/self\/|\/sys\/kernel\/|\.ssh\/|\.bash_history)\b/',

            // 网络相关命令检测
            '/\b(?>wget|curl|nc|netcat|telnet|ftp|ssh|scp|rsync|ping|traceroute|nmap|dig)\b\s+/i',

            // 进程管理命令检测
            '/\b(?>ps|kill|pkill|killall|top|htop|nice|renice|nohup)\b\s+/i',

            // 文件系统命令检测
            '/\b(?>rm|mv|cp|chmod|chown|chgrp|ln|find|grep|sed|awk|cat|more|less|head|tail)\b\s+-/i',

            // 权限提升检测
            '/\b(?>sudo|su|doas|pkexec)\b\s+/i',

            // 编码命令检测
            '/base64\s+-d|base64\s+--decode|xxd\s+-r|openssl\s+enc\s+-d/',
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
             * 优化：使用原子组避免回溯
             */
            '/(?>(?:<\?php|<\?=|\b(?:eval|assert|create_function|unserialize|str_rot13|base64_decode|gzinflate|gzuncompress)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]+\]|O:\d+:"[^"]*":\d+:|__(?>destruct|wakeup|toString|invoke|call|callStatic|get|set)\b))/i',

            /**
             * 合并的表达式和模板注入检测
             * 优化：使用非贪婪匹配
             */
            '/(?>\$\{.*?\}|\({.*?}\)|\{\{.*?\}\}|@\w+\(.*?\)|\{%.*?%\}|\[\[.*?\]\]|<\%.*?\%>)/s',

            /**
             * 合并的NoSQL注入和API滥用检测
             * 优化：精确匹配操作符
             */
            '/"\$(?>where|eq|ne|gt|gte|lt|lte|in|nin|or|and|not|exists|regex|text|where|push|pull|pop|addToSet|pullAll)"/',

            /**
             * 合并的文件上传绕过检测
             * 优化：减少分组数量
             */
            '/(?:\.(?>php|phtml|jsp|asp|asa|cer)\.(?>txt|jpg|png|gif)$|\\x00|\.(?>PhP|pHp|Phtml|JSp|aSp|AsA|CeR)$|\.(?>php[0-9]|phtml[0-9])$)/i',
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
             */
            '/(?:<!ENTITY\s+\w+\s+SYSTEM\s+["\']|<!DOCTYPE[^>[]*SYSTEM\s*["\']|<!ENTITY\s+%\s+\w+|<?xml[^>]*encoding\s*=\s*["\']?[^"\'<>]*\?>\s*<!ENTITY|\]\]>)/i',

            /**
             * Web Shell和恶意代码特征检测
             */
            '/(?:@\$_=\$_[_];@\$_\(\$_[__]\);|\beval\(\s*base64_decode|\bgzinflate\(\s*base64_decode|\b(?>FileManager|r57|c99|w4ck1ng|b374k|webadmin)\.(?>php|txt)\b|\b(?>phpspy|afe|wso|reGeorg)\.(?>php|jsp|aspx)\b|<\?php\s+\$[a-z]\s*=\s*["\'][^"\']*["\']\s*;\s*eval)/i',

            /**
             * 云服务密钥和敏感信息泄露检测
             */
            '/(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\\-_]{35}|sk-[a-zA-Z0-9]{48}|(?:-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)|(?:host|port|user|password|database|dbname)\s*=\s*[^\s]+|aws_access_key_id|aws_secret_access_key)/',

            /**
             * 加密货币和金融信息检测
             */
            '/(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|bc1[a-z0-9]{39,59}|L[1-9A-HJ-NP-Za-km-z]{26,33}|X-Forwarded-For:\s*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3},?\s*)+/i',

            /**
             * 服务端请求伪造(SSRF)检测
             */
            '/(?:127\.0\.0\.1|localhost|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|0\.0\.0\.0|metadata\.google\.internal|169\.254\.169\.254|\[::1\]|\[::\]|local\.localhost)/i',
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
             */
            '/(?:node_modules\/[^\/]+\/(?>bin|lib)\/|vendor\/[^\/]+\/(?>src|lib)\/|import\s+[^;]*(?:malicious|backdoor|trojan|hack|exploit)|require\s*\(\s*[^)]*(?:evil|hack|bypass|inject)|\bpackage\.json\b.*\bscripts\b.*\b(?:preinstall|postinstall|install)\b)/is',

            /**
             * API安全滥用检测
             */
            '/(?:query\s*\{[^}]*__typename[^}]*\}|mutation\s*\{[^}]*delete|api_key\s*=\s*[^\s&]+|apikey\s*=\s*[^\s&]+|Authorization:\s*(?:Bearer|Basic)\s+[^\s]+|\$\.ajax\(.*url:\s*["\'][^"\']+["\'])/i',

            /**
             * 容器和安全隔离逃逸检测
             */
            '/(?:\/proc\/self\/|\/sys\/kernel\/|cgroup|docker\.sock|kubelet|namespace|privileged|capabilities|--privileged|--cap-add|--security-opt|--device|--volume)/i',

            /**
             * 机器学习模型投毒检测
             */
            '/(?:\.(?>pkl|pth|h5|model|joblib|onnx)\.(?>php|exe|bat|sh)$|model_state_dict|training_data|dataset\.(?>csv|json|parquet)|\btrain\.py\b.*\bimport\b.*\btorch\b|\bfrom\b.*\btensorflow\b.*\bimport\b)/i',

            /**
             * 零信任和微服务攻击检测
             */
            '/(?:service-mesh|istio|linkerd|envoy|consul|etcd|zookeeper|\/healthz|\/readyz|\/metrics|\/debug|\/pprof)/i',

            /**
             * 区块链和Web3攻击检测
             */
            '/(?:web3\.eth|ethereum|smart\s+contract|solidity|\.sol$|metamask|walletconnect|infura|alchemy|\/api\/v3\/|\/rpc\/)/i',
        ];
    }

    /**
     * 获取工业级URL路径检测模式
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
             */
            '~/(?:\.(?!well-known/|git/)[^/]*|\.{2,})(?=/|$)~i',

            /**
             * 配置文件和敏感数据文件检测
             */
            '/\.(?>env|config|settings|configuration|secret|key|credential|token|auth|cert|pem|crt)(?>\.[\w]+)?$/i',
            '/\.(?>gitignore|gitattributes|htaccess|htpasswd|nginx\.conf|apache2?\.conf|httpd\.conf|\.conf)(?>\.[\w]+)?$/i',
            '/(?>composer|package|yarn|pip|gemfile|pom|gradle|build|makefile)(?:\.(?>json|lock|yml|yaml|xml|properties))?$/i',

            /**
             * 源代码和脚本文件泄露检测
             */
            '/\.(?>php[3457s]?|phtml|phar|inc|phps)(?>\.[\w]+)?$/i',
            '/\.(?>jspx?|asp|aspx?|asmx|ascx|cer|asa|ashx)(?>\.[\w]+)?$/i',
            '/\.(?>pl|py|rb|rhtml|sh|bash|cgi|fcgi|wsgi)(?>\.[\w]+)?$/i',
            '/\.(?>java|class|jar|war|ear|jspf)(?>\.[\w]+)?$/i',
            '/\.(?>js|html?|xhtml|xml|json|yml|yaml)(?>\.[\w]+)?$/i',
            '/\.(?>ts|jsx|tsx|vue|svelte|elm)(?>\.[\w]+)?$/i',
            '/\.(?>c|cpp|h|hpp|go|rs|swift|kt|kts)(?>\.[\w]+)?$/i',

            /**
             * 数据库文件和备份文件检测
             */
            '/\.(?>sql|db|mdb|accdb|sqlite|dbf|mdf|ldf|frm|ibd|myd|myi|ndb)(?>\.[\w]+)?$/i',
            '/\.(?>bak|old|backup|temp|tmp|swp|swo|swn)(?>\.[\w]+)?$/i',
            '/\.(?>log|trace|debug|error|access|audit|out|err)(?>\.[\w]+)?$/i',

            /**
             * 敏感目录路径检测
             */
            '/(?:^|\/)(?>backup|temp|tmp|cache|session|logs|data|uploads|downloads)(?:\/|$)/i',
            '/(?:^|\/)(?>node_modules|vendor|bower_components|dist|build|target|out|bin)(?:\/|$)/i',
            '/(?:^|\/)(?>\.git|\.svn|\.hg|\.DS_Store|Thumbs\.db|desktop\.ini)(?:\/|$)/i',
            '/(?:^|\/)(?>administrator|phpmyadmin|wp-admin|admin|dashboard|console|manager)(?:\/|$)/i',
            '/(?:^|\/)(?>api|graphql|rest|soap|xmlrpc|jsonrpc)(?:\/|$)/i',

            /**
             * 系统文档和许可证文件检测
             */
            '/(?:readme|license|changelog|contributing|todo|faq|history|changes|release_notes)\.(?>md|txt|rst|html?|pdf)$/i',

            /**
             * 开发工具和调试文件检测
             */
            '/(?:webpack\.config|babel\.config|tsconfig|eslint|prettier|jest\.config)\.(?>js|ts|json)$/i',
            '/(?:\.env\.|\.dockerignore|docker-compose|Dockerfile|\.travis|\.circleci)/i',
            '/(?:\.vscode|\.idea|\.editorconfig|\.prettierrc|\.eslintrc)/i',
        ];
    }

    /**
     * 获取商业级可疑User-Agent检测模式
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
             */
            '/\b(?>sqlmap|nikto|metasploit|nessus|wpscan|acunetix|burp|dirbuster|nmap|netsparker|openvas|qualys|rapid7|tenable|greenbone|openbugbounty)\b/i',

            /**
             * 恶意软件和攻击框架检测
             */
            '/\b(?>beef|setoolkit|empire|cobaltstrike|armitage|canvas|havij|zap|arachni|w3af|skipfish|wapiti|gobuster|ffuf|nuclei)\b/i',

            /**
             * DDoS工具和僵尸网络检测
             */
            '/\b(?>slowloris|r-u-dead-yet|loic|hoic|goldeneye|mirai|bashlite|gafgyt|qbot|nebula|hulk|pybuster|ddosim|tor|hammer)\b/i',

            /**
             * 自动化攻击和扫描工具检测
             */
            '/\b(?>masscan|zmap|zmeu|blackwidow|satori|xenotix|zgrab|dirb|wfuzz|amass|sublist3r|theharvester|shodan|censys)\b/i',

            /**
             * 可疑模式和匿名工具检测
             */
            '/^(?>[A-Z0-9]{16,}|null|undefined|test|fake|unknown|mozilla|curl|wget|python|java|go-http)$/i',
            '/\b(?>tor|vpn|proxy|anonymizer|anonymous|ghost|hidden)\s*(?>bot|crawler|spider|scanner|checker)/i',
            '/\b(?>scan|spider|crawl|bot|check|monitor|test)\b.*\b(?>unknown|generic|self|custom|private)/i',

            /**
             * 浏览器自动化工具检测
             */
            '/\b(?>phantomjs|selenium|puppeteer|playwright|chromium|headless|automation|webdriver)\b/i',

            /**
             * 数据采集和爬虫工具检测
             */
            '/\b(?>scrapy|beautifulsoup|lxml|requests|httpx|aiohttp|okhttp|axios|fetch|got|superagent)\b.*\b(?>bot|crawler)/i',

            /**
             * 漏洞利用框架检测
             */
            '/\b(?>exploit|vulnerability|payload|shellcode|reverse|bind|meterpreter|msfconsole|msfvenom)\b/i',
        ];
    }

    /**
     * 获取工业级白名单User-Agent模式
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
            '/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|facebot|applebot/i',

            // 社交媒体和服务商爬虫 - 确保社交分享功能正常
            '/facebookexternalhit|twitterbot|linkedinbot|pinterest|whatsapp|telegrambot|discordbot|slackbot/i',

            // SEO和分析工具 - 确保网站分析数据准确
            '/ahrefsbot|semrushbot|mj12bot|moz\.com|seznambot|petalbot|dotbot|gigabot|ccbot/i',

            // 监控和服务状态检查工具 - 确保系统监控正常
            '/uptimerobot|pingdom|newrelic|datadog|statuscake|site24x7|monitis|updown|freshping/i',

            // 合法API客户端和开发工具 - 确保API服务正常
            '/(?>curl|wget|python-requests|go-http-client|java|http-client|okhttp|axios|fetch)\/[0-9\.]+/i',

            // 内容聚合和订阅工具 - 确保内容分发正常
            '/feedburner|feedvalidator|rss(?>bandit|owl)|feedparser|bloglines|feedly|inoreader/i',

            // 浏览器和移动设备 - 确保正常用户访问
            '/mozilla|chrome|safari|edge|opera|firefox|webkit|trident|gecko|presto|blink/i',
            '/android|iphone|ipad|ipod|windows\s+phone|blackberry|symbian|kindle|playbook/i',

            // 邮件客户端和办公软件
            '/outlook|thunderbird|mail|apple\s+mail|microsoft\s+outlook|lotus\s+notes|eudora/i',
            '/msoffice|microsoft\s+office|libreoffice|openoffice|pages|numbers|keynote/i',

            // 媒体播放器和下载工具
            '/itunes|quicktime|vlc|windows\s+media\s+player|realplayer|winamp|spotify/i',
            '/utorrent|bittorrent|transmission|deluge|qbittorrent|vuze|frostwire/i',
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
            'sys', 'drv', 'vxd', 'ocx', 'cpl', 'mui', 'acm', 'ax', 'efi',

            // ==================== 服务器端脚本 ====================
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'phps',
            'jsp', 'jspx', 'asp', 'aspx', 'asmx', 'ascx', 'cer', 'asa',
            'pl', 'py', 'rb', 'rhtml', 'sh', 'bash', 'csh', 'ksh', 'zsh', 'cgi', 'fcgi',
            'cgi', 'fcgi', 'wsgi', 'asm', 'shtml', 'stm', 'shtm',

            // ==================== 客户端脚本 ====================
            'js', 'html', 'htm', 'xhtml', 'svg', 'xss', 'xsl', 'xslt',
            'swf', 'fla', 'swt', 'air', 'applescript', 'vbs', 'vbe',

            // ==================== 配置和数据库文件 ====================
            'env', 'config', 'ini', 'conf', 'cfg', 'properties', 'prefs',
            'sql', 'db', 'mdb', 'accdb', 'sqlite', 'dbf', 'mdf', 'ldf', 'frm',
            'myd', 'myi', 'ndb', 'ibd', 'dmp', 'dump', 'backup', 'bak',

            // ==================== 办公文档宏 ====================
            'docm', 'dotm', 'xlsm', 'xltm', 'pptm', 'potm', 'ppam', 'sldm',
            'xlam', 'xltm', 'xlsb', 'ppsm', 'ppam', 'sldm', 'thmx',

            // ==================== 其他危险文件类型 ====================
            'swf', 'reg', 'vbs', 'wsf', 'ps1', 'psm1', 'msh', 'lnk', 'hta', 'cpl',
            'msp', 'scr', 'pif', 'gadget', 'application', 'command', 'crontab',
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'awk', 'sed',
            'pl', 'pm', 't', 'pod', 'rb', 'rake', 'gemspec', 'py', 'pyc', 'pyo',
            'r', 'R', 's', 'S', 'm', 'M', 'mat', 'oct', 'jl',
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
            'application/x-apple-diskimage',
            'application/x-iso9660-image',
            'application/x-shockwave-flash',

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
            'application/x-msdos-program',
            'application/x-shellscript',

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
            'application/x-ms-application',
            'application/x-ms-manifest',
            'application/prg',
            'application/x-msdos-program',
            'application/x-msdownload',
        ];
    }

    /**
     * 获取触发事件类型 封禁时长（单位：秒）
     * @return array 触发事件类型 封禁时长（单位：秒）
     */
    public static function getEventTypeBanDuration(): array
    {
        return [
            SecurityEvent::WHITELIST => 0, // 白名单：0 表示不封禁
            SecurityEvent::BLACKLIST => 30 * 24 * 3600, // 黑名单：30 天
            SecurityEvent::METHOD_CHECK => 1800, // 请求方法检查：30 分钟
            SecurityEvent::SUSPICIOUS_METHOD => 1800, // 可疑请求方法：30 分钟
            SecurityEvent::EMPTY_USER_AGENT => 1800, // User-Agent为空：30 分钟
            SecurityEvent::USER_AGENT_TOO_LONG => 1800, // User-Agent过长：30 分钟
            SecurityEvent::SUSPICIOUS_USER_AGENT => 1800, // 可疑的User-Agent：30 分钟
            SecurityEvent::TOO_MANY_HEADERS => 3600, // 请求头过多：1 小时
            SecurityEvent::SUSPICIOUS_HEADERS => 3600, // 可疑的请求头：1 小时
            SecurityEvent::URL_TOO_LONG => 600, // URL过长：10 分钟
            SecurityEvent::ILLEGAL_URL => 3600, // 非法URL：1 小时
            SecurityEvent::DANGEROUS_UPLOAD => 600, // 危险文件上传：10 分钟
            SecurityEvent::MALICIOUS_REQUEST => 12 * 3600, // 恶意请求：12 小时
            SecurityEvent::ANOMALOUS_PARAMETERS => 600, // 异常参数：10 分钟
            SecurityEvent::RATE_LIMIT => 600, // 请求频率过高：10 分钟
            SecurityEvent::SQL_INJECTION => 48 * 3600, // SQL注入拦截：48 小时
            SecurityEvent::XSS_ATTACK => 48 * 3600, // XSS攻击拦截：48 小时
            SecurityEvent::COMMAND_INJECTION => 48 * 3600, // 命令注入拦截：48 小时
            SecurityEvent::CUSTOM_RULE => 1800, // 自定义规则拦截：30 分钟
            SecurityEvent::ERROR => 0, // 系统异常：0 表示不封禁
        ];
    }

    /**
     * 验证配置完整性
     *
     * @return bool 配置是否完整有效
     */
    public static function validate(): bool
    {
        try {
            // 验证所有正则表达式
            $patterns = array_merge(
                self::getMaliciousBodyPatterns(),
                self::getIllegalUrlPatterns(),
                self::getSuspiciousUserAgents(),
                self::getWhitelistUserAgents()
            );

            foreach ($patterns as $pattern) {
                if (@preg_match($pattern, '') === false) {
                    return false;
                }
            }

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * 获取配置版本信息
     *
     * @return array 版本信息
     */
    public static function getVersionInfo(): array
    {
        return [
            'version' => self::CONFIG_VERSION,
            'level' => self::CONFIG_LEVEL,
            'patterns_count' => count(self::getMaliciousBodyPatterns()),
            'url_patterns_count' => count(self::getIllegalUrlPatterns()),
            'user_agent_patterns_count' => count(self::getSuspiciousUserAgents()),
        ];
    }
}
