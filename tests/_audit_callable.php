<?php
/** Callable 配置解析测试 (v6.0) */
require_once dirname(__DIR__).'/vendor/autoload.php';
use zxf\Security\Config\DefaultConfig;
use zxf\Security\Services\ConfigResolver;

class TestExtensionProvider {
    public static function getItems(): array {
        return ['jpg', 'png'];
    }
    public static function resolve(): array {
        return ['gif', 'webp'];
    }
    public function toArray(): array {
        return ['pdf', 'doc'];
    }
    public function __invoke(): array {
        return ['txt', 'csv'];
    }
    public function getConfig(): array {
        return ['md', 'json'];
    }
    public function all(): array {
        return ['xml', 'yaml'];
    }
}

$ok = 0; $fail = 0;
function assertEq($label, $actual, $expected) {
    global $ok, $fail;
    $pass = $actual === $expected;
    $pass ? $ok++ : $fail++;
    echo '  ' . ($pass ? '✅' : '❌') . " $label\n";
    if (!$pass) {
        echo "     expected: " . json_encode($expected) . "\n";
        echo "     actual:   " . json_encode($actual) . "\n";
    }
}

echo "═══ [1] ConfigResolver 基础测试 ═══\n";

// 静态数组
assertEq('静态数组', ConfigResolver::resolve(['a', 'b']), ['a', 'b']);

// 闭包
assertEq('闭包', ConfigResolver::resolve(function() { return ['c', 'd']; }), ['c', 'd']);

// 类名字符串（getItems）
assertEq('类名-getItems', ConfigResolver::resolve(TestExtensionProvider::class), ['jpg', 'png']);

// 可调用数组（静态方法）
assertEq('可调用数组', ConfigResolver::resolve([TestExtensionProvider::class, 'resolve']), ['gif', 'webp']);

// 实例方法
$instance = new TestExtensionProvider();
assertEq('实例-toArray', ConfigResolver::resolve([$instance, 'toArray']), ['pdf', 'doc']);

// __invoke
assertEq('实例-__invoke', ConfigResolver::resolve($instance), ['txt', 'csv']);

echo "\n═══ [2] DefaultConfig 默认值 + 覆盖测试 ═══\n";

// null = 使用默认值
assertEq('allowed_extensions-null', DefaultConfig::getAllowedExtensions(['upload'=>['allowed_extensions'=>null]]), DefaultConfig::UPLOAD_ALLOWED_EXTENSIONS);
assertEq('blocked_extensions-null', DefaultConfig::getBlockedExtensions(['upload'=>['blocked_extensions'=>null]]), DefaultConfig::UPLOAD_BLOCKED_EXTENSIONS);
assertEq('ua_blacklist-null', DefaultConfig::getUserAgentBlacklist(['user_agent_blacklist'=>null]), DefaultConfig::USER_AGENT_BLACKLIST);
assertEq('http_methods-null', DefaultConfig::getAllowedHttpMethods(['allowed_http_methods'=>null]), DefaultConfig::ALLOWED_HTTP_METHODS);
assertEq('md_patterns-null', DefaultConfig::getMarkdownSyntaxPatterns(['markdown'=>['syntax_patterns'=>null]]), DefaultConfig::MARKDOWN_SYNTAX_PATTERNS);
assertEq('encoding_patterns-null', DefaultConfig::getEncodingSuspiciousPatterns(['encoding_detection'=>['suspicious_patterns'=>null]]), DefaultConfig::ENCODING_SUSPICIOUS_PATTERNS);

// 数组覆盖
assertEq('allowed_extensions-覆盖', DefaultConfig::getAllowedExtensions(['upload'=>['allowed_extensions'=>['zip']]]), ['zip']);
assertEq('blocked_extensions-覆盖', DefaultConfig::getBlockedExtensions(['upload'=>['blocked_extensions'=>['exe']]]), ['exe']);

// callable 覆盖
assertEq('allowed_extensions-callable', DefaultConfig::getAllowedExtensions(['upload'=>['allowed_extensions'=>fn()=>['svg']]]), ['svg']);
assertEq('blocked_extensions-callable', DefaultConfig::getBlockedExtensions(['upload'=>['blocked_extensions'=>[TestExtensionProvider::class,'getItems']]]), ['jpg', 'png']);
assertEq('ua_blacklist-callable', DefaultConfig::getUserAgentBlacklist(['user_agent_blacklist'=>fn()=>['badbot']]), ['badbot']);
assertEq('http_methods-callable', DefaultConfig::getAllowedHttpMethods(['allowed_http_methods'=>fn()=>['GET','POST']]), ['GET','POST']);
assertEq('md_patterns-callable', DefaultConfig::getMarkdownSyntaxPatterns(['markdown'=>['syntax_patterns'=>fn()=>['/test/i']]]), ['/test/i']);
assertEq('encoding_patterns-callable', DefaultConfig::getEncodingSuspiciousPatterns(['encoding_detection'=>['suspicious_patterns'=>fn()=>['test']]]), ['test']);

// response messages 合并
$customMsg = ['sql' => '自定义SQL消息'];
$msgs = DefaultConfig::getResponseMessages(['response'=>['messages'=>$customMsg]]);
assertEq('response-合并', $msgs['sql'], '自定义SQL消息');
assertEq('response-保留默认', $msgs['command'], DefaultConfig::RESPONSE_MESSAGES['command']);

echo "\n════════════════════════════\n";
echo "Total: " . ($ok + $fail) . ", Pass: $ok, Fail: $fail\n";
echo ($fail === 0 ? "✅ ALL PASS!" : "❌ $fail FAILURES") . "\n";
