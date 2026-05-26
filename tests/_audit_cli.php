<?php
/**
 * CLI 模式安全加固专项审计 (v6.0)
 *
 * 验证点：
 * 1. isCliMode() 在 CLI SAPI 下正确返回 true
 * 2. HTTP 专属检测层在 CLI 下被自动禁用
 * 3. logThreat() / blockRequest() / security_log() 源码中存在 try/catch 降级
 * 4. SecurityServiceProvider 视图注册源码中存在容错
 * 5. BuildsInterceptionResponse 中 $request->ip() 等空值已防御性处理
 */

require_once dirname(__DIR__) . '/vendor/autoload.php';

use zxf\Security\Middleware\SecurityMiddleware;

$ok = 0;
$fail = 0;

function assertEq($label, $actual, $expected)
{
    global $ok, $fail;
    $pass = $actual === $expected;
    $pass ? $ok++ : $fail++;
    echo '  ' . ($pass ? '✅' : '❌') . " $label\n";
    if (!$pass) {
        echo "     expected: " . json_encode($expected) . "\n";
        echo "     actual:   " . json_encode($actual) . "\n";
    }
}

echo "═══ [1] CLI SAPI 识别 ═══\n";
assertEq('PHP_SAPI === cli', PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg', true);

echo "\n═══ [2] HTTP 专属检测层在 CLI 下自动禁用 ═══\n";

// 通过反射绕过构造函数（避免 Laravel 全局函数缺失）
$ref = new ReflectionClass(SecurityMiddleware::class);
$middleware = $ref->newInstanceWithoutConstructor();

// 注入最小配置
$prop = $ref->getProperty('config');
$prop->setAccessible(true);
$prop->setValue($middleware, [
    'enabled' => true,
    'detection_layers' => [
        'url_path' => true,
        'encoding' => true,
        'user_agent' => true,
        'headers' => true,
        'body_size' => true,
        'rate_limit' => true,
        'http_method' => true,
        'url_length' => true,
        'high_risk' => true,
        'xss' => true,
        'upload' => true,
        'redirect' => true,
    ],
    'trusted_ips' => [],
    'whitelist' => [],
    'blacklist' => [],
    'log_enabled' => false,
]);

$method = $ref->getMethod('isDetectionEnabled');
$method->setAccessible(true);

// CLI 下应禁用的层
$cliDisabled = ['user_agent', 'headers', 'body_size', 'rate_limit', 'http_method', 'url_length', 'upload'];
foreach ($cliDisabled as $layer) {
    assertEq("CLI 禁用层: $layer", $method->invoke($middleware, $layer), false);
}

// CLI 下仍应启用的层
$cliEnabled = ['url_path', 'encoding', 'high_risk', 'xss', 'redirect'];
foreach ($cliEnabled as $layer) {
    assertEq("CLI 保留层: $layer", $method->invoke($middleware, $layer), true);
}

echo "\n═══ [3] isCliMode() 方法存在且返回 true ═══\n";
$cliMethod = $ref->getMethod('isCliMode');
$cliMethod->setAccessible(true);
assertEq('isCliMode() 返回 true', $cliMethod->invoke($middleware), true);

echo "\n═══ [4] 源码级 try/catch 防御检查 ═══\n";

$srcDir = dirname(__DIR__) . '/src';

// 检查 logThreat() 是否有 try/catch
$buildsFile = file_get_contents($srcDir . '/Security/Middleware/Concerns/BuildsInterceptionResponse.php');
assertEq('logThreat() 包含 try/catch', str_contains($buildsFile, 'protected function logThreat(') && str_contains($buildsFile, 'catch (\\Throwable)'), true);
assertEq('blockRequest() 包含 try/catch', str_contains($buildsFile, "catch (\\Throwable") && str_contains($buildsFile, '默认拦截视图渲染失败，已降级为 JSON 响应'), true);
assertEq('blockRequest() CLI 优先 JSON', str_contains($buildsFile, '$this->isCliMode()'), true);
assertEq('buildInterceptionData ip 防御 null', str_contains($buildsFile, "'ip' => \$request->ip() ?? 'unknown',"), true);
assertEq('buildInterceptionData ua 防御 null', str_contains($buildsFile, "'user_agent' => \$request->userAgent() ?? '',"), true);
assertEq('createInterceptionContext content_type 防御 null', str_contains($buildsFile, "'content_type' => \$request->header('Content-Type') ?? '',"), true);

// 检查 SecurityServiceProvider 是否有视图注册容错
$providerFile = file_get_contents($srcDir . '/Security/Providers/SecurityServiceProvider.php');
assertEq('Provider 视图注册有 bound 检查', str_contains($providerFile, '$this->app->bound(\'view\')'), true);
assertEq('Provider 视图注册有 try/catch', str_contains($providerFile, 'catch (\\Throwable)'), true);

// 检查 helpers.php 是否有 try/catch
$helpersFile = file_get_contents($srcDir . '/helpers.php');
assertEq('security_log() 包含 try/catch', str_contains($helpersFile, 'catch (\\Throwable)'), true);
assertEq('security_log() ip 防御 null', str_contains($helpersFile, "'ip' => \$request?->ip() ?? 'unknown',"), true);
assertEq('security_log() method 防御 null', str_contains($helpersFile, "'method' => \$request?->method() ?? 'CLI',"), true);
assertEq('security_log() url 防御 null', str_contains($helpersFile, "'url' => \$request?->fullUrl() ?? '',"), true);

// 检查 HandlesAccessControl 的 CLI 跳过逻辑
$accessFile = file_get_contents($srcDir . '/Security/Middleware/Concerns/HandlesAccessControl.php');
assertEq('isDetectionEnabled() 包含 CLI 逻辑', str_contains($accessFile, "isCliMode()") && str_contains($accessFile, "'user_agent', 'headers', 'body_size', 'rate_limit', 'http_method', 'url_length', 'upload'"), true);

// 检查 SecurityMiddleware 的 blacklist 日志防御
$middlewareFile = file_get_contents($srcDir . '/Security/Middleware/SecurityMiddleware.php');
assertEq('blacklist 日志防御 null ip', str_contains($middlewareFile, "'IP地址位于黑名单中: ' . (\$request->ip() ?? 'unknown')"), true);

echo "\n═══ [5] 函数签名兼容性 ═══\n";
// 确认所有公共/保护方法签名没有破坏性变更
$expectedMethods = ['handle', 'isCliMode', 'generateRequestId', 'handleThreatDetection'];
foreach ($expectedMethods as $m) {
    assertEq("方法存在: $m", $ref->hasMethod($m), true);
}

// 确认 traits 全部被 use
$traits = $ref->getTraitNames();
$expectedTraits = [
    'zxf\Security\Middleware\Concerns\UsesSafeRegex',
    'zxf\Security\Middleware\Concerns\HandlesAccessControl',
    'zxf\Security\Middleware\Concerns\ValidatesInputIntegrity',
    'zxf\Security\Middleware\Concerns\DetectsAttackPatterns',
    'zxf\Security\Middleware\Concerns\ManagesMarkdownSafety',
    'zxf\Security\Middleware\Concerns\HandlesFileUploads',
    'zxf\Security\Middleware\Concerns\BuildsInterceptionResponse',
];
foreach ($expectedTraits as $t) {
    assertEq("Trait 存在: " . basename(str_replace('\\', '/', $t)), in_array($t, $traits, true), true);
}

echo "\n════════════════════════════\n";
echo "Total: " . ($ok + $fail) . ", Pass: $ok, Fail: $fail\n";
echo ($fail === 0 ? "✅ CLI 加固审计全部通过!" : "❌ $fail 项失败") . "\n";
