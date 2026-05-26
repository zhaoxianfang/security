<?php
/** 最终审计验证 — 使用实际加载的模式 (v6.0) */
if (!function_exists('env')) { function env($k,$d=null){return $d;} }
if (!function_exists('config_path')) { function config_path($p=''){return __DIR__.'/../config/'.$p;} }
require_once dirname(__DIR__).'/vendor/autoload.php';
use zxf\Security\Patterns\PatternService;

function extractPat($item) {
    if(is_string($item)) return $item;
    if(is_array($item) && isset($item['pattern'])) return $item['pattern'];
    return null;
}

$ps = new PatternService();
$hr = $ps->getHighRiskPatterns();
$up = $ps->getUrlPathPatterns();
$xss = $ps->getXssPatterns();

$ok = 0; $fail = 0; $total = 0;
function test($name, $patterns, $input, $type = null) {
    global $ok, $fail, $total; $total++;
    if ($type && isset($patterns[$type])) $patterns = [$type => $patterns[$type]];
    if (!is_array(reset($patterns))) $patterns = ['_' => $patterns];
    
    foreach ($patterns as $t => $pts) {
        foreach ($pts as $p) {
            $pat = is_string($p) ? $p : (is_array($p) && isset($p['pattern']) ? $p['pattern'] : null);
            if ($pat && @preg_match($pat, $input)) { $ok++; echo "  ✅ $name\n"; return; }
        }
    }
    $fail++; echo "  ❌ $name\n";
}

echo "═══ [1] Word Boundary Fix — dot-prefixed files ═══\n";
test('.git/config', $up, '/path/.git/config');
test('.svn', $up, '/path/.svn');
test('.htaccess', $up, '/path/.htaccess');
test('.DS_Store', $up, '/path/.DS_Store');
test('.hg', $up, '/path/.hg');
test('.env in URL', $up, '/path/.env');
test('.env in HR', $hr, '/path/.env', 'path');
test('.svn in HR', $hr, '/path/.svn', 'path');
test('.htaccess in HR', $hr, '/path/.htaccess', 'path');

echo "\n═══ [2] NoSQL Fix — JSON double-quote format ═══\n";
test('$eq JSON', $hr, '{"$eq":"admin"}', 'nosql');
test('$ne JSON', $hr, '{"$ne":null}', 'nosql');
test('$where JSON', $hr, '{"$where":"function(){}"}', 'nosql');
test('$regex JSON', $hr, '{"$regex":"a.*"}', 'nosql');
test('$exists JSON', $hr, '{"$exists":true}', 'nosql');
test('$or JSON', $hr, '{"$or":[{}]}', 'nosql');
test('$and JSON', $hr, '{"$and":[{}]}', 'nosql');
test('$in JSON', $hr, '{"$in":["a"]}', 'nosql');
test('$nin JSON', $hr, '{"$nin":["x"]}', 'nosql');
test('$type JSON', $hr, '{"$type":"str"}', 'nosql');
test('$size JSON', $hr, '{"$size":3}', 'nosql');

echo "\n═══ [3] SQL Edge Cases ═══\n";
test('UNION DISTINCT', $hr, 'union(distinct)select 1,2', 'sql');
test('UNION /**/ block comment', $hr, 'union/**/select/**/1,2', 'sql');
test("OR '1'='1' tautology", $hr, "1' or '1'='1", 'sql');
test("admin'-- comment", $hr, "admin'--", 'sql');

echo "\n═══ [4] Command Edge Cases ═══\n";
test('semicolon+id', $hr, ';id', 'command');

echo "\n═══ [5] Path Edge Cases ═══\n";
test('null byte .%00/', $hr, '.%00/', 'path');
test('deep ../', $hr, '../../../../etc/passwd', 'path');
test('%2e%2e traversal', $hr, '%2e%2e%2fetc%2fpasswd', 'path');

echo "\n═══ [6] Encoding Edge Cases ═══\n";
test('%u unicode', $hr, '%u002e%u002e/', 'encoding');

echo "\n═══ [7] URL Path Detection Full ═══\n";
test('.git/config (URL)', $up, 'https://example.com/.git/config');
test('.DS_Store (URL)', $up, 'https://example.com/.DS_Store');
test('.env (URL)', $up, 'https://example.com/.env');
test('/etc/passwd (URL)', $up, '/etc/passwd');
test('phpmyadmin (URL)', $up, '/phpmyadmin/index.php');
test('backup file .bak', $up, '/backup/config.php.bak');
test('WordPress wp-admin', $up, '/wp-admin/admin.php');
test('docker-compose', $up, '/.dockerignore');
test('backup tar.gz', $up, '/backup/db.tar.gz');
test('log file', $up, '/storage/logs/laravel.log');

echo "\n═══ [8] XSS Patterns ═══\n";
test('<script>alert', $xss, '<script>alert(1)</script>', 'script');
test('onerror XSS', $xss, '<img src=x onerror=alert(1)>', 'dom');
test('<iframe src=js:', $xss, '<iframe src=javascript:alert(1)>', 'tag');
test('v-html Vue XSS', $xss, '<div v-html="<img src=x>">', 'framework');

echo "\n═══ [9] Pre-filter Verification ═══\n";
$pfTests = [
    ['nosql: $eq', 'nosql', '{"$eq":"admin"}', true],
    ['nosql: $and', 'nosql', '{"$and":[{}]}', true],
    ['nosql: $in', 'nosql', '{"$in":["a"]}', true],
    ['nosql: $gt', 'nosql', '{"$gt":10}', true],
    ['command: ;id', 'command', ';id', true],
    ['path: .%00', 'path', '.%00/', true],
    ['encoding: %u', 'encoding', '%u002e', true],
    ['sql: union/**/select', 'sql', 'union/**/select', true],
];

foreach ($pfTests as [$label, $type, $input, $expected]) {
    $result = $ps->preFilter($type, $input);
    $match = $result === $expected;
    $total++; $match ? $ok++ : $fail++;
    echo '  ' . ($match ? '✅' : '❌') . " $label\n";
}

echo "\n════════════════════════════\n";
echo "Total: $total, Pass: $ok, Fail: $fail\n";
echo ($fail === 0 ? "✅ ALL PASS!" : "❌ $fail FAILURES") . "\n";
