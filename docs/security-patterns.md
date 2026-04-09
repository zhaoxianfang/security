# 攻击防护说明

本文档详细介绍中间件检测的各类攻击模式及其防护原理。

## 防护架构

中间件采用14层分层检测架构，按优先级依次执行：

```
┌─────────────────────────────────────────────────────────┐
│  1. 路由排除检查  →  配置的路由直接放行                  │
├─────────────────────────────────────────────────────────┤
│  2. IP白名单检查  →  可信IP直接放行                      │
├─────────────────────────────────────────────────────────┤
│  3. IP黑名单检查  →  已知恶意IP立即拦截                  │
├─────────────────────────────────────────────────────────┤
│  4. URL路径攻击检测 → 直接检测URL中的攻击模式            │
├─────────────────────────────────────────────────────────┤
│  5. 多重编码检测  →  检测编码绕过攻击                    │
├─────────────────────────────────────────────────────────┤
│  6. User-Agent检查 → 封禁已知恶意扫描器                  │
├─────────────────────────────────────────────────────────┤
│  7. HTTP头检查    →  验证关键头部安全性                  │
├─────────────────────────────────────────────────────────┤
│  8. 请求体大小检查 → 防止内存溢出攻击                    │
├─────────────────────────────────────────────────────────┤
│  9. 速率限制      →  防止暴力破解、CC攻击                │
├─────────────────────────────────────────────────────────┤
│ 10. HTTP方法检查  →  拦截非法方法（TRACK、DEBUG等）      │
├─────────────────────────────────────────────────────────┤
│ 11. URL长度检查   →  防止缓冲区溢出                      │
├─────────────────────────────────────────────────────────┤
│ 12. 高危攻击检测  →  SQL/命令/路径/LDAP/XML/NoSQL/SSTI   │
├─────────────────────────────────────────────────────────┤
│ 13. XSS攻击检测   →  跨站脚本（智能识别Markdown）        │
├─────────────────────────────────────────────────────────┤
│ 14. 文件上传检查  →  禁止危险文件上传                    │
└─────────────────────────────────────────────────────────┘
```

## SQL注入防护

### 检测范围

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| UNION注入 | `' UNION ALL SELECT password FROM users--` | 拦截 |
| 堆叠查询 | `'; DROP TABLE users;--` | 拦截 |
| 时间盲注 | `' AND SLEEP(5)--` | 拦截 |
| 错误注入 | `' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--` | 拦截 |
| 文件操作 | `' UNION SELECT LOAD_FILE('/etc/passwd')--` | 拦截 |
| xp_cmdshell | `'; EXEC xp_cmdshell 'net user'--` | 拦截 |

### 检测模式

```php
'high_risk_patterns' => [
    'sql' => [
        // UNION注入
        '/\bunion\s+all\s+select\b/i',
        
        // 堆叠查询
        '/;\s*(?:drop|truncate|alter)\s+(?:table|database)\b/i',
        
        // 时间盲注
        '/sleep\s*\(\s*\d+/i',
        '/benchmark\s*\(\s*\d+/i',
        
        // ...更多模式
    ],
],
```

### 误报控制

- **不过滤正常SQL语句**：`SELECT * FROM users WHERE id = 1` 不会触发
- **支持参数化查询**：预处理语句天然免疫
- **关键词组合检测**：仅匹配 `UNION + SELECT` 组合，单独 `SELECT` 不触发

## 命令注入防护

### 检测范围

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| PHP函数 | `?cmd=system('rm -rf /')` | 拦截 |
| 反引号 | `?cmd=`whoami`` | 拦截 |
| 命令连接 | `?cmd=ls; cat /etc/passwd` | 拦截 |
| 文件包含 | `?file=php://filter/...` | 拦截 |

### 检测模式

```php
'high_risk_patterns' => [
    'command' => [
        // PHP函数 + 危险命令
        '/\b(?:system|exec|shell_exec)\s*\(\s*[\'"\s]*(?:rm|wget|curl|bash)\b/i',
        
        // 命令连接符 + 危险命令
        '/(?:;|\|\||&&)\s*(?:rm|wget|curl|bash)\s+/i',
        
        // 危险协议
        '/\b(?:include|require)\s*\(\s*[\'"]?\s*(?:php|data|expect):/i',
    ],
],
```

### 设计特点

- **函数+命令组合检测**：仅 `system('rm')` 触发，`system('echo')` 不触发
- **支持常见命令**：rm、wget、curl、nc、bash、python 等
- **协议过滤**：阻断 php://、data://、expect:// 等危险封装器

## 路径遍历防护

### 检测范围

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| 经典遍历 | `../../../etc/passwd` | 拦截 |
| Windows遍历 | `..\\..\\windows\\system32\\config\\sam` | 拦截 |
| URL编码 | `%2e%2e%2fetc%2fpasswd` | 拦截 |
| Unicode绕过 | `%c0%ae%c0%ae/` | 拦截 |
| 敏感文件 | `?file=.env` | 拦截 |
| 敏感目录 | `?path=/proc/self/environ` | 拦截 |

### 检测模式（已修复并加强）

```php
'high_risk_patterns' => [
    'path' => [
        // 经典路径遍历（至少两个../）
        '/(?:\.\./){2,}/',

        // Windows路径遍历（至少两个..\）
        '/(?:\.\.\\){2,}/',

        // 混合路径遍历（UNIX/Windows混合）
        '/\.\.(?:/|\\)\.\.(?:/|\\)/',

        // URL编码的遍历（双重编码）
        '/%2e%2e%2f/i',
        '/%252e%252e%252f/i',

        // Unicode规范化攻击
        '/%c0%af/i',
        '/%ef%bc%8f/i',
        '/%e0%80%af/i',

        // 敏感文件访问
        '/\/(?:etc|proc|sys|var|home|root|usr\/local)\/(?:passwd|shadow|hosts|id_rsa|\.env|\.git|\.htaccess|config\.php|database\.php)\b/i',

        // 版本控制/配置文件泄露
        '/\b(?:\.env|\.git\/|\.svn\/|\.htaccess)\b/i',

        // Windows系统目录穿越
        '/\.\.(?:\/|\\)(?:windows|winnt|system32|system|program files|programdata|inetpub)/i',
    ],
],
```

### URL路径专用检测

除了正则模式检测外，中间件还实现了专门的 `detectUrlPathAttacks()` 方法，直接检测URL路径：

- 检查原始路径
- 检查一次URL解码后的路径
- 检查二次URL解码后的路径
- 检测空字节注入
- 检测敏感文件访问

### 防护效果

有效防御以下漏洞：

- **任意文件读取**：通过路径遍历读取服务器敏感文件
- **本地文件包含（LFI）**：包含本地文件执行恶意代码
- **目录穿越**：访问Web根目录外的文件
- **编码绕过攻击**：多重URL编码、Unicode绕过等

## NoSQL注入防护

检测针对MongoDB等NoSQL数据库的注入攻击：

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| 操作符注入 | `{"$gt": ""}` | 拦截 |
| JavaScript执行 | `{"$where": "function() {...}"}` | 拦截 |
| 逻辑绕过 | `{"$or": [{}, {}]}` | 拦截 |

```php
'nosql' => [
    '/\$\s*(?:eq|ne|gt|gte|lt|lte|in|nin|regex|where|or|and)\s*:/i',
    '/\$where\s*:\s*[\'"]\s*function\s*\(/i',
],
```

## SSTI模板注入防护

检测服务器端模板注入攻击：

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| Twig/Laravel注入 | `{{ 7*7 \| raw }}` | 拦截 |
| PHP代码执行 | `{{ $user->shell_exec('id') }}` | 拦截 |

```php
'ssti' => [
    '/\{\{\s*.*\|.*(?:raw|escape|filter)\s*\}\}/i',
    '/\{\{.*(?:eval|exec|system|shell_exec|passthru).*\}\}/i',
],
```

## 编码绕过防护

检测使用各种编码技术绕过WAF的攻击：

| 攻击类型 | 示例 | 检测结果 |
|----------|------|----------|
| 多重URL编码 | `%252e%252e%252f` | 拦截 |
| UTF-8过度编码 | `%c0%af` (/) | 拦截 |
| 空字节注入 | `%00` | 拦截 |
| HTML实体编码 | `&#x3c;script&#x3e;` | 拦截 |

中间件实现了 `detectMultiEncodingAttacks()` 方法，专门检测：
- 空字节注入
- 过高的URL编码比例（可能编码攻击）
- 无效的UTF-8序列

```
编码检测流程：
原始URL → 空字节检查 → 编码比例检查 → 解码后危险模式检查 → 无效UTF-8检查
```

## XSS防护

### 智能识别设计

XSS防护的最大挑战是区分：

1. **真实攻击**：`<script>alert(document.cookie)</script>`
2. **文档示例**：Markdown代码块中的 `<script>alert(1)</script>`

### 检测策略

```php
'xss_patterns' => [
    'script' => [
        // 执行性脚本（不在代码块内时触发）
        '/<script\b[^>]*>[^<]*(?:alert|eval|document)/i',
    ],
    'dom' => [
        // DOM型XSS
        '/\bon\w+\s*=\s*[\'"]?\s*(?:alert|eval|document)/i',
    ],
    'tag' => [
        // 标签注入
        '/<img\b[^>]*onerror\s*=\s*[\'"]?\s*(?:alert|eval)/i',
        '/<svg\b[^>]*onload\s*=\s*[\'"]?\s*(?:alert|eval)/i',
    ],
],
```

### Markdown智能识别

中间件会先移除Markdown代码块，再进行XSS检测：

```php
protected function removeMarkdownCodeBlocks(string $content): string
{
    // 移除 ``` 包裹的代码块
    $content = preg_replace('/```[\s\S]*?```/', ' ', $content);
    
    // 移除 ` 包裹的行内代码
    $content = preg_replace('/`[^`]+`/', ' ', $content);
    
    return $content;
}
```

### 示例对比

| 输入内容 | 检测结果 | 说明 |
|----------|----------|------|
| `<script>alert(1)</script>` | 拦截 | 执行性脚本 |
| ```` ```<script>alert(1)</script>``` ```` | 放行 | 在代码块内 |
| `` `<script>alert(1)</script>` `` | 放行 | 在行内代码内 |
| `<img onerror=alert(1)>` | 拦截 | 事件处理器注入 |
| ```` ```html\n<img onerror=alert(1)>\n``` ```` | 放行 | 在代码块内 |

## 文件上传防护

### 检测维度

1. **扩展名黑名单**：禁止上传可执行脚本
2. **文件大小限制**：防止超大文件DoS
3. **MIME类型验证**：深度验证（可选）

### 禁止上传的文件类型

```php
'blocked_extensions' => [
    // Web脚本（高危）
    'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
    'jsp', 'jspx', 'asp', 'aspx', 'ascx',
    'cfm', 'cfml',
    
    // 脚本文件
    'pl', 'py', 'rb', 'sh', 'bash',
    'ps1', 'bat', 'vbs', 'js',
    
    // 可执行文件
    'exe', 'dll', 'bin', 'msi',
],
```

### 安全建议

1. **目录权限**：上传目录应设为不可执行
   ```bash
   chmod 755 uploads/
   chown www-data:www-data uploads/
   ```

2. **文件重命名**：不使用原始文件名
   ```php
   $filename = md5(uniqid()) . '.' . $extension;
   ```

3. **图片处理**：压缩/转换图片，清除EXIF和潜在恶意代码
   ```php
   Image::make($file)->encode('jpg', 75)->save($path);
   ```

## 速率限制

### 防护场景

- **暴力破解**：防止密码穷举攻击
- **CC攻击**：防止应用层DDoS
- **API滥用**：防止爬虫过度抓取
- **资源耗尽**：防止慢速HTTP攻击

### 限制粒度

基于IP地址限制，使用 Laravel RateLimiter：

```php
$key = 'security:' . $request->ip();

if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
    return response('Too Many Requests', 429);
}

RateLimiter::hit($key, $decayMinutes * 60);
```

### 阈值建议

| 场景 | max_attempts | decay_minutes | 说明 |
|------|-------------|---------------|------|
| 普通网站 | 60 | 1 | 1秒1次 |
| API服务 | 300 | 1 | 5秒1次 |
| 登录接口 | 5 | 5 | 每5分钟5次 |
| 后台管理 | 20 | 1 | 管理面板 |

## 日志记录

### 记录内容

```php
Log::warning('[Security] 安全威胁检测', [
    'type'       => 'sql',           // 威胁类型
    'ip'         => '192.168.1.100', // 攻击者IP
    'method'     => 'GET',           // HTTP方法
    'url'        => 'https://...',   // 完整URL
    'user_agent' => 'Mozilla/5.0',   // 浏览器标识
    'details'    => '匹配模式: ...',  // 详细信息
    'timestamp'  => '2026-04-08...', // 时间戳
]);
```

### 日志分析

统计攻击类型分布：

```bash
grep "安全威胁检测" storage/logs/laravel.log | \
  grep -o '"type":"[^"]*"' | \
  sort | uniq -c | sort -rn
```

提取攻击者IP：

```bash
grep "安全威胁检测" storage/logs/laravel.log | \
  grep -o '"ip":"[^"]*"' | \
  sort | uniq -c | sort -rn | head -20
```
