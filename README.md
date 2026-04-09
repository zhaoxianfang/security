# zxf/security - Laravel 安全中间件

[![PHP](https://img.shields.io/badge/php-8.2+-8892bf)](https://php.net)
[![Laravel](https://img.shields.io/badge/laravel-11+-ff2d20)](https://laravel.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**简洁、高效、智能的 Laravel 安全防护中间件**

---

## 特性

- **14层安全防护** - 全面的安全检测体系，从URL路径到文件上传层层防护
- **精准拦截** - 高危攻击（SQL注入、命令注入、路径遍历、NoSQL、SSTI）严格拦截
- **编码绕过检测** - 检测多重URL编码、UTF-8过度编码、空字节注入等绕过技术
- **智能识别** - 自动识别Markdown文档内容，代码块内的标签不会误拦截
- **零缓存依赖** - 不使用Redis/Memcached，直接使用Laravel原生功能
- **高性能** - 单次请求处理耗时 < 1ms
- **CIDR支持** - IP黑白名单支持网段格式（如 `192.168.0.0/16`）
- **拦截回调** - 支持自定义拦截决策，实现动态放行策略
- **自定义视图** - 支持自定义拦截页面，支持Blade视图/闭包/类方法

---

## 快速开始

### 安装

```bash
composer require zxf/security
```

### 配置

```bash
# 发布配置文件
php artisan vendor:publish --tag=security-config
```

编辑 `.env`：

```env
SECURITY_ENABLED=true
SECURITY_LOG_ENABLED=true
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_ATTEMPTS=60
```

### 使用

中间件会自动注册。如需手动控制，编辑 `bootstrap/app.php`：

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\zxf\Security\Middleware\SecurityMiddleware::class);
})
```

---

## 核心功能

| 功能 | 说明 |
|------|------|
| IP白名单 | 可信IP跳过所有检查 |
| IP黑名单 | 恶意IP直接拦截 |
| URL路径攻击检测 | 直接检测URL中的路径遍历等攻击 |
| 多重编码检测 | 检测空字节、UTF-8过度编码、多重URL编码等绕过技术 |
| User-Agent检查 | 封禁已知恶意扫描器 |
| HTTP头检查 | 验证Host头和禁止的头信息 |
| 请求体大小限制 | 防止内存溢出攻击 |
| 速率限制 | 防止暴力破解、CC攻击 |
| SQL注入检测 | UNION注入、堆叠查询、时间盲注、错误注入 |
| 命令注入检测 | 系统命令执行防护 |
| 路径遍历检测 | `../../../etc/passwd` 等 |
| NoSQL注入检测 | MongoDB等NoSQL数据库注入防护 |
| SSTI检测 | 服务器端模板注入防护 |
| XSS防护 | 智能识别Markdown代码块 |
| 文件上传检查 | 禁止WebShell上传 |

---

## 拦截示例

```bash
# SQL注入 - 被拦截
curl "https://example.com/api?id=1' UNION ALL SELECT password FROM users--"
# → HTTP 403: 请求包含高危安全威胁

# 正常Markdown内容 - 放行
curl -X POST https://example.com/docs \
  -d 'content=```html<script>alert(1)</script>```'
# → HTTP 200: 请求通过
```

---

## 拦截回调（高级功能）

通过 `before_block_callback` 配置，你可以在拦截前执行自定义逻辑：

```php
// config/security.php

'before_block_callback' => function(\zxf\Security\Dto\InterceptionContext $context) {
    // 1. 记录到数据库
    SecurityLog::create($context->toArray());

    // 2. 低风险请求自动放行
    if ($context->getRiskLevel() === 'low') {
        return false; // 放行
    }

    // 3. 特定IP段放行
    if (str_starts_with($context->clientIp, '192.168.')) {
        return false;
    }

    // 4. 发送告警（异步队列）
    SecurityAlertJob::dispatch($context);

    return true; // 拦截
},
```

### 回调返回值说明

| 返回值 | 行为 |
|--------|------|
| `false` | **放行** - 请求继续处理 |
| `true` / `null` | **拦截** - 返回拦截响应给用户 |

### InterceptionContext 对象

回调接收的上下文对象包含以下信息：

```php
$context->threatType           // 威胁类型: sql, xss, command, blacklist...
$context->getThreatTypeDescription() // 中文描述
$context->getRiskLevel()       // 风险等级: high, medium, low
$context->clientIp             // 客户端IP
$context->method               // HTTP方法
$context->url                  // 请求URL
$context->matchedPattern       // 匹配的正则模式
$context->matchedContent       // 匹配的内容片段（脱敏）
$context->allThreats           // 所有检测到的威胁
$context->toArray()            // 转为数组格式
```

### 使用场景

1. **动态放行策略** - 根据业务规则临时放行某些请求
2. **威胁日志记录** - 将拦截事件记录到数据库或外部系统
3. **实时告警通知** - 发送钉钉/企业微信/短信告警
4. **威胁情报分析** - 收集攻击数据用于后续分析

---

## 自定义拦截页面

通过 `response.view` 配置自定义拦截视图：

### 方法1：使用 Blade 视图

```php
// config/security.php
'response' => [
    'view' => 'errors.security',
],
```

创建视图 `resources/views/errors/security.blade.php`：

```blade
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <style>
        body { font-family: sans-serif; padding: 50px; text-align: center; }
        .alert { background: #fee; border: 1px solid #fcc; padding: 30px; border-radius: 5px; max-width: 600px; margin: 0 auto; }
        .threats { background: #f5f5f5; padding: 15px; margin-top: 20px; text-align: left; }
    </style>
</head>
<body>
    <div class="alert">
        <h1>🛡️ 访问被拒绝</h1>
        <p>{{ $message }}</p>
        @if(!empty($threats))
        <div class="threats">
            <strong>威胁类型：</strong> {{ implode(', ', $threats) }}
        </div>
        @endif
    </div>
</body>
</html>
```

### 方法2：使用闭包函数

```php
'response' => [
    'view' => function($data) {
        // 根据威胁类型返回不同视图
        if (in_array('sql', $data['threats'])) {
            return view('errors.sql-injection', $data);
        }
        return view('errors.generic', $data);
    },
],
```

### 视图可用变量

| 变量 | 类型 | 说明 |
|------|------|------|
| `$message` | string | 拦截提示消息 |
| `$blocked` | bool | 是否被拦截 |
| `$threats` | array | 威胁类型数组 |
| `$matched_pattern` | string | 匹配的正则模式 |
| `$matched_content` | string | 匹配的内容片段 |

---

## 文档

- [完整配置指南](docs/configuration.md)
- [攻击防护说明](docs/security-patterns.md)
- [API参考](docs/api.md)
- [常见问题](docs/faq.md)
- [使用示例](docs/examples.md)

---

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件
