<?php

namespace zxf\Security\Bridge;

/**
 * 跨框架桥接层 — 统一封装 Laravel 与 ThinkPHP 8+ 的 API 差异
 *
 * 本包设计目标为"零第三方依赖"，仅依赖 PHP 标准库。
 * 通过运行时检测框架类存在性，自动适配当前运行环境。
 *
 * 支持框架：
 *  - Laravel 11+ / 12+ / 13+
 *  - ThinkPHP 8+
 *
 * 设计原则：
 *  1. 静态方法优先 — 避免中间件中频繁实例化桥接对象
 *  2. 防御式编程 — 框架 API 不可用时返回安全默认值，不抛异常
 *  3. 最小侵入 — 原有 Laravel 逻辑保持不变，ThinkPHP 路径仅做必要映射
 *  4. 类型宽松 — 请求/响应对象统一声明为 object，兼容双框架类型系统
 *
 * @package zxf\Security\Bridge
 * @since 6.1.0
 * @version 6.2.0
 */
class FrameworkBridge
{
    /**
     * 检测当前是否运行在 Laravel 环境
     */
    public static function isLaravel(): bool
    {
        return class_exists('Illuminate\Foundation\Application')
            || class_exists('Illuminate\Contracts\Foundation\Application');
    }

    /**
     * 检测当前是否运行在 ThinkPHP 环境
     */
    public static function isThinkPhp(): bool
    {
        return class_exists('think\App') && !self::isLaravel();
    }

    /**
     * 检测当前框架标识（用于日志/调试）
     */
    public static function getFramework(): string
    {
        if (self::isLaravel()) {
            return 'laravel';
        }
        if (self::isThinkPhp()) {
            return 'thinkphp';
        }
        return 'unknown';
    }

    // ==================== Request 统一接口 ====================

    /**
     * 获取客户端 IP
     */
    public static function requestIp(object $request): ?string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->ip() ?: null;
            }
            if (method_exists($request, 'ip')) {
                return $request->ip();
            }
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * 获取完整 URL（含 scheme 和 host）
     */
    public static function requestFullUrl(object $request): string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->url(true) ?: '';
            }
            if (method_exists($request, 'fullUrl')) {
                return $request->fullUrl() ?? '';
            }
        } catch (\Throwable) {
        }
        return '';
    }

    /**
     * 获取请求路径（不含查询串）
     */
    public static function requestPath(object $request): string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                $path = $request->pathinfo();
                // pathinfo() 可能返回空字符串（非 null），此时回退到 path()
                if ($path === '' || $path === null) {
                    $path = $request->path();
                }
                return $path ?: '';
            }
            if (method_exists($request, 'path')) {
                return $request->path() ?? '';
            }
        } catch (\Throwable) {
        }
        return '';
    }

    /**
     * 获取 HTTP 方法
     */
    public static function requestMethod(object $request): string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return strtoupper($request->method() ?? 'GET');
            }
            if (method_exists($request, 'method')) {
                return strtoupper($request->method() ?? 'GET');
            }
        } catch (\Throwable) {
        }
        return 'GET';
    }

    /**
     * 获取 User-Agent
     */
    public static function requestUserAgent(object $request): ?string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->header('user-agent') ?: null;
            }
            if (method_exists($request, 'userAgent')) {
                return $request->userAgent();
            }
            if (method_exists($request, 'header')) {
                return $request->header('user-agent');
            }
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * 获取所有请求头
     *
     * 返回格式统一为 [name => [value, ...]]（兼容 Laravel HeaderBag）
     */
    public static function requestHeaders(object $request): array
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                $headers = $request->header() ?: [];
                $normalized = [];
                foreach ($headers as $name => $value) {
                    $normalized[$name] = is_array($value) ? $value : [$value];
                }
                return $normalized;
            }
            if (method_exists($request, 'headers') && is_object($request->headers) && method_exists($request->headers, 'all')) {
                return $request->headers->all() ?: [];
            }
        } catch (\Throwable) {
        }
        return [];
    }

    /**
     * 检查是否存在指定请求头
     */
    public static function requestHasHeader(object $request, string $name): bool
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->header($name) !== null;
            }
            if (method_exists($request, 'hasHeader')) {
                return $request->hasHeader($name);
            }
            if (method_exists($request, 'header')) {
                return $request->header($name) !== null;
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 获取单个请求头值
     */
    public static function requestGetHeader(object $request, string $name, mixed $default = null): mixed
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->header($name) ?? $default;
            }
            if (method_exists($request, 'header')) {
                return $request->header($name) ?? $default;
            }
        } catch (\Throwable) {
        }
        return $default;
    }

    /**
     * 获取 Host
     */
    public static function requestGetHost(object $request): ?string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->host() ?: null;
            }
            if (method_exists($request, 'getHost')) {
                return $request->getHost();
            }
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * 获取查询参数
     */
    public static function requestQuery(object $request): array
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->get() ?: [];
            }
            if (method_exists($request, 'query')) {
                return $request->query() ?: [];
            }
        } catch (\Throwable) {
        }
        return [];
    }

    /**
     * 获取 POST 参数
     */
    public static function requestPost(object $request): array
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->post() ?: [];
            }
            if (method_exists($request, 'post')) {
                return $request->post() ?: [];
            }
        } catch (\Throwable) {
        }
        return [];
    }

    /**
     * 获取路由参数
     */
    public static function requestRouteParams(object $request): array
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                // ThinkPHP 的 param() 包含 route + query + post，这里仅取路由参数
                $rule = $request->rule();
                if ($rule && method_exists($rule, 'getName')) {
                    // 尝试从规则获取参数，如果获取不到则返回空数组
                    $params = [];
                    $vars = method_exists($rule, 'getVars') ? $rule->getVars() : [];
                    if (!empty($vars)) {
                        $allParams = $request->param() ?: [];
                        foreach ($vars as $varName) {
                            if (isset($allParams[$varName]) && !isset($request->get()[$varName])) {
                                $params[$varName] = $allParams[$varName];
                            }
                        }
                    }
                    return $params;
                }
                return [];
            }
            $route = method_exists($request, 'route') ? $request->route() : null;
            if ($route && method_exists($route, 'parameters')) {
                return $route->parameters() ?: [];
            }
        } catch (\Throwable) {
        }
        return [];
    }

    /**
     * 获取查询字符串
     */
    public static function requestGetQueryString(object $request): ?string
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->queryString() ?: null;
            }
            if (method_exists($request, 'getQueryString')) {
                return $request->getQueryString();
            }
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * 判断请求是否匹配指定模式（路径匹配）
     */
    public static function requestIs(object $request, string $pattern): bool
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                $path = $request->pathinfo() ?? '';
                // 支持通配符 * → 正则
                if (str_contains($pattern, '*')) {
                    $regex = '#^' . str_replace('\*', '.*', preg_quote($pattern, '#')) . '$#';
                    return (bool) preg_match($regex, $path);
                }
                return $path === $pattern || str_starts_with($path, trim($pattern, '/'));
            }
            if (method_exists($request, 'is')) {
                return $request->is($pattern);
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 判断是否期望 JSON 响应
     */
    public static function requestExpectsJson(object $request): bool
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->isJson();
            }
            if (method_exists($request, 'expectsJson')) {
                return $request->expectsJson();
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 判断是否为 AJAX 请求
     */
    public static function requestIsAjax(object $request): bool
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                return $request->isAjax();
            }
            if (method_exists($request, 'ajax')) {
                return $request->ajax();
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 判断是否为 API 路由
     */
    public static function requestIsApi(object $request): bool
    {
        try {
            $path = self::requestPath($request);
            return str_starts_with($path, 'api/');
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 获取所有上传文件
     *
     * 统一返回可能嵌套的数组结构
     */
    public static function requestAllFiles(object $request): array
    {
        try {
            if (self::isThinkPhp() && $request instanceof \think\Request) {
                $files = $request->file() ?: [];
                $normalized = [];
                foreach ($files as $key => $file) {
                    // ThinkPHP 多文件上传可能返回：
                    // 1. 单文件对象  2. 文件对象数组  3. 原生 $_FILES 格式数组
                    if (is_array($file)) {
                        // 过滤掉原生 $_FILES 元数据数组（含 name/tmp_name 等键）
                        if (isset($file['tmp_name'])) {
                            // 原生 PHP 上传数组，跳过（无法直接转换为文件对象）
                            continue;
                        }
                        $normalized[$key] = array_values(array_filter($file, is_object(...)));
                    } elseif (is_object($file)) {
                        $normalized[$key] = [$file];
                    }
                }
                return $normalized;
            }
            if (method_exists($request, 'allFiles')) {
                $files = $request->allFiles() ?: [];
                // Laravel 已返回标准化结构，但确保一致性
                $normalized = [];
                foreach ($files as $key => $file) {
                    $normalized[$key] = is_array($file) ? $file : [$file];
                }
                return $normalized;
            }
        } catch (\Throwable) {
        }
        return [];
    }

    // ==================== Response 统一接口 ====================

    /**
     * 创建 JSON 响应
     */
    public static function jsonResponse(array $data, int $status = 200): object
    {
        try {
            if (self::isThinkPhp()) {
                return json($data, $status);
            }
            if (function_exists('response')) {
                return response()->json($data, $status);
            }
        } catch (\Throwable) {
        }
        // 极端降级：返回一个可序列化的简单对象
        return new class($data, $status) {
            public function __construct(public array $data, public int $status) {}
            public function withHeaders(array $headers): static { return $this; }
        };
    }

    /**
     * 创建视图响应
     */
    public static function viewResponse(string $view, array $data, int $status = 200): object
    {
        try {
            if (self::isThinkPhp()) {
                $resp = view($view, $data);
                if (is_object($resp) && method_exists($resp, 'code')) {
                    $resp->code($status);
                }
                return $resp;
            }
            if (function_exists('response')) {
                return response()->view($view, $data, $status);
            }
        } catch (\Throwable) {
        }
        return self::plainResponse('View unavailable', $status);
    }

    /**
     * 创建纯文本/ HTML 响应
     */
    public static function plainResponse(string $content, int $status = 200): object
    {
        try {
            if (self::isThinkPhp()) {
                return \think\Response::create($content, 'html', $status);
            }
            if (function_exists('response')) {
                return response($content, $status);
            }
        } catch (\Throwable) {
        }
        return new class($content, $status) {
            public function __construct(public string $content, public int $status) {}
            public function withHeaders(array $headers): static { return $this; }
        };
    }

    // ==================== Log 统一接口 ====================

    public static function logWarning(string $message, array $context = []): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Log')) {
                \think\facade\Log::warning($message, $context);
                return;
            }
            if (class_exists('Illuminate\Support\Facades\Log')) {
                \Illuminate\Support\Facades\Log::warning($message, $context);
            }
        } catch (\Throwable) {
        }
    }

    public static function logError(string $message, array $context = []): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Log')) {
                \think\facade\Log::error($message, $context);
                return;
            }
            if (class_exists('Illuminate\Support\Facades\Log')) {
                \Illuminate\Support\Facades\Log::error($message, $context);
            }
        } catch (\Throwable) {
        }
    }

    public static function logDebug(string $message, array $context = []): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Log')) {
                \think\facade\Log::debug($message, $context);
                return;
            }
            if (class_exists('Illuminate\Support\Facades\Log')) {
                \Illuminate\Support\Facades\Log::debug($message, $context);
            }
        } catch (\Throwable) {
        }
    }

    public static function logInfo(string $message, array $context = []): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Log')) {
                \think\facade\Log::info($message, $context);
                return;
            }
            if (class_exists('Illuminate\Support\Facades\Log')) {
                \Illuminate\Support\Facades\Log::info($message, $context);
            }
        } catch (\Throwable) {
        }
    }

    public static function logCritical(string $message, array $context = []): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Log')) {
                \think\facade\Log::critical($message, $context);
                return;
            }
            if (class_exists('Illuminate\Support\Facades\Log')) {
                \Illuminate\Support\Facades\Log::critical($message, $context);
            }
        } catch (\Throwable) {
        }
    }

    // ==================== Config 统一接口 ====================

    /**
     * 读取配置值
     */
    public static function config(string $key, mixed $default = null): mixed
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Config')) {
                return \think\facade\Config::get($key, $default);
            }
            if (function_exists('config')) {
                return config($key, $default);
            }
        } catch (\Throwable) {
        }
        return $default;
    }

    /**
     * 获取配置目录路径
     */
    public static function configPath(string $path = ''): string
    {
        try {
            if (self::isThinkPhp()) {
                $app = function_exists('app') ? app() : null;
                if ($app !== null && is_object($app) && method_exists($app, 'getConfigPath')) {
                    $base = $app->getConfigPath();
                    return $base . ($path ? ltrim($path, '/') : '');
                }
                return $path;
            }
            if (function_exists('config_path')) {
                return config_path($path);
            }
        } catch (\Throwable) {
        }
        return $path;
    }

    /**
     * 检查容器是否已绑定指定抽象
     */
    public static function appBound(string $abstract): bool
    {
        try {
            if (self::isThinkPhp()) {
                return app()->exists($abstract);
            }
            if (function_exists('app')) {
                return app()->bound($abstract);
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 从容器解析实例
     */
    public static function appMake(string $abstract, array $params = []): mixed
    {
        try {
            if (self::isThinkPhp()) {
                return app()->make($abstract, $params);
            }
            if (function_exists('app')) {
                return app($abstract, $params);
            }
        } catch (\Throwable) {
        }
        return null;
    }

    // ==================== Rate Limit 统一接口 ====================

    /**
     * 检查是否超过速率限制
     *
     * ThinkPHP 下使用 Cache 门面模拟限流桶
     */
    public static function rateLimitTooManyAttempts(string $key, int $maxAttempts): bool
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Cache')) {
                $attempts = (int) \think\facade\Cache::get($key, 0);
                return $attempts >= $maxAttempts;
            }
            if (class_exists('Illuminate\Support\Facades\RateLimiter')) {
                return \Illuminate\Support\Facades\RateLimiter::tooManyAttempts($key, $maxAttempts);
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 记录一次请求尝试
     */
    public static function rateLimitHit(string $key, int $decaySeconds): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\Cache')) {
                // 优先使用原子递增 inc() 减少高并发下的计数丢失（Redis/Memcached 驱动下是原子的）。
                // 首次创建键时（inc 返回 1 或更小），通过 set() 补偿 TTL；
                // 非首次时 TTL 由前次 set 维持，若驱动支持原子过期则自动续期。
                $attempts = (int) \think\facade\Cache::inc($key, 1);
                if ($attempts <= 1) {
                    \think\facade\Cache::set($key, $attempts, $decaySeconds);
                }
                return;
            }
            if (class_exists('Illuminate\Support\Facades\RateLimiter')) {
                \Illuminate\Support\Facades\RateLimiter::hit($key, $decaySeconds);
            }
        } catch (\Throwable) {
        }
    }

    // ==================== UploadedFile 统一接口 ====================

    /**
     * 获取上传文件的客户端原始扩展名
     *
     * Laravel: getClientOriginalExtension()
     * ThinkPHP: extension()
     */
    public static function fileGetClientOriginalExtension(object $file): string
    {
        try {
            if (method_exists($file, 'getClientOriginalExtension')) {
                return strtolower($file->getClientOriginalExtension());
            }
            if (method_exists($file, 'extension')) {
                return strtolower($file->extension());
            }
        } catch (\Throwable) {
        }
        return '';
    }

    /**
     * 获取上传文件的 MIME 类型
     *
     * Laravel: getMimeType()
     * ThinkPHP: getMime()
     */
    public static function fileGetMimeType(object $file): ?string
    {
        try {
            if (method_exists($file, 'getMimeType')) {
                return $file->getMimeType();
            }
            if (method_exists($file, 'getMime')) {
                return $file->getMime();
            }
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * 获取上传文件大小（字节）
     *
     * 双框架方法名一致，统一封装以增强防御性
     */
    public static function fileGetSize(object $file): int
    {
        try {
            if (method_exists($file, 'getSize')) {
                return (int) $file->getSize();
            }
        } catch (\Throwable) {
        }
        return 0;
    }

    /**
     * 检查上传文件是否有效
     *
     * 双框架方法名一致，统一封装以增强防御性
     */
    public static function fileIsValid(object $file): bool
    {
        try {
            if (method_exists($file, 'isValid')) {
                return $file->isValid();
            }
        } catch (\Throwable) {
        }
        return false;
    }

    // ==================== Response Headers 统一接口 ====================

    /**
     * 为响应对象批量设置 HTTP 头
     *
     * 跨框架兼容：Laravel 使用 withHeaders()，ThinkPHP 使用 header()。
     *
     * @param object $response 响应对象
     * @param array<string, string> $headers HTTP 头数组
     * @return object 响应对象
     */
    public static function responseWithHeaders(object $response, array $headers): object
    {
        if (empty($headers)) {
            return $response;
        }

        try {
            if (method_exists($response, 'withHeaders')) {
                return $response->withHeaders($headers);
            }

            if (method_exists($response, 'header')) {
                foreach ($headers as $name => $value) {
                    $response->header($name, $value);
                }
                return $response;
            }
        } catch (\Throwable) {
        }

        return $response;
    }

    // ==================== View 统一接口 ====================

    /**
     * 检查视图是否存在
     */
    public static function viewExists(string $view): bool
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\View')) {
                // ThinkPHP 下检查模板文件是否存在较复杂，简单返回 true 由调用方 try/catch 兜底
                return true;
            }
            if (function_exists('view')) {
                return view()->exists($view);
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * 注册视图命名空间
     */
    public static function addViewNamespace(string $namespace, string $path): void
    {
        try {
            if (self::isThinkPhp() && class_exists('think\facade\View')) {
                // ThinkPHP 8 使用 View::config('view_path') 配置模板路径
                // 安全包在 ThinkPHP 下建议通过拷贝视图文件到项目目录使用
                // 此处仅作预留接口
                return;
            }
            if (function_exists('app')) {
                $app = app();
                if (method_exists($app, 'bound') && $app->bound('view')) {
                    $app['view']->addNamespace($namespace, $path);
                }
            }
        } catch (\Throwable) {
        }
    }

    // ==================== 时间辅助 ====================

    /**
     * 获取当前 ISO 8601 格式时间字符串
     */
    public static function nowIso8601(): string
    {
        try {
            if (self::isLaravel() && function_exists('now')) {
                return now()->toIso8601String();
            }
        } catch (\Throwable) {
        }
        return (new \DateTimeImmutable())->format('c');
    }
}
