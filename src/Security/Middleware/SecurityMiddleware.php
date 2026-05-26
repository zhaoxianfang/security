<?php

namespace zxf\Security\Middleware;

use Closure;
use Illuminate\Http\Request;
use zxf\Security\Dto\InterceptionContext;
use zxf\Security\Services\IpMatcherService;
use zxf\Security\Patterns\PatternService;
use zxf\Security\Middleware\Concerns\UsesSafeRegex;
use zxf\Security\Middleware\Concerns\HandlesAccessControl;
use zxf\Security\Middleware\Concerns\ValidatesInputIntegrity;
use zxf\Security\Middleware\Concerns\DetectsAttackPatterns;
use zxf\Security\Middleware\Concerns\ManagesMarkdownSafety;
use zxf\Security\Middleware\Concerns\HandlesFileUploads;
use zxf\Security\Middleware\Concerns\BuildsInterceptionResponse;

/**
 * Laravel 安全拦截中间件
 *
 * 核心设计理念：
 * 1. 高危操作精准拦截 - 采用高置信度检测模式，确保攻击被拦截
 * 2. 低误报率 - 智能识别合法内容（如Markdown文档中的代码示例）
 * 3. 零缓存依赖 - 不使用任何自定义缓存，直接使用 Laravel 原生功能
 * 4. 高性能 - 精简逻辑，单次请求处理耗时 < 1ms
 * 5. 灵活配置 - 支持回调、动态规则、路由排除
 * 6. 模块化架构 - 按功能拆分为 7 个 Trait，提高可读性和可维护性
 *
 * 安全防护层级（按执行顺序）：
 *  1. 路由排除检查    → HandlesAccessControl
 *  2. IP 白名单检查   → HandlesAccessControl
 *  3. IP 黑名单检查   → HandlesAccessControl
 *  4. URL路径攻击检测 → DetectsAttackPatterns
 *  5. 多重编码检测    → ValidatesInputIntegrity
 *  6. User-Agent检查  → ValidatesInputIntegrity
 *  7. HTTP头检查      → ValidatesInputIntegrity
 *  8. 请求体大小检查  → ValidatesInputIntegrity
 *  9. 请求速率限制    → ValidatesInputIntegrity
 * 10. HTTP方法检查    → ValidatesInputIntegrity
 * 11. URL长度检查     → ValidatesInputIntegrity
 * 12. 高危攻击检测    → DetectsAttackPatterns + ManagesMarkdownSafety
 * 13. XSS攻击检测     → DetectsAttackPatterns + ManagesMarkdownSafety
 * 14. 文件上传检查    → HandlesFileUploads
 *
 * 模块文件：
 *  - Concerns/UsesSafeRegex.php            安全正则 + 输入处理
 *  - Concerns/HandlesAccessControl.php     路由排除 + IP黑白名单 + 检测层开关
 *  - Concerns/ValidatesInputIntegrity.php  UA/Headers/Body/Rate/Method/URL/编码检查
 *  - Concerns/DetectsAttackPatterns.php    URL路径 + 高危攻击 + XSS 模式检测
 *  - Concerns/ManagesMarkdownSafety.php    Markdown 智能识别与旁路
 *  - Concerns/HandlesFileUploads.php       文件上传安全检查
 *  - Concerns/BuildsInterceptionResponse.php  拦截响应 + 日志 + 回调
 *
 * @package zxf\Security\Middleware
 * @version 6.0.0
 */
class SecurityMiddleware
{
    use UsesSafeRegex;
    use HandlesAccessControl;
    use ValidatesInputIntegrity;
    use DetectsAttackPatterns;
    use ManagesMarkdownSafety;
    use HandlesFileUploads;
    use BuildsInterceptionResponse;

    /**
     * 配置缓存数组
     * 在构造函数中一次性加载，避免重复读取配置
     *
     * @var array<string, mixed>
     */
    protected readonly array $config;

    /**
     * 模式服务（延迟加载正则模式，降低内存占用）
     *
     * @var PatternService
     */
    protected readonly PatternService $patternService;

    /**
     * 检测到的威胁类型数组
     * 用于记录多种威胁类型，返回给客户端参考
     *
     * @var array<string>
     */
    protected array $threats = [];

    /**
     * 最后一次匹配的攻击模式
     * 用于回调时传递给开发者
     *
     * @var string
     */
    protected string $lastMatchedPattern = '';

    /**
     * 最后一次匹配的内容片段
     * 用于回调时传递给开发者
     *
     * @var string
     */
    protected string $lastMatchedContent = '';

    /**
     * 当前检测到的威胁类型
     *
     * @var string
     */
    protected string $currentThreatType = '';

    /**
     * 当前请求ID
     * 用于日志记录等处理
     *
     * @var string
     */
    protected string $requestId = '';

    /**
     * @var InterceptionContext 拦截上下文信息
     */
    protected InterceptionContext $context;

    /**
     * 构造函数
     * 预加载配置到内存，提高后续访问速度
     *
     * 注意：正则模式不在此处加载，而是通过 PatternService 延迟加载，
     * 避免 php artisan optimize 时一次性加载所有正则导致内存溢出。
     *
     * ⚠️ 配置加载失败兼容：如果 config('security') 返回空数组，
     *    中间件仍然会被实例化，但 handle() 中 enabled 检查会放行。
     *    日志会记录配置缺失，帮助排查。
     */
    public function __construct()
    {
        $loadedConfig = config('security', []);

        // 防御：如果配置文件未正确合并，强制重新加载
        if (empty($loadedConfig) || !isset($loadedConfig['enabled'])) {
            // 尝试直接 require 配置文件作为最后兜底
            $configPath = dirname(__DIR__, 3) . '/config/security.php';
            if (file_exists($configPath)) {
                $loadedConfig = require $configPath;
            }

            // 如果仍然为空，记录日志并使用安全默认值
            if (empty($loadedConfig) || !is_array($loadedConfig)) {
                if (config('security.log_enabled', true)) {
                    \Illuminate\Support\Facades\Log::warning(
                        '[Security] 安全配置加载失败，将使用最小安全默认值运行',
                        ['config_path' => $configPath]
                    );
                }
                // 最小安全默认值：仅启用基础检测
                $loadedConfig = [
                    'enabled' => true,
                    'detection_layers' => [
                        'url_path' => true, 'encoding' => true,
                        'high_risk' => true, 'xss' => true,
                    ],
                    'trusted_ips' => [],
                    'whitelist' => [],
                ];
            }
        }

        $this->config = $loadedConfig;
        $this->ipMatcher = new IpMatcherService();
        $this->patternService = app(PatternService::class);
    }

    /**
     * 处理传入的HTTP请求
     *
     * 这是中间件的核心方法，按顺序执行各项安全检查。
     * 任何一项检查失败都会立即拦截请求，不再继续后续检查。
     *
     * @param Request $request HTTP请求对象
     * @param Closure $next 下一个中间件处理程序
     * @return mixed 响应对象或向下传递请求
     */
    public function handle(Request $request, Closure $next)
    {
        // 检查中间件是否被禁用
        if (!($this->config['enabled'] ?? true)) {
            return $next($request);
        }

        // 检查是否在排除路由列表中
        if ($this->isExcludedRoute($request)) {
            return $next($request);
        }

        // 获取客户端真实IP地址
        $ip = $request->ip();

        // ========== 第一层：IP 白名单检查 ==========
        if ($this->isWhitelisted($ip, $request)) {
            return $next($request);
        }

        // 生成唯一请求ID
        $this->requestId = $this->generateRequestId();

        // ========== 第二层：IP 黑名单检查 ==========
        if ($this->isBlacklisted($ip, $request)) {
            return $this->handleThreatDetection($request, $next, 'blacklist', function ($request) {
                $this->logThreat($request, 'blacklist', 'IP地址位于黑名单中: ' . $request->ip());
                return $this->blockRequest($request, 'IP已被禁止访问', 403, 'blacklist');
            });
        }

        // ========== 第三层：URL路径攻击检测 ==========
        if ($this->isDetectionEnabled('url_path') && $this->detectUrlPathAttacks($request)) {
            return $this->handleThreatDetection($request, $next, 'url_path_attack', function ($request) {
                $this->logThreat($request, 'url_path_attack', 'URL路径包含攻击模式: ' . $this->lastMatchedPattern);
                return $this->blockRequest($request, '请求包含非法内容', 403, 'url_path_attack');
            });
        }

        // ========== 第四层：多重编码检测 ==========
        if ($this->isDetectionEnabled('encoding') && $this->detectMultiEncodingAttacks($request)) {
            return $this->handleThreatDetection($request, $next, 'encoding_bypass', function ($request) {
                $this->logThreat($request, 'encoding_bypass', '检测到编码绕过攻击');
                return $this->blockRequest($request, '请求格式非法', 403, 'encoding_bypass');
            });
        }

        // ========== 第五层：User-Agent检查 ==========
        if ($this->isDetectionEnabled('user_agent') && $this->isBadUserAgent($request)) {
            return $this->handleThreatDetection($request, $next, 'bad_user_agent', function ($request) {
                $this->logThreat($request, 'bad_user_agent', '恶意User-Agent: ' . $request->userAgent());
                return $this->blockRequest($request, '请求被拒绝', 403, 'bad_user_agent');
            });
        }

        // ========== 第六层：HTTP头检查 ==========
        if ($this->isDetectionEnabled('headers') && $this->hasInvalidHeaders($request)) {
            return $this->handleThreatDetection($request, $next, 'invalid_headers', function ($request) {
                $this->logThreat($request, 'invalid_headers', 'HTTP头检查失败');
                return $this->blockRequest($request, '请求被拒绝', 403, 'invalid_headers');
            });
        }

        // ========== 第七层：请求体大小检查 ==========
        if ($this->isDetectionEnabled('body_size') && $this->isBodyTooLarge($request)) {
            return $this->handleThreatDetection($request, $next, 'body_too_large', function ($request) {
                $this->logThreat($request, 'body_too_large', '请求体大小超过限制');
                return $this->blockRequest($request, '请求体过大', 403, 'body_too_large');
            });
        }

        // ========== 第八层：请求速率限制 ==========
        if ($this->isDetectionEnabled('rate_limit') && $this->isRateLimited($request)) {
            return $this->handleThreatDetection($request, $next, 'rate_limit', function ($request) {
                $this->logThreat($request, 'rate_limit', '请求频率超过限制');
                return $this->blockRequest($request, '请求过于频繁，请稍后再试', 429, 'rate_limit');
            });
        }

        // ========== 第九层：HTTP方法检查 ==========
        if ($this->isDetectionEnabled('http_method') && $this->hasInvalidMethod($request)) {
            return $this->handleThreatDetection($request, $next, 'invalid_method', function ($request) {
                $this->logThreat($request, 'invalid_method', '非法HTTP方法: ' . $request->method());
                return $this->blockRequest($request, '不支持的请求方法', 403, 'invalid_method');
            });
        }

        // ========== 第十层：URL长度检查 ==========
        if ($this->isDetectionEnabled('url_length') && $this->isUrlTooLong($request)) {
            return $this->handleThreatDetection($request, $next, 'url_too_long', function ($request) {
                $this->logThreat($request, 'url_too_long', 'URL长度超限');
                return $this->blockRequest($request, '请求URL过长', 403, 'url_too_long');
            });
        }

        // ========== 第十一层：高危攻击检测 ==========
        if ($this->isDetectionEnabled('high_risk')) {
            $threatType = $this->detectHighRiskAttacks($request);
            if ($threatType !== null) {
                return $this->handleThreatDetection($request, $next, $threatType, function ($request) use ($threatType) {
                    $this->logThreat($request, $threatType, '高危模式匹配: ' . $this->lastMatchedPattern);
                    return $this->blockRequest($request, '请求包含高危安全威胁', 403, $threatType);
                });
            }
        }

        // ========== 第十二层：XSS攻击检测 ==========
        if ($this->isDetectionEnabled('xss')) {
            $xssType = $this->detectXssAttacks($request);
            if ($xssType !== null) {
                return $this->handleThreatDetection($request, $next, $xssType, function ($request) use ($xssType) {
                    $this->logThreat($request, $xssType, 'XSS模式匹配: ' . $this->lastMatchedPattern);
                    return $this->blockRequest($request, '请求包含潜在的安全威胁', 403, $xssType);
                });
            }
        }

        // ========== 第十三层：文件上传检查 ==========
        if ($this->isDetectionEnabled('upload') && $this->hasDangerousUpload($request)) {
            return $this->handleThreatDetection($request, $next, 'dangerous_upload', function ($request) {
                $this->logThreat($request, 'dangerous_upload', '检测到危险文件上传');
                return $this->blockRequest($request, '文件上传被拒绝', 403, 'dangerous_upload');
            });
        }

        // 所有安全检查通过，继续处理请求
        return $next($request);
    }

    /**
     * 统一的威胁检测处理模板
     *
     * 消除 13 层检查中重复的"记录threats → 设置currentThreatType → 创建context → shouldBlock决策"逻辑
     *
     * @param Request $request HTTP请求对象
     * @param Closure $next 下一个中间件
     * @param string $threatType 威胁类型
     * @param callable $onBlock 拦截时执行的回调（日志+响应）
     * @return mixed
     */
    protected function handleThreatDetection(Request $request, Closure $next, string $threatType, callable $onBlock)
    {
        $this->threats[] = $threatType;
        $this->currentThreatType = $threatType;
        $this->context = $this->createInterceptionContext($request, $threatType);

        if ($this->shouldBlock($this->context)) {
            return $onBlock($request);
        }

        return $next($request);
    }

    /**
     * 生成唯一请求ID
     *
     * @return string 格式：SEC_{uniqid}_{8位hash}
     */
    protected function generateRequestId(): string
    {
        try {
            $randomBytes = random_bytes(8);
        } catch (\Random\RandomException) {
            $randomBytes = (string) random_int(10000000, 99999999);
        }

        return 'SEC_' . strtoupper(uniqid()) . '_' . substr(md5($randomBytes), 0, 8);
    }
}
