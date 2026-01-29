<?php

namespace zxf\Security\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 安全白名单管理服务
 *
 * 提供安全的白名单管理功能：
 * 1. 白名单路径分级管理
 * 2. 方法限制和级别控制
 * 3. 安全检查策略
 * 4. 实时配置更新
 * 5. 性能优化
 */
class WhitelistSecurityService
{
    /**
     * 配置管理实例
     */
    protected ConfigManager $config;

    /**
     * 白名单缓存（内存缓存）
     */
    protected array $whitelistCache = [];

    /**
     * 配置版本（用于检测配置变更）
     */
    protected string $configVersion = '';

    /**
     * 构造函数
     */
    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
    }

    /**
     * 检查路径是否在白名单中
     *
     * @param Request $request HTTP请求
     * @return array|null 白名单配置，不在白名单返回null
     */
    public function isWhitelisted(Request $request): ?array
    {
        try {
            $path = $request->path();
            $method = $request->method();

            // 验证路径和方法有效性
            if (empty($path) || empty($method)) {
                return null;
            }

            // 实时读取白名单配置（不使用缓存）
            $whitelistPaths = $this->config->get('url_whitelist_paths', []);

            if (!is_array($whitelistPaths) || empty($whitelistPaths)) {
                return null;
            }

            foreach ($whitelistPaths as $whitelistItem) {
                try {
                    $whitelistConfig = $this->normalizeWhitelistItem($whitelistItem);
                    $whitelistPath = $whitelistConfig['path'];

                    // 检查路径是否有效
                    if (empty($whitelistPath)) {
                        continue;
                    }

                    // 检查路径匹配
                    if ($this->pathMatches($path, $whitelistPath)) {
                        // 检查方法限制
                        if (!empty($whitelistConfig['methods'])) {
                            if (!is_array($whitelistConfig['methods'])) {
                                continue;
                            }
                            if (!in_array($method, $whitelistConfig['methods'], true)) {
                                // 方法不匹配，不在白名单
                                continue;
                            }
                        }

                        // 检查安全级别
                        $level = $whitelistConfig['level'] ?? 'low';

                        // 高风险路径需要额外验证
                        if ($level === 'high') {
                            if (!$this->verifyHighRiskPath($request)) {
                                Log::warning('高风险白名单路径验证失败', [
                                    'path' => $path,
                                    'method' => $method,
                                    'level' => $level,
                                ]);
                                continue;
                            }
                        }

                        return $whitelistConfig;
                    }
                } catch (Throwable $e) {
                    Log::error('处理白名单项异常: ' . $e->getMessage(), [
                        'whitelist_item' => $whitelistItem,
                        'exception' => $e
                    ]);
                    continue;
                }
            }

            return null;
        } catch (Throwable $e) {
            Log::error('白名单检查异常: ' . $e->getMessage(), [
                'exception' => $e
            ]);
            return null;
        }
    }

    /**
     * 检查白名单路径需要保留的安全检查
     *
     * @param array $whitelistConfig 白名单配置
     * @return array 需要保留的安全检查列表
     */
    public function getRequiredChecks(array $whitelistConfig): array
    {
        try {
            $level = $whitelistConfig['level'] ?? 'low';

            // 验证level有效性
            if (!is_string($level) || empty($level)) {
                $level = 'low';
            }

            // 始终保留的安全检查
            $alwaysCheck = $this->config->get('whitelist_security_policy.always_check', [
                'ip_blacklist',
                'rate_limit',
                'body_patterns',
                'file_upload',
                'sql_injection',
                'xss_attack',
                'command_injection',
            ]);

            if (!is_array($alwaysCheck)) {
                $alwaysCheck = [];
            }

            // 根据级别保留的检查
            $levelChecks = $this->config->get("whitelist_security_policy.level_checks.{$level}", []);

            if (!is_array($levelChecks)) {
                $levelChecks = [];
            }

            return array_merge($alwaysCheck, $levelChecks);
        } catch (Throwable $e) {
            Log::error('获取白名单安全检查配置异常: ' . $e->getMessage());
            // 返回默认安全检查列表
            return [
                'ip_blacklist',
                'rate_limit',
                'sql_injection',
                'xss_attack',
            ];
        }
    }

    /**
     * 检查路径是否需要额外认证
     *
     * @param string $path 路径
     * @return bool
     */
    public function requiresAuth(string $path): bool
    {
        try {
            if (empty($path) || !is_string($path)) {
                return false;
            }

            $requireAuthPaths = $this->config->get('whitelist_security_policy.require_auth', []);

            if (!is_array($requireAuthPaths) || empty($requireAuthPaths)) {
                return false;
            }

            foreach ($requireAuthPaths as $pattern) {
                if (empty($pattern) || !is_string($pattern)) {
                    continue;
                }
                if ($this->pathMatches($path, $pattern)) {
                    return true;
                }
            }

            return false;
        } catch (Throwable $e) {
            Log::error('检查路径是否需要认证异常: ' . $e->getMessage(), [
                'path' => $path ?? 'unknown',
            ]);
            return false;
        }
    }

    /**
     * 规范化白名单项配置
     *
     * @param mixed $item 白名单项
     * @return array 规范化后的配置
     */
    protected function normalizeWhitelistItem(mixed $item): array
    {
        if (is_string($item)) {
            return [
                'path' => $item,
                'level' => 'low',
                'methods' => [],
            ];
        }

        if (is_array($item)) {
            $config = [
                'path' => $item['path'] ?? $item[0] ?? '',
                'level' => $item['level'] ?? 'low',
                'methods' => $item['methods'] ?? [],
            ];

            return $config;
        }

        return [
            'path' => '',
            'level' => 'low',
            'methods' => [],
        ];
    }

    /**
     * 检查路径是否匹配
     *
     * @param string $path 实际路径
     * @param string $pattern 匹配模式
     * @return bool
     */
    protected function pathMatches(string $path, string $pattern): bool
    {
        try {
            // 精确匹配
            if ($path === $pattern) {
                return true;
            }

            // 通配符匹配
            if (str_ends_with($pattern, '*')) {
                $prefix = substr($pattern, 0, -1);
                return str_starts_with($path, $prefix);
            }

            // 正则表达式匹配（以 regex: 开头）
            if (str_starts_with($pattern, 'regex:')) {
                $regex = substr($pattern, 6);
                if (empty($regex)) {
                    return false;
                }
                $result = @preg_match($regex, $path);
                if ($result === false) {
                    Log::warning('正则表达式匹配失败', [
                        'pattern' => $pattern,
                        'path' => $path,
                    ]);
                    return false;
                }
                return (bool) $result;
            }

            return false;
        } catch (Throwable $e) {
            Log::error('路径匹配异常: ' . $e->getMessage(), [
                'path' => $path,
                'pattern' => $pattern,
            ]);
            return false;
        }
    }

    /**
     * 验证高风险白名单路径
     *
     * @param Request $request HTTP请求
     * @return bool
     */
    protected function verifyHighRiskPath(Request $request): bool
    {
        try {
            // 1. 检查是否需要认证
            $path = $request->path();
            if (empty($path)) {
                return false;
            }

            if ($this->requiresAuth($path)) {
                $user = $request->user();
                if (!$user) {
                    return false;
                }
            }

            // 2. 检查IP信誉（即使是白名单，高风险IP仍需检查）
            $ip = $request->ip();
            if (empty($ip)) {
                Log::warning('无法获取IP地址，拒绝高风险路径访问');
                return false;
            }

            if ($this->isSuspiciousIp($ip)) {
                Log::warning('高风险IP访问白名单路径', [
                    'path' => $path,
                    'ip' => $ip,
                ]);
                return false;
            }

            // 3. 检查请求频率（防止白名单被滥用）
            if ($this->isRateLimited($request)) {
                return false;
            }

            return true;
        } catch (Throwable $e) {
            Log::error('高风险路径验证异常: ' . $e->getMessage(), [
                'path' => $request->path() ?? 'unknown',
                'exception' => $e
            ]);
            return false;
        }
    }

    /**
     * 检查IP是否可疑
     *
     * @param string $ip IP地址
     * @return bool
     */
    protected function isSuspiciousIp(string $ip): bool
    {
        try {
            // 验证IP有效性
            if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }

            // 检查IP是否在黑名单
            if (class_exists(\zxf\Security\Models\SecurityIp::class)) {
                if (\zxf\Security\Models\SecurityIp::isBlacklisted($ip)) {
                    return true;
                }
            }
        } catch (Throwable $e) {
            Log::error('检查IP可疑性异常: ' . $e->getMessage(), [
                'ip' => $ip,
                'exception' => $e
            ]);
        }

        return false;
    }

    /**
     * 检查请求是否达到频率限制
     *
     * 使用Laravel内置缓存实现速率限制，避免依赖外部服务
     *
     * @param Request $request HTTP请求
     * @return bool
     */
    protected function isRateLimited(Request $request): bool
    {
        try {
            if (!$this->config->get('enable_rate_limiting', true)) {
                return false;
            }

            $ip = $request->ip();
            $path = $request->path();

            // 验证IP和路径有效性
            if (empty($ip) || empty($path)) {
                Log::warning('无法获取IP或路径，跳过频率限制检查');
                return false;
            }

            $key = 'whitelist:' . $ip . ':' . $path;

            // 白名单路径的频率限制更宽松
            $limits = [
                'minute' => 1000,  // 每分钟1000次
                'hour' => 10000,   // 每小时10000次
            ];

            foreach ($limits as $period => $maxRequests) {
                $periodKey = $key . ':' . $period;
                $currentCount = cache()->get($periodKey, 0);

                if (!is_numeric($currentCount)) {
                    $currentCount = 0;
                }

                if ($currentCount >= $maxRequests) {
                    Log::warning('白名单路径频率限制触发', [
                        'path' => $path,
                        'ip' => $ip,
                        'period' => $period,
                        'count' => $currentCount,
                        'max' => $maxRequests,
                    ]);
                    return true;
                }

                // 原子性递增计数器
                cache()->put($periodKey, $currentCount + 1, $period);
            }
        } catch (Throwable $e) {
            Log::error('白名单路径频率限制检查失败', [
                'error' => $e->getMessage(),
                'path' => $request->path() ?? 'unknown',
                'exception' => $e
            ]);
            // 忽略错误，放行请求
        }

        return false;
    }

    /**
     * 清除白名单缓存
     *
     * 在配置变更时调用
     */
    public function clearCache(): void
    {
        $this->whitelistCache = [];
        $this->configVersion = '';

        Log::debug('白名单缓存已清除');
    }

    /**
     * 获取白名单统计信息
     *
     * @return array
     */
    public function getStats(): array
    {
        try {
            $whitelistPaths = $this->config->get('url_whitelist_paths', []);

            if (!is_array($whitelistPaths)) {
                $whitelistPaths = [];
            }

            $stats = [
                'total' => count($whitelistPaths),
                'by_level' => [
                    'low' => 0,
                    'medium' => 0,
                    'high' => 0,
                ],
                'with_method_restriction' => 0,
                'patterns' => [],
            ];

            foreach ($whitelistPaths as $item) {
                try {
                    $config = $this->normalizeWhitelistItem($item);
                    $level = $config['level'] ?? 'low';

                    // 确保level是有效的
                    if (!isset($stats['by_level'][$level])) {
                        $stats['by_level'][$level] = 0;
                    }

                    $stats['by_level'][$level]++;
                    if (!empty($config['methods'])) {
                        $stats['with_method_restriction']++;
                    }

                    $stats['patterns'][] = [
                        'path' => $config['path'],
                        'level' => $level,
                        'methods' => $config['methods'] ?: null,
                    ];
                } catch (Throwable $e) {
                    Log::error('处理白名单统计异常: ' . $e->getMessage());
                    continue;
                }
            }

            return $stats;
        } catch (Throwable $e) {
            Log::error('获取白名单统计异常: ' . $e->getMessage());
            return [
                'total' => 0,
                'by_level' => [
                    'low' => 0,
                    'medium' => 0,
                    'high' => 0,
                ],
                'with_method_restriction' => 0,
                'patterns' => [],
            ];
        }
    }

    /**
     * 验证白名单配置安全性
     *
     * @return array 验证结果
     */
    public function validateWhitelistSecurity(): array
    {
        try {
            $issues = [];
            $warnings = [];

            $whitelistPaths = $this->config->get('url_whitelist_paths', []);

            if (!is_array($whitelistPaths)) {
                return [
                    'issues' => [],
                    'warnings' => [],
                    'total_issues' => 0,
                    'total_warnings' => 0,
                ];
            }

            foreach ($whitelistPaths as $item) {
                try {
                    $config = $this->normalizeWhitelistItem($item);
                    $path = $config['path'];
                    $level = $config['level'] ?? 'low';

                    // 检查危险通配符
                    if (in_array($path, ['api/*', 'v1/*', 'v2/*', 'rest/*', 'assets/*', 'public/*', 'static/*'], true)) {
                        $issues[] = [
                            'type' => 'dangerous_wildcard',
                            'path' => $path,
                            'message' => "危险的通配符路径: {$path}，建议移除或使用精确路径",
                            'severity' => 'critical',
                        ];
                    }

                    // 检查高风险路径
                    if ($level === 'high' && empty($config['methods'])) {
                        $warnings[] = [
                            'type' => 'high_risk_no_method_restriction',
                            'path' => $path,
                            'message' => "高风险路径 {$path} 没有方法限制，建议添加方法限制",
                            'severity' => 'warning',
                        ];
                    }

                    // 检查GraphQL
                    if ($path === 'graphql') {
                        $warnings[] = [
                            'type' => 'graphql_requires_security',
                            'path' => $path,
                            'message' => "GraphQL端点需要额外的安全措施和认证",
                            'severity' => 'warning',
                        ];
                    }
                } catch (Throwable $e) {
                    Log::error('验证白名单安全项异常: ' . $e->getMessage());
                    continue;
                }
            }

            // 检查通配符比例
            $wildcardCount = 0;
            foreach ($whitelistPaths as $item) {
                try {
                    $config = $this->normalizeWhitelistItem($item);
                    if (str_ends_with($config['path'], '*')) {
                        $wildcardCount++;
                    }
                } catch (Throwable $e) {
                    continue;
                }
            }

            if (count($whitelistPaths) > 0) {
                $wildcardRatio = $wildcardCount / count($whitelistPaths);
                if ($wildcardRatio > 0.5) {
                    $warnings[] = [
                        'type' => 'too_many_wildcards',
                        'message' => "白名单中通配符比例过高 ({$wildcardRatio})，可能存在安全风险",
                        'severity' => 'warning',
                    ];
                }
            }

            return [
                'issues' => $issues,
                'warnings' => $warnings,
                'total_issues' => count($issues),
                'total_warnings' => count($warnings),
            ];
        } catch (Throwable $e) {
            Log::error('验证白名单安全性异常: ' . $e->getMessage());
            return [
                'issues' => [],
                'warnings' => [],
                'total_issues' => 0,
                'total_warnings' => 0,
            ];
        }
    }
}
