<?php

namespace zxf\Security\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 配置热重载服务
 *
 * 实现配置修改后立即生效，无需重启应用：
 * 1. 配置变更检测
 * 2. 自动缓存清理
 * 3. 实时配置更新
 * 4. 性能监控
 */
class ConfigHotReloadService
{
    /**
     * 配置管理实例
     */
    protected ?ConfigManager $config = null;

    /**
     * 当前配置版本
     */
    protected string $currentVersion = '';

    /**
     * 配置文件路径
     */
    protected string $configPath;

    /**
     * 上次修改时间
     */
    protected int $lastModified = 0;

    /**
     * 是否已初始化
     */
    protected bool $initialized = false;

    /**
     * 构造函数
     *
     * 延迟初始化以避免递归
     */
    public function __construct(ConfigManager $config = null)
    {
        // 不在构造函数中初始化，避免递归调用
        // 设置引用但不调用其方法
        $this->config = $config;
        $this->configPath = config_path('security.php');
    }

    /**
     * 初始化（延迟调用）
     */
    protected function initialize(): void
    {
        if ($this->initialized) {
            return;
        }

        $this->initialized = true;

        try {
            if (!file_exists($this->configPath)) {
                Log::warning('配置文件不存在', [
                    'path' => $this->configPath,
                ]);
                return;
            }

            $this->lastModified = filemtime($this->configPath);
            $this->currentVersion = $this->generateVersion();

            // 缓存初始版本
            Cache::forever($this->getVersionKey(), $this->currentVersion);

        } catch (\Exception $e) {
            Log::error('ConfigHotReloadService 初始化失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }
    }

    /**
     * 确保已初始化
     */
    protected function ensureInitialized(): void
    {
        if (!$this->initialized) {
            $this->initialize();
        }
    }

    /**
     * 检查配置是否已更新
     *
     * @return bool
     */
    public function hasConfigChanged(): bool
    {
        $this->ensureInitialized();

        try {
            if (!file_exists($this->configPath)) {
                return false;
            }

            $currentModified = filemtime($this->configPath);

            if ($currentModified > $this->lastModified) {
                $this->lastModified = $currentModified;
                return true;
            }

            return false;

        } catch (\Exception $e) {
            Log::error('检查配置变更失败', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * 热重载配置
     *
     * @return bool 是否成功
     */
    public function reloadConfig(): bool
    {
        $this->ensureInitialized();

        try {
            // 检查是否启用热重载（直接读取配置，避免递归）
            $enabled = $this->getHotReloadEnabled();
            if (!$enabled) {
                return false;
            }

            // 检查配置是否有变更
            if (!$this->hasConfigChanged()) {
                return false;
            }

            Log::info('开始热重载安全配置', [
                'path' => $this->configPath,
            ]);

            // 1. 清除配置缓存
            $this->clearConfigCache();

            // 2. 重新加载配置文件
            $this->reloadConfigFile();

            // 3. 更新版本号
            $newVersion = $this->updateVersion();

            // 4. 清除相关服务缓存
            $this->clearServiceCaches();

            Log::info('安全配置热重载成功', [
                'new_version' => $newVersion,
            ]);

            return true;

        } catch (\Exception $e) {
            Log::error('安全配置热重载失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * 清除配置缓存
     */
    protected function clearConfigCache(): void
    {
        try {
            // 清除Laravel配置缓存
            if (function_exists('app')) {
                try {
                    app()->forgetInstance('config');
                } catch (\Exception $e) {
                    // 忽略错误
                }
            }

            // 清除自定义配置缓存（如果存在）
            if ($this->config !== null) {
                try {
                    $this->config->clearCache();
                } catch (\Exception $e) {
                    Log::warning('清除ConfigManager缓存失败', [
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            Log::debug('配置缓存已清除');

        } catch (\Exception $e) {
            Log::error('清除配置缓存失败', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * 获取热重载是否启用（直接读取，避免递归）
     */
    protected function getHotReloadEnabled(): bool
    {
        try {
            // 直接从Laravel配置读取，避免通过ConfigManager
            $enabled = config('security.hot_reload.enabled', true);
            return (bool) $enabled;
        } catch (\Exception $e) {
            Log::warning('读取热重载配置失败，使用默认值', [
                'error' => $e->getMessage(),
            ]);
            return true;
        }
    }

    /**
     * 重新加载配置文件
     */
    protected function reloadConfigFile(): void
    {
        // 强制重新加载配置文件
        $config = require $this->configPath;

        if (function_exists('app')) {
            try {
                app()['config']->set('security', $config);
            } catch (\Exception $e) {
                // 忽略错误
            }
        }

        Log::debug('配置文件已重新加载');
    }

    /**
     * 更新版本号
     *
     * @return string 新版本号
     */
    protected function updateVersion(): string
    {
        $newVersion = $this->generateVersion();
        $this->currentVersion = $newVersion;

        Cache::forever($this->getVersionKey(), $newVersion);

        return $newVersion;
    }

    /**
     * 生成配置版本号
     *
     * @return string
     */
    protected function generateVersion(): string
    {
        return md5(file_get_contents($this->configPath) . microtime());
    }

    /**
     * 获取版本键
     *
     * @return string
     */
    protected function getVersionKey(): string
    {
        return $this->config->get('hot_reload.version_key', 'security:config:version');
    }

    /**
     * 清除服务缓存
     */
    protected function clearServiceCaches(): void
    {
        try {
            // 清除白名单缓存
            if (class_exists(WhitelistSecurityService::class)) {
                $whitelistService = app(WhitelistSecurityService::class);
                $whitelistService->clearCache();
            }

            // 清除规则引擎缓存
            if (class_exists(RuleEngineService::class)) {
                $ruleEngine = app(RuleEngineService::class);
                $ruleEngine->clearCache();
            }

            // 清除威胁评分缓存
            if (class_exists(ThreatScoringService::class)) {
                $threatScoring = app(ThreatScoringService::class);
                $threatScoring->clearCache();
            }

            // 清除IP缓存
            if (class_exists(IpManagerService::class)) {
                $ipManager = app(IpManagerService::class);
                $ipManager->clearAllCache();
            }

            Log::debug('服务缓存已清除');

        } catch (\Exception $e) {
            Log::warning('清除服务缓存时出错', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * 手动触发配置重载
     *
     * @return bool
     */
    public function forceReload(): bool
    {
        $this->lastModified = 0; // 强制触发变更检测
        return $this->reloadConfig();
    }

    /**
     * 获取当前配置版本
     *
     * @return string
     */
    public function getCurrentVersion(): string
    {
        return $this->currentVersion;
    }

    /**
     * 检查配置项是否应实时读取（不缓存）
     *
     * @param string $key 配置键
     * @return bool
     */
    public function shouldReadRealtime(string $key): bool
    {
        $this->ensureInitialized();

        try {
            // 直接从Laravel配置读取，避免通过ConfigManager导致递归
            $noCacheKeys = config('security.hot_reload.no_cache_keys', []);

            foreach ($noCacheKeys as $pattern) {
                if (str_ends_with($pattern, '*')) {
                    $prefix = substr($pattern, 0, -1);
                    if (str_starts_with($key, $prefix)) {
                        return true;
                    }
                } elseif ($key === $pattern) {
                    return true;
                }
            }

            return false;

        } catch (\Exception $e) {
            Log::warning('检查实时读取配置失败', [
                'key' => $key,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * 获取配置变更统计
     *
     * @return array
     */
    public function getStats(): array
    {
        $this->ensureInitialized();

        try {
            return [
                'current_version' => $this->currentVersion,
                'last_modified' => $this->lastModified,
                'config_path' => $this->configPath,
                'file_exists' => file_exists($this->configPath),
                'hot_reload_enabled' => $this->getHotReloadEnabled(),
            ];
        } catch (\Exception $e) {
            Log::error('获取配置统计失败', [
                'error' => $e->getMessage(),
            ]);
            return [
                'current_version' => $this->currentVersion,
                'last_modified' => $this->lastModified,
                'config_path' => $this->configPath,
                'file_exists' => false,
                'hot_reload_enabled' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}
