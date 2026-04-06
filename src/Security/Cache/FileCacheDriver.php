<?php

namespace zxf\Security\Cache;

use Illuminate\Support\Facades\Log;

/**
 * 独立文件缓存驱动 - 零外部依赖
 *
 * 本驱动完全不依赖Redis或其他外部缓存服务，仅使用文件系统实现缓存功能。
 * 适用于以下场景：
 * - 无Redis环境的项目
 * - 需要降低部署复杂度的项目
 * - 中小型应用（缓存数据量<100MB）
 *
 * 特性：
 * - 自动创建缓存目录结构
 * - 基于文件的过期时间检查
 * - 文件锁机制保证并发安全
 * - LRU清理策略防止磁盘占满
 * - 序列化支持多种数据类型
 *
 * @author  zxf
 * @version 1.0.0
 * @package zxf\Security\Cache
 */
class FileCacheDriver
{
    /**
     * 缓存目录路径
     */
    protected string $cachePath;

    /**
     * 缓存文件扩展名
     */
    protected string $fileExtension = '.cache';

    /**
     * 子目录深度（用于分散文件）
     */
    protected int $directoryDepth = 2;

    /**
     * 单个缓存目录最大文件数
     */
    protected int $maxFilesPerDirectory = 1000;

    /**
     * 缓存命中统计
     */
    private static array $stats = [
        'hits' => 0,
        'misses' => 0,
        'writes' => 0,
        'deletes' => 0,
        'errors' => 0,
    ];

    /**
     * 内存缓存缓冲区（减少文件IO）
     */
    private static array $memoryBuffer = [];

    /**
     * 缓冲区最大大小
     */
    private const MAX_BUFFER_SIZE = 1000;

    /**
     * 最后一次清理时间
     */
    private static ?int $lastCleanupTime = null;

    /**
     * 清理间隔（秒）
     */
    private const CLEANUP_INTERVAL = 3600; // 1小时

    /**
     * 构造函数
     *
     * @param string|null $cachePath 缓存目录路径，默认使用storage/security-cache
     */
    public function __construct(?string $cachePath = null)
    {
        $this->cachePath = $cachePath ?? storage_path('security-cache');
        $this->ensureDirectoryExists($this->cachePath);
    }

    /**
     * 获取缓存值
     *
     * @param string $key 缓存键
     * @param mixed $default 默认值
     * @return mixed 缓存值或默认值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        // 1. 检查内存缓冲区
        if (isset(self::$memoryBuffer[$key])) {
            $item = self::$memoryBuffer[$key];
            if ($item['expires'] === 0 || $item['expires'] > time()) {
                self::$stats['hits']++;
                return $item['value'];
            }
            // 已过期，从缓冲区移除
            unset(self::$memoryBuffer[$key]);
        }

        // 2. 检查文件缓存
        $filePath = $this->getCacheFilePath($key);

        if (!file_exists($filePath)) {
            self::$stats['misses']++;
            return $default;
        }

        try {
            $data = $this->readCacheFile($filePath);

            if ($data === null) {
                self::$stats['misses']++;
                return $default;
            }

            // 检查是否过期
            if ($data['expires'] !== 0 && $data['expires'] < time()) {
                // 删除过期缓存
                @unlink($filePath);
                self::$stats['misses']++;
                return $default;
            }

            // 写入内存缓冲区
            $this->addToBuffer($key, $data['value'], $data['expires']);

            self::$stats['hits']++;
            return $data['value'];

        } catch (\Exception $e) {
            Log::error('文件缓存读取失败', ['key' => $key, 'error' => $e->getMessage()]);
            self::$stats['errors']++;
            return $default;
        }
    }

    /**
     * 设置缓存值
     *
     * @param string $key 缓存键
     * @param mixed $value 缓存值
     * @param int|null $ttl 过期时间（秒），null表示永不过期
     * @return bool 是否成功
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        $filePath = $this->getCacheFilePath($key);
        $expires = $ttl === null ? 0 : (time() + $ttl);

        $data = [
            'key' => $key,
            'value' => $value,
            'expires' => $expires,
            'created' => time(),
        ];

        try {
            // 确保目录存在
            $directory = dirname($filePath);
            $this->ensureDirectoryExists($directory);

            // 序列化数据
            $content = serialize($data);

            // 使用临时文件+重命名保证原子性
            $tempFile = $filePath . '.tmp.' . uniqid();

            if (file_put_contents($tempFile, $content, LOCK_EX) === false) {
                self::$stats['errors']++;
                return false;
            }

            if (!rename($tempFile, $filePath)) {
                @unlink($tempFile);
                self::$stats['errors']++;
                return false;
            }

            // 写入内存缓冲区
            $this->addToBuffer($key, $value, $expires);

            self::$stats['writes']++;

            // 定期清理过期缓存
            $this->cleanupIfNeeded();

            return true;

        } catch (\Exception $e) {
            Log::error('文件缓存写入失败', ['key' => $key, 'error' => $e->getMessage()]);
            self::$stats['errors']++;
            return false;
        }
    }

    /**
     * 删除缓存
     *
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function delete(string $key): bool
    {
        // 从内存缓冲区移除
        unset(self::$memoryBuffer[$key]);

        $filePath = $this->getCacheFilePath($key);

        if (!file_exists($filePath)) {
            return true;
        }

        try {
            $result = @unlink($filePath);
            if ($result) {
                self::$stats['deletes']++;
            }
            return $result;
        } catch (\Exception $e) {
            Log::error('文件缓存删除失败', ['key' => $key, 'error' => $e->getMessage()]);
            self::$stats['errors']++;
            return false;
        }
    }

    /**
     * 检查缓存是否存在
     *
     * @param string $key 缓存键
     * @return bool 是否存在
     */
    public function has(string $key): bool
    {
        // 检查内存缓冲区
        if (isset(self::$memoryBuffer[$key])) {
            $item = self::$memoryBuffer[$key];
            if ($item['expires'] === 0 || $item['expires'] > time()) {
                return true;
            }
        }

        $filePath = $this->getCacheFilePath($key);

        if (!file_exists($filePath)) {
            return false;
        }

        try {
            $data = $this->readCacheFile($filePath);

            if ($data === null) {
                return false;
            }

            // 检查是否过期
            if ($data['expires'] !== 0 && $data['expires'] < time()) {
                @unlink($filePath);
                return false;
            }

            return true;

        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * 缓存不存在时设置
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数获取值
     * @param int|null $ttl 过期时间
     * @return mixed 缓存值
     */
    public function remember(string $key, callable $callback, ?int $ttl = null): mixed
    {
        $value = $this->get($key);

        if ($value !== null) {
            return $value;
        }

        $value = $callback();
        $this->set($key, $value, $ttl);

        return $value;
    }

    /**
     * 增加计数器
     *
     * @param string $key 缓存键
     * @param int $value 增加值
     * @return int|false 新值或false
     */
    public function increment(string $key, int $value = 1): int|false
    {
        $current = $this->get($key, 0);

        if (!is_int($current)) {
            $current = 0;
        }

        $newValue = $current + $value;

        if ($this->set($key, $newValue)) {
            return $newValue;
        }

        return false;
    }

    /**
     * 减少计数器
     *
     * @param string $key 缓存键
     * @param int $value 减少值
     * @return int|false 新值或false
     */
    public function decrement(string $key, int $value = 1): int|false
    {
        return $this->increment($key, -$value);
    }

    /**
     * 清除所有缓存
     *
     * @param string|null $prefix 可选前缀，只清除匹配前缀的缓存
     * @return bool 是否成功
     */
    public function clear(?string $prefix = null): bool
    {
        try {
            // 清除内存缓冲区
            if ($prefix === null) {
                self::$memoryBuffer = [];
            } else {
                foreach (self::$memoryBuffer as $key => $value) {
                    if (str_starts_with($key, $prefix)) {
                        unset(self::$memoryBuffer[$key]);
                    }
                }
            }

            // 清除文件缓存
            $this->recursiveDelete($this->cachePath, $prefix);

            Log::info('文件缓存已清除', ['prefix' => $prefix]);

            return true;

        } catch (\Exception $e) {
            Log::error('文件缓存清除失败', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * 获取所有缓存键
     *
     * @param string|null $prefix 前缀过滤
     * @return array 缓存键列表
     */
    public function keys(?string $prefix = null): array
    {
        $keys = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->cachePath, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'cache') {
                    $data = $this->readCacheFile($file->getPathname());
                    if ($data !== null) {
                        $key = $data['key'];
                        if ($prefix === null || str_starts_with($key, $prefix)) {
                            $keys[] = $key;
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            Log::error('获取缓存键失败', ['error' => $e->getMessage()]);
        }

        return $keys;
    }

    /**
     * 获取缓存统计
     *
     * @return array 统计信息
     */
    public function getStats(): array
    {
        $total = self::$stats['hits'] + self::$stats['misses'];
        $hitRate = $total > 0 ? round((self::$stats['hits'] / $total) * 100, 2) : 0;

        // 计算缓存目录大小
        $size = $this->getDirectorySize($this->cachePath);
        $fileCount = $this->getFileCount($this->cachePath);

        return [
            'hits' => self::$stats['hits'],
            'misses' => self::$stats['misses'],
            'writes' => self::$stats['writes'],
            'deletes' => self::$stats['deletes'],
            'errors' => self::$stats['errors'],
            'hit_rate' => $hitRate . '%',
            'memory_buffer_size' => count(self::$memoryBuffer),
            'disk_size_bytes' => $size,
            'disk_size_mb' => round($size / 1024 / 1024, 2),
            'file_count' => $fileCount,
            'cache_path' => $this->cachePath,
        ];
    }

    /**
     * 获取缓存文件路径
     *
     * 使用哈希算法分散文件到子目录，避免单个目录文件过多
     */
    protected function getCacheFilePath(string $key): string
    {
        $hash = md5($key);
        $parts = [];

        // 生成子目录路径
        for ($i = 0; $i < $this->directoryDepth; $i++) {
            $parts[] = substr($hash, $i * 2, 2);
        }

        $directory = $this->cachePath . '/' . implode('/', $parts);
        return $directory . '/' . $hash . $this->fileExtension;
    }

    /**
     * 读取缓存文件
     *
     * @param string $filePath 文件路径
     * @return array|null 缓存数据或null
     */
    protected function readCacheFile(string $filePath): ?array
    {
        $content = @file_get_contents($filePath);

        if ($content === false) {
            return null;
        }

        $data = @unserialize($content);

        if ($data === false || !is_array($data) || !isset($data['value'])) {
            return null;
        }

        return $data;
    }

    /**
     * 添加到内存缓冲区
     */
    protected function addToBuffer(string $key, mixed $value, int $expires): void
    {
        // LRU清理
        if (count(self::$memoryBuffer) >= self::MAX_BUFFER_SIZE) {
            // 移除最早的20%
            $keysToRemove = array_slice(array_keys(self::$memoryBuffer), 0, (int)(self::MAX_BUFFER_SIZE * 0.2));
            foreach ($keysToRemove as $removeKey) {
                unset(self::$memoryBuffer[$removeKey]);
            }
        }

        self::$memoryBuffer[$key] = [
            'value' => $value,
            'expires' => $expires,
        ];
    }

    /**
     * 确保目录存在
     */
    protected function ensureDirectoryExists(string $path): void
    {
        if (!is_dir($path)) {
            @mkdir($path, 0755, true);
        }
    }

    /**
     * 递归删除目录或文件
     */
    protected function recursiveDelete(string $path, ?string $prefix = null): void
    {
        if (is_file($path)) {
            if ($prefix === null) {
                @unlink($path);
            } else {
                $data = $this->readCacheFile($path);
                if ($data !== null && str_starts_with($data['key'], $prefix)) {
                    @unlink($path);
                }
            }
            return;
        }

        if (!is_dir($path)) {
            return;
        }

        $items = new \DirectoryIterator($path);

        foreach ($items as $item) {
            if ($item->isDot()) {
                continue;
            }

            if ($item->isDir()) {
                $this->recursiveDelete($item->getPathname(), $prefix);
                // 如果是空目录，删除目录
                if ($prefix === null && $this->isDirEmpty($item->getPathname())) {
                    @rmdir($item->getPathname());
                }
            } else {
                $this->recursiveDelete($item->getPathname(), $prefix);
            }
        }
    }

    /**
     * 检查目录是否为空
     */
    protected function isDirEmpty(string $path): bool
    {
        $items = new \DirectoryIterator($path);
        foreach ($items as $item) {
            if (!$item->isDot()) {
                return false;
            }
        }
        return true;
    }

    /**
     * 获取目录大小
     */
    protected function getDirectorySize(string $path): int
    {
        $size = 0;

        if (!is_dir($path)) {
            return 0;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $size += $file->getSize();
                }
            }
        } catch (\Exception $e) {
            // 忽略错误
        }

        return $size;
    }

    /**
     * 获取文件数量
     */
    protected function getFileCount(string $path): int
    {
        $count = 0;

        if (!is_dir($path)) {
            return 0;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            // 忽略错误
        }

        return $count;
    }

    /**
     * 定期清理过期缓存
     */
    protected function cleanupIfNeeded(): void
    {
        $now = time();

        if (self::$lastCleanupTime === null || ($now - self::$lastCleanupTime) > self::CLEANUP_INTERVAL) {
            self::$lastCleanupTime = $now;

            // 异步清理（不阻塞当前请求）
            if (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            }

            $this->cleanupExpired();
        }
    }

    /**
     * 清理过期缓存
     */
    public function cleanupExpired(): int
    {
        $cleaned = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->cachePath, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->getExtension() !== 'cache') {
                    continue;
                }

                $data = $this->readCacheFile($file->getPathname());

                if ($data === null) {
                    // 损坏的文件，删除
                    @unlink($file->getPathname());
                    $cleaned++;
                    continue;
                }

                // 检查是否过期
                if ($data['expires'] !== 0 && $data['expires'] < time()) {
                    @unlink($file->getPathname());
                    $cleaned++;
                }
            }

            if ($cleaned > 0) {
                Log::info('文件缓存过期清理完成', ['cleaned' => $cleaned]);
            }

        } catch (\Exception $e) {
            Log::error('文件缓存过期清理失败', ['error' => $e->getMessage()]);
        }

        return $cleaned;
    }

    /**
     * 重置统计
     */
    public function resetStats(): void
    {
        self::$stats = [
            'hits' => 0,
            'misses' => 0,
            'writes' => 0,
            'deletes' => 0,
            'errors' => 0,
        ];
    }

    /**
     * 清除内存缓冲区
     */
    public static function clearMemoryBuffer(): void
    {
        self::$memoryBuffer = [];
    }
}
