<?php

namespace zxf\Security\Utils;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;
use Illuminate\Cache\RedisStore;
use Illuminate\Cache\MemcachedStore;
use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\ApcStore;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\DynamoDbStore;
use Illuminate\Cache\NullStore;
use ReflectionClass;
use Exception;

/**
 * 获取 laravel 中的缓存键名工具类
 * // 基本用法
 * $cacheKeys = new GetCacheKeys();
 *
 * // 获取所有缓存键
 * $allKeys = $cacheKeys->getAll();
 *
 * // 获取指定前缀的缓存键
 * $userKeys = $cacheKeys->getAll('security:');
 *
 * // 限制返回数量
 * $limitedKeys = $cacheKeys->getAll('', 100);
 *
 * // 保留完整前缀
 * $fullKeys = $cacheKeys->getAll('', null, false);
 *
 * // 获取统计信息
 * $stats = $cacheKeys->getStats('security:');
 *
 * // 清空指定前缀的缓存
 * $result = $cacheKeys->clearByPrefix('security:');
 *
 * // 设置自定义的最大数量
 * $cacheKeys->setDefaultMaxSize(5000);
 */
class GetCacheKeys
{
    /**
     * @var \Illuminate\Contracts\Cache\Store 缓存存储实例
     */
    protected $store;

    /**
     * @var string 缓存前缀
     */
    protected $cachePrefix;

    /**
     * @var int 默认最大返回数量
     */
    protected $defaultMaxSize = 10000;

    /**
     * 构造函数
     *
     * @param \Illuminate\Contracts\Cache\Store|null $store 缓存存储实例，默认为null时使用默认缓存
     */
    public function __construct($store = null)
    {
        $this->store = $store ?? Cache::getStore();
        $this->cachePrefix = config('cache.prefix', '-cache-');
    }

    /**
     * 获取所有缓存键名
     *
     * @param string $prefix 键名前缀 eg. 'security:'
     * @param int|null $maxSize 最大返回数量限制
     * @param bool $removePrefix 是否移除缓存键中的前缀
     * @return array 缓存键名数组
     * @throws \RuntimeException 当缓存驱动不支持或发生错误时抛出
     */
    public function getAll(string $prefix = '', ?int $maxSize = null, bool $removePrefix = true): array
    {
        $maxSize = $maxSize ?? $this->defaultMaxSize;
        $storeName = get_class($this->store);
        $fullPrefix = $prefix ? $this->cachePrefix . $prefix : $this->cachePrefix;

        // 根据不同的存储驱动调用相应的处理方法
        if ($this->store instanceof RedisStore) {
            return $this->getFromRedis($fullPrefix, $maxSize, $removePrefix);
        } elseif ($this->store instanceof MemcachedStore) {
            return $this->getFromMemcached($fullPrefix, $maxSize);
        } elseif ($this->store instanceof DatabaseStore) {
            return $this->getFromDatabase($fullPrefix, $maxSize);
        } elseif ($this->store instanceof FileStore) {
            return $this->getFromFilesystem($prefix, $maxSize);
        } elseif ($this->store instanceof DynamoDbStore) {
            return $this->getFromDynamoDB($fullPrefix, $maxSize, $removePrefix);
        } elseif ($this->store instanceof ApcStore) {
            return $this->getFromApc($fullPrefix, $maxSize);
        } elseif ($this->store instanceof ArrayStore) {
            return $this->getFromArray($prefix, $maxSize);
        } elseif ($this->store instanceof NullStore) {
            return [];
        } else {
            throw new \RuntimeException("不支持的缓存驱动: {$storeName}");
        }
    }

    /**
     * 从 Redis 获取缓存键名
     *
     * @param string $pattern 搜索模式
     * @param int $maxSize 最大数量
     * @param bool $removePrefix 是否移除前缀
     * @return array
     */
    protected function getFromRedis(string $pattern, int $maxSize, bool $removePrefix): array
    {
        try {
            $redis = $this->store->connection();
            $keys = [];

            // 使用 SCAN 命令迭代获取，避免阻塞 Redis
            $cursor = 0;
            do {
                // 处理不同的 Redis 客户端（predis/phpredis）
                if (method_exists($redis, 'scan')) {
                    // phpredis
                    $result = $redis->scan($cursor, $pattern, 500);
                    if ($result === false) break;

                    list($cursor, $batchKeys) = [$result[0] ?? 0, $result[1] ?? []];
                } else {
                    // predis
                    $result = $redis->scan($cursor, [
                        'MATCH' => $pattern,
                        'COUNT' => 500
                    ]);
                    $cursor = $result[0];
                    $batchKeys = $result[1];
                }

                // 处理获取到的键
                foreach ($batchKeys as $key) {
                    if ($removePrefix && $this->cachePrefix && strpos($key, $this->cachePrefix) === 0) {
                        $key = substr($key, strlen($this->cachePrefix));
                    }
                    $keys[] = $key;

                    if (count($keys) >= $maxSize) {
                        break 2;
                    }
                }

            } while ($cursor != 0 && count($keys) < $maxSize);

            sort($keys);
            return array_unique($keys);

        } catch (Exception $e) {
            throw new \RuntimeException("Redis 缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从 Memcached 获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @return array
     */
    protected function getFromMemcached(string $prefix, int $maxSize): array
    {
        try {
            $memcached = $this->store->getMemcached();
            $keys = [];

            // 获取所有 slabs 信息
            $slabs = $memcached->getStats('slabs');
            if (!$slabs) return [];

            foreach ($slabs as $server => $slabData) {
                if (!is_array($slabData)) continue;

                foreach (array_keys($slabData) as $slabId) {
                    if (!is_numeric($slabId)) continue;

                    // 获取每个 slab 中的缓存项
                    $cacheDump = $memcached->getStats('cachedump', (int)$slabId, 0);
                    if (!is_array($cacheDump)) continue;

                    foreach ($cacheDump as $server => $entries) {
                        if (!is_array($entries)) continue;

                        foreach ($entries as $key => $details) {
                            // 过滤前缀
                            if ($prefix && !str_starts_with($key, $prefix)) {
                                continue;
                            }
                            $keys[] = $key;

                            if (count($keys) >= $maxSize) {
                                break 3;
                            }
                        }
                    }
                }
            }

            return array_unique($keys);

        } catch (Exception $e) {
            throw new \RuntimeException("Memcached 缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从数据库获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @return array
     */
    protected function getFromDatabase(string $prefix, int $maxSize): array
    {
        try {
            $connection = $this->store->getConnection();

            // 获取缓存表名 - 兼容不同 Laravel 版本
            $table = 'cache';
            if (method_exists($this->store, 'getTable')) {
                $table = $this->store->getTable();
            } else {
                // 从配置中获取表名
                $table = config('cache.stores.database.table', 'cache');
            }

            $query = $connection->table($table)->select('key');

            if ($prefix) {
                $query->where('key', 'like', $prefix . '%');
            }

            // 过滤已过期的缓存
            $query->where(function ($q) {
                $q->whereNull('expiration')
                    ->orWhere('expiration', '>', time());
            });

            return $query->orderBy('key')
                ->limit($maxSize)
                ->pluck('key')
                ->toArray();

        } catch (Exception $e) {
            throw new \RuntimeException("数据库缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从文件系统获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @return array
     */
    protected function getFromFilesystem(string $prefix, int $maxSize): array
    {
        try {
            $filesystem = $this->store->getFilesystem();
            $directory = $this->store->getDirectory();
            $extension = $this->store->getFileExtension() ?: '';

            $keys = [];

            // 构建搜索模式
            $pattern = $directory . DIRECTORY_SEPARATOR;
            if ($prefix) {
                // 前缀可能包含目录分隔符
                $pattern .= str_replace('*', '\*', $prefix) . '*';
            } else {
                $pattern .= '*';
            }
            $pattern .= $extension;

            // 获取所有匹配的文件
            $files = glob($pattern, GLOB_NOSORT);

            foreach ($files as $file) {
                if (!is_file($file)) continue;

                // 提取键名
                $key = basename($file, $extension);

                // 验证缓存是否过期
                try {
                    $contents = $filesystem->get($file);
                    if ($contents) {
                        $expiration = (int) substr($contents, 0, 10);
                        if ($expiration !== 0 && $expiration <= time()) {
                            continue; // 跳过已过期的缓存
                        }
                    }
                } catch (Exception $e) {
                    // 读取文件失败，跳过
                    continue;
                }

                $keys[] = $key;

                if (count($keys) >= $maxSize) {
                    break;
                }
            }

            sort($keys);
            return $keys;

        } catch (Exception $e) {
            throw new \RuntimeException("文件缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从 DynamoDB 获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @param bool $removePrefix 是否移除前缀
     * @return array
     */
    protected function getFromDynamoDB(string $prefix, int $maxSize, bool $removePrefix): array
    {
        try {
            $keys = [];

            // 获取 DynamoDB 表和客户端
            $table = $this->store->getTable();
            $client = $this->store->getClient();

            // 构建查询参数
            $params = [
                'TableName' => $table,
                'ProjectionExpression' => '#k',
                'ExpressionAttributeNames' => [
                    '#k' => 'key'
                ],
                'Limit' => min($maxSize, 100),
            ];

            if ($prefix) {
                $params['FilterExpression'] = 'begins_with(#k, :prefix)';
                $params['ExpressionAttributeValues'] = [
                    ':prefix' => ['S' => $prefix]
                ];
            }

            // 使用 Scan 操作获取所有键
            $result = $client->scan($params);

            while (isset($result['Items']) && count($keys) < $maxSize) {
                foreach ($result['Items'] as $item) {
                    if (isset($item['key']['S'])) {
                        $key = $item['key']['S'];

                        if ($removePrefix && $this->cachePrefix && strpos($key, $this->cachePrefix) === 0) {
                            $key = substr($key, strlen($this->cachePrefix));
                        }

                        $keys[] = $key;

                        if (count($keys) >= $maxSize) {
                            break 2;
                        }
                    }
                }

                // 处理分页
                if (isset($result['LastEvaluatedKey'])) {
                    $params['ExclusiveStartKey'] = $result['LastEvaluatedKey'];
                    $result = $client->scan($params);
                } else {
                    break;
                }
            }

            sort($keys);
            return array_unique($keys);

        } catch (Exception $e) {
            throw new \RuntimeException("DynamoDB 缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从 APC/APCu 获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @return array
     */
    protected function getFromApc(string $prefix, int $maxSize): array
    {
        // 检查是否支持 APCu
        if (!function_exists('apcu_cache_info')) {
            throw new \RuntimeException("APCu 扩展不可用");
        }

        try {
            $cacheInfo = apcu_cache_info();
            if (!isset($cacheInfo['cache_list'])) {
                return [];
            }

            $keys = [];
            foreach ($cacheInfo['cache_list'] as $item) {
                if (!isset($item['info'])) continue;

                $key = $item['info'];

                // 过滤前缀
                if ($prefix && !str_starts_with($key, $prefix)) {
                    continue;
                }

                $keys[] = $key;

                if (count($keys) >= $maxSize) {
                    break;
                }
            }

            sort($keys);
            return array_unique($keys);

        } catch (Exception $e) {
            throw new \RuntimeException("APC/APCu 缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 从 Array 存储获取缓存键名
     *
     * @param string $prefix 前缀
     * @param int $maxSize 最大数量
     * @return array
     */
    protected function getFromArray(string $prefix, int $maxSize): array
    {
        try {
            // 使用反射获取 ArrayStore 中的缓存数组
            $reflection = new ReflectionClass($this->store);
            $property = $reflection->getProperty('storage');
            $property->setAccessible(true);

            $storage = $property->getValue($this->store);
            $keys = [];

            foreach (array_keys($storage) as $key) {
                // 过滤前缀
                if ($prefix && !str_starts_with($key, $prefix)) {
                    continue;
                }

                $keys[] = $key;

                if (count($keys) >= $maxSize) {
                    break;
                }
            }

            sort($keys);
            return array_unique($keys);

        } catch (Exception $e) {
            throw new \RuntimeException("Array 缓存键获取失败: " . $e->getMessage());
        }
    }

    /**
     * 获取缓存统计信息
     *
     * @param string $prefix 前缀
     * @return array
     */
    public function getStats(string $prefix = ''): array
    {
        $keys = $this->getAll($prefix);

        return [
            'count' => count($keys),
            'keys' => $keys,
            'driver' => get_class($this->store),
            'prefix' => $this->cachePrefix,
        ];
    }

    /**
     * 清空指定前缀的缓存
     *
     * @param string $prefix 前缀
     * @return bool
     */
    public function clearByPrefix(string $prefix = 'security:'): bool
    {
        try {
            $keys = $this->getAll($prefix, null, false);

            foreach ($keys as $key) {
                Cache::forget($key);
            }

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * 设置默认最大返回数量
     *
     * @param int $maxSize
     * @return $this
     */
    public function setDefaultMaxSize(int $maxSize): self
    {
        $this->defaultMaxSize = $maxSize;
        return $this;
    }

    /**
     * 获取支持的驱动列表
     *
     * @return array
     */
    public static function getSupportedDrivers(): array
    {
        return [
            RedisStore::class,
            MemcachedStore::class,
            DatabaseStore::class,
            FileStore::class,
            DynamoDbStore::class,
            ApcStore::class,
            ArrayStore::class,
            NullStore::class,
        ];
    }
}
