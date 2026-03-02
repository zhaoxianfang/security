<?php

namespace zxf\Security\Contracts;

/**
 * 缓存管理接口
 *
 * 定义缓存管理的核心功能契约
 * 遵循依赖倒置原则（DIP），缓存实现与业务逻辑解耦
 * 
 * @author  zxf
 * @version 3.0.0
 * @package zxf\Security\Contracts
 */
interface CacheManagerInterface
{
    /**
     * 获取缓存值
     *
     * @param string $key 缓存键
     * @param mixed $default 默认值
     * @return mixed 缓存值
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * 设置缓存值
     *
     * @param string $key 缓存键
     * @param mixed $value 缓存值
     * @param int|null $ttl 过期时间（秒）
     * @return bool 是否成功
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool;

    /**
     * 删除缓存值
     *
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function delete(string $key): bool;

    /**
     * 检查缓存是否存在
     *
     * @param string $key 缓存键
     * @return bool 是否存在
     */
    public function has(string $key): bool;

    /**
     * 清除所有缓存
     *
     * @return bool 是否成功
     */
    public function clear(): bool;

    /**
     * 获取或设置缓存（如果不存在）
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数
     * @param int|null $ttl 过期时间（秒）
     * @return mixed 缓存值
     */
    public function remember(string $key, callable $callback, ?int $ttl = null): mixed;

    /**
     * 获取或设置缓存（永久）
     *
     * @param string $key 缓存键
     * @param callable $callback 回调函数
     * @return mixed 缓存值
     */
    public function rememberForever(string $key, callable $callback): mixed;

    /**
     * 批量获取缓存
     *
     * @param array $keys 缓存键数组
     * @return array 缓存值数组
     */
    public function many(array $keys): array;

    /**
     * 批量设置缓存
     *
     * @param array $values 键值对数组
     * @param int|null $ttl 过期时间（秒）
     * @return bool 是否成功
     */
    public function setMany(array $values, ?int $ttl = null): bool;

    /**
     * 批量删除缓存
     *
     * @param array $keys 缓存键数组
     * @return bool 是否成功
     */
    public function deleteMany(array $keys): bool;

    /**
     * 增加缓存值
     *
     * @param string $key 缓存键
     * @param int $value 增加值
     * @return int|false 新值或false
     */
    public function increment(string $key, int $value = 1): int|false;

    /**
     * 减少缓存值
     *
     * @param string $key 缓存键
     * @param int $value 减少值
     * @return int|false 新值或false
     */
    public function decrement(string $key, int $value = 1): int|false;

    /**
     * 获取缓存前缀
     *
     * @return string 缓存前缀
     */
    public function getPrefix(): string;
}
