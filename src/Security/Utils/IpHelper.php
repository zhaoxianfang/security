<?php

namespace zxf\Security\Utils;

use InvalidArgumentException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * IP地址辅助工具类
 *
 * 提供统一的IP地址判断和处理功能，避免重复代码
 * 基于PHP 8.2+ 和 Laravel 11+
 *
 * @package zxf\Security\Utils
 */
class IpHelper
{
    /**
     * 缓存前缀
     */
    private const CACHE_PREFIX = 'security:ip:helper:';
    
    /**
     * 缓存TTL（秒）
     */
    private const CACHE_TTL = 300;
    
    /**
     * 内网IP判断缓存
     */
    protected static array $intranetCache = [];
    
    /**
     * 验证IP地址格式
     *
     * @param string $ip IP地址
     * @return bool 是否有效
     */
    public static function isValid(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * 判断是否为IPv4地址
     *
     * @param string $ip IP地址
     * @return bool 是否为IPv4
     */
    public static function isIpv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
    
    /**
     * 判断是否为IPv6地址
     *
     * @param string $ip IP地址
     * @return bool 是否为IPv6
     */
    public static function isIpv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }
    
    /**
     * 判断IP是否为内网/私有地址 - 带缓存优化
     *
     * 使用 is_intranet_ip 函数作为核心判断逻辑
     * 增加缓存机制提高性能
     *
     * @param string $ip IP地址
     * @param bool $useCache 是否使用缓存
     * @param array $options 额外选项
     * @return bool 是否为内网IP
     */
    public static function isIntranet(string $ip, bool $useCache = true, array $options = []): bool
    {
        // 快速验证IP格式
        if (!self::isValid($ip)) {
            return false;
        }
        
        // 使用缓存
        if ($useCache) {
            $cacheKey = self::CACHE_PREFIX . 'intranet:' . md5($ip);
            
            // 检查静态缓存
            if (isset(self::$intranetCache[$cacheKey])) {
                return self::$intranetCache[$cacheKey];
            }
            
            // 检查Laravel Cache
            $cached = Cache::get($cacheKey);
            if ($cached !== null) {
                self::$intranetCache[$cacheKey] = $cached;
                return $cached;
            }
            
            // 缓存未命中，执行判断
            $result = self::checkIntranetIp($ip, $options);
            
            // 缓存结果
            self::$intranetCache[$cacheKey] = $result;
            Cache::put($cacheKey, $result, self::CACHE_TTL);
            
            return $result;
        }
        
        // 不使用缓存，直接判断
        return self::checkIntranetIp($ip, $options);
    }
    
    /**
     * 内网IP检查核心逻辑
     *
     * 调用 is_intranet_ip 全局函数
     *
     * @param string $ip IP地址
     * @param array $options 选项
     * @return bool 是否为内网IP
     */
    protected static function checkIntranetIp(string $ip, array $options = []): bool
    {
        try {
            return \is_intranet_ip($ip, $options);
        } catch (Throwable $e) {
            Log::error('内网IP判断失败', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }
    
    /**
     * 判断是否为回环地址
     *
     * @param string $ip IP地址
     * @return bool 是否为回环地址
     */
    public static function isLoopback(string $ip): bool
    {
        if (!self::isValid($ip)) {
            return false;
        }
        
        // IPv4: 127.0.0.0/8
        if (self::isIpv4($ip)) {
            $ipLong = ip2long($ip);
            return ($ipLong & 0xFF000000) === 0x7F000000;
        }
        
        // IPv6: ::1/128
        return $ip === '::1';
    }
    
    /**
     * 判断是否为链路本地地址
     *
     * @param string $ip IP地址
     * @return bool 是否为链路本地地址
     */
    public static function isLinkLocal(string $ip): bool
    {
        if (!self::isValid($ip)) {
            return false;
        }
        
        // IPv4: 169.254.0.0/16
        if (self::isIpv4($ip)) {
            $ipLong = ip2long($ip);
            return ($ipLong & 0xFFFF0000) === 0xA9FE0000;
        }
        
        // IPv6: fe80::/10
        if (self::isIpv6($ip)) {
            $ipBin = inet_pton($ip);
            return ($ipBin[0] & 0xC0) === 0x80;
        }
        
        return false;
    }
    
    /**
     * 判断是否为私有IP地址（标准私有地址）
     *
     * @param string $ip IP地址
     * @return bool 是否为私有IP
     */
    public static function isPrivate(string $ip): bool
    {
        if (!self::isValid($ip)) {
            return false;
        }
        
        // IPv4 私有地址
        if (self::isIpv4($ip)) {
            $ipLong = ip2long($ip);
            
            // 10.0.0.0/8
            if (($ipLong & 0xFF000000) === 0x0A000000) {
                return true;
            }
            
            // 172.16.0.0/12
            if (($ipLong & 0xFFF00000) === 0xAC100000) {
                return true;
            }
            
            // 192.168.0.0/16
            if (($ipLong & 0xFFFF0000) === 0xC0A80000) {
                return true;
            }
            
            return false;
        }
        
        // IPv6 私有地址 (fc00::/7)
        if (self::isIpv6($ip)) {
            $ipBin = inet_pton($ip);
            return ($ipBin[0] & 0xFE) === 0xFC;
        }
        
        return false;
    }
    
    /**
     * 判断IP是否在CIDR范围内
     *
     * @param string $ip IP地址
     * @param string $cidr CIDR格式，如 192.168.1.0/24
     * @return bool 是否在范围内
     */
    public static function ipInRange(string $ip, string $cidr): bool
    {
        try {
            // 验证IP格式
            if (!self::isValid($ip)) {
                return false;
            }
            
            // 解析CIDR
            if (!str_contains($cidr, '/')) {
                // 无掩码，精确匹配
                return $ip === $cidr;
            }
            
            [$network, $maskLen] = explode('/', $cidr, 2);
            $maskLen = (int)$maskLen;
            
            // IPv4 CIDR匹配
            if (self::isIpv4($ip) && self::isIpv4($network)) {
                $ipLong = ip2long($ip);
                $networkLong = ip2long($network);
                $mask = -1 << (32 - $maskLen);
                
                return ($ipLong & $mask) === ($networkLong & $mask);
            }
            
            // IPv6 CIDR匹配
            if (self::isIpv6($ip) && self::isIpv6($network)) {
                $ipBin = inet_pton($ip);
                $networkBin = inet_pton($network);
                
                $bytes = 16;
                $fullBytes = intdiv($maskLen, 8);
                $remBits = $maskLen % 8;
                
                for ($i = 0; $i < $fullBytes; $i++) {
                    if ($ipBin[$i] !== $networkBin[$i]) {
                        return false;
                    }
                }
                
                if ($remBits > 0) {
                    $mask = 0xFF << (8 - $remBits);
                    if (($ipBin[$fullBytes] & $mask) !== ($networkBin[$fullBytes] & $mask)) {
                        return false;
                    }
                }
                
                return true;
            }
            
            return false;
        } catch (Throwable $e) {
            Log::error('CIDR范围判断失败', [
                'ip' => $ip,
                'cidr' => $cidr,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }
    
    /**
     * 获取客户端真实IP地址
     *
     * 优先从X-Forwarded-For、X-Real-IP等代理头获取
     * 避免伪造，需要验证IP有效性
     *
     * @param array $headers HTTP头数组
     * @return string IP地址
     */
    public static function getRealIp(array $headers = []): string
    {
        if (function_exists('request') && empty($headers)) {
            $request = \request();
            $headers = [
                'x-forwarded-for' => $request->header('x-forwarded-for'),
                'x-real-ip' => $request->header('x-real-ip'),
                'cf-connecting-ip' => $request->header('cf-connecting-ip'),
                'x-client-ip' => $request->header('x-client-ip'),
            ];
        }

        $ipHeaders = [
            'x-forwarded-for',
            'x-real-ip',
            'cf-connecting-ip',
            'x-client-ip',
        ];

        foreach ($ipHeaders as $header) {
            $value = $headers[$header] ?? null;
            if ($value) {
                // X-Forwarded-For 可能包含多个IP，取第一个
                if (str_contains($value, ',')) {
                    $value = trim(explode(',', $value)[0]);
                }

                // 验证IP有效性
                if (self::isValid($value)) {
                    return $value;
                }
            }
        }

        // 没有代理头，返回默认
        return function_exists('request') ? \request()->ip() : '127.0.0.1';
    }
    
    /**
     * 规范化IP地址
     *
     * 将IP地址转换为统一格式
     *
     * @param string $ip IP地址
     * @return string 规范化后的IP
     */
    public static function normalize(string $ip): string
    {
        if (!self::isValid($ip)) {
            throw new InvalidArgumentException("无效的IP地址: {$ip}");
        }
        
        // IPv4: 去除前导零，转换为小写
        if (self::isIpv4($ip)) {
            return strtolower(trim($ip));
        }
        
        // IPv6: 压缩格式
        if (self::isIpv6($ip)) {
            $ipBin = inet_pton($ip);
            return inet_ntop($ipBin);
        }
        
        return $ip;
    }
    
    /**
     * 检查IP是否在多个CIDR范围内
     *
     * @param string $ip IP地址
     * @param array $cidrs CIDR数组
     * @return bool 是否在任一范围内
     */
    public static function ipInAnyRange(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::ipInRange($ip, $cidr)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 批量检查IP是否为内网IP
     *
     * @param array $ips IP地址数组
     * @param bool $useCache 是否使用缓存
     * @return array 判断结果 ['ip' => bool]
     */
    public static function batchIsIntranet(array $ips, bool $useCache = true): array
    {
        $results = [];
        
        foreach ($ips as $ip) {
            if (!self::isValid($ip)) {
                $results[$ip] = false;
                continue;
            }
            
            $results[$ip] = self::isIntranet($ip, $useCache);
        }
        
        return $results;
    }
    
    /**
     * 清除内网IP判断缓存
     *
     * @return void
     */
    public static function clearIntranetCache(): void
    {
        self::$intranetCache = [];
        
        // 清除Laravel Cache中的内网IP缓存
        // 注意：这里只清除本工具类的缓存
        if (function_exists('clean_security_cache')) {
            clean_security_cache();
        }
    }
    
    /**
     * 获取IP地址类型
     *
     * @param string $ip IP地址
     * @return string IP类型
     */
    public static function getIpType(string $ip): string
    {
        if (!self::isValid($ip)) {
            return 'invalid';
        }
        
        if (self::isIntranet($ip, false)) {
            return 'intranet';
        }
        
        if (self::isLoopback($ip)) {
            return 'loopback';
        }
        
        if (self::isLinkLocal($ip)) {
            return 'linklocal';
        }
        
        if (self::isPrivate($ip)) {
            return 'private';
        }
        
        return 'public';
    }
    
    /**
     * 获取工具类统计信息
     *
     * @return array 统计信息
     */
    public static function getStats(): array
    {
        return [
            'intranet_cache_size' => count(self::$intranetCache),
            'cache_ttl' => self::CACHE_TTL,
            'cache_prefix' => self::CACHE_PREFIX,
        ];
    }
}
