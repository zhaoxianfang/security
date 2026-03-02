<?php

namespace zxf\Security\Utils;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Request;
use zxf\Security\Constants\SecurityConstants;

/**
 * IP验证工具类（增强版）
 *
 * 提供完善的IP验证功能：
 * 1. IP地址格式验证（IPv4/IPv6）
 * 2. CIDR格式验证
 * 3. 代理IP链验证
 * 4. 内网IP识别
 * 5. IP范围匹配
 */
class IPValidator
{
    /**
     * 验证IPv4地址
     */
    public static function isValidIPv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * 验证IPv6地址
     */
    public static function isValidIPv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * 验证IP地址（IPv4或IPv6）
     */
    public static function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * 验证IPv4 CIDR格式
     *
     * @param string $cidr CIDR字符串，如 "192.168.1.0/24"
     * @return bool 是否有效
     */
    public static function isValidIPv4CIDR(string $cidr): bool
    {
        if (!preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/', $cidr, $matches)) {
            return false;
        }

        // 验证每个八位组
        for ($i = 1; $i <= 4; $i++) {
            $octet = (int) $matches[$i];
            if ($octet < 0 || $octet > 255) {
                return false;
            }
        }

        // 验证掩码长度
        $mask = (int) $matches[5];
        if ($mask < 0 || $mask > SecurityConstants::MAX_IPV4_CIDR) {
            return false;
        }

        return true;
    }

    /**
     * 验证IPv6 CIDR格式
     *
     * @param string $cidr CIDR字符串
     * @return bool 是否有效
     */
    public static function isValidIPv6CIDR(string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }

        [$ip, $mask] = explode('/', $cidr, 2);

        if (!self::isValidIPv6($ip)) {
            return false;
        }

        $maskInt = (int) $mask;
        if ($maskInt < 0 || $maskInt > SecurityConstants::MAX_IPV6_CIDR) {
            return false;
        }

        return true;
    }

    /**
     * 验证CIDR格式（IPv4或IPv6）
     *
     * @param string $cidr CIDR字符串
     * @return bool 是否有效
     */
    public static function isValidCIDR(string $cidr): bool
    {
        return self::isValidIPv4CIDR($cidr) || self::isValidIPv6CIDR($cidr);
    }

    /**
     * 检查IP是否为内网IP
     *
     * @param string $ip IP地址
     * @return bool 是否为内网IP
     */
    public static function isInternalIP(string $ip): bool
    {
        if (!self::isValidIP($ip)) {
            return false;
        }

        foreach (SecurityConstants::INTRANET_RANGES as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查IP是否在指定CIDR范围内
     *
     * @param string $ip IP地址
     * @param string $cidr CIDR范围
     * @return bool 是否在范围内
     */
    public static function ipInRange(string $ip, string $cidr): bool
    {
        if (!self::isValidIP($ip) || !str_contains($cidr, '/')) {
            return false;
        }

        [$rangeIP, $netmask] = explode('/', $cidr, 2);
        $netmaskInt = (int) $netmask;

        if (self::isValidIPv4($ip) && self::isValidIPv4($rangeIP)) {
            return self::ipv4InRange($ip, $rangeIP, $netmaskInt);
        }

        if (self::isValidIPv6($ip) && self::isValidIPv6($rangeIP)) {
            return self::ipv6InRange($ip, $rangeIP, $netmaskInt);
        }

        return false;
    }

    /**
     * 检查IPv4是否在范围内
     */
    private static function ipv4InRange(string $ip, string $rangeIP, int $netmask): bool
    {
        $ipLong = ip2long($ip);
        $rangeLong = ip2long($rangeIP);

        if ($ipLong === false || $rangeLong === false) {
            return false;
        }

        $maskLong = -1 << (32 - $netmask);
        $networkLong = $rangeLong & $maskLong;

        return ($ipLong & $maskLong) === $networkLong;
    }

    /**
     * 检查IPv6是否在范围内
     */
    private static function ipv6InRange(string $ip, string $rangeIP, int $netmask): bool
    {
        $ipBinary = inet_pton($ip);
        $rangeBinary = inet_pton($rangeIP);

        if ($ipBinary === false || $rangeBinary === false) {
            return false;
        }

        $fullBytes = (int) ($netmask / 8);
        $remainingBits = $netmask % 8;

        // 比较完整字节
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBinary[$i] !== $rangeBinary[$i]) {
                return false;
            }
        }

        // 比较剩余位
        if ($remainingBits > 0) {
            $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
            if ((ord($ipBinary[$fullBytes]) & $mask) !== (ord($rangeBinary[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 获取客户端真实IP（增强版）
     *
     * 支持代理IP链验证，防止IP伪造
     *
     * @param \Illuminate\Http\Request|null $request 请求对象
     * @return string 真实IP地址
     */
    public static function getClientRealIP(?\Illuminate\Http\Request $request = null): string
    {
        $request = $request ?? Request::instance();

        // 获取配置的信任代理
        $trustedProxies = config('security.trusted_proxies', []);

        // 获取配置的信任头
        $trustedHeaders = config('security.trusted_headers', [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
        ]);

        // 如果没有配置信任代理，直接返回IP
        if (empty($trustedProxies)) {
            return $request->ip();
        }

        // 检查请求是否来自信任代理
        if (!self::isFromTrustedProxy($request, $trustedProxies)) {
            return $request->ip();
        }

        // 尝试从信任头中获取IP
        foreach ($trustedHeaders as $header) {
            $ip = $request->server->get($header);

            if (!empty($ip)) {
                // 处理多个IP的情况（X-Forwarded-For可能包含多个IP）
                $ips = array_map('trim', explode(',', $ip));
                $realIP = null;

                // 从后往前找，找到第一个非内网IP
                foreach (array_reverse($ips) as $candidateIP) {
                    if (self::isValidIP($candidateIP) && !self::isInternalIP($candidateIP)) {
                        $realIP = $candidateIP;
                        break;
                    }
                }

                // 如果找到真实IP，验证并返回
                if ($realIP !== null) {
                    if (self::isValidIP($realIP)) {
                        return $realIP;
                    }

                    Log::warning('无效的客户端IP', [
                        'header' => $header,
                        'ip' => $realIP,
                        'original' => $ip,
                    ]);
                }
            }
        }

        // 如果没有从信任头中获取到有效IP，返回原始IP
        return $request->ip();
    }

    /**
     * 检查请求是否来自信任代理
     */
    private static function isFromTrustedProxy(\Illuminate\Http\Request $request, array $trustedProxies): bool
    {
        $remoteIP = $request->ip();

        foreach ($trustedProxies as $proxy) {
            // 如果是CIDR，检查是否在范围内
            if (str_contains($proxy, '/')) {
                if (self::ipInRange($remoteIP, $proxy)) {
                    return true;
                }
            } else {
                // 直接比较IP
                if ($remoteIP === $proxy) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 标准化IP地址
     *
     * 将IPv6的压缩格式展开为完整格式
     */
    public static function normalizeIP(string $ip): string
    {
        if (!self::isValidIP($ip)) {
            return $ip;
        }

        if (self::isValidIPv4($ip)) {
            return $ip;
        }

        // 处理IPv6
        $binary = inet_pton($ip);
        if ($binary === false) {
            return $ip;
        }

        return inet_ntop($binary);
    }

    /**
     * 比较两个IP地址是否相同（标准化后）
     */
    public static function compareIP(string $ip1, string $ip2): bool
    {
        return self::normalizeIP($ip1) === self::normalizeIP($ip2);
    }
}
