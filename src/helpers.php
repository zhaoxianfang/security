<?php

/**
 * zxf/security 辅助函数
 *
 * 本文件提供了一系列便捷的全局函数，用于：
 * 1. 安全事件日志记录
 * 2. IP地址类型判断
 * 3. CIDR网段匹配
 *
 * 这些函数可在应用任何地方调用，无需引入额外命名空间。
 */

use zxf\Security\Bridge\FrameworkBridge;

// ==================== 日志记录函数 ====================

if (!function_exists('security_log')) {
    /**
     * 记录安全事件日志
     *
     * 将安全相关事件记录到框架日志系统，便于后续分析和审计。
     * 日志级别为 WARNING，可通过通道过滤快速定位安全事件。
     *
     * 跨框架兼容：通过 FrameworkBridge 自动适配 Laravel 或 ThinkPHP 日志系统。
     *
     * 使用场景：
     * - 记录自定义安全检查的结果
     * - 标记可疑用户行为
     * - 审计关键操作（如登录、权限变更）
     *
     * @param string $type    事件类型标识符，如 'brute_force'、'data_leak'、'privilege_escalation'
     * @param string $message 人类可读的日志消息
     * @param array  $context 额外的上下文信息，如用户ID、IP地址、操作对象等
     * @return void
     *
     * @example
     * // 记录暴力破解尝试
     * security_log('brute_force', '多次登录失败', [
     *     'ip' => $request->ip(),
     *     'username' => $request->username,
     *     'attempts' => 5,
     * ]);
     *
     * @example
     * // 记录数据导出操作
     * security_log('data_export', '批量导出用户数据', [
     *     'operator_id' => auth()->id(),
     *     'record_count' => 1000,
     *     'ip' => $request->ip(),
     * ]);
     */
    function security_log(string $type, string $message, array $context = []): void
    {
        try {
            // 检查日志功能是否启用（通过配置控制）
            if (!FrameworkBridge::config('security.log_enabled', true)) {
                return;
            }

            // 尝试获取当前请求对象，自动补充请求信息
            // 兼容 Laravel (request()) 和 ThinkPHP (\think\facade\Request::instance())
            $request = null;
            if (function_exists('request')) {
                $request = request();
            } elseif (class_exists('think\facade\Request')) {
                $request = \think\facade\Request::instance();
            }

            // 构建日志数据
            $logData = array_merge([
                'type' => $type,
                'ip' => $request ? (FrameworkBridge::requestIp($request) ?? 'unknown') : 'unknown',
                'url' => $request ? FrameworkBridge::requestFullUrl($request) : '',
                'method' => $request ? FrameworkBridge::requestMethod($request) : 'CLI',
                'user_agent' => $request ? substr(FrameworkBridge::requestUserAgent($request) ?? '', 0, 200) : null,
            ], $context);

            // 记录到框架日志，使用 WARNING 级别便于区分
            FrameworkBridge::logWarning("[Security] {$type}: {$message}", $logData);
        } catch (\Throwable) {
            // CLI 模式下日志驱动异常（如磁盘满、syslog 不可用）不应阻断业务流程。
            // 静默降级：安全日志失败不是致命错误，继续执行。
        }
    }
}

// ==================== IP 地址判断函数 ====================

if (!function_exists('is_intranet_ip')) {
    /**
     * 检查IP地址是否为内网/私有地址
     *
     * 根据 RFC1918 标准判断IP是否属于私有地址空间。
     * 内网IP通常无需严格的安全检查，可提高性能并减少误报。
     *
     * 判定范围：
     * - 10.0.0.0/8      (A类私网，约1677万个地址)
     * - 172.16.0.0/12   (B类私网，约104万个地址)
     * - 192.168.0.0/16  (C类私网，约6.5万个地址)
     * - 127.0.0.0/8     (本地回环)
     * - 169.254.0.0/16  (链路本地/APIPA)
     *
     * @param string $ip 要检查的IP地址（IPv4或IPv6）
     * @return bool true=内网IP，false=公网IP
     *
     * @example
     * // 检查当前请求是否来自内网
     * if (is_intranet_ip(request()->ip())) {
     *     // 内网访问，跳过某些限制
     * }
     *
     * @example
     * // 检查特定IP
     * $isInternal = is_intranet_ip('192.168.1.50'); // true
     * $isInternal = is_intranet_ip('8.8.8.8');      // false
     */
    function is_intranet_ip(string $ip): bool
    {
        // 本地回环地址快速检查
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return true;
        }

        // IPv4 私有地址段（RFC1918）
        $privateRanges = [
            '10.0.0.0/8',        // A类私网
            '172.16.0.0/12',     // B类私网
            '192.168.0.0/16',    // C类私网
            '127.0.0.0/8',       // 本地回环
            '169.254.0.0/16',    // 链路本地（APIPA）
        ];

        // 逐一检查是否匹配任一私有网段
        foreach ($privateRanges as $range) {
            if (ip_in_cidr($ip, $range)) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('ip_in_cidr')) {
    /**
     * 检查IP地址是否在CIDR范围内
     *
     * CIDR（无类别域间路由）表示法如 192.168.1.0/24
     * 本函数支持IPv4和IPv6的精确匹配和网段匹配。
     *
     * 算法原理：
     * IPv4: 将IP地址转换为32位整数，计算掩码并比较
     * IPv6: 使用 inet_pton 转换为二进制，按位比较
     *
     * 性能说明：
     * - 精确匹配：O(1)字符串比较
     * - CIDR匹配：O(1)位运算，极快
     *
     * @param string $ip    要检查的IP地址（IPv4或IPv6）
     * @param string $cidr  CIDR范围，如 '192.168.1.0/24' 或单个IP '192.168.1.100'
     * @return bool true=IP在范围内，false=不在范围内
     *
     * @example
     * // IPv4 CIDR网段匹配
     * $inRange = ip_in_cidr('192.168.1.50', '192.168.1.0/24'); // true
     * $inRange = ip_in_cidr('192.168.2.1', '192.168.1.0/24');  // false
     *
     * @example
     * // IPv6 CIDR网段匹配
     * $inRange = ip_in_cidr('2001:db8::1', '2001:db8::/32'); // true
     *
     * @example
     * // 精确匹配（不含斜杠）
     * $inRange = ip_in_cidr('192.168.1.100', '192.168.1.100'); // true
     * $inRange = ip_in_cidr('192.168.1.100', '192.168.1.101'); // false
     *
     * @example
     * // 批量检查IP列表
     * $allowedRanges = ['192.168.0.0/16', '10.0.0.0/8'];
     * $clientIp = request()->ip();
     * $isAllowed = collect($allowedRanges)->some(fn($range) => ip_in_cidr($clientIp, $range));
     */
    function ip_in_cidr(string $ip, string $cidr): bool
    {
        // 不含斜杠：视为精确IP匹配
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        // 解析CIDR：分割网络地址和前缀长度
        [$subnet, $prefixLength] = explode('/', $cidr);
        $prefixLength = (int) $prefixLength;

        // IPv6处理
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);

            if ($ipBin === false || $subnetBin === false) {
                return false;
            }

            if (strlen($ipBin) !== 16 || strlen($subnetBin) !== 16) {
                return false;
            }

            $fullBytes = intdiv($prefixLength, 8);
            $remainingBits = $prefixLength % 8;

            for ($i = 0; $i < $fullBytes; $i++) {
                if ($ipBin[$i] !== $subnetBin[$i]) {
                    return false;
                }
            }

            if ($remainingBits > 0 && $fullBytes < 16) {
                $mask = 0xFF << (8 - $remainingBits);
                if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($subnetBin[$fullBytes]) & $mask)) {
                    return false;
                }
            }

            return true;
        }

        // IPv4处理
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // 将IP地址转换为32位长整数
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);

            // 转换失败检查（无效IP）
            if ($ipLong === false || $subnetLong === false) {
                return false;
            }

            // 防御 64 位 PHP 的 ip2long() 符号扩展问题
            // 强制截断为无符号 32 位值，避免 >127.255.255.255 的 IP 匹配错误
            $ipLong = $ipLong & 0xFFFFFFFF;
            $subnetLong = $subnetLong & 0xFFFFFFFF;

            // 计算子网掩码
            // 例如 /24 对应掩码 0xFFFFFFFF << 8 = 0xFFFFFF00
            $mask = -1 << (32 - $prefixLength);

            // 将子网地址对齐到网络边界
            $subnetLong &= $mask;

            // 判断IP是否在同一网络
            return ($ipLong & $mask) === $subnetLong;
        }

        // 不支持的IP格式
        return false;
    }
}

// ==================== 扩展功能函数（可选） ====================

if (!function_exists('security_hash_ip')) {
    /**
     * 对IP地址进行匿名化处理
     *
     * 用于日志记录时保护用户隐私，符合GDPR等法规要求。
     * 使用HMAC-SHA256，需要配置密钥。
     *
     * @param string $ip IP地址
     * @return string 哈希值（前16位）
     *
     * @example
     * $hashed = security_hash_ip('192.168.1.100');
     * // 返回: a3f7b2d8...（可用于关联分析，但无法还原原始IP）
     */
    function security_hash_ip(string $ip): string
    {
        // 优先使用应用密钥；若未配置，使用随机生成的运行时密钥（每次进程不同），
        // 避免硬编码弱密钥导致哈希可被彩虹表破解。
        $key = FrameworkBridge::config('app.key');
        if (empty($key) || !is_string($key)) {
            $key = bin2hex(random_bytes(32));
        }

        $hash = hash_hmac('sha256', $ip, $key);
        return substr($hash, 0, 16);
    }
}

if (!function_exists('security_mask_ip')) {
    /**
     * 对IP地址进行掩码处理（保留网段信息）
     *
     * 用于日志展示，隐藏主机位，保留网络位。
     *
     * @param string $ip     IP地址
     * @param int    $prefix 保留的前缀长度（默认24，即保留前3段）
     * @return string 掩码后的IP，如 192.168.1.xxx
     *
     * @example
     * $masked = security_mask_ip('192.168.1.100');
     * // 返回: 192.168.1.xxx
     */
    function security_mask_ip(string $ip, int $prefix = 24): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip; // IPv6或未识别，原样返回
        }

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return $ip;
        }

        $mask = -1 << (32 - $prefix);
        $network = $ipLong & $mask;

        // 构建掩码字符串
        $segments = $prefix / 8;
        $octets = explode('.', long2ip($network));

        $result = [];
        for ($i = 0; $i < 4; $i++) {
            $result[] = $i < $segments ? $octets[$i] : 'xxx';
        }

        return implode('.', $result);
    }
}
