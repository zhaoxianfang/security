<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use zxf\Security\Models\SecurityIp;

/**
 * IP类型变更事件
 *
 * 当IP类型自动转换时触发（如 monitoring -> suspicious -> blacklist）
 * 
 * 注意：此事件不使用队列，直接同步触发
 */
class IpTypeChanged
{
    use Dispatchable;

    /**
     * 创建新的事件实例
     * 
     * @param SecurityIp $ip IP记录模型
     * @param string $oldType 原始类型
     * @param string $newType 新类型
     */
    public function __construct(
        public SecurityIp $ip,
        public string $oldType = '',
        public string $newType = ''
    ) {}
}
