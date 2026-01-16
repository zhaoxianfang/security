<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP类型变更事件
 *
 * 当IP类型自动转换时触发（如 monitoring -> suspicious -> blacklist）
 */
class IpTypeChanged
{
    use Dispatchable, SerializesModels;

    /**
     * 创建新的事件实例
     */
    public function __construct(
        public SecurityIp $ip,
        public string $oldType = '',
        public string $newType = ''
    ) {}
}
