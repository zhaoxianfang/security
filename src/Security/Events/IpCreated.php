<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP记录创建事件
 *
 * 当新的IP记录被创建时触发
 */
class IpCreated
{
    use Dispatchable, SerializesModels;

    /**
     * 创建新的事件实例
     */
    public function __construct(
        public SecurityIp $ip
    ) {}
}
