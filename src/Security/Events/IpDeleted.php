<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP记录删除事件
 *
 * 当IP记录被删除时触发
 */
class IpDeleted
{
    use Dispatchable, SerializesModels;

    /**
     * 创建新的事件实例
     */
    public function __construct(
        public SecurityIp $ip
    ) {}
}
