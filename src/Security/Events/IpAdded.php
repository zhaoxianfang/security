<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP添加事件
 *
 * 当IP被添加到白名单/黑名单/可疑列表时触发
 */
class IpAdded
{
    use Dispatchable, SerializesModels;

    /**
     * 创建新的事件实例
     */
    public function __construct(
        public SecurityIp $ip
    ) {}
}
