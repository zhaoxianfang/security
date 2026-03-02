<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use zxf\Security\Models\SecurityIp;

/**
 * IP记录删除事件
 *
 * 当IP记录被删除时触发
 * 
 * 注意：此事件不使用队列，直接同步触发
 */
class IpDeleted
{
    use Dispatchable;

    /**
     * 创建新的事件实例
     * 
     * @param SecurityIp $ip IP记录模型
     */
    public function __construct(
        public SecurityIp $ip
    ) {}
}
