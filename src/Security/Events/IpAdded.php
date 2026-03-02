<?php

namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use zxf\Security\Models\SecurityIp;

/**
 * IP添加事件
 *
 * 当IP被添加到白名单/黑名单/可疑列表时触发
 * 
 * 注意：此事件不使用队列，直接同步触发
 */
class IpAdded
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
