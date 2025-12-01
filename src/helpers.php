<?php

use zxf\Security\Services\ConfigManager;

if (! function_exists('security_config')) {
    /**
     * 获取安全包的配置
     * @return array|mixed
     */
    function security_config(?string $key = null, $default = null): mixed
    {
        return !empty($key) ? ConfigManager::instance()->get($key,$default) : ConfigManager::instance()->all();
    }
}
