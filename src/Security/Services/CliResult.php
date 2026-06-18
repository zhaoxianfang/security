<?php

namespace zxf\Security\Services;

/**
 * CLI 命令检查结果 — 不可变值对象
 *
 * 由 CliCommandProtector::check() 返回，统一表达三种决策：
 *   - pass：放行，命令正常执行
 *   - blocked：阻断，不可交互（block 模式）
 *   - needsConfirmation：需要用户交互确认（confirm 模式）
 *
 * @package zxf\Security\Services
 * @since 6.5.0
 */
readonly class CliResult
{
    /**
     * @param string $action 动作：'pass' | 'blocked' | 'confirm'
     * @param string $commandName 命令名称
     * @param string $appEnv 当前环境
     */
    private function __construct(
        public string $action,
        public string $commandName = '',
        public string $appEnv = '',
    ) {
    }

    // ── 工厂方法 ──

    public static function pass(): self
    {
        return new self('pass');
    }

    public static function blocked(string $commandName, string $appEnv): self
    {
        return new self('blocked', $commandName, $appEnv);
    }

    public static function needsConfirmation(string $commandName, string $appEnv): self
    {
        return new self('confirm', $commandName, $appEnv);
    }

    // ── 状态查询 ──

    public function isPass(): bool
    {
        return $this->action === 'pass';
    }

    public function isBlocked(): bool
    {
        return $this->action === 'blocked';
    }

    /**
     * 判断结果是否为「需要用户交互确认」
     */
    public function isConfirm(): bool
    {
        return $this->action === 'confirm';
    }
}
