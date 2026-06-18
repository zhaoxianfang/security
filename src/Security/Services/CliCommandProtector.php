<?php

namespace zxf\Security\Services;

use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Helper\QuestionHelper;

/**
 * CLI 命令保护器 — Laravel / ThinkPHP 共享实现
 *
 * 统一抽取两个框架 Provider 中重复的 CLI 命令保护逻辑，
 * 实现配置驱动的危险命令识别、排除、交互确认和阻断。
 *
 * 设计原则：
 *  - 零框架依赖：仅依赖 Symfony Console + PHP 标准库
 *  - 配置驱动：所有危险命令清单、排除列表、模式均由 config 控制
 *  - 交互优先：默认 confirm 模式，CI/CD 自动拒绝
 *
 * @package zxf\Security\Services
 * @since 6.5.0
 */
class CliCommandProtector
{
    /**
     * 配置数组缓存
     */
    private array $config;

    /**
     * @param array $config 安全配置数组（security.*）
     */
    public function __construct(array $config)
    {
        $this->config = $config;
    }

    // ═══════════════════════════════════════════════════════════════
    // 公共入口（由 Provider 调用）
    // ═══════════════════════════════════════════════════════════════

    /**
     * 检查 CLI 命令是否应被拦截或确认
     *
     * @param string $commandName 命令名称（如 "migrate:fresh"）
     * @param string $appEnv 当前 APP_ENV 值
     * @param object|null $input Symfony Console InputInterface（可选）
     * @param object|null $output Symfony Console OutputInterface（可选）
     * @return CliResult 处理结果
     */
    public function check(string $commandName, string $appEnv, ?object $input = null, ?object $output = null): CliResult
    {
        if ($commandName === '') {
            return CliResult::pass();
        }

        // 步骤 1：子开关
        $dbConfig = $this->config['database_operation'] ?? [];
        if (!($dbConfig['block_table_destruction'] ?? true)) {
            return CliResult::pass();
        }

        // 步骤 2：排除命令列表
        if ($this->isExcludedCommand($commandName)) {
            return CliResult::pass();
        }

        // 步骤 3：危险命令检查
        if (!$this->isDangerousCommand($commandName)) {
            return CliResult::pass();
        }

        // 步骤 4：环境检查
        if (!$this->shouldBlockInEnvironment($appEnv)) {
            return CliResult::pass();
        }

        // 步骤 5：CLI 模式决策
        $cliMode = $dbConfig['cli_mode'] ?? 'confirm';

        if ($cliMode === 'off') {
            return CliResult::pass();
        }

        if ($cliMode === 'block') {
            return CliResult::blocked($commandName, $appEnv);
        }

        // confirm 模式
        return CliResult::needsConfirmation($commandName, $appEnv);
    }

    // ═══════════════════════════════════════════════════════════════
    // 交互式确认
    // ═══════════════════════════════════════════════════════════════

    /**
     * 执行交互式确认（警告横幅 + 等待用户输入）
     *
     * @param string $commandName 命令名称
     * @param string $appEnv 当前环境
     * @param object|null $input Symfony Console InputInterface
     * @param object|null $output Symfony Console OutputInterface
     * @return bool true=用户确认继续，false=取消
     */
    public function confirm(string $commandName, string $appEnv, ?object $input = null, ?object $output = null): bool
    {
        // 输出警告横幅
        $this->renderWarningBanner($commandName, $appEnv, $output);

        // 交互确认
        $confirmed = $this->askForConfirmation($input, $output);

        // 输出结果
        if (!$confirmed) {
            $this->renderCancelledMessage($output);
            return false;
        }

        $this->renderProceedingMessage($output);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    // 阻断输出（block 模式）
    // ═══════════════════════════════════════════════════════════════

    /**
     * 输出阻断横幅（block 模式，不可交互）
     *
     * @param string $commandName 命令名称
     * @param string $appEnv 当前环境
     * @param object|null $output Symfony Console OutputInterface
     */
    public function renderBlockBanner(string $commandName, string $appEnv, ?object $output = null): void
    {
        $lines = [
            '',
            '╔══════════════════════════════════════════════════════════════╗',
            '║  🔐 Security Interception — Database Operation Blocked     ║',
            '╠══════════════════════════════════════════════════════════════╣',
            '║                                                            ║',
            '║  Command : ' . str_pad($commandName, 48) . '║',
            '║  Status  : BLOCKED                                         ║',
            '║  Env     : ' . str_pad($appEnv, 48) . '║',
            '║                                                            ║',
            '║  Reason : Database table destruction — irreversible.       ║',
            '║                                                            ║',
            '║  ── How to allow ──────────────────────────────────────    ║',
            '║                                                            ║',
            '║  1. Exclude this command in config/security.php:           ║',
            '║     \'exclude_commands\' => [\'' . $commandName . '\']               ║',
            '║                                                            ║',
            '║  2. Or switch to confirm mode:                            ║',
            '║     \'cli_mode\' => \'confirm\'                                ║',
            '║                                                            ║',
            '╚══════════════════════════════════════════════════════════════╝',
            '',
        ];

        $this->writeLines($lines, $output, 'error');
    }

    // ═══════════════════════════════════════════════════════════════
    // 内部方法
    // ═══════════════════════════════════════════════════════════════

    /**
     * 输出警告横幅
     */
    protected function renderWarningBanner(string $commandName, string $appEnv, ?object $output): void
    {
        $lines = [
            '',
            '╔══════════════════════════════════════════════════════════════╗',
            '║  ⚠️  Security Warning — Dangerous Database Operation        ║',
            '╠══════════════════════════════════════════════════════════════╣',
            '║                                                            ║',
            '║  Command : ' . str_pad($commandName, 48) . '║',
            '║  Env     : ' . str_pad($appEnv, 48) . '║',
            '║                                                            ║',
            '║  This command may cause irreversible data loss or schema   ║',
            '║  changes. Proceed only if you understand the consequences. ║',
            '║                                                            ║',
            '╚══════════════════════════════════════════════════════════════╝',
            '',
        ];

        $this->writeLines($lines, $output, 'error');
    }

    /**
     * 输出取消消息
     */
    protected function renderCancelledMessage(?object $output): void
    {
        $msg = 'Command cancelled. No changes were made.';
        if ($output) {
            $output->writeln('');
            $output->writeln("<comment>  ✗ {$msg}</comment>");
            $output->writeln('');
        } else {
            fwrite(STDERR, PHP_EOL . "  ✗ {$msg}" . PHP_EOL . PHP_EOL);
            fflush(STDERR);
        }
    }

    /**
     * 输出继续执行消息
     */
    protected function renderProceedingMessage(?object $output): void
    {
        $msg = '⚠️  User confirmed. Proceeding with caution...';
        if ($output) {
            $output->writeln('');
            $output->writeln("<comment>  {$msg}</comment>");
            $output->writeln('');
        } else {
            fwrite(STDERR, PHP_EOL . "  {$msg}" . PHP_EOL . PHP_EOL);
            fflush(STDERR);
        }
    }

    /**
     * 写入行（Console Output 或 STDERR 降级）
     */
    protected function writeLines(array $lines, ?object $output, string $tag = ''): void
    {
        if ($output) {
            if ($tag !== '') {
                foreach ($lines as $line) {
                    $output->writeln("<{$tag}>{$line}</{$tag}>");
                }
            } else {
                $output->writeln($lines);
            }
        } else {
            fwrite(STDERR, implode(PHP_EOL, $lines) . PHP_EOL);
            fflush(STDERR);
        }
    }

    /**
     * 交互式确认（Symfony Console 优先，降级到原始终端）
     */
    protected function askForConfirmation(?object $input, ?object $output): bool
    {
        if ($input && $output) {
            $helper = new QuestionHelper();

            $question = new ConfirmationQuestion(
                '<question>  Do you really wish to run this command? (yes/no) [no]:</question> ',
                false,
                '/^(?:yes|y)$/i'
            );

            if (!$input->isInteractive()) {
                if ($output->isVerbose()) {
                    $output->writeln('<comment>  Non-interactive mode detected. Command automatically rejected.</comment>');
                }
                return false;
            }

            return (bool) $helper->ask($input, $output, $question);
        }

        // 降级：原始终端读取
        fwrite(STDERR, '  Do you really wish to run this command? (yes/no) [no]: ');
        fflush(STDERR);

        if (PHP_OS_FAMILY !== 'Windows') {
            $tty = @fopen('/dev/tty', 'r');
            if ($tty) {
                $answer = fgets($tty);
                fclose($tty);
                return is_string($answer) && strtolower(trim($answer)) === 'yes';
            }
        }

        $answer = fgets(STDIN);
        return is_string($answer) && strtolower(trim($answer)) === 'yes';
    }

    // ═══════════════════════════════════════════════════════════════
    // 危险命令检查（配置驱动）
    // ═══════════════════════════════════════════════════════════════

    /**
     * 判断是否为配置中定义的危险命令
     *
     * 命令清单来源（优先级从高到低）：
     *   1. 用户配置: database_operation.dangerous_commands (支持 ['*'] 全匹配)
     *   2. 内置默认: getBuiltinDangerousCommands()
     *
     * 支持通配符：command:sub* 可匹配 command:sub-anything
     */
    public function isDangerousCommand(string $commandName): bool
    {
        $dbConfig = $this->config['database_operation'] ?? [];

        // 用户自定义清单优先
        $dangerousCommands = $dbConfig['dangerous_commands'] ?? null;

        if (is_array($dangerousCommands) && !empty($dangerousCommands)) {
            // ['*'] → 匹配所有命令
            if (in_array('*', $dangerousCommands, true)) {
                return true;
            }
            return $this->matchCommandList($commandName, $dangerousCommands);
        }

        // 回退到内置默认清单
        return $this->matchCommandList($commandName, $this->getBuiltinDangerousCommands());
    }

    /**
     * 获取内置危险命令默认清单（按等级分三级）
     *
     * @return array<string>
     */
    public function getBuiltinDangerousCommands(): array
    {
        return [
            // 🔴 最高危 — 模块/数据库不可逆删除
            'module:delete',
            // 🟠 高危 — 数据库表结构破坏
            'migrate:fresh', 'migrate:refresh', 'migrate:reset', 'migrate:rollback',
            'db:wipe', 'schema:dump',
            'module:migrate-refresh', 'module:migrate-fresh',
            'module:migrate-reset', 'module:migrate-rollback',
            // 🟡 中危 — 批量数据操作
            'module:migrate', 'module:seed', 'module:migrate-status',
        ];
    }

    /**
     * 匹配命令名与清单（支持精确匹配和通配符）
     */
    protected function matchCommandList(string $commandName, array $list): bool
    {
        $commandBase = strtolower(trim(strstr($commandName . ' ', ' ', true) ?: $commandName));

        foreach ($list as $item) {
            if (!is_string($item) || $item === '') {
                continue;
            }

            $item = strtolower(trim($item));

            // 精确匹配
            if ($commandBase === $item) {
                return true;
            }

            // 通配符匹配：command:* 或 command:sub*
            if (str_ends_with($item, '*')) {
                $prefix = rtrim($item, '*');
                if (str_starts_with($commandBase, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ═══════════════════════════════════════════════════════════════
    // 排除检查
    // ═══════════════════════════════════════════════════════════════

    /**
     * 检查命令是否在排除列表中
     */
    public function isExcludedCommand(string $commandName): bool
    {
        $dbConfig = $this->config['database_operation'] ?? [];
        $excludeCommands = $dbConfig['exclude_commands'] ?? [];

        if (empty($excludeCommands)) {
            return false;
        }

        $lowerCommand = strtolower($commandName);
        foreach ($excludeCommands as $excludedCmd) {
            if (is_string($excludedCmd) && $excludedCmd !== ''
                && str_contains($lowerCommand, strtolower($excludedCmd))) {
                return true;
            }
        }

        return false;
    }

    // ═══════════════════════════════════════════════════════════════
    // 环境检查
    // ═══════════════════════════════════════════════════════════════

    /**
     * 检查当前环境是否应拦截 CLI 命令
     */
    public function shouldBlockInEnvironment(string $appEnv): bool
    {
        $dbConfig = $this->config['database_operation'] ?? [];
        $environments = $dbConfig['environments'] ?? [];

        if (empty($environments)) {
            $environments = ['production'];
        }

        // 'all' — 所有环境
        if (in_array('all', $environments, true)) {
            return true;
        }

        // 'cli' — 当前在 CLI 中始终匹配
        if (in_array('cli', $environments, true)) {
            return true;
        }

        // 具体环境名匹配
        $appEnv = strtolower($appEnv);
        foreach ($environments as $env) {
            if (!is_string($env) || $env === 'cli' || $env === 'all') {
                continue;
            }
            if (strtolower($env) === $appEnv) {
                return true;
            }
        }

        return false;
    }

    // ═══════════════════════════════════════════════════════════════
    // 环境包检测辅助
    // ═══════════════════════════════════════════════════════════════

    /**
     * 检查 CLI 保护是否应启用（双重门：主开关 OR 环境配置）
     */
    public static function isCliProtectionEnabled(array $config): bool
    {
        if (!($config['enabled'] ?? true)) {
            return false;
        }

        $dbEnabled = $config['detection_layers']['database_operation'] ?? false;
        $dbEnvironments = $config['database_operation']['environments'] ?? [];
        $hasEnvConfig = is_array($dbEnvironments) && !empty($dbEnvironments);

        return $dbEnabled || $hasEnvConfig;
    }
}
