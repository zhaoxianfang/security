<?php

namespace zxf\Security\Middleware\Concerns;

/**
 * 攻击模式检测
 *
 * 负责基于正则模式的攻击检测，包括：
 *  - URL 路径攻击（路径遍历、敏感文件泄露）
 *  - 高危攻击（SQL注入、命令注入、SSTI、SSRF 等 10 类）
 *  - XSS 攻击（脚本注入、DOM型、标签注入、编码绕过、框架特定）
 *
 * 支持 Markdown 智能旁路（通过 ManagesMarkdownSafety trait）。
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 */
trait DetectsAttackPatterns
{
    // ==================== URL 路径攻击检测 ====================

    /**
     * 检测URL路径和查询参数中的攻击
     * 专门检测路径遍历等直接出现在URL路径或查询参数中的攻击
     *
     * 优化：使用 PatternService 延迟加载模式，减少内存占用
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return bool true=检测到攻击，false=正常
     */
    protected function detectUrlPathAttacks(\Illuminate\Http\Request $request): bool
    {
        $excludeRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules_exclude'] ?? []);
        $interceptRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules'] ?? []);

        // 从 PatternService 获取模式（延迟加载 + 统一排除/追加规则）
        $pathPatterns = $this->patternService->getUrlPathPatterns($excludeRules, $interceptRules);

        if (empty($pathPatterns)) {
            return false;
        }

        // 收集所有需要检查的来源
        $checkSources = [];

        // 1. URL路径（原始和解码）— 先截断防止超长 URL 消耗内存
        $url = $this->truncateInput($request->fullUrl());
        $checkSources['url'] = [$url, urldecode($url)];

        // 2. 路由参数（含解码变形）
        $routeParams = $request->route()?->parameters() ?? [];
        $this->collectParamsForCheck($routeParams, $checkSources, 'route');

        // 3. 查询参数值（独立检查每个参数值，避免仅依赖 fullUrl 整体匹配）
        $queryParams = $request->query() ?? [];
        $this->collectParamsForCheck($queryParams, $checkSources, 'query');

        // 检查所有来源
        foreach ($checkSources as $_source => $strings) {
            foreach ($strings as $checkString) {
                if (!is_string($checkString) || empty($checkString)) {
                    continue;
                }

                // 对每个来源字符串截断后再检查，防止超长参数绕过
                $checkString = $this->truncateInput($checkString);

                foreach ($pathPatterns as $item) {
                    if ($this->safePregMatch($item['pattern'], $checkString)) {
                        $this->lastMatchedPattern = $item['pattern'];
                        $this->lastMatchedContent = mb_substr($checkString, 0, 100);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 收集参数用于检查
     *
     * @param array $params 参数数组
     * @param array $checkSources 检查来源数组（引用）
     * @param string $prefix 前缀标识
     * @return void
     */
    protected function collectParamsForCheck(array $params, array &$checkSources, string $prefix, int $depth = 0): void
    {
        // 防御：限制递归深度，防止攻击者发送超深嵌套数组导致栈溢出
        if ($depth > 10) {
            return;
        }

        foreach ($params as $key => $value) {
            if (is_string($value)) {
                // 原始值（截断防止超长输入消耗内存）
                $truncated = $this->truncateInput($value);
                $checkSources[$prefix . '.' . $key][] = $truncated;
                // 解码后的值
                $decoded = urldecode($truncated);
                $checkSources[$prefix . '.' . $key][] = $decoded;
                // 双重解码
                $checkSources[$prefix . '.' . $key][] = urldecode($decoded);
            } elseif (is_array($value)) {
                // 递归处理数组
                $this->collectParamsForCheck($value, $checkSources, $prefix . '.' . $key, $depth + 1);
            }
        }
    }

    // ==================== 高危攻击检测 ====================

    /**
     * 检测高危攻击
     *
     * 优化说明：
     * 1. 使用 PatternService 延迟加载模式，减少内存占用
     * 2. 对输入执行预过滤（str_contains），快速跳过不相关模式组
     * 3. 按攻击类型分组预检，避免无意义的正则匹配
     * 4. 支持 Markdown 内容智能识别 — 文档中的 SQL/命令代码示例可豁免
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function detectHighRiskAttacks(\Illuminate\Http\Request $request): ?string
    {
        $excludeRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules_exclude'] ?? []);
        $interceptRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules'] ?? []);

        // 从 PatternService 获取模式（延迟加载 + 统一排除/追加规则）
        $patterns = $this->patternService->getHighRiskPatterns($excludeRules, $interceptRules);

        if (empty($patterns)) {
            return null;
        }

        // 如果开放重定向检测被关闭，从模式中移除 redirect 类型
        // 避免误报：多数应用中 redirect_uri/callback 参数是正常的业务行为
        if (!($this->config['detection_layers']['redirect'] ?? false)) {
            unset($patterns['redirect']);
            if (empty($patterns)) {
                return null;
            }
        }

        // 1. 首先检查URL路径（重要：路径遍历攻击通常直接出现在URL中）
        $urlPath = $request->path();

        // 路径遍历预过滤：仅当包含 ../ 或 %2e 时才检查 path 类型
        $lowerPath = strtolower($urlPath);
        if (str_contains($lowerPath, '..') || str_contains($lowerPath, '%2e')) {
            $pathResult = $this->checkPatternsAgainstInput($patterns, $urlPath, ['path']);
            if ($pathResult !== null) {
                return $pathResult;
            }
        }

        // 2. 检查完整URL（包含查询字符串）— 全量检测（使用 redirect 策略1模式）
        $fullUrl = $this->truncateInput($request->fullUrl());
        $urlResult = $this->checkPatternsAgainstInput($patterns, $fullUrl);
        if ($urlResult !== null) {
            return $urlResult;
        }

        // 3. 针对性地检查 URL 类参数（redirect_uri/callback/url/webhook 等）→ SSRF/重定向
        //    使用 redirect 策略2-7 和 ssrf 模式匹配解码后的参数值
        $urlParamResult = $this->checkUrlParamsForSsrRedirect($patterns, $request);
        if ($urlParamResult !== null) {
            return $urlParamResult;
        }

        // 4. 独立检查每个查询/POST参数值（防止攻击载荷被稀释在各来源中）
        $individualResult = $this->checkIndividualParamsForHighRisk($patterns, $request);
        if ($individualResult !== null) {
            return $individualResult;
        }

        // 5. 检查请求输入数据（支持 Markdown 智能识别旁路）
        $input = $this->getInputString($request, false);
        $input = $this->truncateInput($input);

        $inputResult = $this->checkHighRiskInputWithMarkdownBypass($patterns, $input);
        if ($inputResult !== null) {
            return $inputResult;
        }

        return null;
    }

    /**
     * 检查输入字符串是否匹配攻击模式
     *
     * 优化：支持按类型预过滤，减少不必要的正则匹配
     *
     * @param array $patterns 攻击模式数组
     * @param string $input 输入字符串
     * @param array|null $limitTypes 限制检查的类型（null=检查全部）
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkPatternsAgainstInput(array $patterns, string $input, ?array $limitTypes = null): ?string
    {
        if (empty($input)) {
            return null;
        }

        $types = $limitTypes ?? array_keys($patterns);

        foreach ($types as $type) {
            // 跳过不存在的类型
            if (!isset($patterns[$type])) {
                continue;
            }

            // 预过滤优化：通过 str_contains 快速跳过不相关的模式组
            if (!$this->patternService->preFilter($type, $input)) {
                continue;
            }

            foreach ($patterns[$type] as $item) {
                $pattern = $item['pattern'];
                $matches = [];
                if ($this->safePregMatch($pattern, $input, $matches)) {
                    $this->threats[] = $type;
                    $this->lastMatchedPattern = $pattern;
                    $this->lastMatchedContent = $this->sanitizeMatchedContent($matches[0] ?? '');
                    return $type;
                }
            }
        }

        return null;
    }

    /**
     * 针对性地检查 URL 类参数中的 SSRF/重定向攻击
     *
     * 提取查询参数和请求体中包含 http(s)/ftp/等 URL 的值，
     * 单独用 SSRF 和 redirect 模式检查，避免被无关输入稀释。
     *
     * 目标参数名匹配：redirect_uri, callback, url, webhook, notify_url,
     * return, next, target, link, goto, continue 等
     *
     * 双层检查策略：
     *  1. 完整查询串 → redirect 策略1（参数名+URL整体模式）
     *  2. 解码后的参数值 → redirect 策略2-7 + ssrf 模式
     *
     * @param array $patterns 攻击模式数组
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkUrlParamsForSsrRedirect(array $patterns, \Illuminate\Http\Request $request): ?string
    {
        // 仅当 SSRF 或 redirect 检测类型存在时才执行
        $availableTypes = array_intersect(['ssrf', 'redirect'], array_keys($patterns));
        if (empty($availableTypes)) {
            return null;
        }

        // URL类参数的常见名称（不区分大小写）
        $urlParamNames = [
            'redirect_uri', 'redirect_url', 'redirect', 'redirect_to',
            'callback', 'callback_url', 'return_url', 'return', 'return_to',
            'url', 'target_url', 'link', 'goto', 'next', 'continue',
            'webhook', 'webhook_url', 'notify_url', 'notify',
            'forward', 'dest', 'destination', 'ref', 'referer', 'referrer',
            'origin', 'source_url', 'image_url', 'img_url',
        ];

        // 收集所有参数值（含解码变形）— 逐来源遍历避免 array_merge 复制大 POST 数组
        $urlValues = [];

        foreach ([$request->query() ?? [], $request->post() ?? []] as $source) {
            foreach ($source as $key => $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                $isUrlParam = in_array(strtolower($key), $urlParamNames, true);

                // 解码变体：1次解码、2次解码
                $decoded1 = urldecode($value);
                $decoded2 = urldecode($decoded1);

                // 检查解码后是否包含 URL 特征
                $candidates = [];
                if ($this->isUrlLike($value) || $isUrlParam) {
                    $candidates[] = $this->truncateInput($decoded1);
                }
                if ($decoded2 !== $decoded1 && ($this->isUrlLike($decoded2) || $isUrlParam)) {
                    $candidates[] = $this->truncateInput($decoded2);
                }

                foreach ($candidates as $candidate) {
                    $urlValues[] = [
                        'value' => $candidate,
                        'param' => $key,
                        'isUrlParam' => $isUrlParam,
                    ];
                }
            }
        }

        if (empty($urlValues)) {
            return null;
        }

        // 按优先级检查
        foreach ($urlValues as $item) {
            // URL类参数名 → 同时检查 redirect + ssrf（使用策略2-7模式）
            // 非URL类参数名 → 仅检查 ssrf（内网IP/危险协议等）
            $targetTypes = $item['isUrlParam']
                ? $availableTypes  // redirect + ssrf
                : array_values(array_intersect(['ssrf'], $availableTypes));

            if (empty($targetTypes)) {
                continue;
            }

            $result = $this->checkPatternsAgainstInput($patterns, $item['value'], $targetTypes);
            if ($result !== null) {
                return $result;
            }
        }

        return null;
    }

    /**
     * 判断一个值是否包含 URL（http/https/ftp/gopher/file/dict 协议）或协议省略型
     *
     * @param string $value 要检查的值
     * @return bool
     */
    protected function isUrlLike(string $value): bool
    {
        // 先解码再截断，避免截断破坏 URL 编码序列（如 %3A 被截成 %3）
        $decoded = $this->truncateInput(urldecode($value));
        // 检测完整协议头 或 // 协议省略型
        return $this->safePregMatch('#\b(?:https?|ftp|gopher|dict|file)://#i', $decoded)
            || $this->safePregMatch('#^//[a-z0-9]#i', $decoded);
    }

    /**
     * 独立检查每个查询/POST参数值中是否包含高危攻击模式
     *
     * 与合并输入检测互补：合并检测识别上下文关联的攻击（如完整SQL语句），
     * 本方法确保单个参数中的攻击载荷不被合并后的其他数据稀释。
     *
     * 适用类型：sql, command, encoding, ssti, nosql, xml, ldap, file_include, path
     * 不适用：redirect, ssrf（由 checkUrlParamsForSsrRedirect 专门处理）
     *         header_injection（由 HTTP 头检查专门处理）
     *
     * 注意：path 类型同时由 detectUrlPathAttacks 和本方法检查，形成防御纵深。
     *       即使 url_path 检测层被关闭，高危检测层仍能拦截 query string 中的
     *       .php/.asp/.jsp 等脚本扩展名和路径遍历。
     *
     * @param array $patterns 攻击模式数组
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkIndividualParamsForHighRisk(array $patterns, \Illuminate\Http\Request $request): ?string
    {
        // 需要独立检查的类型（不与合并输入混淆）
        // path 类型也包含在内：防止 url_path 检测层关闭后，query string 中的
        // .php/.asp/.jsp 等脚本扩展名和路径遍历被绕过（防御纵深）
        $checkTypes = array_intersect(
            ['sql', 'command', 'encoding', 'ssti', 'nosql', 'xml', 'ldap', 'file_include', 'path'],
            array_keys($patterns)
        );

        if (empty($checkTypes)) {
            return null;
        }

        // 收集所有参数值并解码 — 逐来源遍历避免 array_merge 复制大数组
        foreach ([$request->query() ?? [], $request->post() ?? [], $request->route()?->parameters() ?? []] as $source) {
            foreach ($source as $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                $candidates = [
                    $value,                    // 原始值
                    urldecode($value),         // 解码1次
                    urldecode(urldecode($value)), // 解码2次
                ];

                foreach (array_unique($candidates) as $candidate) {
                    $candidate = $this->truncateInput($candidate);

                    // 预过滤：快速跳过不可能的类型
                    $activeTypes = [];
                    foreach ($checkTypes as $type) {
                        if ($this->patternService->preFilter($type, $candidate)) {
                            $activeTypes[] = $type;
                        }
                    }

                    if (empty($activeTypes)) {
                        continue;
                    }

                    $result = $this->checkPatternsAgainstInput($patterns, $candidate, $activeTypes);
                    if ($result !== null) {
                        return $result;
                    }
                }
            }
        }

        return null;
    }

    /**
     * 检查高危攻击输入（含 Markdown 智能识别旁路）
     *
     * 当启用 Markdown 旁路且输入被识别为 Markdown 文档时，
     * 单独处理代码块中的教学示例（SQL/命令等），避免误报。
     *
     * 策略：
     *  1. 非旁路类型 → 始终全量检测
     *  2. 旁路类型（sql/command/path 等）→ 先移除代码块再检测
     *
     * @param array $patterns 攻击模式数组
     * @param string $input 输入字符串
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkHighRiskInputWithMarkdownBypass(array $patterns, string $input): ?string
    {
        if (empty($input)) {
            return null;
        }

        // 检查是否需要 Markdown 危险代码旁路
        if (!$this->shouldBypassMarkdownDangerousCode($input)) {
            // 正常全量检测
            return $this->checkPatternsAgainstInput($patterns, $input);
        }

        // === Markdown 旁路模式 ===
        $bypassTypes = $this->getMarkdownBypassTypes();
        $allTypes = array_keys($patterns);
        $nonBypassTypes = array_values(array_diff($allTypes, $bypassTypes));

        // 第一步：检查非旁路类型（SSRF/编码绕过/Header注入 等始终检测）
        if (!empty($nonBypassTypes)) {
            $result = $this->checkPatternsAgainstInput($patterns, $input, $nonBypassTypes);
            if ($result !== null) {
                return $result;
            }
        }

        // 第二步：对旁路类型，移除代码块后再检测
        if (!empty($bypassTypes)) {
            $cleanInput = $this->removeMarkdownCodeBlocks($input);
            // 仅当移除代码块后内容发生变化时才重新检测
            if ($cleanInput !== $input && !empty(trim($cleanInput))) {
                // 只保留实际存在于 patterns 中的旁路类型
                $availableBypassTypes = array_values(array_intersect($bypassTypes, $allTypes));
                if (!empty($availableBypassTypes)) {
                    return $this->checkPatternsAgainstInput($patterns, $cleanInput, $availableBypassTypes);
                }
            }
        }

        return null;
    }

    // ==================== XSS 攻击检测 ====================

    /**
     * 检测XSS攻击
     *
     * 优化说明：
     * 1. 使用 PatternService 延迟加载模式
     * 2. 对每种 XSS 类型进行预过滤，快速跳过不相关输入
     * 3. 独立检查每个参数值（防止载荷在合并输入中被稀释）
     *
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function detectXssAttacks(\Illuminate\Http\Request $request): ?string
    {
        $excludeRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules_exclude'] ?? []);
        $interceptRules = \zxf\Security\Patterns\PatternService::resolveRules($this->config['intercept_rules'] ?? []);

        // 从 PatternService 获取模式（延迟加载 + 统一排除/追加规则）
        $patterns = $this->patternService->getXssPatterns($excludeRules, $interceptRules);

        if (empty($patterns)) {
            return null;
        }

        // 1. 检查URL路径（反射型XSS常出现在URL中）
        $urlPath = urldecode($this->truncateInput($request->path()));
        $urlPathResult = $this->checkXssPatterns($patterns, $urlPath, $urlPath);
        if ($urlPathResult !== null) {
            return $urlPathResult;
        }

        // 2. 检查查询字符串（整体）
        $queryString = urldecode($this->truncateInput($request->getQueryString() ?? ''));
        $queryResult = $this->checkXssPatterns($patterns, $queryString, $queryString);
        if ($queryResult !== null) {
            return $queryResult;
        }

        // 3. 独立检查每个查询/POST/路由参数值（防止载荷稀释）
        $individualResult = $this->checkIndividualParamsForXss($patterns, $request);
        if ($individualResult !== null) {
            return $individualResult;
        }

        // 4. 检查请求体输入（合并后，含 Markdown 旁路）
        $rawInput = $this->getInputString($request, false);
        $cleanInput = $this->getInputString($request, true);

        // 限制输入长度
        $rawInput = $this->truncateInput($rawInput);
        $cleanInput = $this->truncateInput($cleanInput);

        $inputResult = $this->checkXssPatterns($patterns, $cleanInput, $rawInput);
        if ($inputResult !== null) {
            return $inputResult;
        }

        return null;
    }

    /**
     * 检查XSS攻击模式
     *
     * 优化：使用预过滤快速跳过不相关的 XSS 类型
     * 支持 Markdown 智能识别 — 文档中的脚本代码示例可豁免
     *
     * @param array $patterns XSS模式数组
     * @param string $input 要检查的输入（已清理代码块）
     * @param string $rawInput 原始输入（含代码块，用于Markdown检测）
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function checkXssPatterns(array $patterns, string $input, string $rawInput): ?string
    {
        if (empty($input)) {
            return null;
        }

        $markdownConfig = $this->config['markdown'] ?? [];
        $smartDetection = $markdownConfig['smart_detection'] ?? true;
        $allowScriptInMarkdown = $markdownConfig['allow_script_in_markdown'] ?? false;

        foreach ($patterns as $type => $typePatterns) {
            // 预过滤优化：快速跳过不相关的 XSS 类型
            if (!$this->patternService->preFilter('xss_' . $type, $input)) {
                continue;
            }

            foreach ($typePatterns as $item) {
                $pattern = $item['pattern'];
                $matches = [];
                if ($this->safePregMatch($pattern, $input, $matches)) {
                    // Markdown 智能识别旁路：仅在明确开启时生效
                    if ($smartDetection && $allowScriptInMarkdown) {
                        if ($this->isLikelyMarkdownContent($rawInput, $pattern)) {
                            continue;
                        }
                    }

                    $threatType = 'xss_' . $type;
                    $this->threats[] = $threatType;
                    $this->lastMatchedPattern = $pattern;
                    $this->lastMatchedContent = $this->sanitizeMatchedContent($matches[0] ?? '');
                    return $threatType;
                }
            }
        }

        return null;
    }

    /**
     * 独立检查每个查询/POST/路由参数值中是否包含 XSS 攻击模式
     *
     * 与合并输入检测互补：合并检测识别跨参数关联的 XSS 攻击，
     * 本方法确保单个参数中的 XSS 载荷不被合并后的数据稀释。
     *
     * 覆盖所有 XSS 类型：script, dom, tag, encoding, framework
     *
     * @param array $patterns XSS 模式数组（按类型分组）
     * @param \Illuminate\Http\Request $request HTTP请求对象
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function checkIndividualParamsForXss(array $patterns, \Illuminate\Http\Request $request): ?string
    {
        if (empty($patterns)) {
            return null;
        }

        $allTypes = array_keys($patterns);
        if (empty($allTypes)) {
            return null;
        }

        // 收集所有参数值并解码 — 逐来源遍历避免 array_merge 复制大数组
        foreach ([$request->query() ?? [], $request->post() ?? [], $request->route()?->parameters() ?? []] as $source) {
            foreach ($source as $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                // 多级解码：原始 → 1次解码 → 2次解码
                $candidates = array_unique([
                    $value,
                    urldecode($value),
                    urldecode(urldecode($value)),
                ]);

                foreach ($candidates as $candidate) {
                    $candidate = $this->truncateInput($candidate);

                    // 预过滤：快速跳过不相关的 XSS 类型
                    $activeTypes = [];
                    foreach ($allTypes as $type) {
                        if ($this->patternService->preFilter('xss_' . $type, $candidate)) {
                            $activeTypes[] = $type;
                        }
                    }

                    if (empty($activeTypes)) {
                        continue;
                    }

                    // 对每个活跃类型检查模式
                    foreach ($activeTypes as $type) {
                        if (!isset($patterns[$type])) {
                            continue;
                        }

                        foreach ($patterns[$type] as $item) {
                            $pattern = $item['pattern'];
                            $matches = [];
                            if ($this->safePregMatch($pattern, $candidate, $matches)) {
                                $threatType = 'xss_' . $type;
                                $this->threats[] = $threatType;
                                $this->lastMatchedPattern = $pattern;
                                $this->lastMatchedContent = $this->sanitizeMatchedContent($matches[0] ?? '');
                                return $threatType;
                            }
                        }
                    }
                }
            }
        }

        return null;
    }
}
