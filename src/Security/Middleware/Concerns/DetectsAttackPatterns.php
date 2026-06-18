<?php

namespace zxf\Security\Middleware\Concerns;

use zxf\Security\Bridge\FrameworkBridge;

/**
 * 攻击模式检测
 *
 * 负责基于正则模式的攻击检测，包括：
 *  - URL 路径攻击（路径遍历、敏感文件泄露）
 *  - 高危攻击（SQL注入、命令注入、SSTI、SSRF 等 18 类）
 *  - XSS 攻击（脚本注入、DOM型、标签注入、编码绕过、框架特定）
 *
 * 支持 Markdown 智能旁路（通过 ManagesMarkdownSafety trait）。
 * 支持 JSON API 上下文感知旁路（减少 API 请求的 SQL/XSS 误报）。
 *
 * 跨框架兼容：所有方法接受 object 类型请求对象，内部通过 FrameworkBridge 统一访问。
 *
 * ══════════════════════════════════════════════════════════════════════
 * 宿主类依赖（由 SecurityMiddleware 提供）：
 *   - getExcludeRules(): array   — 获取缓存排除规则（惰性解析，请求级）
 *   - getInterceptRules(): array — 获取缓存追加规则（惰性解析，请求级）
 *   - truncateInput(): string    — 截断输入防止正则回溯
 *   - safePregMatch(): bool      — 安全正则匹配
 *   - sanitizeMatchedContent(): string — 脱敏处理匹配内容
 *   - getInputString(): string   — 扁平化获取请求输入
 *   - isJsonApiRequest(): bool  — 判断是否为JSON API请求
 *   - $this->config[][]: mixed   — 安全配置数组
 *   - $this->patternService: PatternService — 模式服务实例
 *   - $this->threats[]: array    — 检测到的威胁类型数组
 *   - $this->lastMatchedPattern: string — 最后匹配的模式
 *   - $this->lastMatchedContent: string — 最后匹配的内容
 *
 * @package zxf\Security\Middleware\Concerns
 * @since 5.4.0
 * @version 6.3.0
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
     * @param object $request HTTP请求对象
     * @return bool true=检测到攻击，false=正常
     */
    protected function detectUrlPathAttacks(object $request): bool
    {
        $excludeRules = $this->getExcludeRules();
        $interceptRules = $this->getInterceptRules();

        $pathPatterns = $this->patternService->getUrlPathPatterns($excludeRules, $interceptRules);

        if (empty($pathPatterns)) {
            return false;
        }

        $checkSources = [];

        // 1. URL路径（原始和解码）— 使用快速截断（框架返回值已是合法 UTF-8）
        $url = $this->truncateInputKnown(FrameworkBridge::requestFullUrl($request));
        $checkSources['url'] = [$url, $this->truncateInputKnown($this->cachedUrldecode($url, 1))];

        // 2. 路由参数（含解码变形）
        $routeParams = FrameworkBridge::requestRouteParams($request);
        $this->collectParamsForCheck($routeParams, $checkSources, 'route');

        // 3. 查询参数值
        $queryParams = FrameworkBridge::requestQuery($request);
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
        if ($depth > 10) {
            return;
        }

        foreach ($params as $key => $value) {
            if (is_string($value)) {
                $truncated = $this->truncateInput($value);
                $checkSources[$prefix . '.' . $key][] = $truncated;
                // 使用请求级缓存解码（避免同一请求重复 urldecode）
                $decoded = $this->truncateInput($this->cachedUrldecode($value, 1));
                $checkSources[$prefix . '.' . $key][] = $decoded;
                $doubleDecoded = $this->truncateInput($this->cachedUrldecode($value, 2));
                $checkSources[$prefix . '.' . $key][] = $doubleDecoded;
            } elseif (is_array($value)) {
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
     * @param object $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function detectHighRiskAttacks(object $request): ?string
    {
        // 使用缓存规则方法，避免同一请求中多次调用 ConfigResolver
        $excludeRules = $this->getExcludeRules();
        $interceptRules = $this->getInterceptRules();

        // 从 PatternService 获取模式（延迟加载 + 统一排除/追加规则）
        $patterns = $this->patternService->getHighRiskPatterns($excludeRules, $interceptRules);

        if (empty($patterns)) {
            return null;
        }

        // 根据 detection_layers 配置过滤已关闭的检测类型
        // 新类型默认开启（与 isDetectionEnabled 默认值一致），可通过配置关闭以减少特定场景误报
        $layerTypeMap = [
            'redirect' => 'redirect',
            'deserialization' => 'deserialization',
            'prototype_pollution' => 'prototype_pollution',
            'jndi' => 'jndi',
            'http_smuggling' => 'http_smuggling',
            'graphql' => 'graphql',
            'webshell' => 'webshell',
        ];
        foreach ($layerTypeMap as $layer => $type) {
            if (!($this->config['detection_layers'][$layer] ?? true)) {
                unset($patterns[$type]);
            }
        }
        if (empty($patterns)) {
            return null;
        }

        // 1. 首先检查URL路径（重要：路径遍历攻击通常直接出现在URL中）
        $urlPath = FrameworkBridge::requestPath($request);

        // 路径遍历预过滤：仅当包含 ../ 或 %2e 时才检查 path 类型
        $lowerPath = strtolower($urlPath);
        if (str_contains($lowerPath, '..') || str_contains($lowerPath, '%2e')) {
            $pathResult = $this->checkPatternsAgainstInput($patterns, $urlPath, ['path']);
            if ($pathResult !== null) {
                return $pathResult;
            }
        }

        // 2. 检查完整URL（包含查询字符串）— 全量检测
        $fullUrl = $this->truncateInputKnown(FrameworkBridge::requestFullUrl($request));
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
        $input = $this->truncateInputKnown($input);

        $inputResult = $this->checkHighRiskInputWithMarkdownBypass($patterns, $input);
        if ($inputResult !== null) {
            return $inputResult;
        }

        // 6. 独立检查每个参数值（避免跨参数拼接导致误报）
        // 此方法已在 checkIndividualParamsForHighRisk 中实现，此处不再重复
        // 但需要确保 checkIndividualParamsForHighRisk 的预过滤逻辑正确

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

        // 批量预过滤：一次 strtolower + 一次遍历，对同一 input 检查所有候选类型
        $activeTypes = $this->patternService->preFilterBatch($input, $types);

        if (empty($activeTypes)) {
            return null; // 没有任何类型通过预过滤，快速跳过
        }

        foreach ($activeTypes as $type) {
            if (!isset($patterns[$type])) {
                continue;
            }

            foreach ($patterns[$type] as $item) {
                $pattern = $item['pattern'];
                $matches = [];
                if ($this->safePregMatch($pattern, $input, $matches)) {
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
     * @param object $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkUrlParamsForSsrRedirect(array $patterns, object $request): ?string
    {
        // 仅当 SSRF 或 redirect 检测类型存在时才执行
        $availableTypes = array_intersect(['ssrf', 'redirect'], array_keys($patterns));
        if (empty($availableTypes)) {
            return null;
        }

        // URL类参数的常见名称（从配置读取，支持开发者自定义扩展）
        $urlParamNames = $this->config['api_bypass']['url_param_names'] ?? [
            'redirect_uri', 'redirect_url', 'redirect', 'redirect_to',
            'callback', 'callback_url', 'return_url', 'return_to',
            'webhook', 'webhook_url', 'notify_url', 'notify',
            'forward', 'dest', 'destination', 'goto', 'continue',
        ];

        // 收集所有参数值（含解码变形）— 逐来源遍历避免 array_merge 复制大 POST 数组
        $urlValues = [];

        foreach ([FrameworkBridge::requestQuery($request), FrameworkBridge::requestPost($request)] as $source) {
            foreach ($source as $key => $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                $isUrlParam = in_array(strtolower($key), $urlParamNames, true);

                // 解码变体：使用请求级缓存
                $decoded1 = $this->cachedUrldecode($value, 1);
                $decoded2 = $this->cachedUrldecode($value, 2);

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
        $decoded = $this->truncateInput($this->cachedUrldecode($value, 1));
        return $this->safePregMatch('#\b(?:https?|ftp|gopher|dict|file)://#i', $decoded)
            || $this->safePregMatch('#^//[a-z0-9]#i', $decoded);
    }

    /**
     * 独立检查每个查询/POST参数值中是否包含高危攻击模式
     *
     * 与合并输入检测互补：合并检测识别上下文关联的攻击（如完整SQL语句），
     * 本方法确保单个参数中的攻击载荷不被合并后的其他数据稀释。
     *
     * 适用类型：sql, command, encoding, ssti, nosql, xml, ldap, file_include, path,
     *          deserialization, prototype_pollution, jndi, http_smuggling, graphql, webshell
     * 不适用：redirect, ssrf（由 checkUrlParamsForSsrRedirect 专门处理）
     *         header_injection（由 HTTP 头检查专门处理）
     *
     * 注意：path 类型同时由 detectUrlPathAttacks 和本方法检查，形成防御纵深。
     *       即使 url_path 检测层被关闭，高危检测层仍能拦截 query string 中的
     *       .php/.asp/.jsp 等脚本扩展名和路径遍历。
     *
     * JSON 感知优化：
     *   - 当 JSON API 旁路启用且请求为 JSON 格式时，跳过 sql/xss 类检测
     *   - 保留 ssrf/command/file_include/deserialization 等类型（JSON 场景仍可能发生）
     *
     * @param array $patterns 攻击模式数组
     * @param object $request HTTP请求对象
     * @return string|null 检测到的威胁类型，未检测到返回null
     */
    protected function checkIndividualParamsForHighRisk(array $patterns, object $request): ?string
    {
        // 需要独立检查的类型（不与合并输入混淆）
        // path 类型也包含在内：防止 url_path 检测层关闭后，query string 中的
        // .php/.asp/.jsp 等脚本扩展名和路径遍历被绕过（防御纵深）
        $baseCheckTypes = ['sql', 'command', 'encoding', 'ssti', 'nosql', 'xml', 'ldap', 'file_include', 'path'];
        $extendedCheckTypes = ['deserialization', 'prototype_pollution', 'jndi', 'http_smuggling', 'graphql', 'webshell'];
        
        $allCandidateTypes = array_merge($baseCheckTypes, $extendedCheckTypes);
        $checkTypes = array_intersect($allCandidateTypes, array_keys($patterns));

        if (empty($checkTypes)) {
            return null;
        }

        // JSON API 智能旁路：对于 JSON 请求跳过 SQL/XSS 类检测以减少误报
        // JSON 数据中常见 SQL关键字（select/from/where）或 HTML标签作为纯数据内容
        $isJsonApi = $this->isJsonApiRequest($request);
        $jsonBypassEnabled = $this->config['detection_layers']['json_aware_bypass'] ?? true;
        
        if ($isJsonApi && $jsonBypassEnabled) {
            // JSON 场景中排除高误报类型，保留真正高危的类型
            // 跳过的类型从配置中读取，支持开发者按业务场景自定义
            $jsonSkipTypes = $this->config['api_bypass']['skip_high_risk_types'] ?? ['sql', 'ssti'];
            $checkTypes = array_values(array_diff($checkTypes, $jsonSkipTypes));
        }

        if (empty($checkTypes)) {
            return null;
        }

        // ═══ 获取输入并缓存解码结果 ═══
        // 此处生成的候选值在后续 checkIndividualParamsForHighRisk 等多个步骤中复用，
        // 通过 UsesSafeRegex 的 cachedUrldecode() 和 normalizeInput() 缓存避免重复计算。
        foreach ([FrameworkBridge::requestQuery($request), FrameworkBridge::requestPost($request), FrameworkBridge::requestRouteParams($request)] as $source) {
            foreach ($source as $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                // 内联去重替代 array_unique([$value, urldecode($value), urldecode(urldecode($value))])
                // 3 元素场景下 array_unique 创建哈希表的开销 > 手动比较
                $candidate1 = $this->truncateInput($value);
                $candidate2 = $this->truncateInput($this->cachedUrldecode($value, 1));
                $candidate3 = $this->truncateInput($this->cachedUrldecode($value, 2));

                // 手工去重 (3 元素，最多 3 次 string 比较)
                $candidates = [$candidate1];
                if ($candidate2 !== $candidate1) {
                    $candidates[] = $candidate2;
                }
                if ($candidate3 !== $candidate1 && $candidate3 !== $candidate2) {
                    $candidates[] = $candidate3;
                }

                foreach ($candidates as $candidate) {
                    // 批量预过滤：一次 strtolower + str_contains 遍历所有候选类型
                    $activeTypes = $this->patternService->preFilterBatch($candidate, $checkTypes);

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
     * @param object $request HTTP请求对象
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function detectXssAttacks(object $request): ?string
    {
        // JSON API 智能旁路：JSON 请求体中 HTML 标签通常是纯数据
        $jsonBypassEnabled = $this->config['detection_layers']['json_aware_bypass'] ?? true;
        if ($jsonBypassEnabled && $this->isJsonApiRequest($request)) {
            $urlPath = $this->truncateInput($this->cachedUrldecode(FrameworkBridge::requestPath($request), 1));
            $queryString = $this->truncateInput($this->cachedUrldecode(FrameworkBridge::requestGetQueryString($request) ?? '', 1));
            
            // 对 URL 路径和查询字符串做轻量级预检：包含 < 且包含 >
            if (!str_contains($urlPath, '<') && !str_contains($urlPath, '>')
                && !str_contains($queryString, '<') && !str_contains($queryString, '>')
                && !str_contains(strtolower($queryString), 'javascript')
                && !str_contains(strtolower($queryString), 'onerror')
            ) {
                return null; // 快速跳过
            }
        }

        // 使用缓存规则方法，避免同一请求中多次调用 ConfigResolver
        $excludeRules = $this->getExcludeRules();
        $interceptRules = $this->getInterceptRules();

        // 从 PatternService 获取模式（延迟加载 + 统一排除/追加规则）
        $patterns = $this->patternService->getXssPatterns($excludeRules, $interceptRules);

        if (empty($patterns)) {
            return null;
        }

        // XSS 子类型过滤：通过 DefaultConfig 统一合并默认值与用户配置
        $xssSubtypes = \zxf\Security\Config\DefaultConfig::getXssSubtypes($this->config);
        foreach ($patterns as $subtype => $_) {
            if (isset($xssSubtypes[$subtype]) && $xssSubtypes[$subtype] === false) {
                unset($patterns[$subtype]);
            }
        }

        if (empty($patterns)) {
            return null;
        }

        // 1. 检查URL路径（反射型XSS常出现在URL中）
        $urlPath = $this->truncateInput($this->cachedUrldecode(FrameworkBridge::requestPath($request), 1));
        $urlPathResult = $this->checkXssPatterns($patterns, $urlPath, $urlPath);
        if ($urlPathResult !== null) {
            return $urlPathResult;
        }

        // 2. 检查查询字符串（整体）
        $queryString = $this->truncateInput($this->cachedUrldecode(FrameworkBridge::requestGetQueryString($request) ?? '', 1));
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

        // 批量预过滤：一次 strtolower 检查所有 XSS 类型
        $xssTypeKeys = array_map(fn(string $type) => 'xss_' . $type, array_keys($patterns));
        $activeTypes = $this->patternService->preFilterBatch($input, $xssTypeKeys);

        if (empty($activeTypes)) {
            return null;
        }

        $activeTypes = array_map(fn(string $t) => substr($t, 4), $activeTypes);

        foreach ($activeTypes as $type) {
            if (!isset($patterns[$type])) {
                continue;
            }

            foreach ($patterns[$type] as $item) {
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
     * @param object $request HTTP请求对象
     * @return string|null 检测到的XSS类型，未检测到返回null
     */
    protected function checkIndividualParamsForXss(array $patterns, object $request): ?string
    {
        if (empty($patterns)) {
            return null;
        }

        $allTypes = array_keys($patterns);
        if (empty($allTypes)) {
            return null;
        }

        // 收集所有参数值并解码 — 逐来源遍历避免 array_merge 复制大数组
        foreach ([FrameworkBridge::requestQuery($request), FrameworkBridge::requestPost($request), FrameworkBridge::requestRouteParams($request)] as $source) {
            foreach ($source as $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }

                // 内联去重替代 array_unique（节省哈希表创建开销）
                $c1 = $this->truncateInput($value);
                $c2 = $this->truncateInput($this->cachedUrldecode($value, 1));
                $c3 = $this->truncateInput($this->cachedUrldecode($value, 2));

                $candidates = [$c1];
                if ($c2 !== $c1) $candidates[] = $c2;
                if ($c3 !== $c1 && $c3 !== $c2) $candidates[] = $c3;

                foreach ($candidates as $candidate) {
                    // 批量预过滤：一次 strtolower 检查所有 XSS 类型
                    $activeTypes = $this->patternService->preFilterBatch(
                        $candidate, 
                        array_map(fn(string $t) => 'xss_' . $t, $allTypes)
                    );
                    // 还原为原始类型名（去掉 xss_ 前缀）
                    $activeTypes = array_map(fn(string $t) => substr($t, 4), $activeTypes);

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

    // ==================== JSON API 智能旁路 ====================

    /**
     * 判断是否为 JSON API 请求
     *
     * 用于智能旁路：JSON 数据中的 SQL 关键字/HTML 标签通常是纯数据内容而非攻击载荷。
     * 检测维度（四维判定）：
     *  1. Content-Type 为 application/json 或 multipart/related（广泛兼容）
     *  2. 请求 Accept 头明确偏好 JSON（排除 text/html 和通配符）
     *  3. 请求路径匹配 API 前缀（/api/, /v1/ 等）
     *  4. X-Requested-With: XMLHttpRequest + Accept JSON（Ajax 调用）
     *
     * @param object $request HTTP请求对象
     * @return bool
     */
    protected function isJsonApiRequest(object $request): bool
    {
        // 1. Content-Type 检查（支持 JSON 变体）
        $contentType = FrameworkBridge::requestGetHeader($request, 'Content-Type');
        if ($contentType !== null) {
            $ctLower = strtolower($contentType);
            if (str_contains($ctLower, 'application/json') 
                || str_contains($ctLower, 'application/vnd.api+json')
                || str_contains($ctLower, 'application/problem+json')
            ) {
                return true;
            }
        }

        // 2. Accept 头检查（仅当明确只接受 JSON 时）
        $accept = FrameworkBridge::requestGetHeader($request, 'Accept');
        if ($accept !== null) {
            $acceptLower = strtolower($accept);
            if (str_contains($acceptLower, 'application/json') 
                && !str_contains($acceptLower, 'text/html')
                && !str_contains($acceptLower, '*/*')
            ) {
                return true;
            }
        }

        // 3. 路径模式检查
        $path = strtolower(FrameworkBridge::requestPath($request));
        $apiPrefixes = $this->config['api_bypass']['prefixes'] ?? ['/api/', '/v1/', '/v2/', '/v3/', '/graphql'];
        foreach ($apiPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        // 4. Ajax 调用 + JSON Accept 组合
        $isAjax = FrameworkBridge::requestIsAjax($request);
        $expectsJson = FrameworkBridge::requestExpectsJson($request);
        if ($isAjax || $expectsJson) {
            return true;
        }

        return false;
    }
}
