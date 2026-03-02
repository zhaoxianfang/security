# Laravel 安全扩展包 - 设计模式文档

## 📋 文档概述

本文档详细阐述Laravel安全扩展包中使用的设计模式，包括模式定义、应用场景、实现细节和最佳实践。

**文档版本**: 3.0.0  
**最后更新**: 2026-03-01  
**作者**: zxf

---

## 📖 目录

1. [责任链模式 (Chain of Responsibility)](#责任链模式)
2. [策略模式 (Strategy)](#策略模式)
3. [工厂模式 (Factory)](#工厂模式)
4. [装饰器模式 (Decorator)](#装饰器模式)
5. [观察者模式 (Observer)](#观察者模式)
6. [模板方法模式 (Template Method)](#模板方法模式)
7. [单例模式 (Singleton)](#单例模式)
8. [适配器模式 (Adapter)](#适配器模式)
9. [门面模式 (Facade)](#门面模式)
10. [依赖注入模式 (Dependency Injection)](#依赖注入模式)

---

## 责任链模式

### 定义

将处理请求的多个处理器串联起来，每个处理器都有机会处理请求，直到某个处理器处理完毕或所有处理器都处理完为止。

### 应用场景

- **SecurityMiddleware**: 中间件处理器链
- **安全检查器**: 多个安全检查器依次执行

### 实现方式

#### 接口定义

```php
namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

interface SecurityMiddlewareHandlerInterface
{
    /**
     * 处理请求
     *
     * @param Request $request HTTP请求对象
     * @param callable $next 下一个处理器
     * @return mixed 处理结果
     */
    public function handle(Request $request, callable $next): mixed;

    /**
     * 设置下一个处理器
     *
     * @param SecurityMiddlewareHandlerInterface|null $handler 下一个处理器
     * @return void
     */
    public function setNext(?SecurityMiddlewareHandlerInterface $handler): void;

    /**
     * 获取下一个处理器
     *
     * @return SecurityMiddlewareHandlerInterface|null 下一个处理器
     */
    public function getNext(): ?SecurityMiddlewareHandlerInterface;
}
```

#### 抽象基类

```php
namespace zxf\Security\Middleware\Handlers;

use zxf\Security\Contracts\SecurityMiddlewareHandlerInterface;
use Illuminate\Http\Request;
use zxf\Security\Services\ConfigManager;

abstract class AbstractSecurityHandler implements SecurityMiddlewareHandlerInterface
{
    protected ?SecurityMiddlewareHandlerInterface $next = null;
    protected ConfigManager $config;
    protected string $name;
    protected int $priority = 100;
    protected bool $enabled = true;

    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
        $this->enabled = $this->getConfigValue('enabled', true);
    }

    /**
     * 处理请求（模板方法）
     */
    public function handle(Request $request, callable $next): mixed
    {
        // 1. 检查是否应该跳过
        if ($this->shouldSkip($request)) {
            return $next($request);
        }

        // 2. 检查是否启用
        if (!$this->isEnabled()) {
            return $next($request);
        }

        // 3. 执行前置处理
        $beforeResult = $this->before($request);
        if ($beforeResult !== null) {
            return $beforeResult;
        }

        // 4. 执行核心处理逻辑（由子类实现）
        $result = $this->doHandle($request, $next);

        // 5. 执行后置处理
        $this->after($request, $result);

        return $result;
    }

    /**
     * 执行核心处理逻辑（抽象方法）
     */
    abstract protected function doHandle(Request $request, callable $next): mixed;

    public function setNext(?SecurityMiddlewareHandlerInterface $handler): void
    {
        $this->next = $handler;
    }

    public function getNext(): ?SecurityMiddlewareHandlerInterface
    {
        return $this->next;
    }

    // ... 其他方法
}
```

#### 具体处理器

```php
namespace zxf\Security\Middleware\Handlers;

use Illuminate\Http\Request;

/**
 * 黑名单检查处理器
 */
class BlacklistHandler extends AbstractSecurityHandler
{
    protected string $name = 'BlacklistHandler';
    protected string $configPrefix = 'blacklist_check';
    protected int $priority = 20;

    protected function doHandle(Request $request, callable $next): mixed
    {
        $ipManager = app(\zxf\Security\Services\IpManagerService::class);

        if ($ipManager->isBlacklisted($request)) {
            return $this->createBlockResponse(
                $request,
                'IP在黑名单中'
            );
        }

        // 传递给下一个处理器
        if ($this->next) {
            return $this->next->handle($request, $next);
        }

        return $next($request);
    }

    public function shouldSkip(Request $request): bool
    {
        // 内网IP可以跳过黑名单检查
        if ($this->getConfigValue('skip_intranet', false)) {
            return is_intranet_ip($request->ip());
        }
        return false;
    }
}
```

#### 处理器链构建

```php
namespace zxf\Security\Middleware;

use zxf\Security\Contracts\SecurityMiddlewareHandlerInterface;
use zxf\Security\Middleware\Handlers\BlacklistHandler;
use zxf\Security\Middleware\Handlers\RateLimitHandler;
use zxf\Security\Middleware\Handlers\ThreatDetectionHandler;

class SecurityMiddleware
{
    protected ?SecurityMiddlewareHandlerInterface $handlerChain = null;

    protected function buildHandlerChain(): SecurityMiddlewareHandlerInterface
    {
        // 创建处理器
        $handlers = [
            new BlacklistHandler($this->config),
            new RateLimitHandler($this->config),
            new ThreatDetectionHandler($this->config),
        ];

        // 按优先级排序
        usort($handlers, fn($a, $b) => $a->getPriority() <=> $b->getPriority());

        // 构建责任链
        $chain = array_shift($handlers);
        $current = $chain;

        foreach ($handlers as $handler) {
            $current->setNext($handler);
            $current = $handler;
        }

        return $chain;
    }

    public function handle($request, \Closure $next)
    {
        if ($this->handlerChain === null) {
            $this->handlerChain = $this->buildHandlerChain();
        }

        return $this->handlerChain->handle($request, $next);
    }
}
```

### 优势

1. **降低耦合度**: 处理器之间不需要知道彼此的存在
2. **增强灵活性**: 可以动态添加或删除处理器
3. **易于扩展**: 新增处理器无需修改现有代码
4. **职责单一**: 每个处理器只负责一个特定的检查

### 最佳实践

1. **合理设置优先级**: 确保处理器按正确的顺序执行
2. **避免过长链**: 责任链过长会影响性能
3. **异常处理**: 每个处理器应有良好的异常处理
4. **日志记录**: 记录每个处理器的执行情况

---

## 策略模式

### 定义

定义一系列算法，将每个算法封装起来，并使它们可以互换。策略模式让算法独立于使用它的客户端而变化。

### 应用场景

- **威胁检测**: 不同的威胁检测策略
- **限流**: 不同的限流策略
- **缓存**: 不同的缓存策略

### 实现方式

#### 策略接口

```php
namespace zxf\Security\Contracts;

use Illuminate\Http\Request;

interface ThreatDetectorInterface
{
    /**
     * 检测威胁
     *
     * @param Request $request HTTP请求对象
     * @return array 威胁列表
     */
    public function detectThreats(Request $request): array;

    /**
     * 计算威胁评分
     *
     * @param array $threats 威胁列表
     * @return float 威胁评分（0-100）
     */
    public function calculateThreatScore(array $threats): float;
}
```

#### 具体策略

```php
namespace zxf\Security\Strategies;

use zxf\Security\Contracts\ThreatDetectorInterface;
use Illuminate\Http\Request;

/**
 * SQL注入检测策略
 */
class SqlInjectionDetector implements ThreatDetectorInterface
{
    protected array $patterns = [
        '/union\s+select/i',
        '/or\s+1\s*=\s*1/i',
        '/drop\s+table/i',
        '/exec\s*\(/i',
    ];

    public function detectThreats(Request $request): array
    {
        $threats = [];

        foreach (['query', 'body', 'header'] as $source) {
            $data = $this->getDataFromSource($request, $source);
            $foundThreats = $this->detectInData($data, 'SQLInjection');
            $threats = array_merge($threats, $foundThreats);
        }

        return $threats;
    }

    public function calculateThreatScore(array $threats): float
    {
        $score = 0;
        foreach ($threats as $threat) {
            if ($threat['type'] === 'SQLInjection') {
                $score += 25;
            }
        }
        return min(100, $score);
    }

    protected function detectInData(array $data, string $type): array
    {
        $threats = [];
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                foreach ($this->patterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $threats[] = [
                            'type' => $type,
                            'field' => $key,
                            'value' => substr($value, 0, 100),
                            'pattern' => $pattern,
                        ];
                        break;
                    }
                }
            }
        }
        return $threats;
    }
}
```

```php
namespace zxf\Security\Strategies;

use zxf\Security\Contracts\ThreatDetectorInterface;
use Illuminate\Http\Request;

/**
 * XSS攻击检测策略
 */
class XssAttackDetector implements ThreatDetectorInterface
{
    protected array $patterns = [
        '/<script[^>]*>.*?<\/script>/i',
        '/javascript:/i',
        '/on\w+\s*=/i',
    ];

    public function detectThreats(Request $request): array
    {
        $threats = [];

        foreach (['query', 'body'] as $source) {
            $data = $this->getDataFromSource($request, $source);
            $foundThreats = $this->detectInData($data, 'XSSAttack');
            $threats = array_merge($threats, $foundThreats);
        }

        return $threats;
    }

    public function calculateThreatScore(array $threats): float
    {
        $score = 0;
        foreach ($threats as $threat) {
            if ($threat['type'] === 'XSSAttack') {
                $score += 20;
            }
        }
        return min(100, $score);
    }
}
```

#### 策略上下文

```php
namespace zxf\Security\Services;

use zxf\Security\Contracts\ThreatDetectorInterface;
use Illuminate\Http\Request;

/**
 * 威胁检测服务
 */
class ThreatDetectionService
{
    /**
     * 威胁检测策略列表
     */
    protected array $detectors = [];

    /**
     * 添加检测策略
     */
    public function addDetector(ThreatDetectorInterface $detector): void
    {
        $this->detectors[] = $detector;
    }

    /**
     * 移除检测策略
     */
    public function removeDetector(string $detectorClass): void
    {
        $this->detectors = array_filter(
            $this->detectors,
            fn($detector) => !($detector instanceof $detectorClass)
        );
    }

    /**
     * 执行所有检测策略
     */
    public function detectAll(Request $request): array
    {
        $allThreats = [];

        foreach ($this->detectors as $detector) {
            $threats = $detector->detectThreats($request);
            $allThreats = array_merge($allThreats, $threats);
        }

        return $allThreats;
    }

    /**
     * 计算总体威胁评分
     */
    public function calculateTotalScore(Request $request): float
    {
        $allThreats = $this->detectAll($request);
        $totalScore = 0;

        foreach ($this->detectors as $detector) {
            $score = $detector->calculateThreatScore($allThreats);
            $totalScore = max($totalScore, $score);
        }

        return min(100, $totalScore);
    }
}
```

#### 策略使用

```php
// 创建威胁检测服务
$threatService = new ThreatDetectionService();

// 添加检测策略
$threatService->addDetector(new SqlInjectionDetector());
$threatService->addDetector(new XssAttackDetector());
$threatService->addDetector(new CommandInjectionDetector());

// 执行检测
$threats = $threatService->detectAll($request);

// 计算威胁评分
$score = $threatService->calculateTotalScore($request);
```

### 优势

1. **算法可互换**: 可以轻松切换不同的策略
2. **易于扩展**: 新增策略无需修改现有代码
3. **降低耦合**: 策略之间相互独立
4. **提高可维护性**: 每个策略独立开发和测试

### 最佳实践

1. **策略命名**: 策略类名应清楚表达其功能
2. **策略文档**: 为每个策略提供详细文档
3. **策略测试**: 每个策略都应有完整的单元测试
4. **策略配置**: 支持通过配置启用/禁用策略

---

## 工厂模式

### 定义

定义创建对象的接口，让子类决定实例化哪一个类。工厂模式使一个类的实例化延迟到其子类。

### 应用场景

- **安全检查器**: 创建不同类型的安全检查器
- **检测器**: 创建不同类型的威胁检测器
- **缓存**: 创建不同类型的缓存实例

### 实现方式

#### 简单工厂

```php
namespace zxf\Security\Factories;

use zxf\Security\Checkers\AbstractSecurityChecker;

/**
 * 安全检查器工厂
 */
class SecurityCheckerFactory
{
    /**
     * 创建安全检查器
     *
     * @param string $type 检查器类型
     * @return AbstractSecurityChecker 安全检查器实例
     * @throws InvalidArgumentException
     */
    public static function create(string $type): AbstractSecurityChecker
    {
        return match($type) {
            'sql_injection' => new SqlInjectionChecker(),
            'xss_attack' => new XssAttackChecker(),
            'command_injection' => new CommandInjectionChecker(),
            'path_traversal' => new PathTraversalChecker(),
            default => throw new InvalidArgumentException("Unknown checker type: {$type}")
        };
    }

    /**
     * 批量创建检查器
     *
     * @param array $types 检查器类型数组
     * @return array 检查器实例数组
     */
    public static function createBatch(array $types): array
    {
        return array_map(fn($type) => self::create($type), $types);
    }
}
```

#### 抽象工厂

```php
namespace zxf\Security\Factories;

use zxf\Security\Contracts\CacheManagerInterface;

/**
 * 缓存工厂接口
 */
interface CacheFactoryInterface
{
    public function createCache(): CacheManagerInterface;
    public function createMemoryCache(): CacheManagerInterface;
    public function createFileCache(): CacheManagerInterface;
}
```

```php
namespace zxf\Security\Factories;

use zxf\Security\Contracts\CacheManagerInterface;
use zxf\Security\Cache\SecurityCacheManager;
use zxf\Security\Cache\MemoryCacheManager;
use zxf\Security\Cache\FileCacheManager;

/**
 * 安全缓存工厂
 */
class SecurityCacheFactory implements CacheFactoryInterface
{
    public function createCache(): CacheManagerInterface
    {
        return new SecurityCacheManager();
    }

    public function createMemoryCache(): CacheManagerInterface
    {
        return new MemoryCacheManager();
    }

    public function createFileCache(): CacheManagerInterface
    {
        return new FileCacheManager();
    }
}
```

#### 工厂方法

```php
namespace zxf\Security\Services;

use zxf\Security\Contracts\CacheManagerInterface;

/**
 * 配置热重载服务
 */
class ConfigHotReloadService
{
    protected ?CacheManagerInterface $cache = null;

    /**
     * 工厂方法：创建缓存实例
     */
    protected function createCache(): CacheManagerInterface
    {
        if ($this->cache === null) {
            $this->cache = app(SecurityCacheFactory::class)->createCache();
        }
        return $this->cache;
    }
}
```

### 优势

1. **解耦对象创建**: 客户端不需要知道如何创建对象
2. **易于扩展**: 新增产品类只需添加工厂方法
3. **代码复用**: 创建逻辑集中在一处
4. **便于测试**: 可以工厂进行Mock

### 最佳实践

1. **命名规范**: 工厂类名应包含"Factory"后缀
2. **异常处理**: 创建失败时抛出明确的异常
3. **配置驱动**: 支持通过配置决定创建哪种对象
4. **类型安全**: 使用类型提示确保返回正确类型

---

## 装饰器模式

### 定义

动态地给一个对象添加一些额外的职责。就增加功能来说，装饰器模式相比生成子类更为灵活。

### 应用场景

- **缓存装饰器**: 为缓存添加统计、日志等功能
- **日志装饰器**: 为服务添加日志记录功能
- **性能监控装饰器**: 为服务添加性能监控功能

### 实现方式

#### 装饰器接口

```php
namespace zxf\Security\Contracts;

interface CacheManagerInterface
{
    public function get(string $key, mixed $default = null): mixed;
    public function set(string $key, mixed $value, ?int $ttl = null): bool;
    public function delete(string $key): bool;
    public function clear(): bool;
}
```

#### 基础实现

```php
namespace zxf\Security\Cache;

use zxf\Security\Contracts\CacheManagerInterface;
use Illuminate\Support\Facades\Cache;

/**
 * 基础缓存实现
 */
class BasicCacheManager implements CacheManagerInterface
{
    protected string $prefix = 'security:';

    public function get(string $key, mixed $default = null): mixed
    {
        return Cache::get($this->prefix . $key, $default);
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        return Cache::put($this->prefix . $key, $value, $ttl ?? 300);
    }

    public function delete(string $key): bool
    {
        return Cache::forget($this->prefix . $key);
    }

    public function clear(): bool
    {
        return Cache::flush();
    }
}
```

#### 装饰器实现

```php
namespace zxf\Security\Cache\Decorators;

use zxf\Security\Contracts\CacheManagerInterface;
use Illuminate\Support\Facades\Log;

/**
 * 统计装饰器
 */
class StatsCacheDecorator implements CacheManagerInterface
{
    protected CacheManagerInterface $cache;
    protected array $stats = [
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'deletes' => 0,
    ];

    public function __construct(CacheManagerInterface $cache)
    {
        $this->cache = $cache;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->cache->get($key, $default);
        
        if ($value === $default) {
            $this->stats['misses']++;
        } else {
            $this->stats['hits']++;
        }
        
        return $value;
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        $this->stats['sets']++;
        return $this->cache->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        $this->stats['deletes']++;
        return $this->cache->delete($key);
    }

    public function clear(): bool
    {
        return $this->cache->clear();
    }

    /**
     * 获取统计信息
     */
    public function getStats(): array
    {
        return $this->stats;
    }
}
```

```php
namespace zxf\Security\Cache\Decorators;

use zxf\Security\Contracts\CacheManagerInterface;
use Illuminate\Support\Facades\Log;

/**
 * 日志装饰器
 */
class LoggingCacheDecorator implements CacheManagerInterface
{
    protected CacheManagerInterface $cache;
    protected bool $enableLogging = true;

    public function __construct(CacheManagerInterface $cache, bool $enableLogging = true)
    {
        $this->cache = $cache;
        $this->enableLogging = $enableLogging;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if ($this->enableLogging) {
            Log::debug('Cache Get', ['key' => $key]);
        }
        
        return $this->cache->get($key, $default);
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        if ($this->enableLogging) {
            Log::debug('Cache Set', ['key' => $key, 'ttl' => $ttl]);
        }
        
        return $this->cache->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        if ($this->enableLogging) {
            Log::debug('Cache Delete', ['key' => $key]);
        }
        
        return $this->cache->delete($key);
    }

    public function clear(): bool
    {
        if ($this->enableLogging) {
            Log::debug('Cache Clear');
        }
        
        return $this->cache->clear();
    }
}
```

#### 使用装饰器

```php
// 创建基础缓存
$basicCache = new BasicCacheManager();

// 添加统计装饰器
$cacheWithStats = new StatsCacheDecorator($basicCache);

// 添加日志装饰器
$cacheWithStatsAndLogging = new LoggingCacheDecorator($cacheWithStats, true);

// 使用装饰后的缓存
$cacheWithStatsAndLogging->set('key', 'value', 300);
$value = $cacheWithStatsAndLogging->get('key');

// 获取统计信息
$stats = $cacheWithStatsAndLogging->getStats();
```

### 优势

1. **动态扩展**: 运行时动态添加功能
2. **灵活组合**: 可以自由组合多个装饰器
3. **单一职责**: 每个装饰器只负责一个功能
4. **避免类爆炸**: 比继承更灵活

### 最佳实践

1. **装饰器顺序**: 注意装饰器的执行顺序
2. **性能考虑**: 避免过多装饰器影响性能
3. **透明性**: 装饰器不应改变被装饰对象的接口
4. **文档记录**: 记录每个装饰器的功能和影响

---

## 观察者模式

### 定义

定义对象间的一种一对多的依赖关系，当一个对象的状态发生改变时，所有依赖于它的对象都得到通知并被自动更新。

### 应用场景

- **IP事件**: IP添加、删除、更新时通知监听器
- **安全事件**: 威胁检测到时通知监听器
- **配置变更**: 配置更新时通知相关服务

### 实现方式

#### 事件类

```php
namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP已创建事件
 */
class IpCreated
{
    use Dispatchable;

    public function __construct(
        public SecurityIp $ip
    ) {}
}
```

```php
namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP已更新事件
 */
class IpUpdated
{
    use Dispatchable;

    public function __construct(
        public SecurityIp $ip,
        public array $changes = []
    ) {}
}
```

```php
namespace zxf\Security\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use zxf\Security\Models\SecurityIp;

/**
 * IP已删除事件
 */
class IpDeleted
{
    use Dispatchable;

    public function __construct(
        public SecurityIp $ip
    ) {}
}
```

#### 事件监听器

```php
namespace App\Listeners;

use zxf\Security\Events\IpCreated;
use Illuminate\Support\Facades\Log;

/**
 * 记录IP创建事件
 */
class LogIpCreated
{
    public function handle(IpCreated $event): void
    {
        Log::info('IP已创建', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
            'reason' => $event->ip->reason,
            'threat_score' => $event->ip->threat_score,
        ]);

        // 高威胁IP发送告警
        if ($event->ip->threat_score > 80) {
            $this->sendAlert($event->ip);
        }
    }

    protected function sendAlert(SecurityIp $ip): void
    {
        // 发送告警通知
        // 可以是邮件、短信、Slack等
    }
}
```

```php
namespace App\Listeners;

use zxf\Security\Events\IpUpdated;
use Illuminate\Support\Facades\Log;

/**
 * 记录IP更新事件
 */
class LogIpUpdated
{
    public function handle(IpUpdated $event): void
    {
        Log::info('IP已更新', [
            'ip' => $event->ip->ip_address,
            'type' => $event->ip->type,
            'threat_score' => $event->ip->threat_score,
            'changes' => $event->changes,
        ]);

        // 威胁评分显著升高时发送告警
        if (isset($event->changes['threat_score']) && 
            $event->changes['threat_score'] > 80) {
            $this->sendAlert($event->ip);
        }
    }

    protected function sendAlert(SecurityIp $ip): void
    {
        // 发送告警通知
    }
}
```

#### 事件订阅者

```php
namespace App\Listeners;

use Illuminate\Support\Facades\Log;
use zxf\Security\Events\IpCreated;
use zxf\Security\Events\IpUpdated;
use zxf\Security\Events\IpDeleted;

/**
 * IP事件订阅者
 */
class IpEventSubscriber
{
    public function handleIpCreated(IpCreated $event): void
    {
        Log::info('IP创建事件', ['ip' => $event->ip->ip_address]);
    }

    public function handleIpUpdated(IpUpdated $event): void
    {
        Log::info('IP更新事件', ['ip' => $event->ip->ip_address]);
    }

    public function handleIpDeleted(IpDeleted $event): void
    {
        Log::info('IP删除事件', ['ip' => $event->ip->ip_address]);
    }

    public function subscribe($events): array
    {
        return [
            IpCreated::class => 'handleIpCreated',
            IpUpdated::class => 'handleIpUpdated',
            IpDeleted::class => 'handleIpDeleted',
        ];
    }
}
```

#### 注册事件

```php
// app/Providers/EventServiceProvider.php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
use zxf\Security\Events\IpCreated;
use zxf\Security\Events\IpUpdated;
use zxf\Security\Events\IpDeleted;
use App\Listeners\LogIpCreated;
use App\Listeners\LogIpUpdated;
use App\Listeners\IpEventSubscriber;

class EventServiceProvider extends ServiceProvider
{
    protected $listen = [
        IpCreated::class => [
            LogIpCreated::class,
        ],
        IpUpdated::class => [
            LogIpUpdated::class,
        ],
        IpDeleted::class => [
            LogIpDeleted::class,
        ],
    ];

    protected $subscribe = [
        IpEventSubscriber::class,
    ];
}
```

#### 触发事件

```php
namespace zxf\Security\Services;

use zxf\Security\Events\IpCreated;
use zxf\Security\Events\IpUpdated;
use zxf\Security\Events\IpDeleted;
use zxf\Security\Models\SecurityIp;

class IpManagerService
{
    public function addToWhitelist(string $ip, string $reason = ''): SecurityIp
    {
        $ipRecord = SecurityIp::create([
            'ip_address' => $ip,
            'type' => 'whitelist',
            'reason' => $reason,
        ]);

        // 触发事件
        event(new IpCreated($ipRecord));

        return $ipRecord;
    }

    public function updateThreatScore(string $ip, float $score): bool
    {
        $ipRecord = SecurityIp::where('ip_address', $ip)->first();
        
        if (!$ipRecord) {
            return false;
        }

        $oldScore = $ipRecord->threat_score;
        $ipRecord->threat_score = $score;
        $ipRecord->save();

        // 触发事件
        event(new IpUpdated($ipRecord, [
            'threat_score' => $score,
            'old_threat_score' => $oldScore,
        ]));

        return true;
    }

    public function deleteIp(string $ip): bool
    {
        $ipRecord = SecurityIp::where('ip_address', $ip)->first();
        
        if (!$ipRecord) {
            return false;
        }

        // 触发事件
        event(new IpDeleted($ipRecord));

        return $ipRecord->delete();
    }
}
```

### 优势

1. **松耦合**: 事件源和监听器之间松耦合
2. **易于扩展**: 可以添加任意数量的监听器
3. **异步处理**: 支持异步事件处理
4. **职责分离**: 事件触发和事件处理分离

### 最佳实践

1. **事件命名**: 事件类名应清晰表达事件内容
2. **参数设计**: 事件应包含足够的上下文信息
3. **错误处理**: 监听器应有良好的错误处理
4. **性能考虑**: 避免在监听器中执行耗时操作

---

## 模板方法模式

### 定义

定义一个操作中的算法的骨架，而将一些步骤延迟到子类中。模板方法使得子类可以不改变一个算法的结构即可重定义该算法的某些特定步骤。

### 应用场景

- **抽象检查器**: 定义检查的骨架流程
- **抽象处理器**: 定义处理的骨架流程
- **抽象服务**: 定义服务的骨架流程

### 实现方式

#### 抽象类

```php
namespace zxf\Security\Checkers;

use zxf\Security\Contracts\SecurityCheckerInterface;
use Illuminate\Http\Request;
use zxf\Security\Services\ConfigManager;

/**
 * 抽象安全检查器
 */
abstract class AbstractSecurityChecker implements SecurityCheckerInterface
{
    protected ConfigManager $config;
    protected string $name;
    protected int $priority = 100;
    protected bool $enabled = true;

    public function __construct(ConfigManager $config)
    {
        $this->config = $config;
        $this->enabled = $this->getConfigValue('enabled', true);
    }

    /**
     * 检查模板方法（骨架流程）
     */
    public function check(Request $request): array
    {
        // 1. 检查是否应该跳过
        if ($this->shouldSkip($request)) {
            return $this->skipResult($request);
        }

        // 2. 检查是否启用
        if (!$this->isEnabled()) {
            return $this->disabledResult($request);
        }

        // 3. 执行检查逻辑（由子类实现）
        return $this->doCheck($request);
    }

    /**
     * 执行检查逻辑（抽象方法）
     */
    abstract protected function doCheck(Request $request): array;

    /**
     * 检查是否应该跳过（可由子类重写）
     */
    protected function shouldSkip(Request $request): bool
    {
        return false;
    }

    /**
     * 生成成功结果
     */
    protected function successResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'success',
            'passed' => true,
            'message' => '安全检查通过',
        ];
    }

    /**
     * 生成失败结果
     */
    protected function failureResult(Request $request, string $message): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'failed',
            'passed' => false,
            'message' => $message,
        ];
    }

    /**
     * 生成跳过结果
     */
    protected function skipResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'skipped',
            'passed' => true,
            'message' => '检查已跳过',
        ];
    }

    /**
     * 生成禁用结果
     */
    protected function disabledResult(Request $request): array
    {
        return [
            'checker' => $this->getName(),
            'status' => 'disabled',
            'passed' => true,
            'message' => '检查器已禁用',
        ];
    }
}
```

#### 具体实现

```php
namespace zxf\Security\Checkers;

use Illuminate\Http\Request;

/**
 * SQL注入检查器
 */
class SqlInjectionChecker extends AbstractSecurityChecker
{
    protected string $name = 'SqlInjectionChecker';
    protected string $configPrefix = 'threat_detection.sql_injection';
    protected int $priority = 30;

    protected function doCheck(Request $request): array
    {
        $patterns = $this->getConfigValue('patterns', []);
        $dataSources = ['query', 'body', 'header'];

        foreach ($dataSources as $source) {
            $data = $this->getDataFromSource($request, $source);
            $detected = $this->detectSqlInjection($data, $patterns);

            if ($detected) {
                return $this->failureResult(
                    $request,
                    '检测到SQL注入攻击'
                );
            }
        }

        return $this->successResult($request);
    }

    protected function detectSqlInjection(array $data, array $patterns): bool
    {
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                foreach ($patterns as $pattern) {
                    if (@preg_match($pattern, $value)) {
                        $this->logDetection('SQL注入检测', [
                            'field' => $key,
                            'pattern' => $pattern,
                        ]);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
```

### 优势

1. **代码复用**: 公共逻辑在父类中实现一次
2. **扩展点清晰**: 子类只需实现特定的方法
3. **控制反转**: 父类控制流程，子类实现细节
4. **易于维护**: 修改算法结构只需修改父类

### 最佳实践

1. **模板方法**: 使用final防止子类重写
2. **钩子方法**: 提供可选的钩子方法
3. **文档清晰**: 明确标注哪些方法需要子类实现
4. **异常处理**: 在模板方法中统一处理异常

---

## 单例模式

### 定义

确保一个类只有一个实例，并提供一个全局访问点。

### 应用场景

- **配置管理器**: 全局唯一的配置管理器
- **缓存管理器**: 全局唯一的缓存管理器
- **日志记录器**: 全局唯一的日志记录器

### 实现方式

```php
namespace zxf\Security\Services;

use Illuminate\Support\Facades\Config;

/**
 * 配置管理器（单例模式）
 */
class ConfigManager
{
    private static ?ConfigManager $instance = null;
    
    protected array $config = [];

    /**
     * 私有构造函数
     */
    private function __construct()
    {
        $this->loadConfig();
    }

    /**
     * 获取单例实例
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 禁止克隆
     */
    private function __clone()
    {
        throw new \RuntimeException('ConfigManager cannot be cloned');
    }

    /**
     * 禁止反序列化
     */
    public function __wakeup(): void
    {
        throw new \RuntimeException('ConfigManager cannot be unserialized');
    }

    /**
     * 加载配置
     */
    protected function loadConfig(): void
    {
        $this->config = Config::get('security', []);
    }

    /**
     * 获取配置值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return data_get($this->config, $key, $default);
    }

    /**
     * 设置配置值
     */
    public function set(string $key, mixed $value): void
    {
        data_set($this->config, $key, $value);
    }
}
```

### 优势

1. **唯一实例**: 确保全局只有一个实例
2. **全局访问**: 提供全局访问点
3. **延迟初始化**: 首次使用时才创建实例
4. **线程安全**: 在PHP中由于单线程执行天然安全

### 最佳实践

1. **私有构造**: 防止外部创建实例
2. **禁止克隆**: 覆盖__clone方法
3. **禁止反序列化**: 覆盖__wakeup方法
4. **测试友好**: 提供reset方法用于测试

---

## 适配器模式

### 定义

将一个类的接口转换成客户希望的另一个接口。适配器模式使得原本由于接口不兼容而不能一起工作的那些类可以一起工作。

### 应用场景

- **缓存适配器**: 适配不同的缓存驱动
- **日志适配器**: 适配不同的日志驱动
- **数据库适配器**: 适配不同的数据库驱动

### 实现方式

#### 目标接口

```php
namespace zxf\Security\Contracts;

interface CacheManagerInterface
{
    public function get(string $key, mixed $default = null): mixed;
    public function set(string $key, mixed $value, ?int $ttl = null): bool;
    public function delete(string $key): bool;
    public function clear(): bool;
}
```

#### 被适配者

```php
namespace App\Services;

/**
 * 第三方缓存服务
 */
class ThirdPartyCacheService
{
    public function read(string $key): mixed
    {
        // 读取缓存
    }

    public function write(string $key, mixed $value, int $ttl): bool
    {
        // 写入缓存
    }

    public function remove(string $key): bool
    {
        // 删除缓存
    }

    public function flush(): bool
    {
        // 清空缓存
    }
}
```

#### 适配器

```php
namespace zxf\Security\Adapters;

use zxf\Security\Contracts\CacheManagerInterface;
use App\Services\ThirdPartyCacheService;

/**
 * 第三方缓存适配器
 */
class ThirdPartyCacheAdapter implements CacheManagerInterface
{
    protected ThirdPartyCacheService $cache;
    protected string $prefix = 'security:';

    public function __construct(ThirdPartyCacheService $cache)
    {
        $this->cache = $cache;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->cache->read($this->prefix . $key);
        return $value ?? $default;
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        return $this->cache->write($this->prefix . $key, $value, $ttl ?? 300);
    }

    public function delete(string $key): bool
    {
        return $this->cache->remove($this->prefix . $key);
    }

    public function clear(): bool
    {
        return $this->cache->flush();
    }
}
```

### 优势

1. **接口统一**: 统一不同服务的接口
2. **解耦**: 客户端不需要知道具体实现
3. **复用**: 可以复用现有的类
4. **灵活**: 可以随时切换不同的实现

### 最佳实践

1. **接口清晰**: 适配器接口应清晰易懂
2. **异常处理**: 适配器应处理好异常转换
3. **性能考虑**: 避免不必要的包装开销
4. **文档记录**: 记录适配器的转换逻辑

---

## 门面模式

### 定义

为子系统中的一组接口提供一个一致的界面，门面模式定义了一个高层接口，这个接口使得这一子系统更加容易使用。

### 应用场景

- **安全门面**: 提供统一的安全API
- **配置门面**: 提供统一的配置API
- **缓存门面**: 提供统一的缓存API

### 实现方式

```php
namespace zxf\Security\Facades;

use Illuminate\Support\Facades\Facade;
use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\ThreatDetectionService;

/**
 * 安全门面
 */
class Security extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'security';
    }

    /**
     * 添加IP到白名单
     */
    public static function addToWhitelist(string $ip, string $reason = ''): bool
    {
        return static::app(IpManagerService::class)->addToWhitelist($ip, $reason);
    }

    /**
     * 添加IP到黑名单
     */
    public static function addToBlacklist(string $ip, string $reason = ''): bool
    {
        return static::app(IpManagerService::class)->addToBlacklist($ip, $reason);
    }

    /**
     * 封禁IP
     */
    public static function banIp(string $ip, string $type = 'Manual', float $score = 0): bool
    {
        return static::app(IpManagerService::class)->banIp($ip, $type, $score);
    }

    /**
     * 解除IP封禁
     */
    public static function unbanIp(string $ip): bool
    {
        return static::app(IpManagerService::class)->unbanIp($ip);
    }

    /**
     * 检查限流
     */
    public static function checkRateLimit(\Illuminate\Http\Request $request): bool
    {
        return static::app(RateLimiterService::class)->checkRateLimit($request);
    }

    /**
     * 检测威胁
     */
    public static function detectThreats(\Illuminate\Http\Request $request): array
    {
        return static::app(ThreatDetectionService::class)->detectThreats($request);
    }
}
```

### 优势

1. **简化接口**: 提供简单易用的接口
2. **降低耦合**: 客户端不直接依赖子系统
3. **提高易用性**: 隐藏子系统的复杂性
4. **便于测试**: 可以更容易地模拟门面

### 最佳实践

1. **方法命名**: 门面方法名应清晰易懂
2. **参数设计**: 参数设计应简洁合理
3. **异常处理**: 门面应提供友好的异常信息
4. **文档完善**: 为门面提供详细的使用文档

---

## 依赖注入模式

### 定义

依赖注入（Dependency Injection, DI）是一种实现控制反转（Inversion of Control, IoC）的技术，它将类的依赖项从类内部移到类外部，由外部容器来提供依赖项。

### 应用场景

- **服务构造函数**: 通过构造函数注入依赖
- **方法参数**: 通过方法参数注入依赖
- **属性注入**: 通过属性注入依赖

### 实现方式

#### 构造函数注入

```php
namespace zxf\Security\Middleware;

use zxf\Security\Services\IpManagerService;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Services\ThreatDetectionService;
use Illuminate\Http\Request;
use Closure;

/**
 * 安全中间件
 */
class SecurityMiddleware
{
    protected IpManagerService $ipManager;
    protected RateLimiterService $rateLimiter;
    protected ThreatDetectionService $threatDetector;

    /**
     * 构造函数注入
     */
    public function __construct(
        IpManagerService $ipManager,
        RateLimiterService $rateLimiter,
        ThreatDetectionService $threatDetector
    ) {
        $this->ipManager = $ipManager;
        $this->rateLimiter = $rateLimiter;
        $this->threatDetector = $threatDetector;
    }

    public function handle(Request $request, Closure $next)
    {
        // 使用注入的服务
        if ($this->ipManager->isBlacklisted($request)) {
            return response('Access Denied', 403);
        }

        if (!$this->rateLimiter->checkRateLimit($request)) {
            return response('Too Many Requests', 429);
        }

        return $next($request);
    }
}
```

#### 方法注入

```php
namespace zxf\Security\Services;

use zxf\Security\Contracts\CacheManagerInterface;

/**
 * IP管理服务
 */
class IpManagerService
{
    /**
     * 方法注入：缓存管理器
     */
    public function getIpStats(string $ip, ?CacheManagerInterface $cache = null): array
    {
        // 使用注入的缓存管理器，如果没有则使用默认的
        $cache = $cache ?? app(CacheManagerInterface::class);
        
        return $cache->get("ip:stats:{$ip}", []);
    }
}
```

#### 接口注入

```php
namespace zxf\Security\Services;

use zxf\Security\Contracts\IpManagerInterface;
use zxf\Security\Contracts\RateLimiterInterface;
use zxf\Security\Contracts\ThreatDetectorInterface;

/**
 * 安全服务
 */
class SecurityService
{
    protected IpManagerInterface $ipManager;
    protected RateLimiterInterface $rateLimiter;
    protected ThreatDetectorInterface $threatDetector;

    /**
     * 构造函数注入（接口）
     */
    public function __construct(
        IpManagerInterface $ipManager,
        RateLimiterInterface $rateLimiter,
        ThreatDetectorInterface $threatDetector
    ) {
        $this->ipManager = $ipManager;
        $this->rateLimiter = $rateLimiter;
        $this->threatDetector = $threatDetector;
    }
}
```

### 优势

1. **降低耦合**: 类不再依赖于具体的实现
2. **易于测试**: 可以轻松注入Mock对象
3. **提高灵活性**: 可以轻松替换实现
4. **符合SOLID**: 遵循依赖倒置原则

### 最佳实践

1. **依赖接口**: 优先依赖接口而非具体类
2. **构造函数注入**: 优先使用构造函数注入
3. **合理设计**: 避免过多的依赖
4. **明确文档**: 为依赖项提供清晰的文档

---

## 总结

### 设计模式总结

| 模式 | 用途 | 优势 | 适用场景 |
|-----|------|------|---------|
| 责任链模式 | 请求处理链 | 降低耦合，灵活扩展 | 中间件处理链 |
| 策略模式 | 算法封装 | 算法可互换，易于扩展 | 威胁检测、限流 |
| 工厂模式 | 对象创建 | 解耦创建和使用 | 检查器创建 |
| 装饰器模式 | 动态扩展 | 运行时扩展，灵活组合 | 缓存装饰器 |
| 观察者模式 | 事件监听 | 松耦合，易于扩展 | 事件系统 |
| 模板方法模式 | 算法骨架 | 代码复用，扩展点清晰 | 抽象检查器 |
| 单例模式 | 唯一实例 | 全局访问，延迟初始化 | 配置管理器 |
| 适配器模式 | 接口适配 | 统一接口，复用现有类 | 缓存适配器 |
| 门面模式 | 简化接口 | 简化复杂系统 | 安全门面 |
| 依赖注入模式 | 依赖管理 | 降低耦合，易于测试 | 服务依赖 |

### 设计原则

1. **SOLID原则**: 单一职责、开闭、里氏替换、接口隔离、依赖倒置
2. **DRY原则**: 不要重复自己
3. **KISS原则**: 保持简单
4. **YAGNI原则**: 你不会需要它（不要过度设计）

### 最佳实践

1. **模式选择**: 根据实际需求选择合适的设计模式
2. **文档记录**: 为模式的使用提供详细文档
3. **代码审查**: 通过代码审查确保模式正确使用
4. **性能考虑**: 注意模式对性能的影响

---

**文档版本**: 3.0.0  
**最后更新**: 2026-03-01  
**作者**: zxf
