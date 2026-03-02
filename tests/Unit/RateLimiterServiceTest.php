<?php

namespace zxf\Security\Tests\Unit;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use zxf\Security\Services\RateLimiterService;
use zxf\Security\Tests\TestCase;
use function zxf\Security\security_check_rate_limit;

class RateLimiterServiceTest extends TestCase
{
    protected RateLimiterService $rateLimiter;

    protected function setUp(): void
    {
        parent::setUp();

        $this->rateLimiter = app(RateLimiterService::class);

        // 清理缓存
        $this->rateLimiter->clearCache();
    }

    /** @test */
    public function it_can_check_rate_limit_for_ip()
    {
        $ip = '192.168.1.1';
        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        $result = $this->rateLimiter->check($request);

        $this->assertIsArray($result);
        $this->assertFalse($result['blocked']);
    }

    /** @test */
    public function it_can_block_request_when_rate_limit_exceeded()
    {
        $ip = '192.168.1.2';
        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        // 设置极低限制用于测试
        config(['security.rate_limits.second' => 1]);

        // 第一次请求应该通过
        $result1 = $this->rateLimiter->check($request);
        $this->assertFalse($result1['blocked']);

        // 第二次请求应该被限制
        $result2 = $this->rateLimiter->check($request);
        $this->assertTrue($result2['blocked']);
        $this->assertArrayHasKey('retry_after', $result2);
    }

    /** @test */
    public function it_can_increment_rate_limit_counter()
    {
        $ip = '192.168.1.3';

        security_increment_rate_limit($ip);

        $rateInfo = $this->rateLimiter->getClientRateInfo(
            Request::create('/', 'GET')->server->set('REMOTE_ADDR', $ip)
        );

        $this->assertEquals(1, $rateInfo['second']['count']);
    }

    /** @test */
    public function it_can_clear_rate_limit_for_ip()
    {
        $ip = '192.168.1.4';

        // 增加计数
        security_increment_rate_limit($ip);

        // 清除限制
        security_clear_rate_limit($ip);

        // 检查应该通过
        $result = $this->rateLimiter->check(
            Request::create('/', 'GET')->server->set('REMOTE_ADDR', $ip)
        );

        $this->assertFalse($result['blocked']);
    }

    /** @test */
    public function it_can_get_client_rate_info()
    {
        $ip = '192.168.1.5';
        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        security_increment_rate_limit($ip);

        $rateInfo = $this->rateLimiter->getClientRateInfo($request);

        $this->assertIsArray($rateInfo);
        $this->assertArrayHasKey('second', $rateInfo);
        $this->assertArrayHasKey('minute', $rateInfo);
        $this->assertArrayHasKey('hour', $rateInfo);
        $this->assertArrayHasKey('day', $rateInfo);
    }

    /** @test */
    public function it_can_batch_check_multiple_fingerprints()
    {
        $fingerprints = [
            'fp1' => '192.168.1.10',
            'fp2' => '192.168.1.11',
            'fp3' => '192.168.1.12',
        ];

        $results = $this->rateLimiter->batchCheck($fingerprints);

        $this->assertIsArray($results);
        $this->assertCount(3, $results);
    }

    /** @test */
    public function it_can_get_rate_limit_stats()
    {
        $ip = '192.168.1.6';

        security_increment_rate_limit($ip);

        $stats = $this->rateLimiter->getRateLimitStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_checks', $stats);
        $this->assertArrayHasKey('total_blocked', $stats);
    }

    /** @test */
    public function it_can_reset_client_rate_limit()
    {
        $ip = '192.168.1.7';
        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        security_increment_rate_limit($ip);

        $result = $this->rateLimiter->resetClientRateLimit($request);

        $this->assertTrue($result);
    }

    /** @test */
    public function it_uses_different_rate_limits_for_different_windows()
    {
        $ip = '192.168.1.8';
        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        // 设置不同窗口的限制
        config([
            'security.rate_limits.second' => 2,
            'security.rate_limits.minute' => 5,
            'security.rate_limits.hour' => 10,
        ]);

        // 发送2个请求
        for ($i = 0; $i < 2; $i++) {
            $this->rateLimiter->check($request);
            security_increment_rate_limit($ip);
        }

        // 第3个请求应该在秒级窗口被限制
        $result = $this->rateLimiter->check($request);
        $this->assertTrue($result['blocked']);
    }
}
