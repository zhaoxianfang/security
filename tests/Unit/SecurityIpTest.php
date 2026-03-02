<?php

namespace zxf\Security\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use zxf\Security\Models\SecurityIp;
use zxf\Security\Tests\TestCase;
use function zxf\Security\{security_is_whitelisted, security_is_blacklisted};

class SecurityIpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 清空测试数据
        SecurityIp::query()->delete();
        Cache::forget('security:whitelist');
        Cache::forget('security:blacklist');
    }

    /** @test */
    public function it_can_add_ip_to_whitelist()
    {
        $ip = '192.168.1.100';
        $reason = '测试服务器';

        $result = security_add_to_whitelist($ip, $reason);

        $this->assertTrue($result);

        $securityIp = SecurityIp::where('ip_address', $ip)->first();
        $this->assertNotNull($securityIp);
        $this->assertEquals('whitelist', $securityIp->type);
        $this->assertEquals($reason, $securityIp->reason);
    }

    /** @test */
    public function it_can_add_ip_to_blacklist()
    {
        $ip = '10.0.0.100';
        $reason = '恶意攻击';

        $result = security_add_to_blacklist($ip, $reason);

        $this->assertTrue($result);

        $securityIp = SecurityIp::where('ip_address', $ip)->first();
        $this->assertNotNull($securityIp);
        $this->assertEquals('blacklist', $securityIp->type);
        $this->assertEquals($reason, $securityIp->reason);
    }

    /** @test */
    public function it_can_check_if_ip_is_whitelisted()
    {
        $ip = '192.168.1.101';
        security_add_to_whitelist($ip, '测试');

        $this->assertTrue(security_is_whitelisted($ip));
        $this->assertFalse(security_is_blacklisted($ip));
    }

    /** @test */
    public function it_can_check_if_ip_is_blacklisted()
    {
        $ip = '10.0.0.101';
        security_add_to_blacklist($ip, '测试');

        $this->assertTrue(security_is_blacklisted($ip));
        $this->assertFalse(security_is_whitelisted($ip));
    }

    /** @test */
    public function it_can_add_cidr_range()
    {
        $cidr = '10.0.0.0/24';
        $reason = '僵尸网络';

        $result = security_add_to_blacklist($cidr, $reason);

        $this->assertTrue($result);

        $securityIp = SecurityIp::where('ip_address', $cidr)->first();
        $this->assertNotNull($securityIp);
        $this->assertEquals('blacklist', $securityIp->type);
    }

    /** @test */
    public function it_can_check_cidr_range()
    {
        $cidr = '10.0.0.0/24';
        security_add_to_blacklist($cidr, '测试');

        $this->assertTrue(security_is_blacklisted('10.0.0.1'));
        $this->assertTrue(security_is_blacklisted('10.0.0.255'));
        $this->assertFalse(security_is_blacklisted('10.0.1.1'));
    }

    /** @test */
    public function it_can_remove_ip_from_whitelist()
    {
        $ip = '192.168.1.102';
        security_add_to_whitelist($ip, '测试');

        $result = SecurityIp::removeFromWhitelist($ip);

        $this->assertTrue($result);
        $this->assertFalse(security_is_whitelisted($ip));
    }

    /** @test */
    public function it_can_remove_ip_from_blacklist()
    {
        $ip = '10.0.0.102';
        security_add_to_blacklist($ip, '测试');

        $result = SecurityIp::removeFromBlacklist($ip);

        $this->assertTrue($result);
        $this->assertFalse(security_is_blacklisted($ip));
    }

    /** @test */
    public function it_can_update_threat_score()
    {
        $ip = '192.168.1.103';
        SecurityIp::addToWhitelist($ip, '测试');

        $securityIp = SecurityIp::where('ip_address', $ip)->first();
        $securityIp->threat_score = 50.0;
        $securityIp->save();

        $this->assertEquals(50.0, $securityIp->fresh()->threat_score);
    }

    /** @test */
    public function it_can_check_and_update_type_based_on_threat_score()
    {
        $ip = '192.168.1.104';
        $securityIp = SecurityIp::addToMonitoring($ip, '测试');

        // 提高威胁评分
        $securityIp->threat_score = 85.0;
        $securityIp->trigger_count = 6;
        $securityIp->save();

        $securityIp->checkAndUpdateType();

        $this->assertEquals('blacklist', $securityIp->fresh()->type);
    }

    /** @test */
    public function it_can_apply_natural_decay_to_threat_score()
    {
        $ip = '192.168.1.105';
        $securityIp = SecurityIp::addToMonitoring($ip, '测试');
        $securityIp->threat_score = 100.0;
        $securityIp->save();

        $securityIp->applyNaturalDecay();

        $this->assertLessThan(100.0, $securityIp->fresh()->threat_score);
    }

    /** @test */
    public function it_can_record_request()
    {
        $ip = '192.168.1.106';
        $securityIp = SecurityIp::addToMonitoring($ip, '测试');

        $securityIp->recordRequest($ip, false);

        $this->assertEquals(1, $securityIp->fresh()->request_count);
    }

    /** @test */
    public function it_can_cleanup_expired_records()
    {
        $ip1 = '192.168.1.107';
        $ip2 = '192.168.1.108';

        SecurityIp::addToWhitelist($ip1, '测试', now()->addDays(-1));
        SecurityIp::addToBlacklist($ip2, '测试', now()->addWeek());

        $count = SecurityIp::cleanupExpired();

        $this->assertGreaterThan(0, $count);
    }

    /** @test */
    public function it_can_batch_check_ips()
    {
        $ips = ['192.168.1.200', '192.168.1.201', '192.168.1.202'];

        security_add_to_whitelist($ips[0], '测试1');
        security_add_to_blacklist($ips[1], '测试2');

        $results = SecurityIp::batchCheck($ips);

        $this->assertEquals('whitelist', $results[$ips[0]]);
        $this->assertEquals('blacklist', $results[$ips[1]]);
        $this->assertNull($results[$ips[2]]);
    }

    /** @test */
    public function it_can_get_ip_stats()
    {
        $ip = '192.168.1.109';
        security_add_to_whitelist($ip, '测试');

        $stats = SecurityIp::getIpStats($ip);

        $this->assertIsArray($stats);
        $this->assertEquals($ip, $stats['ip_address']);
        $this->assertArrayHasKey('type', $stats);
        $this->assertArrayHasKey('threat_score', $stats);
    }

    /** @test */
    public function it_can_get_high_threat_ips()
    {
        $ip1 = '10.0.0.50';
        $ip2 = '10.0.0.51';

        $secIp1 = SecurityIp::addToMonitoring($ip1, '测试1');
        $secIp1->threat_score = 90.0;
        $secIp1->save();

        $secIp2 = SecurityIp::addToMonitoring($ip2, '测试2');
        $secIp2->threat_score = 85.0;
        $secIp2->save();

        $highThreatIps = SecurityIp::getHighThreatIps(10);

        $this->assertCount(2, $highThreatIps);
    }
}
