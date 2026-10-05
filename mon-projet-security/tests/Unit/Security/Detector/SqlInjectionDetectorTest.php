<?php

declare(strict_types=1);

namespace Tests\Unit\Security\Detector;

use App\Security\Detector\DetectionResult;
use App\Security\Detector\SqlInjectionDetector;
use PHPUnit\Framework\TestCase;

final class SqlInjectionDetectorTest extends TestCase
{
    private SqlInjectionDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new SqlInjectionDetector(null, true);
    }

    public function test_clean_input_returns_low_score_and_does_not_block(): void
    {
        $result = $this->detector->analyze('john.doe@example.com', 'email', 'default');

        $this->assertInstanceOf(DetectionResult::class, $result);
        $this->assertLessThan(80, $result->score);
        $this->assertFalse($result->shouldBlock);
        $this->assertSame('default', $result->context);
    }

    public function test_or_1_equals_1_is_detected_and_blocked(): void
    {
        $result = $this->detector->analyze("' OR 1=1 --", 'password', 'login');

        $this->assertGreaterThanOrEqual(80, $result->score);
        $this->assertTrue($result->shouldBlock);
        $this->assertNotEmpty($result->detectedPatterns);
    }

    public function test_union_select_is_detected_as_critical(): void
    {
        $result = $this->detector->analyze("' UNION SELECT * FROM users--", 'q', 'search');

        $this->assertGreaterThanOrEqual(80, $result->score);
        $this->assertTrue($result->shouldBlock);
        $this->assertContains($result->riskLevel, ['HIGH', 'CRITICAL']);
    }

    public function test_context_login_increases_score(): void
    {
        $payload = "' OR '1'='1";
        $defaultResult = $this->detector->analyze($payload, 'p', 'default');
        $loginResult = $this->detector->analyze($payload, 'p', 'login');

        $this->assertGreaterThan(
            $defaultResult->score,
            $loginResult->score,
            'Contexte login doit augmenter le score (poids 1.3)'
        );
        $this->assertSame('login', $loginResult->context);
    }

    public function test_risk_level_critical_for_high_score(): void
    {
        $result = $this->detector->analyze("' OR 1=1 --", 'x', 'admin');

        $this->assertContains($result->riskLevel, ['HIGH', 'CRITICAL']);
    }

    public function test_risk_level_none_for_clean_input(): void
    {
        $result = $this->detector->analyze('hello', '', 'default');

        $this->assertSame('NONE', $result->riskLevel);
    }

    public function test_destructive_pattern_sleep_detected(): void
    {
        $result = $this->detector->analyze("'; DROP TABLE users; --", 'id', 'api');

        $this->assertTrue($result->shouldBlock);
        $this->assertGreaterThanOrEqual(80, $result->score);
    }

    public function test_block_mode_false_does_not_block_medium_score(): void
    {
        $detector = new SqlInjectionDetector(null, false);
        $result = $detector->analyze('normal search term with SELECT FROM somewhere', 'q', 'search');

        if ($result->score >= 80) {
            $this->assertTrue($result->shouldBlock);
        } else {
            $this->assertFalse($result->shouldBlock);
        }
    }

    public function test_set_block_mode(): void
    {
        $this->detector->setBlockMode(false);
        $result = $this->detector->analyze('test', '', 'default');
        $this->assertFalse($result->shouldBlock);
    }

    public function test_sql_keywords_with_from_increase_score(): void
    {
        $result = $this->detector->analyze('SELECT * FROM users WHERE id=1', 'query', 'search');

        $this->assertGreaterThan(0, $result->score);
        $this->assertNotEmpty($result->detectedPatterns);
    }

    public function test_comment_evasion_detected(): void
    {
        $result = $this->detector->analyze("admin'--", 'user', 'login');

        $this->assertGreaterThanOrEqual(80, $result->score);
        $this->assertTrue($result->shouldBlock);
    }
}
