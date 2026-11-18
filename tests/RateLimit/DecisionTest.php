<?php
/**
 * Headers, and the decision worth reporting.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use SugarCommerce\Security\RateLimit\Decision;
use PHPUnit\Framework\TestCase;

final class DecisionTest extends TestCase {

	private const NOW = 1800000040;

	private function decision( int $limit, int $count, ?bool $allowed = null ): Decision {
		return new Decision( $allowed ?? $count <= $limit, $limit, $count, max( 0, $limit - $count ), 1800000060, 60, self::NOW );
	}

	public function test_legacy_headers_on_an_allowed_request(): void {
		$this->assertSame(
			array(
				'X-RateLimit-Limit'     => '120',
				'X-RateLimit-Remaining' => '117',
				'X-RateLimit-Reset'     => '1800000060',
			),
			$this->decision( 120, 3 )->headers()
		);
	}

	public function test_legacy_headers_on_a_refusal_carry_retry_after(): void {
		$headers = $this->decision( 10, 11 )->headers( Decision::LEGACY );

		$this->assertSame( '0', $headers['X-RateLimit-Remaining'] );
		$this->assertSame( '20', $headers['Retry-After'] );
	}

	public function test_standard_headers(): void {
		$this->assertSame(
			array(
				'RateLimit-Limit'     => '10',
				'RateLimit-Remaining' => '0',
				'RateLimit-Reset'     => '20',
				'RateLimit-Policy'    => '10;w=60',
				'Retry-After'         => '20',
			),
			$this->decision( 10, 12 )->headers( Decision::STANDARD )
		);
	}

	public function test_retry_after_only_on_a_refusal_unless_asked_for_when_spent(): void {
		$spent = $this->decision( 10, 10 );

		$this->assertTrue( $spent->allowed );
		$this->assertArrayNotHasKey( 'Retry-After', $spent->headers() );
		$this->assertSame( '20', $spent->headers( Decision::LEGACY, true )['Retry-After'] );
		$this->assertArrayNotHasKey( 'Retry-After', $this->decision( 10, 9 )->headers( Decision::LEGACY, true ) );
	}

	public function test_retry_after_is_at_least_one_second(): void {
		$decision = new Decision( false, 1, 2, 0, 1800000060, 60, 1800000060 );

		$this->assertSame( 1, $decision->retry_after() );
	}

	public function test_tightest_prefers_a_refusal(): void {
		$general = $this->decision( 120, 3 );
		$money   = $this->decision( 10, 11 );

		$this->assertSame( $money, Decision::tightest( $general, $money ) );
		$this->assertSame( $money, Decision::tightest( $money, $general ) );
	}

	public function test_tightest_otherwise_reports_the_least_remaining(): void {
		$general = $this->decision( 120, 3 );
		$money   = $this->decision( 10, 3 );

		$this->assertSame( $money, Decision::tightest( $general, $money ) );
		$this->assertSame( $money, Decision::tightest( $money, $general ) );
	}

	public function test_tightest_of_two_refusals_is_the_longer_wait(): void {
		$soon  = new Decision( false, 5, 6, 0, 1800000060, 60, self::NOW );
		$later = new Decision( false, 5, 6, 0, 1800000600, 600, self::NOW );

		$this->assertSame( $later, Decision::tightest( $soon, $later ) );
		$this->assertSame( $later, Decision::tightest( $later, $soon ) );
	}

	public function test_tightest_ignores_unlimited_and_is_unlimited_of_nothing(): void {
		$general = $this->decision( 120, 3 );

		$this->assertSame( $general, Decision::tightest( Decision::unlimited(), $general ) );
		$this->assertFalse( Decision::tightest()->limited );
		$this->assertFalse( Decision::tightest( Decision::unlimited() )->limited );
	}
}
