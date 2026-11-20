<?php
/**
 * Verification: whose fault a refusal is.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Models\Turnstile\Reason;
use SugarCommerce\Security\Models\Turnstile\Verification;
use PHPUnit\Framework\TestCase;

final class VerificationTest extends TestCase {

	public function test_each_secret_code_is_a_configuration_problem(): void {
		foreach ( array( 'missing-input-secret', 'invalid-input-secret', 'invalid-parsed-secret', 'invalid-widget-id' ) as $code ) {
			$answer = Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( $code ) ) );

			$this->assertTrue( $answer->misconfigured(), $code );
			$this->assertFalse( $answer->unavailable(), $code );
		}

		$this->assertFalse( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) )->misconfigured() );
	}

	public function test_internal_error_is_cloudflare_and_bad_request_is_not(): void {
		$this->assertTrue( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'internal-error' ) ) )->unavailable() );
		$this->assertFalse( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'bad-request' ) ) )->unavailable() );
	}

	public function test_a_spent_token_is_stale(): void {
		$this->assertTrue( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'timeout-or-duplicate' ) ) )->stale() );
		$this->assertFalse( Verification::unanswered( Reason::Unreachable )->stale() );
	}

	public function test_success_has_no_reason_and_anything_of_the_wrong_type_is_absent(): void {
		$answer = Verification::from_siteverify( array( 'success' => true, 'hostname' => 5, 'action' => array( 'x' ), 'error-codes' => 'nope' ) );

		$this->assertTrue( $answer->success );
		$this->assertNull( $answer->reason );
		$this->assertSame( '', $answer->hostname );
		$this->assertSame( '', $answer->action );
		$this->assertSame( array(), $answer->codes );
		$this->assertSame( array(), $answer->summary() );

		$this->assertFalse( Verification::from_siteverify( array( 'success' => 'true' ) )->success, 'Only true is success.' );
	}

	public function test_refused_keeps_what_cloudflare_said(): void {
		$answer = Verification::from_siteverify( array( 'success' => true, 'hostname' => 'a.example', 'action' => 'x', 'challenge_ts' => '2026-10-22T15:14:30.096Z' ) )->refused( Reason::WrongHostname );

		$this->assertFalse( $answer->success );
		$this->assertSame( 'a.example', $answer->hostname );
		$this->assertSame( 'x', $answer->action );
		$this->assertNotNull( $answer->challenged_at );
		$this->assertSame( array( 'wrong_hostname' ), $answer->summary() );
	}

	public function test_age_is_never_negative_and_null_when_unknown(): void {
		$answer = Verification::from_siteverify( array( 'success' => true, 'challenge_ts' => '2026-10-22T15:14:30Z' ) );
		$at     = $answer->challenged_at->getTimestamp();

		$this->assertSame( 30, $answer->age( $at + 30 ) );
		$this->assertSame( 0, $answer->age( $at - 5 ) );
		$this->assertNull( Verification::from_siteverify( array( 'success' => true ) )->age() );
		$this->assertNull( Verification::from_siteverify( array( 'success' => true, 'challenge_ts' => '+1 year' ) )->age() );
	}

	public function test_reason_values_never_change(): void {
		$this->assertSame(
			array( 'no_secret', 'no_token', 'token_too_long', 'unreachable', 'http_error', 'unreadable', 'rejected', 'wrong_hostname', 'wrong_action', 'expired' ),
			array_map( static fn( Reason $reason ): string => $reason->value, Reason::cases() )
		);
	}
}
