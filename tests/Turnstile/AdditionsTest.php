<?php
/**
 * What Turnstile gained in the move: named error codes, narrowed copies of
 * a verifier, a bounded answer, and the module served from the library.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\Turnstile\ErrorCode;
use SugarCommerce\Security\Turnstile\Reason;
use SugarCommerce\Security\Turnstile\Turnstile;
use SugarCommerce\Security\Turnstile\Verification;
use SugarCommerce\Security\Turnstile\Verifier;

final class AdditionsTest extends TestCase {

	private const SECRET = '0x4AAAAAAAreal-secret-key';

	protected function setUp(): void {
		ts_reset();
	}

	/* ─── Error codes ──────────────────────────────────────────────── */

	public function test_cloudflares_codes_are_named(): void {
		$answer = Verification::from_siteverify(
			array(
				'success'     => false,
				'error-codes' => array( 'timeout-or-duplicate', 'something-new' ),
			)
		);

		$this->assertSame( array( ErrorCode::TimeoutOrDuplicate, ErrorCode::Unknown ), $answer->errors() );
		$this->assertTrue( $answer->has( ErrorCode::TimeoutOrDuplicate ) );
		$this->assertFalse( $answer->has( ErrorCode::InternalError ) );
		$this->assertSame( array( 'timeout-or-duplicate', 'something-new' ), $answer->codes, 'The raw codes are kept for the log.' );
	}

	public function test_cloudflare_saying_unknown_is_not_a_code(): void {
		$this->assertSame( ErrorCode::Unknown, ErrorCode::from_cloudflare( 'unknown' ) );
		$this->assertSame( ErrorCode::BadRequest, ErrorCode::from_cloudflare( 'bad-request' ) );
	}

	public function test_only_secret_and_widget_codes_are_the_sites_fault(): void {
		$sites = array( ErrorCode::MissingInputSecret, ErrorCode::InvalidInputSecret, ErrorCode::InvalidParsedSecret, ErrorCode::InvalidWidgetId );

		foreach ( ErrorCode::cases() as $code ) {
			$this->assertSame( in_array( $code, $sites, true ), $code->misconfigured(), $code->value );

			$answer = Verification::from_siteverify(
				array(
					'success'     => false,
					'error-codes' => array( $code->value ),
				)
			);

			$this->assertSame( in_array( $code, $sites, true ), $answer->misconfigured(), $code->value );
		}

		$this->assertTrue( Verification::unanswered( Reason::NoSecret )->misconfigured() );
		$this->assertFalse( Verification::unanswered( Reason::NoToken )->misconfigured() );
	}

	public function test_only_an_internal_error_is_worth_retrying(): void {
		foreach ( ErrorCode::cases() as $code ) {
			$this->assertSame( ErrorCode::InternalError === $code, $code->worth_retrying(), $code->value );
		}
	}

	public function test_an_internal_error_is_cloudflare_being_unavailable(): void {
		$answer = Verification::from_siteverify(
			array(
				'success'     => false,
				'error-codes' => array( 'internal-error' ),
			)
		);

		$this->assertTrue( $answer->unavailable() );
		$this->assertFalse( $answer->stale() );
	}

	/* ─── Narrowed copies ──────────────────────────────────────────── */

	public function test_for_hostnames_narrows_a_copy_and_leaves_the_original(): void {
		$any  = new Verifier( self::SECRET );
		$shop = $any->for_hostnames( 'Shop.Example.com' );

		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'hostname' => 'evil.example' ) ),
			ts_answer( array( 'success' => true, 'hostname' => 'evil.example' ) ),
			ts_answer( array( 'success' => true, 'hostname' => 'shop.example.com' ) ),
		);

		$this->assertTrue( $any->verify( 'token' )->success );
		$this->assertSame( Reason::WrongHostname, $shop->verify( 'token' )->reason );
		$this->assertTrue( $shop->verify( 'token' )->success );
	}

	public function test_for_action_narrows_a_copy_and_leaves_the_original(): void {
		$any    = new Verifier( self::SECRET );
		$signup = $any->for_action( 'signup' );

		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'action' => 'login' ) ),
			ts_answer( array( 'success' => true, 'action' => 'login' ) ),
		);

		$this->assertTrue( $any->verify( 'token' )->success );
		$this->assertSame( Reason::WrongAction, $signup->verify( 'token' )->reason );
	}

	public function test_passes_is_verify_without_the_reason(): void {
		$verifier = new Verifier( self::SECRET );

		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true ) ),
			ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) ),
		);

		$this->assertTrue( $verifier->passes( 'token', '203.0.113.9' ) );
		$this->assertFalse( $verifier->passes( 'token' ) );
		$this->assertFalse( $verifier->passes( '' ), 'No token is refused without asking.' );
		$this->assertCount( 2, $GLOBALS['ts_requests'] );
		$this->assertSame( '203.0.113.9', $GLOBALS['ts_requests'][0][1]['body']['remoteip'] );
	}

	/* ─── The request ──────────────────────────────────────────────── */

	public function test_the_answer_read_is_bounded(): void {
		$GLOBALS['ts_responses'] = array( ts_answer( array( 'success' => true ) ) );

		( new Verifier( self::SECRET ) )->verify( 'token' );

		$this->assertSame( Verifier::MAX_ANSWER, $GLOBALS['ts_requests'][0][1]['limit_response_size'] );
		$this->assertSame( 0, $GLOBALS['ts_requests'][0][1]['redirection'] );
	}

	/* ─── Test secrets ─────────────────────────────────────────────── */

	public function test_any_prefix_counts_every_1x_2x_3x_secret(): void {
		$this->assertFalse( Verifier::is_test_secret( '1x0000-reshaped' ) );
		$this->assertTrue( Verifier::is_test_secret( '1x0000-reshaped', true ) );
		$this->assertTrue( Verifier::is_test_secret( '3xABC', true ) );
		$this->assertFalse( Verifier::is_test_secret( '4x0000000000000000000000AA', true ) );
		$this->assertFalse( Verifier::is_test_secret( '1X0000', true ), 'Cloudflare writes a lower-case x.' );
		$this->assertTrue( Verifier::is_test_secret( '2x0000000000000000000000000000000AA' ) );
	}

	/* ─── The module ───────────────────────────────────────────────── */

	public function test_the_module_is_served_from_the_library_by_default(): void {
		$turnstile = new Turnstile( array( 'id' => 'demo' ) );

		$this->assertSame( 'https://example.com/wp-content/security/assets/js/turnstile.js', $turnstile->widget()->module_url() );
	}

	public function test_a_module_url_given_wins(): void {
		$turnstile = new Turnstile(
			array(
				'id'         => 'demo',
				'module_url' => 'https://cdn.example/turnstile.js',
			)
		);

		$this->assertSame( 'https://cdn.example/turnstile.js', $turnstile->widget()->module_url() );
	}
}
