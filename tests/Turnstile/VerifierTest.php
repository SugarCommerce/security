<?php
/**
 * Verifier and Verification: asking Cloudflare, and reading the answer.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Turnstile\Reason;
use SugarCommerce\Security\Turnstile\Verification;
use SugarCommerce\Security\Turnstile\Verifier;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class VerifierTest extends TestCase {

	private const SECRET = '0x4AAAAAAAreal-secret';

	protected function setUp(): void {
		ts_reset();
	}

	public function test_it_posts_the_four_parameters_siteverify_takes(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true ) );

		( new Verifier( self::SECRET, array(), '', 7 ) )->verify( 'tok', '203.0.113.9', 'key-1' );

		[ $url, $args ] = $GLOBALS['ts_requests'][0];

		$this->assertSame( Verifier::ENDPOINT, $url );
		$this->assertSame(
			array(
				'secret'          => self::SECRET,
				'response'        => 'tok',
				'remoteip'        => '203.0.113.9',
				'idempotency_key' => 'key-1',
			),
			$args['body']
		);
		$this->assertSame( 7, $args['timeout'] );
		$this->assertSame( 0, $args['redirection'] );
	}

	public function test_an_address_that_is_not_one_and_an_empty_key_are_left_out(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true ) );

		( new Verifier( self::SECRET, array(), '', 0 ) )->verify( 'tok', 'not-an-ip' );

		$args = $GLOBALS['ts_requests'][0][1];

		$this->assertSame( array( 'secret', 'response' ), array_keys( $args['body'] ) );
		$this->assertSame( 1, $args['timeout'], 'At least a second.' );
	}

	public function test_nothing_is_sent_without_a_secret_a_token_or_with_a_token_too_long(): void {
		$this->assertSame( Reason::NoSecret, ( new Verifier( '' ) )->verify( 'tok' )->reason );
		$this->assertSame( Reason::NoToken, ( new Verifier( self::SECRET ) )->verify( '' )->reason );
		$this->assertSame( Reason::TokenTooLong, ( new Verifier( self::SECRET ) )->verify( str_repeat( 'a', Verifier::MAX_TOKEN + 1 ) )->reason );
		$this->assertSame( array(), $GLOBALS['ts_requests'] );

		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true ) );
		$this->assertTrue( ( new Verifier( self::SECRET ) )->verify( str_repeat( 'a', Verifier::MAX_TOKEN ) )->success, 'The longest token Cloudflare issues is asked about.' );
	}

	public function test_no_secret_is_a_configuration_problem(): void {
		$answer = ( new Verifier( '' ) )->verify( 'tok' );

		$this->assertTrue( $answer->misconfigured() );
		$this->assertFalse( $answer->unavailable() );
		$this->assertFalse( ( new Verifier( '' ) )->configured() );
		$this->assertTrue( ( new Verifier( self::SECRET ) )->configured() );
	}

	public function test_no_answer_a_server_error_and_an_unreadable_answer_are_cloudflare_unavailable(): void {
		$GLOBALS['ts_responses'] = array(
			new WP_Error( 'http_request_failed', 'timed out' ),
			ts_answer( array( 'success' => false, 'error-codes' => array( 'internal-error' ) ), 500 ),
			array( 'response' => array( 'code' => 502 ), 'body' => '<html>' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json' ),
			ts_answer( array( 'success' => 'yes' ) ),
		);

		$verifier = new Verifier( self::SECRET );
		$answers  = array();

		for ( $i = 0; $i < 5; $i++ ) {
			$answers[] = $verifier->verify( 'tok' );
		}

		$this->assertSame( array( Reason::Unreachable, Reason::HttpError, Reason::HttpError, Reason::Unreadable, Reason::Unreadable ), array_map( static fn( Verification $v ) => $v->reason, $answers ) );
		$this->assertSame( array( 'internal-error' ), $answers[1]->codes, 'The codes of a server error are kept for the log.' );

		foreach ( $answers as $answer ) {
			$this->assertFalse( $answer->success );
			$this->assertTrue( $answer->unavailable() );
		}
	}

	public function test_a_rejection_keeps_cloudflares_codes(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response', 42 ) ) );

		$answer = ( new Verifier( self::SECRET ) )->verify( 'tok' );

		$this->assertSame( Reason::Rejected, $answer->reason );
		$this->assertSame( array( 'invalid-input-response' ), $answer->codes );
		$this->assertSame( array( 'invalid-input-response' ), $answer->summary() );
		$this->assertFalse( $answer->misconfigured() );
		$this->assertFalse( $answer->unavailable() );
		$this->assertFalse( $answer->stale() );
	}

	public function test_a_token_from_another_hostname_is_refused(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'hostname' => 'evil.example' ) ),
			ts_answer( array( 'success' => true, 'hostname' => 'WWW.Example.com' ) ),
			ts_answer( array( 'success' => true ) ),
		);

		$verifier = new Verifier( self::SECRET, array( ' www.example.com ', '', 'example.com' ) );

		$this->assertSame( Reason::WrongHostname, $verifier->verify( 'tok' )->reason );
		$this->assertTrue( $verifier->verify( 'tok' )->success, 'Compared without case.' );
		$this->assertSame( Reason::WrongHostname, $verifier->verify( 'tok' )->reason, 'An answer without a hostname cannot be shown to be for this site.' );
	}

	public function test_a_missing_hostname_is_refused_only_when_one_is_expected(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'hostname' => '' ) ),
			ts_answer( array( 'success' => true, 'hostname' => '' ) ),
		);

		$this->assertSame( Reason::WrongHostname, ( new Verifier( self::SECRET, array( 'example.com' ) ) )->verify( 'tok' )->reason );
		$this->assertTrue( ( new Verifier( self::SECRET ) )->verify( 'tok' )->success, 'With no expectation, any hostname will do.' );
	}

	public function test_no_hostnames_accepts_any(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'hostname' => 'anywhere.example' ) );

		$this->assertTrue( ( new Verifier( self::SECRET ) )->verify( 'tok' )->success );
	}

	public function test_a_token_for_another_form_is_refused(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'action' => 'login' ) ),
			ts_answer( array( 'success' => true, 'action' => 'signup' ) ),
			ts_answer( array( 'success' => true ) ),
		);

		$verifier = new Verifier( self::SECRET, array(), 'signup' );

		$answer = $verifier->verify( 'tok' );

		$this->assertSame( Reason::WrongAction, $answer->reason );
		$this->assertSame( array( 'wrong_action' ), $answer->summary() );
		$this->assertTrue( $verifier->verify( 'tok' )->success );
		$this->assertSame( Reason::WrongAction, $verifier->verify( 'tok' )->reason, 'A widget without an action is not this form.' );
	}

	public function test_a_widget_without_an_action_is_refused_only_when_one_is_expected(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'action' => '' ) ),
			ts_answer( array( 'success' => true, 'action' => '' ) ),
		);

		$this->assertSame( Reason::WrongAction, ( new Verifier( self::SECRET, array(), 'checkout' ) )->verify( 'tok' )->reason );
		$this->assertTrue( ( new Verifier( self::SECRET ) )->verify( 'tok' )->success, 'With no expectation, any action will do.' );
	}

	public function test_cloudflares_test_secrets_skip_the_hostname_and_action_checks(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'hostname' => 'example.com', 'action' => 'other' ) );

		$this->assertTrue( ( new Verifier( '1x0000000000000000000000000000000AA', array( 'shop.test' ), 'signup' ) )->verify( 'tok' )->success );
	}

	public function test_it_recognises_only_the_published_test_secrets(): void {
		$this->assertTrue( Verifier::is_test_secret( '1x0000000000000000000000000000000AA' ) );
		$this->assertTrue( Verifier::is_test_secret( '2x0000000000000000000000000000000AA' ) );
		$this->assertTrue( Verifier::is_test_secret( '3x0000000000000000000000000000000AA' ) );
		$this->assertFalse( Verifier::is_test_secret( '4x0000000000000000000000000000000AA' ) );
		$this->assertFalse( Verifier::is_test_secret( '1x0000000000000000000000000000000AA ' ) );
		$this->assertFalse( Verifier::is_test_secret( '0x4AAAAAAAreal' ) );
	}

	public function test_within_refuses_a_challenge_solved_too_long_ago(): void {
		$solved = gmdate( 'Y-m-d\TH:i:s.096\Z', 1_800_000_000 );

		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'challenge_ts' => $solved ) ),
			ts_answer( array( 'success' => true, 'challenge_ts' => $solved ) ),
			ts_answer( array( 'success' => true ) ),
			ts_answer( array( 'success' => true, 'challenge_ts' => 'now' ) ),
		);

		$verifier = new Verifier( self::SECRET, array(), '', Verifier::TIMEOUT, 0, 1_800_000_061 );

		$expired = $verifier->within( 60 )->verify( 'tok' );

		$this->assertSame( Reason::Expired, $expired->reason );
		$this->assertTrue( $expired->stale(), 'Too old is the visitor\'s to put right.' );
		$this->assertTrue( $verifier->within( 61 )->verify( 'tok' )->success );
		$this->assertSame( Reason::Expired, $verifier->within( 60 )->verify( 'tok' )->reason, 'No timestamp cannot be shown to be recent.' );
		$this->assertSame( Reason::Expired, $verifier->within( 60 )->verify( 'tok' )->reason, '"now" is not a timestamp.' );
	}

	public function test_no_age_limit_by_default(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'challenge_ts' => '2001-01-01T00:00:00Z' ) );

		$this->assertTrue( ( new Verifier( self::SECRET ) )->verify( 'tok' )->success );
	}

	public function test_the_secret_never_appears_in_a_dump(): void {
		$dump = print_r( ( new Verifier( self::SECRET, array( 'example.com' ) ) )->__debugInfo(), true );

		$this->assertStringNotContainsString( self::SECRET, $dump );
		$this->assertStringContainsString( '[redacted]', $dump );
	}
}
