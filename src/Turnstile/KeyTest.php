<?php
/**
 * A Test Keys button.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * Checks the saved keys as far as they can be checked from the server.
 *
 * Only a browser can make a real token, so a whole check cannot be run
 * from here. What can be learnt is whether Cloudflare accepts the secret
 * key: siteverify is asked about a token that is deliberately not one,
 * and its answer is about the token (`invalid-input-response`) when the
 * secret is good and about the secret (`invalid-input-secret`) when it
 * is not. Either is an answer; the second is the one the owner needs to
 * hear about.
 *
 * The site key cannot be checked this way at all -- Cloudflare has no
 * question to ask about one without a browser -- so its shape is looked
 * at and the owner is told to try a protected form, which is the only
 * real test.
 *
 * It tests what is saved, not what is typed: a secret is never in the
 * page to send.
 *
 * @since 1.0.0
 */
final class KeyTest {

	/**
	 * The test for one plugin's keys.
	 *
	 * @param Turnstile $turnstile Its configuration.
	 *
	 * @since 1.0.0
	 */
	public function __construct( private Turnstile $turnstile ) {
	}

	/**
	 * Run it, for the button.
	 *
	 * @return array{success: bool, message: string}
	 * @since 1.0.0
	 */
	public function run(): array {
		$site   = $this->turnstile->site_key();
		$secret = $this->turnstile->secret();

		if ( '' === $site || '' === $secret ) {
			return self::say( false, $this->turnstile->message( 'test_save_first' ) );
		}

		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]{10,}$/', $site ) ) {
			return self::say( false, $this->turnstile->message( 'test_site_key' ) );
		}

		$answer = ( new Verifier( $secret, array(), '', (int) $this->turnstile->option( 'timeout' ) ) )
			->verify( (string) $this->turnstile->option( 'key_test_token' ), '', wp_generate_uuid4() );

		if ( $answer->misconfigured() ) {
			$this->turnstile->record()->problem( 'misconfigured', 'test', $answer->summary(), $secret );

			return self::say( false, $this->turnstile->message( 'test_refused' ) );
		}

		if ( $answer->unavailable() ) {
			return self::say( false, $this->turnstile->message( 'test_unreachable' ) );
		}

		// An answer about the token, which is what was hoped for: the
		// secret is one Cloudflare knows.
		$this->turnstile->record()->answered();

		if ( Verifier::is_test_secret( $secret ) ) {
			return self::say( true, $this->turnstile->message( 'test_test_keys' ) );
		}

		return self::say( true, $this->turnstile->message( 'test_accepted' ) );
	}

	/**
	 * An answer in the shape a button reads.
	 *
	 * @param bool   $success Whether the keys look right.
	 * @param string $message What to tell the owner.
	 *
	 * @return array{success: bool, message: string}
	 * @since 1.0.0
	 */
	private static function say( bool $success, string $message ): array {
		return array(
			'success' => $success,
			'message' => $message,
		);
	}
}
