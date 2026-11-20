<?php
/**
 * Turnstile: checking a token.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Traits\Turnstile;

use SugarCommerce\Security\Models\Turnstile\Verification;
use SugarCommerce\Security\Turnstile\Verifier;
use WP_Error;

/**
 * Asking Cloudflare about a token, once a request, and turning its answer
 * into true or the plugin's error. For {@see \SugarCommerce\Security\Turnstile\Turnstile}.
 *
 * @since 1.0.0
 */
trait Verifying {

	/**
	 * The error for a check that has not been completed.
	 *
	 * @return WP_Error
	 * @since 1.0.0
	 */
	public function incomplete(): WP_Error {
		return new WP_Error(
			$this->config['codes']['incomplete'],
			$this->message( 'incomplete' ),
			array(
				'status' => 400,
				'field'  => $this->config['field'],
			)
		);
	}

	/**
	 * Check a token.
	 *
	 * True where Turnstile is not in use for the place: there is nothing
	 * to pass. Whether this person has to pass it at all is required(),
	 * which the caller asks first.
	 *
	 * @param string               $token What the widget produced.
	 * @param string               $place The place it was produced for.
	 * @param array<string, mixed> $who   Who sent it, for the hooks. The
	 *                                    address sent to Cloudflare is
	 *                                    `ip` when given, and otherwise
	 *                                    the `visitor_ip` option's.
	 *
	 * @return true|WP_Error
	 * @since 1.0.0
	 */
	public function verify( string $token, string $place, array $who = array() ): true|WP_Error {
		$place = self::place( $place );

		if ( ! $this->enabled( $place ) ) {
			return true;
		}

		$token = trim( $token );

		if ( '' === $token ) {
			return $this->incomplete();
		}

		$key = hash( 'sha256', $place . '|' . $token );

		if ( ! isset( $this->asked[ $key ] ) ) {
			$this->asked[ $key ] = $this->ask( $token, $place, $who );
		}

		return $this->asked[ $key ];
	}

	/**
	 * Ask Cloudflare, and turn its answer into the plugin's.
	 *
	 * @param string               $token The token.
	 * @param string               $place The place.
	 * @param array<string, mixed> $who   Who sent it.
	 *
	 * @return true|WP_Error
	 * @since 1.0.0
	 */
	private function ask( string $token, string $place, array $who ): true|WP_Error {
		$secret = $this->secret();
		$ip     = (string) ( $who['ip'] ?? '' );

		$verifier = new Verifier( $secret, $this->hostnames(), $place, (int) $this->config['timeout'], (int) $this->config['max_age'] );

		// The address itself, not whatever the plugin stores: it is sent
		// and not kept.
		$answer = $verifier->verify( $token, '' !== $ip ? $ip : $this->visitor_ip(), wp_generate_uuid4() );

		if ( $answer->success ) {
			$this->record()->answered();

			return true;
		}

		$passed = $this->let_through( $answer, $place, $who, $secret );

		/**
		 * Fires when a Cloudflare Turnstile check does not pass.
		 *
		 * For a token Cloudflare refused, and for a check that could not
		 * be made. Not for a form sent with no token at all.
		 *
		 * @param string               $place  The place.
		 * @param string[]             $codes  Cloudflare's error codes, or, when
		 *                                     it gave none, why the answer was
		 *                                     refused: `unreachable`, `http_error`,
		 *                                     `unreadable`, `wrong_hostname`,
		 *                                     `wrong_action`, `expired`,
		 *                                     `token_too_long`.
		 * @param array<string, mixed> $who    Who sent it.
		 * @param bool                 $passed Whether they were let through
		 *                                     all the same, by the fail-open
		 *                                     policy.
		 *
		 * @since 1.0.0
		 */
		do_action( $this->hook( 'failed' ), $place, $answer->summary(), $who, $passed );

		if ( $passed ) {
			return true;
		}

		// Cloudflare answered about the token, so the check itself works.
		if ( ! $answer->misconfigured() && ! $answer->unavailable() ) {
			$this->record()->answered();
		}

		if ( $answer->stale() ) {
			return $this->incomplete();
		}

		return new WP_Error(
			$this->config['codes']['failed'],
			$this->message( 'failed' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Whether a check that could not be made lets the visitor through.
	 *
	 * The problem is written down whichever way it goes, so the owner is
	 * told either way.
	 *
	 * @param Verification         $answer What came back.
	 * @param string               $place  The place.
	 * @param array<string, mixed> $who    Who sent the token.
	 * @param string               $secret The secret key that was used.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function let_through( Verification $answer, string $place, array $who, string $secret ): bool {
		$kind = '';

		if ( $answer->misconfigured() ) {
			$kind = 'misconfigured';
		} elseif ( $answer->unavailable() ) {
			$kind = 'unavailable';
		}

		if ( '' === $kind ) {
			return false;
		}

		$this->record()->problem( $kind, $place, $answer->summary(), $secret );

		/**
		 * Filter whether a visitor is let through when Turnstile cannot be asked.
		 *
		 * The default is the plugin's `fail_open` policy.
		 *
		 * @param bool                 $open  Whether to let them through.
		 * @param string               $place The place.
		 * @param string               $kind  `unavailable` (no answer from
		 *                                    Cloudflare, or a server error
		 *                                    there) or `misconfigured` (the
		 *                                    secret key is missing or not
		 *                                    accepted).
		 * @param array<string, mixed> $who   Who sent the token.
		 *
		 * @since 1.0.0
		 */
		return (bool) apply_filters( $this->hook( 'fail_open' ), $this->fails_open( $kind, $place, $who ), $place, $kind, $who );
	}

	/**
	 * The visitor's address, when the caller gave none.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private function visitor_ip(): string {
		$given = $this->config['visitor_ip'];

		if ( is_callable( $given ) ) {
			return (string) $given();
		}

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		return false === filter_var( $ip, FILTER_VALIDATE_IP ) ? '' : $ip;
	}
}
