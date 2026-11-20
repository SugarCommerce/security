<?php
/**
 * A limiter bound to an action and an identity.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit;

use SugarCommerce\Security\Models\RateLimit\Decision;

/**
 * Returned by {@see Limiter::for()}. Holds the counter's name, so a call
 * site states the allowance and nothing else:
 *
 *     $limiter->for( 'login', $ip )->hit( 5, 600 );
 *
 * **Nothing to count against is the visitor's address.** An empty
 * identity -- a form with no email -- is filled in by {@see Limiter::for()}
 * with the address the request came from, never left as one shared
 * counter (any caller could then lock out all the others) and never let
 * through unlimited.
 *
 * @since 1.0.0
 */
final readonly class Limit {

	/**
	 * A bound limit.
	 *
	 * @param Limiter $limiter  The limiter.
	 * @param string  $action   What is limited.
	 * @param string  $identity Who is doing it.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		private Limiter $limiter,
		private string $action,
		private string $identity
	) {
	}

	/**
	 * Count one more, and say whether it is one too many.
	 *
	 * @param int       $limit     Attempts allowed in one window. Nought or
	 *                             less is no limit.
	 * @param int       $window    The window's length, in seconds.
	 * @param bool|null $fail_open When the store cannot count: true lets
	 *                             the attempt through, false refuses it,
	 *                             null takes the limiter's default.
	 *
	 * @return Decision
	 * @since 1.0.0
	 */
	public function hit( int $limit, int $window, ?bool $fail_open = null ): Decision {
		return $this->limiter->hit( $this->name(), $limit, $window, $fail_open );
	}

	/**
	 * Whether one more would be allowed, without counting it.
	 *
	 * @param int $limit  Attempts allowed in one window.
	 * @param int $window The window's length, in seconds.
	 *
	 * @return Decision
	 * @since 1.0.0
	 */
	public function check( int $limit, int $window ): Decision {
		return $this->limiter->check( $this->name(), $limit, $window );
	}

	/**
	 * How many there have been in this window.
	 *
	 * @param int $window The window's length, in seconds.
	 *
	 * @return int
	 * @since 1.0.0
	 */
	public function count( int $window ): int {
		return $this->limiter->count( $this->name(), $window );
	}

	/**
	 * Start this window again.
	 *
	 * @param int $window The window's length, in seconds.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function reset( int $window ): void {
		$this->limiter->reset( $this->name(), $window );
	}

	/**
	 * The counter's name: `action:identity`, the identity normalised.
	 *
	 * '' when either part is empty, which the limiter refuses to count.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function name(): string {
		$action   = trim( $this->action );
		$identity = self::identity( $this->identity );

		return '' === $action || '' === $identity ? '' : $action . ':' . $identity;
	}

	/**
	 * The form of an identity that is counted.
	 *
	 * Without this, one caller is as many counters as it has spellings:
	 *
	 * - **An IPv6 address counts as its /64.** A single host is routinely
	 *   given a whole /64 and can use any of its 2^64 addresses, so a limit
	 *   per address is no limit -- rotate the last 64 bits and every
	 *   request is a first. Hosts sharing one /64 share one allowance,
	 *   which is how the network sees them too.
	 * - **An address is written one way.** `2001:DB8::1`, `2001:db8:0::1`
	 *   and the IPv4-mapped `::ffff:192.0.2.1` are the same callers as
	 *   `2001:db8::1` and `192.0.2.1`.
	 * - **Case is folded beyond ASCII** when mbstring is there, so
	 *   `JÖRG@example.com` and `jörg@example.com` are one address.
	 *
	 * Anything else -- trailing junk on an email address, say -- is the
	 * caller's to normalise, the same way it does before whatever the
	 * limit protects.
	 *
	 * @param string $identity As the caller gave it.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public static function identity( string $identity ): string {
		$identity = trim( $identity );
		$binary   = false === filter_var( $identity, FILTER_VALIDATE_IP ) ? false : inet_pton( $identity );

		if ( false !== $binary && 16 === strlen( $binary ) ) {
			if ( str_starts_with( $binary, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
				$binary = substr( $binary, 12 );
			} else {
				return ( inet_ntop( substr( $binary, 0, 8 ) . str_repeat( "\0", 8 ) ) ?: $identity ) . '/64';
			}
		}

		if ( false !== $binary ) {
			return inet_ntop( $binary ) ?: $identity;
		}

		return function_exists( 'mb_strtolower' ) && mb_check_encoding( $identity, 'UTF-8' )
			? mb_strtolower( $identity, 'UTF-8' )
			: strtolower( $identity );
	}
}
