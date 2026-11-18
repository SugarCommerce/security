<?php
/**
 * How often something may be tried.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit;

use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\RateLimit\Stores\Fallback;
use SugarCommerce\Security\RateLimit\Stores\ObjectCache;
use SugarCommerce\Security\RateLimit\Stores\Table;
use SensitiveParameter;

/**
 * Counting attempts, so that two arriving together are both counted.
 *
 * **Fixed windows.** A counter is named for what is counted and for the
 * stretch of time it is in -- ten minutes, say, starting on the ten-minute
 * marks. The simplest thing that is atomic, and it tells a client exactly
 * when to come back. Its known cost is that somebody can use a full
 * allowance just before a mark and another just after; twice the limit
 * across the boundary is still a limit.
 *
 * **Every attempt is counted**, including the ones refused. A caller over
 * its limit stays over it for the rest of the window, and two counters
 * asked about one request (an address and an email, say) each stay an
 * honest count of attempts.
 *
 * **Nothing about a person is kept.** A counter's key is a salted hash of
 * what it counts and the window it is in, so a store says "something was
 * tried four times" and not who by.
 *
 * **The key is the whole design.** `hit( 'login', … )` is one counter for
 * the whole internet, and five attempts from anybody lock out everybody.
 * {@see self::for()} takes the identity separately so it cannot be left
 * out.
 *
 * @since 1.0.0
 */
final class Limiter {

	/**
	 * The secret counter names are hashed with; null for the site's
	 * `nonce` salt, through core's wp_hash().
	 *
	 * @var string|null
	 */
	private ?string $secret;

	/**
	 * A limiter.
	 *
	 * @param Store       $store  Where the counters live.
	 * @param string|null $secret What names are hashed with. Defaults to
	 *                            the site's `nonce` salt. Changing it
	 *                            starts every count again, once.
	 * @param int|null    $now    A fixed clock, for tests.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		private readonly Store $store,
		#[SensitiveParameter] ?string $secret = null,
		private readonly ?int $now = null
	) {
		$this->secret = $secret;
	}

	/**
	 * Keep the secret out of var_dump() and print_r().
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	public function __debugInfo(): array {
		return array(
			'store'  => $this->store,
			'secret' => '[redacted]',
			'now'    => $this->now,
		);
	}

	/**
	 * A limiter on the cheapest store that is atomic on this site.
	 *
	 * With a persistent object cache -- Redis, Memcached -- its own
	 * increment, which costs no query at all, falling back to the table
	 * should the cache refuse. Without one, the table.
	 *
	 * Where the same limit must behave the same on every host (a limit
	 * that differs from host to host is one nobody can reason about), use
	 * the table on its own: `new Limiter( new Stores\Table( … ) )`.
	 *
	 * @param string        $table The table, prefix included.
	 * @param callable|null $ready Whether the table is there to count in.
	 * @param string        $group The object-cache group.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public static function auto( string $table, ?callable $ready = null, string $group = 'rate_limit' ): self {
		$table = new Table( $table, $ready );

		return new self( wp_using_ext_object_cache() ? new Fallback( new ObjectCache( $group ), $table ) : $table );
	}

	/**
	 * Bind this limiter to an action and who is doing it.
	 *
	 * @param string $action   What is limited: `login`, `checkout_ip`.
	 * @param string $identity Who is doing it: an address, an email, an
	 *                         id. Normalised ({@see Limit::identity()})
	 *                         and hashed before it is stored.
	 *
	 * @return Limit
	 * @since 1.0.0
	 */
	public function for( string $action, string $identity ): Limit {
		return new Limit( $this, $action, $identity );
	}

	/**
	 * Count one more of something, and say whether it is one too many.
	 *
	 * @param string $name   What is counted, identity and all:
	 *                       `checkout_ip:203.0.113.9`.
	 * @param int    $limit  Attempts allowed in one window. Nought or less
	 *                       is no limit, and nothing is counted.
	 * @param int    $window The window's length, in seconds.
	 *
	 * @return Decision Allowed while the count, this one included, is no
	 *                  more than the limit.
	 * @since 1.0.0
	 */
	public function hit( string $name, int $limit, int $window ): Decision {
		if ( $limit < 1 || '' === trim( $name ) ) {
			return Decision::unlimited();
		}

		$window = max( 1, $window );
		$now    = $this->now();
		$index  = intdiv( $now, $window );

		// Kept until the window after this one has ended as well, so a
		// counter is never removed while it could still be counted on.
		$count = $this->store->increment( $this->key( $name, $window, $now ), ( $index + 2 ) * $window - $now );

		return $this->decide( $count <= $limit, $limit, $count, $window, $now );
	}

	/**
	 * Whether one more of something would be allowed, without counting it.
	 *
	 * For showing what is left, or for refusing before doing any work.
	 *
	 * @param string $name   What is counted.
	 * @param int    $limit  Attempts allowed in one window.
	 * @param int    $window The window's length, in seconds.
	 *
	 * @return Decision Allowed while the count is below the limit.
	 * @since 1.0.0
	 */
	public function check( string $name, int $limit, int $window ): Decision {
		if ( $limit < 1 || '' === trim( $name ) ) {
			return Decision::unlimited();
		}

		$window = max( 1, $window );
		$now    = $this->now();
		$count  = $this->store->get( $this->key( $name, $window, $now ) );

		return $this->decide( $count < $limit, $limit, $count, $window, $now );
	}

	/**
	 * How many of something there have been in this window.
	 *
	 * @param string $name   What is counted.
	 * @param int    $window The window's length, in seconds.
	 *
	 * @return int
	 * @since 1.0.0
	 */
	public function count( string $name, int $window ): int {
		if ( '' === trim( $name ) ) {
			return 0;
		}

		return $this->store->get( $this->key( $name, max( 1, $window ), $this->now() ) );
	}

	/**
	 * Forget a count: start this window again for one thing.
	 *
	 * After the thing being protected succeeds, so somebody who mistyped
	 * a code four times is not left one try from being locked out.
	 *
	 * @param string $name   What is counted.
	 * @param int    $window The window's length, in seconds.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function reset( string $name, int $window ): void {
		if ( '' !== trim( $name ) ) {
			$this->store->forget( $this->key( $name, max( 1, $window ), $this->now() ) );
		}
	}

	/**
	 * A counter's key in the store.
	 *
	 * What is counted, which window, and the secret, hashed: the same
	 * thing in the same window is the same counter, and the counter cannot
	 * be turned back into an address or an email.
	 *
	 * @param string $name   What is counted.
	 * @param int    $window The window's length, in seconds.
	 * @param int    $now    The time.
	 *
	 * @return string 64 hexadecimal characters.
	 * @since 1.0.0
	 */
	public function key( string $name, int $window, int $now ): string {
		$data = $name . '|' . $window . '|' . intdiv( $now, $window );

		// Core's wp_hash( …, 'nonce', 'sha256' ) is hash_hmac( 'sha256', …,
		// wp_salt( 'nonce' ) ), the default secret this always had, so every
		// counter keeps its key. A secret of the caller's own has no scheme
		// to name, so it is hashed here.
		return null === $this->secret
			? wp_hash( $data, 'nonce', 'sha256' )
			: hash_hmac( 'sha256', $data, $this->secret );
	}

	/**
	 * The store counters live in.
	 *
	 * @return Store
	 * @since 1.0.0
	 */
	public function store(): Store {
		return $this->store;
	}

	/**
	 * A decision, with the window worked out.
	 *
	 * @param bool $allowed Whether it is allowed.
	 * @param int  $limit   The limit.
	 * @param int  $count   The count.
	 * @param int  $window  The window's length.
	 * @param int  $now     The time.
	 *
	 * @return Decision
	 * @since 1.0.0
	 */
	private function decide( bool $allowed, int $limit, int $count, int $window, int $now ): Decision {
		return new Decision(
			$allowed,
			$limit,
			$count,
			max( 0, $limit - $count ),
			( intdiv( $now, $window ) + 1 ) * $window,
			$window,
			$now
		);
	}

	/**
	 * The time.
	 *
	 * @return int
	 * @since 1.0.0
	 */
	private function now(): int {
		return $this->now ?? Clock::time();
	}
}
