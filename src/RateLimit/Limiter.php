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

use InvalidArgumentException;
use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\Models\RateLimit\Decision;
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
 * **Nothing to count against is the visitor's address, never no limit.**
 * A form with no email, a request with no account: {@see self::for()}
 * counts it against the address the request came from
 * ({@see self::client()}), so it is limited like any other caller. With
 * no address either -- a command line -- or with no action, it throws: a
 * limit with nothing to count is a bug to fix, not a door to leave open.
 *
 * **A store that cannot count refuses, unless told otherwise.** When the
 * store answers 0 -- the table not installed, the database refusing --
 * the attempt was not counted, and the decision is the failure policy's:
 * refused by default, as the retired package refused by throwing, and let
 * through where a call (or {@see self::fail_open()}) says an outage of the
 * counter must not be an outage of the thing it protects. Either way it
 * is reported ({@see self::on_failure()}; error_log() by default) and the
 * decision says so ({@see Decision::$failed}).
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
	 * Who an empty identity is counted as.
	 *
	 * @var callable|null
	 */
	private $client = null;

	/**
	 * Whether an attempt the store could not count goes ahead by default.
	 *
	 * @var bool
	 */
	private bool $fail_open = false;

	/**
	 * Told when the store could not count.
	 *
	 * @var callable|null
	 */
	private $report = null;

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
	 * Who an empty identity is counted as.
	 *
	 * The visitor's address. By default the connection's own
	 * (`REMOTE_ADDR`, when it is an address), which is what
	 * sugarcommerce/network's `ClientIp::resolve()` answers with no proxy
	 * trusted: right for a site reached directly, and on a site behind a
	 * proxy one shared counter per proxy -- so a site behind one passes the
	 * resolver it already trusts:
	 *
	 *     $limiter->client( fn() => ClientIp::resolve( null, TrustedProxies::cloudflare() ) );
	 *
	 * @param callable $resolver Returns the address, or null/'' for none.
	 *
	 * @return static
	 * @since 1.0.0
	 */
	public function client( callable $resolver ): static {
		$this->client = $resolver;

		return $this;
	}

	/**
	 * Let attempts the store could not count go ahead, by default.
	 *
	 * For a limiter whose every limit is a courtesy rather than a defence.
	 * A call can still say otherwise ({@see self::hit()}).
	 *
	 * @param bool $open True to let them through, false to refuse them.
	 *
	 * @return static
	 * @since 1.0.0
	 */
	public function fail_open( bool $open = true ): static {
		$this->fail_open = $open;

		return $this;
	}

	/**
	 * What to tell when the store could not count.
	 *
	 * Called with the counter's hashed key and whether the attempt was let
	 * through. Replaces the default error_log() line -- a plugin with a
	 * logger of its own sends it there.
	 *
	 * @param callable $report fn( string $key, bool $allowed ): void.
	 *
	 * @return static
	 * @since 1.0.0
	 */
	public function on_failure( callable $report ): static {
		$this->report = $report;

		return $this;
	}

	/**
	 * Bind this limiter to an action and who is doing it.
	 *
	 * @param string $action   What is limited: `login`, `checkout_ip`.
	 * @param string $identity Who is doing it: an address, an email, an
	 *                         id. Normalised ({@see Limit::identity()})
	 *                         and hashed before it is stored. Empty
	 *                         counts against the visitor's address
	 *                         ({@see self::client()}).
	 *
	 * @return Limit
	 * @since 1.0.0
	 *
	 * @throws InvalidArgumentException When the action is empty, or the
	 *                                  identity is and the request has no
	 *                                  address either.
	 */
	public function for( string $action, string $identity ): Limit {
		if ( '' === trim( $action ) ) {
			throw new InvalidArgumentException( 'A rate limit needs an action name.' );
		}

		if ( '' === trim( $identity ) ) {
			$identity = trim( (string) ( null === $this->client ? self::remote_address() : call_user_func( $this->client ) ) );
		}

		if ( '' === $identity ) {
			throw new InvalidArgumentException(
				'A rate limit needs an identity to count against -- an address, an email, an id -- and this request has no address to fall back on. '
				. 'Counting nobody in particular would put every such caller on one counter, and any of them could lock out all the others.'
			);
		}

		return new Limit( $this, $action, $identity );
	}

	/**
	 * Count one more of something, and say whether it is one too many.
	 *
	 * @param string $name   What is counted, identity and all:
	 *                       `checkout_ip:203.0.113.9`.
	 * @param int    $limit  Attempts allowed in one window. Nought or less
	 *                       is no limit, and nothing is counted.
	 * @param int       $window    The window's length, in seconds.
	 * @param bool|null $fail_open When the store cannot count: true lets
	 *                             the attempt through, false refuses it,
	 *                             null takes the limiter's default
	 *                             (refuse, unless {@see self::fail_open()}).
	 *
	 * @return Decision Allowed while the count, this one included, is no
	 *                  more than the limit.
	 * @since 1.0.0
	 *
	 * @throws InvalidArgumentException When the name is empty.
	 */
	public function hit( string $name, int $limit, int $window, ?bool $fail_open = null ): Decision {
		self::named( $name );

		if ( $limit < 1 ) {
			return Decision::unlimited();
		}

		$window = max( 1, $window );
		$now    = $this->now();
		$index  = intdiv( $now, $window );
		$key    = $this->key( $name, $window, $now );

		// Kept until the window after this one has ended as well, so a
		// counter is never removed while it could still be counted on.
		$count = $this->store->increment( $key, ( $index + 2 ) * $window - $now );

		if ( $count < 1 ) {
			return $this->failed( $key, $fail_open ?? $this->fail_open, $limit, $window, $now );
		}

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
	 * @return Decision Allowed while the count is below the limit. A store
	 *                  that cannot be read reads as nought: looking
	 *                  decides nothing, and the hit() that follows applies
	 *                  the failure policy.
	 * @since 1.0.0
	 *
	 * @throws InvalidArgumentException When the name is empty.
	 */
	public function check( string $name, int $limit, int $window ): Decision {
		self::named( $name );

		if ( $limit < 1 ) {
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
	 *
	 * @throws InvalidArgumentException When the name is empty.
	 */
	public function count( string $name, int $window ): int {
		self::named( $name );

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
	 *
	 * @throws InvalidArgumentException When the name is empty.
	 */
	public function reset( string $name, int $window ): void {
		self::named( $name );

		$this->store->forget( $this->key( $name, max( 1, $window ), $this->now() ) );
	}

	/**
	 * The address the connection came from, when it is one.
	 *
	 * @return string '' when there is none: a command line, say.
	 * @since 1.0.0
	 */
	private static function remote_address(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Validated as an address on the next line; only an address is used.
		$address = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] ) ? trim( $_SERVER['REMOTE_ADDR'] ) : '';

		return false === filter_var( $address, FILTER_VALIDATE_IP ) ? '' : $address;
	}

	/**
	 * Refuse a counter with no name.
	 *
	 * '' would be one counter for every caller that had nothing to count
	 * against, and any of them could lock out all the others. The retired
	 * package threw here too.
	 *
	 * @param string $name What is counted.
	 *
	 * @return void
	 * @since 1.0.0
	 *
	 * @throws InvalidArgumentException When it is empty.
	 */
	private static function named( string $name ): void {
		if ( '' === trim( $name ) ) {
			throw new InvalidArgumentException( 'A rate limit needs a name to count: use Limiter::for( $action, $identity ).' );
		}
	}

	/**
	 * The decision when the store could not count, reported.
	 *
	 * @param string $key     The counter's key.
	 * @param bool   $allowed Whether the attempt goes ahead.
	 * @param int    $limit   The limit.
	 * @param int    $window  The window's length.
	 * @param int    $now     The time.
	 *
	 * @return Decision
	 * @since 1.0.0
	 */
	private function failed( string $key, bool $allowed, int $limit, int $window, int $now ): Decision {
		if ( null !== $this->report ) {
			call_user_func( $this->report, $key, $allowed );
		} else {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- A limit that is not being enforced has to be seen.
			error_log( sprintf( 'Rate limit: the store could not count %s; the attempt was %s.', substr( $key, 0, 12 ), $allowed ? 'let through' : 'refused' ) );
		}

		return new Decision(
			$allowed,
			$limit,
			0,
			$allowed ? $limit : 0,
			( intdiv( $now, $window ) + 1 ) * $window,
			$window,
			$now,
			true,
			true
		);
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
