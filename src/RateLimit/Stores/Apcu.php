<?php
/**
 * Counters in APCu.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit\Stores;

use SugarCommerce\Security\RateLimit\Store;

/**
 * Shared memory on one server: atomic, and no query at all.
 *
 * For a site with APCu and no persistent object cache. `apcu_inc()` adds
 * under a lock inside the extension, so there is no read-then-write window
 * for counts to be lost through.
 *
 * Counters are per machine. Behind a load balancer each server keeps its
 * own, and the real limit is the one set times the number of servers; use
 * the table there. And APCu is off on the command line unless
 * `apc.enable_cli` is set, so a cron job or a WP-CLI command counts nothing
 * here -- which this store reports as "could not count", so a limiter lets
 * the attempt through, or a {@see Fallback} counts it in the table.
 *
 *     new Fallback( new Apcu( 'myplugin:' ), new Table( $table ) )
 *
 * @since 1.0.0
 */
final readonly class Apcu implements Store {

	/**
	 * A store.
	 *
	 * @since 1.0.0
	 *
	 * @param string $prefix Put before every key, so several plugins can
	 *                       share one APCu segment.
	 */
	public function __construct( private string $prefix = 'rate_limit:' ) {
	}

	/**
	 * Whether APCu can be used in this process.
	 *
	 * Asked of APCu itself: `extension_loaded( 'apcu' )` is true on a
	 * command line where it is switched off.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public static function available(): bool {
		return function_exists( 'apcu_enabled' ) && apcu_enabled();
	}

	/**
	 * {@inheritDoc}
	 */
	#[\Override]
	public function increment( string $key, int $ttl ): int {
		if ( ! self::available() ) {
			return 0;
		}

		// One call that creates the key or adds to it: creating it first
		// with a separate add would reopen the race.
		$count = apcu_inc( $this->prefix . $key, 1, $success, max( 1, $ttl ) );

		return false === $count ? 0 : max( 0, (int) $count );
	}

	/**
	 * {@inheritDoc}
	 */
	#[\Override]
	public function get( string $key ): int {
		if ( ! self::available() ) {
			return 0;
		}

		$count = apcu_fetch( $this->prefix . $key, $found );

		return $found && is_int( $count ) ? max( 0, $count ) : 0;
	}

	/**
	 * {@inheritDoc}
	 */
	#[\Override]
	public function forget( string $key ): void {
		if ( self::available() ) {
			apcu_delete( $this->prefix . $key );
		}
	}
}
