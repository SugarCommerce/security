<?php
/**
 * Counters in a persistent object cache.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit\Stores;

use SugarCommerce\Security\RateLimit\Store;

/**
 * Counts with the object cache's own increment: no query at all.
 *
 * A persistent object cache -- Redis, Memcached -- adds one in a single
 * step, so twenty requests arriving together are counted one to twenty.
 * WordPress's own cache, without a drop-in, lasts one request and counts
 * nothing worth counting, so this store answers 0 ("could not count")
 * unless an external cache is in use. Some drop-ins implement
 * `wp_cache_incr()` as a read and a write; where that matters, use the
 * table, or put the table behind this one with {@see Fallback}.
 *
 * @since 1.0.0
 */
final class ObjectCache implements Store {

	/**
	 * A store.
	 *
	 * @param string $group The cache group the counters go in.
	 *
	 * @since 1.0.0
	 */
	public function __construct( private readonly string $group = 'rate_limit' ) {
	}

	/**
	 * {@inheritDoc}
	 */
	public function increment( string $key, int $ttl ): int {
		if ( ! wp_using_ext_object_cache() ) {
			return 0;
		}

		// add() is refused when the key is there, so of two requests only
		// one starts the count and both then add to it.
		wp_cache_add( $key, 0, $this->group, max( 1, $ttl ) );

		$count = wp_cache_incr( $key, 1, $this->group );

		return false === $count ? 0 : max( 0, (int) $count );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key ): int {
		if ( ! wp_using_ext_object_cache() ) {
			return 0;
		}

		return max( 0, (int) wp_cache_get( $key, $this->group ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forget( string $key ): void {
		wp_cache_delete( $key, $this->group );
	}
}
