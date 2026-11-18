<?php
/**
 * One store, or another when it cannot count.
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
 * Counts in the first store, and in the second whenever the first says it
 * could not.
 *
 * The usual pair is the object cache, which costs nothing when it is
 * there, and the table, which is atomic everywhere:
 *
 *     new Fallback( new ObjectCache(), new Table( $table ) )
 *
 * @since 1.0.0
 */
final readonly class Fallback implements Store {

	/**
	 * A store.
	 *
	 * @param Store $first Asked first.
	 * @param Store $then  Asked when the first answers 0.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		private Store $first,
		private Store $then
	) {
	}

	/**
	 * {@inheritDoc}
	 */
	public function increment( string $key, int $ttl ): int {
		$count = $this->first->increment( $key, $ttl );

		return $count > 0 ? $count : $this->then->increment( $key, $ttl );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key ): int {
		$count = $this->first->get( $key );

		return $count > 0 ? $count : $this->then->get( $key );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forget( string $key ): void {
		$this->first->forget( $key );
		$this->then->forget( $key );
	}
}
