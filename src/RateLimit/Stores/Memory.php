<?php
/**
 * Counters for one process.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit\Stores;

use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\RateLimit\Store;

/**
 * Counters that live as long as the request.
 *
 * For tests, and for a long-running worker that wants a second check of
 * its own. Useless for limiting a website: every PHP worker has its own
 * copy, so the real limit is the one set times the number of workers.
 *
 * @since 1.0.0
 */
final class Memory implements Store {

	/**
	 * Counters, as key => [ count, expires at ].
	 *
	 * @var array<string, array{0: int, 1: int}>
	 */
	private array $counters = array();

	/**
	 * A store.
	 *
	 * @param int|null $now A fixed clock, for tests.
	 *
	 * @since 1.0.0
	 */
	public function __construct( private ?int $now = null ) {
	}

	/**
	 * {@inheritDoc}
	 */
	public function increment( string $key, int $ttl ): int {
		$now = $this->now();

		if ( ! isset( $this->counters[ $key ] ) || $this->counters[ $key ][1] <= $now ) {
			$this->counters[ $key ] = array( 0, $now + max( 1, $ttl ) );
		}

		return ++$this->counters[ $key ][0];
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key ): int {
		if ( ! isset( $this->counters[ $key ] ) || $this->counters[ $key ][1] <= $this->now() ) {
			return 0;
		}

		return $this->counters[ $key ][0];
	}

	/**
	 * {@inheritDoc}
	 */
	public function forget( string $key ): void {
		unset( $this->counters[ $key ] );
	}

	/**
	 * Move the clock, for a test that crosses a window.
	 *
	 * @param int|null $now The time, or null for the real one.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function travel( ?int $now ): void {
		$this->now = $now;
	}

	/**
	 * Forget every counter.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function flush(): void {
		$this->counters = array();
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
