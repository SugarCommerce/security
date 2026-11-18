<?php
/**
 * Where counters live.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\RateLimit;

/**
 * A counter two requests arriving together cannot both read as nought.
 *
 * The one requirement that matters is that increment() is **atomic**. The
 * obvious counter -- a transient -- is read, added to and written back:
 * two requests that arrive together both read four and both write five,
 * and a script that sends twenty at once is counted as one. Under exactly
 * the burst a limit exists to stop, it undercounts.
 *
 * @since 1.0.0
 */
interface Store {

	/**
	 * Add one to a counter and say what it now reads.
	 *
	 * The adding and the reading are one step as far as any other request
	 * can tell: two requests at the same instant get two different answers.
	 *
	 * @param string $key Which counter. Already includes the window it is for.
	 * @param int    $ttl How long the counter must be kept, at least, in seconds.
	 *
	 * @return int The count, this one included. 0 when nothing could be
	 *             counted -- the limiter then lets the attempt through.
	 * @since 1.0.0
	 */
	public function increment( string $key, int $ttl ): int;

	/**
	 * Read a counter without changing it.
	 *
	 * @param string $key Which counter.
	 *
	 * @return int 0 when there is none.
	 * @since 1.0.0
	 */
	public function get( string $key ): int;

	/**
	 * Forget a counter.
	 *
	 * @param string $key Which counter.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function forget( string $key ): void;
}
