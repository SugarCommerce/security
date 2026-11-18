<?php
/**
 * Counters in a database table.
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
 * Counts with one statement on a unique index, which is atomic everywhere
 * WordPress runs.
 *
 * **Why a table.** The obvious counter is a transient, and a transient is
 * read, added to and written back: two requests that arrive together both
 * read four and both write five, and a script that sends twenty at once is
 * counted as one. `wp_cache_incr()` is atomic on Redis and Memcached, but
 * most sites have neither, and some object-cache drop-ins implement it as
 * the same read and write. One statement on a unique index is atomic on
 * every MySQL and MariaDB:
 *
 *     INSERT … ON DUPLICATE KEY UPDATE hits = hits + 1
 *
 * The database takes the row's lock for it, so twenty together are
 * counted one to twenty. It costs one small write and one indexed read
 * per counter, on a request that is worth limiting, and nothing on a page
 * view.
 *
 * **The table is the host's.** Its name is given in full, prefix and all,
 * and whoever owns it creates it -- with a schema class, a migration, or
 * {@see self::schema()}. It needs these columns:
 *
 *  - `bucket` char(64), UNIQUE -- the counter's hashed key
 *  - `hits` int unsigned -- the count
 *  - `date_expires` datetime NULL, indexed -- when the row can go (UTC)
 *  - `date_created`, `date_modified` datetime -- UTC
 *
 * **Each row carries the date it can go**, and only rows past that date
 * are ever removed ({@see self::clean()}), so no count is lost while its
 * window is open.
 *
 * @since 1.0.0
 */
final class Table implements Store {

	/**
	 * Whether the table is there, when the host can say.
	 *
	 * @var callable|null
	 */
	private $ready;

	/**
	 * A store.
	 *
	 * @param string        $table The table's full name: `$wpdb->prefix . 'myplugin_rate_limits'`.
	 * @param callable|null $ready Asked before every query; false means the
	 *                             table is not there (a plugin half
	 *                             installed), and nothing is counted.
	 * @param int|null      $now   A fixed clock, for tests.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		private readonly string $table,
		?callable $ready = null,
		private readonly ?int $now = null
	) {
		$this->ready = $ready;
	}

	/**
	 * The table's name.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function table(): string {
		return $this->table;
	}

	/**
	 * {@inheritDoc}
	 */
	public function increment( string $key, int $ttl ): int {
		global $wpdb;

		if ( ! $this->ready() ) {
			return 0;
		}

		$now     = $this->now();
		$created = gmdate( 'Y-m-d H:i:s', $now );
		$expires = gmdate( 'Y-m-d H:i:s', $now + max( 1, $ttl ) );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- The one statement that makes the count atomic, which no query class offers.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i ( bucket, hits, date_expires, date_created, date_modified )
				VALUES ( %s, 1, %s, %s, %s )
				ON DUPLICATE KEY UPDATE hits = hits + 1, date_modified = VALUES( date_modified )',
				$this->table,
				$key,
				$expires,
				$created,
				$created
			)
		);

		// Read after the write, so what comes back is at least this
		// request's own count. Another arriving in between makes it one
		// higher, which errs towards refusing and never towards letting
		// two through on one allowance.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT hits
				FROM %i
				WHERE bucket = %s',
				$this->table,
				$key
			)
		);
		// phpcs:enable
	}

	/**
	 * {@inheritDoc}
	 */
	public function get( string $key ): int {
		global $wpdb;

		if ( ! $this->ready() ) {
			return 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- A count that decides a refusal must not be a cached one.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT hits
				FROM %i
				WHERE bucket = %s',
				$this->table,
				$key
			)
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function forget( string $key ): void {
		global $wpdb;

		if ( ! $this->ready() ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- By the hashed key, which is the unique index.
		$wpdb->delete( $this->table, array( 'bucket' => $key ) );
	}

	/**
	 * Remove the counters whose time is up.
	 *
	 * For a daily job. One statement on the index: the rows are a few
	 * dozen bytes each and there is nothing to do with one but delete it.
	 * A row whose window could still be counted on is never touched.
	 *
	 * @return int How many went.
	 * @since 1.0.0
	 */
	public function clean(): int {
		global $wpdb;

		if ( ! $this->ready() ) {
			return 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One delete by date on the index.
		return (int) $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i
				WHERE date_expires IS NOT NULL
				AND date_expires < %s',
				$this->table,
				gmdate( 'Y-m-d H:i:s', $this->now() )
			)
		);
	}

	/**
	 * A CREATE TABLE statement for a host that has no table of its own.
	 *
	 * In the shape dbDelta() reads: two spaces before PRIMARY KEY, one
	 * column or key a line.
	 *
	 *     require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	 *     dbDelta( Table::schema( $table, $wpdb->get_charset_collate() ) );
	 *
	 * @param string $table           The table's full name.
	 * @param string $charset_collate `$wpdb->get_charset_collate()`.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public static function schema( string $table, string $charset_collate = '' ): string {
		$table = preg_replace( '/[^A-Za-z0-9_$]/', '', $table );

		return trim(
			"CREATE TABLE {$table} (
id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
bucket char(64) NOT NULL DEFAULT '',
hits int(11) unsigned NOT NULL DEFAULT 0,
date_expires datetime DEFAULT NULL,
date_created datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
date_modified datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
PRIMARY KEY  (id),
UNIQUE KEY bucket (bucket),
KEY date_expires (date_expires),
KEY date_created (date_created)
) {$charset_collate}"
		);
	}

	/**
	 * Whether the table is there to count in.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function ready(): bool {
		return null === $this->ready || (bool) call_user_func( $this->ready );
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
