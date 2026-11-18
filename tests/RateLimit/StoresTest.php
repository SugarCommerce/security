<?php
/**
 * The table, object-cache, fallback and memory stores.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Stores\Fallback;
use SugarCommerce\Security\RateLimit\Stores\Memory;
use SugarCommerce\Security\RateLimit\Stores\ObjectCache;
use SugarCommerce\Security\RateLimit\Stores\Table;
use SugarCommerce\Security\Tests\RateLimit\Support\FakeWpdb;
use PHPUnit\Framework\TestCase;

final class StoresTest extends TestCase {

	private const NOW   = 1800000123;
	private const TABLE = 'wp_myplugin_rate_limits';

	private FakeWpdb $db;

	protected function setUp(): void {
		$this->db       = new FakeWpdb();
		$GLOBALS['wpdb'] = $this->db;

		unset( $GLOBALS['rl_cache'], $GLOBALS['rl_cache_ttl'], $GLOBALS['rl_ext_cache'], $GLOBALS['rl_cache_broken'] );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wpdb'], $GLOBALS['rl_cache'], $GLOBALS['rl_cache_ttl'], $GLOBALS['rl_ext_cache'], $GLOBALS['rl_cache_broken'] );
	}

	private function table( ?callable $ready = null, int $now = self::NOW ): Table {
		return new Table( self::TABLE, $ready, $now );
	}

	public function test_table_counts_in_one_row_per_counter(): void {
		$store = $this->table();

		$this->assertSame( 1, $store->increment( 'k1', 600 ) );
		$this->assertSame( 2, $store->increment( 'k1', 600 ) );
		$this->assertSame( 1, $store->increment( 'k2', 600 ) );
		$this->assertSame( 2, $store->get( 'k1' ) );
		$this->assertSame( 0, $store->get( 'missing' ) );
		$this->assertCount( 2, $this->db->rows[ self::TABLE ] );
	}

	public function test_table_counts_with_the_atomic_upsert_and_reads_after(): void {
		$this->table()->increment( 'k1', 600 );

		$this->assertStringContainsString( 'ON DUPLICATE KEY UPDATE hits = hits + 1', $this->db->log[0] );
		$this->assertStringStartsWith( 'SELECT hits', trim( $this->db->log[1] ) );
	}

	public function test_table_row_keeps_its_first_expiry(): void {
		$this->table()->increment( 'k1', 600 );
		$this->table( null, self::NOW + 60 )->increment( 'k1', 540 );

		$row = $this->db->rows[ self::TABLE ]['k1'];

		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 600 ), $row['date_expires'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), $row['date_created'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 60 ), $row['date_modified'] );
	}

	public function test_limiter_writes_the_row_the_host_already_has(): void {
		$limiter = new Limiter( $this->table(), null, self::NOW );

		$limiter->hit( 'checkout_ip:203.0.113.9', 5, 600 );

		// What the host's own counter wrote for the same attempt: the bucket
		// and the expiry ( floor( now / window ) + 2 ) * window.
		$bucket  = hash_hmac( 'sha256', 'checkout_ip:203.0.113.9|600|' . (int) floor( self::NOW / 600 ), wp_salt( 'nonce' ) );
		$expires = gmdate( 'Y-m-d H:i:s', ( (int) floor( self::NOW / 600 ) + 2 ) * 600 );

		$this->assertArrayHasKey( $bucket, $this->db->rows[ self::TABLE ] );
		$this->assertSame( $expires, $this->db->rows[ self::TABLE ][ $bucket ]['date_expires'] );
	}

	public function test_table_not_ready_counts_nothing_and_asks_nothing(): void {
		$store = $this->table( static fn(): bool => false );

		$this->assertSame( 0, $store->increment( 'k1', 600 ) );
		$this->assertSame( 0, $store->get( 'k1' ) );
		$store->forget( 'k1' );
		$this->assertSame( 0, $store->clean() );
		$this->assertSame( array(), $this->db->log );

		$this->assertTrue( ( new Limiter( $store, 's', self::NOW ) )->hit( 'a:b', 1, 600 )->allowed );
	}

	public function test_table_ready_is_asked(): void {
		$this->assertSame( 1, $this->table( static fn(): bool => true )->increment( 'k1', 600 ) );
	}

	public function test_table_forget_removes_one_counter(): void {
		$store = $this->table();

		$store->increment( 'k1', 600 );
		$store->increment( 'k2', 600 );
		$store->forget( 'k1' );

		$this->assertSame( 0, $store->get( 'k1' ) );
		$this->assertSame( 1, $store->get( 'k2' ) );
	}

	public function test_clean_removes_only_rows_whose_time_is_up(): void {
		$this->table( null, self::NOW - 1000 )->increment( 'old', 600 );     // Expired 400 seconds ago.
		$this->table( null, self::NOW - 600 )->increment( 'edge', 600 );     // Expires this second.
		$this->table()->increment( 'live', 600 );
		$this->db->rows[ self::TABLE ]['forever'] = array(
			'hits'          => 1,
			'date_expires'  => null,
			'date_created'  => '2026-01-01 00:00:00',
			'date_modified' => '2026-01-01 00:00:00',
		);

		$this->assertSame( 1, $this->table()->clean() );
		$this->assertSame( array( 'edge', 'live', 'forever' ), array_keys( $this->db->rows[ self::TABLE ] ) );
	}

	public function test_schema_has_the_columns_the_store_writes(): void {
		$sql = Table::schema( 'wp_myplugin_rate_limits', 'DEFAULT CHARSET=utf8mb4' );

		$this->assertStringStartsWith( 'CREATE TABLE wp_myplugin_rate_limits (', $sql );

		foreach ( array( 'bucket char(64)', 'hits int(11) unsigned', 'date_expires datetime DEFAULT NULL', 'date_created datetime', 'date_modified datetime', 'UNIQUE KEY bucket (bucket)', 'KEY date_expires (date_expires)', 'PRIMARY KEY  (id)' ) as $part ) {
			$this->assertStringContainsString( $part, $sql );
		}

		$this->assertStringEndsWith( ') DEFAULT CHARSET=utf8mb4', $sql );
		$this->assertStringStartsWith( 'CREATE TABLE wp_xdrop (', Table::schema( 'wp_x`drop' ) );
	}

	public function test_object_cache_counts_only_with_an_external_cache(): void {
		$store = new ObjectCache( 'myplugin_rate_limit' );

		$this->assertSame( 0, $store->increment( 'k1', 120 ), 'No persistent cache: nothing counted.' );
		$this->assertSame( 0, $store->get( 'k1' ) );

		$GLOBALS['rl_ext_cache'] = true;

		$this->assertSame( 1, $store->increment( 'k1', 120 ) );
		$this->assertSame( 2, $store->increment( 'k1', 120 ) );
		$this->assertSame( 2, $store->get( 'k1' ) );
		$this->assertSame( 120, $GLOBALS['rl_cache_ttl']['myplugin_rate_limit']['k1'] );

		$store->forget( 'k1' );
		$this->assertSame( 0, $store->get( 'k1' ) );
	}

	public function test_object_cache_that_cannot_increment_counts_nothing(): void {
		$GLOBALS['rl_ext_cache']    = true;
		$GLOBALS['rl_cache_broken'] = true;

		$this->assertSame( 0, ( new ObjectCache() )->increment( 'k1', 60 ) );
	}

	public function test_fallback_uses_the_second_store_only_when_the_first_cannot_count(): void {
		$GLOBALS['rl_ext_cache'] = true;

		$table = $this->table();
		$store = new Fallback( new ObjectCache(), $table );

		$this->assertSame( 1, $store->increment( 'k1', 60 ) );
		$this->assertSame( array(), $this->db->log, 'The cache counted; the table was not asked.' );

		$GLOBALS['rl_cache_broken'] = true;

		$this->assertSame( 1, $store->increment( 'k2', 60 ) );
		$this->assertSame( 1, $table->get( 'k2' ) );
		$this->assertSame( 1, $store->get( 'k2' ) );
		$this->assertSame( 1, $store->get( 'k1' ) );

		$store->forget( 'k1' );
		$store->forget( 'k2' );
		$this->assertSame( 0, $store->get( 'k1' ) );
		$this->assertSame( 0, $store->get( 'k2' ) );
	}

	public function test_auto_is_the_table_without_a_cache_and_the_pair_with_one(): void {
		$this->assertInstanceOf( Table::class, Limiter::auto( self::TABLE )->store() );

		$GLOBALS['rl_ext_cache'] = true;

		$this->assertInstanceOf( Fallback::class, Limiter::auto( self::TABLE )->store() );
	}

	public function test_memory_counters_expire(): void {
		$store = new Memory( self::NOW );

		$store->increment( 'k1', 10 );
		$this->assertSame( 1, $store->get( 'k1' ) );

		$store->travel( self::NOW + 10 );
		$this->assertSame( 0, $store->get( 'k1' ) );
		$this->assertSame( 1, $store->increment( 'k1', 10 ) );

		$store->flush();
		$this->assertSame( 0, $store->get( 'k1' ) );
	}
}
