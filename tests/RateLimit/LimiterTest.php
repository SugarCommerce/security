<?php
/**
 * The limiter's rules, on the memory store.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use SugarCommerce\Security\RateLimit\Decision;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Store;
use SugarCommerce\Security\RateLimit\Stores\Memory;
use PHPUnit\Framework\TestCase;

final class LimiterTest extends TestCase {

	/**
	 * 123 seconds into a ten-minute window.
	 */
	private const NOW = 1800000123;

	private function limiter( Memory $store, int $now = self::NOW ): Limiter {
		return new Limiter( $store, 'secret', $now );
	}

	public function test_allows_up_to_the_limit_and_refuses_the_next(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		for ( $i = 1; $i <= 5; $i++ ) {
			$decision = $limiter->hit( 'checkout_ip:203.0.113.9', 5, 600 );

			$this->assertTrue( $decision->allowed, "attempt $i" );
			$this->assertSame( $i, $decision->count );
			$this->assertSame( 5 - $i, $decision->remaining );
		}

		$sixth = $limiter->hit( 'checkout_ip:203.0.113.9', 5, 600 );

		$this->assertTrue( $sixth->denied() );
		$this->assertSame( 6, $sixth->count );
		$this->assertSame( 0, $sixth->remaining );
	}

	public function test_counts_refused_attempts_too(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		for ( $i = 0; $i < 8; $i++ ) {
			$limiter->hit( 'a:b', 2, 600 );
		}

		$this->assertSame( 8, $limiter->count( 'a:b', 600 ) );
	}

	public function test_window_end_and_retry_after(): void {
		$decision = $this->limiter( new Memory( self::NOW ) )->hit( 'a:b', 1, 600 );

		$this->assertSame( 1800000600, $decision->reset );
		$this->assertSame( 477, $decision->retry_after() );
		$this->assertSame( 600, $decision->window );
	}

	public function test_a_new_window_starts_the_count_again(): void {
		$store = new Memory( self::NOW );

		$this->limiter( $store )->hit( 'a:b', 1, 600 );
		$this->assertTrue( $this->limiter( $store )->hit( 'a:b', 1, 600 )->denied() );

		$store->travel( 1800000600 );
		$this->assertTrue( $this->limiter( $store, 1800000600 )->hit( 'a:b', 1, 600 )->allowed );
	}

	public function test_the_last_second_of_a_window_is_still_that_window(): void {
		$store = new Memory( self::NOW );

		$this->limiter( $store )->hit( 'a:b', 1, 600 );

		$store->travel( 1800000599 );
		$this->assertTrue( $this->limiter( $store, 1800000599 )->hit( 'a:b', 1, 600 )->denied() );
	}

	public function test_nought_or_less_is_no_limit_and_counts_nothing(): void {
		$store   = new Memory( self::NOW );
		$limiter = $this->limiter( $store );

		foreach ( array( 0, -1 ) as $limit ) {
			$decision = $limiter->hit( 'a:b', $limit, 600 );

			$this->assertTrue( $decision->allowed );
			$this->assertFalse( $decision->limited );
			$this->assertSame( array(), $decision->headers() );
		}

		$this->assertSame( 0, $limiter->count( 'a:b', 600 ) );
	}

	/**
	 * '' would be one counter for everybody with nothing to count against;
	 * the retired package refused it by throwing, and so does this.
	 */
	public function test_an_empty_name_is_refused_not_one_shared_counter(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		foreach ( array( 'hit', 'check', 'count', 'reset' ) as $method ) {
			try {
				'hit' === $method || 'check' === $method ? $limiter->{$method}( '  ', 1, 600 ) : $limiter->{$method}( '', 600 );
				$this->fail( "{$method}() counted a counter with no name." );
			} catch ( \InvalidArgumentException ) {
				$this->addToAssertionCount( 1 );
			}
		}
	}

	public function test_check_looks_without_counting(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		$limiter->hit( 'a:b', 2, 600 );

		$look = $limiter->check( 'a:b', 2, 600 );
		$this->assertTrue( $look->allowed );
		$this->assertSame( 1, $look->count );
		$this->assertSame( 1, $look->remaining );
		$this->assertSame( 1, $limiter->count( 'a:b', 600 ) );

		$limiter->hit( 'a:b', 2, 600 );
		$this->assertTrue( $limiter->check( 'a:b', 2, 600 )->denied(), 'Nothing left: the next would be refused.' );
		$this->assertFalse( $limiter->check( 'a:b', 0, 600 )->limited );
	}

	public function test_reset_starts_the_window_again_for_one_name(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		$limiter->hit( 'a:b', 1, 600 );
		$limiter->hit( 'a:c', 1, 600 );
		$limiter->reset( 'a:b', 600 );

		$this->assertSame( 0, $limiter->count( 'a:b', 600 ) );
		$this->assertSame( 1, $limiter->count( 'a:c', 600 ) );
		$this->assertTrue( $limiter->hit( 'a:b', 1, 600 )->allowed );
	}

	public function test_different_windows_are_different_counters(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );

		$limiter->hit( 'a:b', 1, 600 );

		$this->assertSame( 0, $limiter->count( 'a:b', 60 ) );
	}

	public function test_the_key_is_the_salted_hash_of_name_window_and_window_number(): void {
		$limiter = new Limiter( new Memory(), null, self::NOW );

		// The formula the host's existing rows were written with.
		$expected = hash_hmac( 'sha256', 'checkout_ip:203.0.113.9|600|' . (int) floor( self::NOW / 600 ), wp_salt( 'nonce' ) );

		$this->assertSame( $expected, $limiter->key( 'checkout_ip:203.0.113.9', 600, self::NOW ) );
		$this->assertSame( 64, strlen( $expected ) );
	}

	public function test_the_store_is_asked_to_keep_a_counter_until_the_next_window_ends(): void {
		$store = new class() implements Store {
			public array $asked = array();

			public function increment( string $key, int $ttl ): int {
				$this->asked[] = $ttl;

				return 1;
			}

			public function get( string $key ): int {
				return 0;
			}

			public function forget( string $key ): void {
			}
		};

		( new Limiter( $store, 'secret', self::NOW ) )->hit( 'a:b', 5, 600 );

		// ( floor( now / window ) + 2 ) * window, less now.
		$this->assertSame( array( ( 3000000 + 2 ) * 600 - self::NOW ), $store->asked );
		$this->assertSame( 1077, $store->asked[0] );
	}

	public function test_a_store_that_cannot_count_refuses_unless_told_otherwise(): void {
		$store = new class() implements Store {
			public function increment( string $key, int $ttl ): int {
				return 0;
			}

			public function get( string $key ): int {
				return 0;
			}

			public function forget( string $key ): void {
			}
		};

		$told    = 0;
		$limiter = ( new Limiter( $store, 'secret', self::NOW ) )->on_failure(
			static function () use ( &$told ): void {
				++$told;
			}
		);

		$refused = $limiter->hit( 'a:b', 1, 600 );

		$this->assertTrue( $refused->denied() );
		$this->assertTrue( $refused->failed );
		$this->assertSame( 0, $refused->remaining );
		$this->assertSame( 477, $refused->retry_after(), 'Come back when the window ends.' );

		$allowed = $limiter->hit( 'a:b', 1, 600, true );

		$this->assertTrue( $allowed->allowed );
		$this->assertTrue( $allowed->failed );
		$this->assertSame( 1, $allowed->remaining );
		$this->assertSame( 2, $told );
	}

	public function test_a_window_below_one_second_is_one_second(): void {
		$decision = $this->limiter( new Memory( self::NOW ) )->hit( 'a:b', 1, 0 );

		$this->assertSame( 1, $decision->window );
		$this->assertSame( self::NOW + 1, $decision->reset );
	}

	public function test_the_secret_is_not_dumped(): void {
		$dump = print_r( new Limiter( new Memory(), 'do-not-print-me' ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions

		$this->assertStringNotContainsString( 'do-not-print-me', $dump );
	}

	public function test_for_binds_the_action_and_the_identity(): void {
		$limiter = $this->limiter( new Memory( self::NOW ) );
		$limit   = $limiter->for( 'login', '203.0.113.9' );

		$this->assertTrue( $limit->hit( 1, 600 )->allowed );
		$this->assertTrue( $limit->hit( 1, 600 )->denied() );
		$this->assertSame( 2, $limit->count( 600 ) );
		$this->assertSame( 2, $limiter->count( 'login:203.0.113.9', 600 ), 'The same counter as the name spelled out.' );
		$this->assertTrue( $limit->check( 1, 600 )->denied() );

		$limit->reset( 600 );
		$this->assertSame( 0, $limit->count( 600 ) );
		$this->assertTrue( $limiter->for( 'login', '198.51.100.1' )->hit( 1, 600 )->allowed, 'Another caller has its own counter.' );
	}

	/**
	 * A form with no email is still limited: against the address the
	 * request came from, not let through and not one shared counter.
	 */
	public function test_an_empty_identity_counts_against_the_visitors_address(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';

		try {
			$limiter = $this->limiter( new Memory( self::NOW ) );

			foreach ( array( '', '   ' ) as $identity ) {
				$this->assertSame( 'login:203.0.113.9', $limiter->for( 'login', $identity )->name() );
			}

			$this->assertTrue( $limiter->for( 'login', '' )->hit( 1, 600 )->allowed );
			$this->assertTrue( $limiter->for( 'login', '' )->hit( 1, 600 )->denied(), 'The second is over the limit, not unlimited.' );
			$this->assertTrue( $limiter->for( 'login', '203.0.113.9' )->check( 1, 600 )->denied(), 'The same counter as the address given.' );
		} finally {
			unset( $_SERVER['REMOTE_ADDR'] );
		}
	}

	public function test_a_site_behind_a_proxy_says_who_the_visitor_is(): void {
		$_SERVER['REMOTE_ADDR'] = '10.0.0.5';

		try {
			$limiter = $this->limiter( new Memory( self::NOW ) )->client( static fn(): string => '198.51.100.7' );

			$this->assertSame( 'login:198.51.100.7', $limiter->for( 'login', '' )->name() );
		} finally {
			unset( $_SERVER['REMOTE_ADDR'] );
		}
	}

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function nothing_to_count(): array {
		return array(
			'no action'                     => array( '', '203.0.113.9' ),
			'no identity and no address'    => array( 'login', '' ),
			'blank identity and no address' => array( 'login', '  ' ),
		);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider( 'nothing_to_count' )]
	public function test_nothing_to_count_against_is_refused( string $action, string $identity ): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->limiter( new Memory( self::NOW ) )->for( $action, $identity );
	}

	/**
	 * Only an address is an address: a proxy that writes `unknown` into
	 * REMOTE_ADDR is not one counter for everybody.
	 */
	public function test_a_remote_addr_that_is_not_an_address_is_none(): void {
		$_SERVER['REMOTE_ADDR'] = 'unknown';

		try {
			$this->expectException( \InvalidArgumentException::class );

			$this->limiter( new Memory( self::NOW ) )->for( 'login', '' );
		} finally {
			unset( $_SERVER['REMOTE_ADDR'] );
		}
	}

	public function test_a_resolver_with_no_address_is_refused_too(): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->limiter( new Memory( self::NOW ) )->client( static fn(): ?string => null )->for( 'login', '' );
	}

	public function test_unlimited_is_allowed_and_silent(): void {
		$decision = Decision::unlimited();

		$this->assertTrue( $decision->allowed );
		$this->assertFalse( $decision->denied() );
		$this->assertSame( 0, $decision->retry_after() );
		$this->assertSame( array(), $decision->headers( Decision::STANDARD ) );
	}
}
