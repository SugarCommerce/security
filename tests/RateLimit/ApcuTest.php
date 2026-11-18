<?php
/**
 * The APCu store.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Stores\Apcu;
use SugarCommerce\Security\RateLimit\Stores\Fallback;
use SugarCommerce\Security\RateLimit\Stores\Memory;

/**
 * Where APCu is not there -- a command line without `apc.enable_cli` -- the
 * store says it could not count, and the attempt goes through or to the
 * store behind it. Where it is, it counts.
 */
final class ApcuTest extends TestCase {

	public function test_it_counts_where_apcu_is_on_and_says_it_cannot_where_it_is_off(): void {
		$store = new Apcu( 'test:' . bin2hex( random_bytes( 4 ) ) . ':' );

		if ( Apcu::available() ) {
			$this->assertSame( 1, $store->increment( 'k', 60 ) );
			$this->assertSame( 2, $store->increment( 'k', 60 ) );
			$this->assertSame( 2, $store->get( 'k' ) );

			$store->forget( 'k' );
			$this->assertSame( 0, $store->get( 'k' ) );

			return;
		}

		$this->assertSame( 0, $store->increment( 'k', 60 ) );
		$this->assertSame( 0, $store->get( 'k' ) );
		$store->forget( 'k' );
	}

	public function test_behind_a_fallback_the_limit_still_holds(): void {
		$limiter = new Limiter( new Fallback( new Apcu( 'test:' . bin2hex( random_bytes( 4 ) ) . ':' ), new Memory( 1_800_000_000 ) ), 'secret', 1_800_000_000 );

		$this->assertTrue( $limiter->hit( 'login:a', 2, 600 )->allowed );
		$this->assertTrue( $limiter->hit( 'login:a', 2, 600 )->allowed );
		$this->assertTrue( $limiter->hit( 'login:a', 2, 600 )->denied() );
	}
}
