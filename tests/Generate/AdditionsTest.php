<?php
/**
 * What the generators gained in the move: typed slugs, short ids, API key
 * digests, and stricter UUID checks.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Generate;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\ApiKey;
use SugarCommerce\Security\Random;
use SugarCommerce\Security\Uuid;

final class AdditionsTest extends TestCase {

	protected function tearDown(): void {
		Clock::reset();
	}

	/* ─── Short ids ────────────────────────────────────────────────── */

	public function test_an_id_is_prefixed_hex(): void {
		$this->assertMatchesRegularExpression( '/^evt_[a-f0-9]{16}$/D', Random::id( 'evt' ) );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{8}$/D', Random::id( '', 4 ) );
	}

	public function test_an_id_needs_some_randomness(): void {
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{8}$/D', Random::id( '', 4 ) );

		$this->expectException( \InvalidArgumentException::class );

		Random::id( 'x', 3 );
	}

	public function test_ids_do_not_repeat(): void {
		$ids = array();

		for ( $i = 0; $i < 200; $i++ ) {
			$ids[] = Random::id( 'x' );
		}

		$this->assertCount( 200, array_unique( $ids ) );
	}

	/* ─── API keys ─────────────────────────────────────────────────── */

	public function test_api_key_prefix_can_show_fewer_characters(): void {
		$key = ApiKey::make( 'sc_sk_live', 7 );

		$this->assertSame( 18, strlen( $key['prefix'] ) );
		$this->assertStringStartsWith( 'sc_sk_live_', $key['prefix'] );
		$this->assertStringStartsWith( $key['prefix'], $key['key'] );
		$this->assertSame( 'sk_', ApiKey::make( 'sk', 0 )['prefix'] );
		$this->assertSame( 15, strlen( ApiKey::make( 'sk', 12 )['prefix'] ) );
	}

	public function test_api_key_refuses_to_show_most_of_the_secret(): void {
		$this->expectException( \InvalidArgumentException::class );

		ApiKey::make( 'sk', 13 );
	}

	public function test_api_key_refuses_a_negative_count(): void {
		$this->expectException( \InvalidArgumentException::class );

		ApiKey::make( 'sk', -1 );
	}

	public function test_digest_agrees_with_matches(): void {
		$this->assertTrue( ApiKey::matches( 'sk_abc', ApiKey::digest( 'sk_abc' ) ) );
	}

	public function test_digest_is_stable_and_hex(): void {
		$this->assertSame( hash( 'sha256', 'sk_abc' ), ApiKey::digest( 'sk_abc' ) );
		$this->assertNotSame( ApiKey::digest( 'sk_abc' ), ApiKey::digest( 'sk_abd' ) );
	}

	public function test_digest_is_what_make_stores(): void {
		$key = ApiKey::make();

		$this->assertSame( $key['hash'], ApiKey::digest( $key['key'] ) );
		$this->assertMatchesRegularExpression( '/^sk_[A-Za-z0-9_-]{43}$/D', $key['key'] );
	}

	/* ─── UUIDs ────────────────────────────────────────────────────── */

	public function test_a_uuid_with_a_trailing_newline_is_rejected(): void {
		$uuid = Uuid::v7();

		$this->assertFalse( Uuid::is_valid( $uuid . "\n" ) );
		$this->assertFalse( Uuid::is_valid( $uuid . "\n", 7 ) );
	}

	public function test_a_version_outside_one_to_eight_matches_nothing(): void {
		$this->assertFalse( Uuid::is_valid( '0' . substr( Uuid::v4(), 1 ), 10 ) );
		$this->assertFalse( Uuid::is_valid( Uuid::v4(), 0 ) );
		$this->assertFalse( Uuid::is_valid( Uuid::v4(), 9 ) );
		$this->assertFalse( Uuid::is_valid( '00000000-0000-0000-8000-000000000000', 0 ), 'Version 0 is not one, even where the digit is there.' );
		$this->assertTrue( Uuid::is_valid( Uuid::v4(), 4 ) );
	}

	public function test_a_v7_minted_under_a_frozen_clock_carries_its_time(): void {
		Clock::freeze( 1_800_000_000 );

		$this->assertSame( 1_800_000_000_000, Uuid::timestamp( Uuid::v7() ) );
	}
}
