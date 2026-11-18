<?php
/**
 * Keys and hashes through core's wp_hash(), the same bytes as before.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SugarCommerce\Security\Hash;
use SugarCommerce\Security\Keys;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Stores\Memory;
use SugarCommerce\Security\Turnstile\Record;
use SugarCommerce\Security\Uuid;

/**
 * Every expected value below was computed by the code before it called
 * wp_hash() -- `hash_hmac( 'sha256', $data, wp_salt( $scheme ) )` written
 * out -- under this suite's salts. A link already emailed, a digest already
 * stored and a rate-limit counter already counting all depend on these
 * staying the same.
 */
final class CoreHashTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['st_salt'] = str_repeat( 'k', 64 );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['st_salt'] );
	}

	public function test_signing_keys_are_unchanged(): void {
		$this->assertSame( 'de2814361b3ce113f1d7be65be5cd4df54a41ac1325e2840696f01dea5f0e4a1', Keys::signing() );
		$this->assertSame( '4ca1ff99094eda42e11ead85b8c34c801d56921fb8fc19361eeb04d8a9e8c1a3', Keys::signing( 'downloads' ) );
	}

	public function test_derived_keys_and_site_digests_are_unchanged(): void {
		$this->assertSame( 'a5eb154dbd8fd36497a1646a55501da9f26295a281aedac0ac081d2150079193', Keys::derive( 'hash/visitors' ) );
		$this->assertSame( 'e68c867c08458a64c8543cb9d29152a235d420750d2edc92c6beaa6096a7723c', Hash::site( 'visitors' )->ip( '203.0.113.7' ) );
	}

	public function test_a_default_rate_limit_counter_keeps_its_key(): void {
		$this->assertSame(
			'95f45867d57201bf9a3fffc0dc7fa2c54f9aeb4f97c521e77d8f6b9dabbc6970',
			( new Limiter( new Memory() ) )->key( 'login|203.0.113.7', 60, 1700000000 )
		);
	}

	public function test_a_limiter_with_its_own_secret_does_not_use_the_salt(): void {
		$data = 'login|203.0.113.7|60|' . intdiv( 1700000000, 60 );

		$this->assertSame(
			hash_hmac( 'sha256', $data, 'own-secret' ),
			( new Limiter( new Memory(), 'own-secret' ) )->key( 'login|203.0.113.7', 60, 1700000000 )
		);
	}

	public function test_a_turnstile_key_fingerprint_is_unchanged(): void {
		$fingerprint = new ReflectionMethod( Record::class, 'fingerprint' );

		$this->assertSame( 'addc8dbbe88d', $fingerprint->invoke( null, '0x4AAAAAAA-secret' ) );
	}

	public function test_the_salt_guard_still_stands_in_front_of_core(): void {
		$GLOBALS['st_salt'] = 'put your unique phrase hereput your unique phrase here';

		$this->expectException( \RuntimeException::class );

		Keys::signing();
	}

	public function test_a_v4_uuid_is_cores(): void {
		$uuid = Uuid::v4();

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $uuid );
		$this->assertNotSame( $uuid, Uuid::v4() );
	}
}
