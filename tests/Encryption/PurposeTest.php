<?php
/**
 * A key for each purpose, a floor under a caller's key, and every value the
 * shared-key code wrote still read.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Encryption;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\Encryption\Cipher;
use SugarCommerce\Security\Encryption\Secrets;
use WP_Error;

final class PurposeTest extends TestCase {

	/**
	 * The key the fixtures below were written under.
	 */
	private const KEY = 'a-key-of-the-callers-own-at-least-32-bytes';

	protected function setUp(): void {
		ts_reset();
	}

	/* ─── Written before purposes ──────────────────────────────────── */

	/**
	 * Written by the cipher when every purpose shared one key, under a key
	 * of the caller's own and under the test site's, encrypted and sealed.
	 *
	 * @return array<string, array{string, string|null, string}>
	 */
	public static function shared_key_values(): array {
		return array(
			'encrypted, own key' => array( 'decrypt', self::KEY, '__SHOP_ENCRYPTED__v2:xg3RNNTBQ1kIXADUlP4MJkpq4g+ZNApYjPWoMFfTP3N90V7t/YVBd/VY' ),
			'encrypted, site key' => array( 'decrypt', null, '__SHOP_ENCRYPTED__v2:3GjCzWCW6SZsCBLL6xvSep/2Pcm16LCYkFZiANZ8/LVHzWiHuSsBm8nQ' ),
			'sealed, own key'    => array( 'open', self::KEY, '2um1TO31xgl6aQtqKHW1AhRcIqw+3Vintb3TelawD9ks7CF9y5R+B68K' ),
			'sealed, site key'   => array( 'open', null, '8Qx6OBzkeM7uvb+kSDjQVZjEoQuA0SoxsILnVRzNX2eYMkOgPz6ASd/S' ),
		);
	}

	#[DataProvider( 'shared_key_values' )]
	public function test_a_value_written_under_the_shared_key_still_reads( string $method, ?string $key, string $stored ): void {
		$this->assertSame( 'fixture secret', ( new Cipher( 'shop', $key ) )->{$method}( $stored ) );
		$this->assertSame( 'fixture secret', ( new Cipher( 'shop', $key, 'shop/named' ) )->{$method}( $stored ), 'Naming a purpose later still reads it.' );
	}

	public function test_a_shared_key_value_is_older_and_saving_it_moves_it(): void {
		$cipher = new Cipher( 'shop', self::KEY );
		$stored = '__SHOP_ENCRYPTED__v2:xg3RNNTBQ1kIXADUlP4MJkpq4g+ZNApYjPWoMFfTP3N90V7t/YVBd/VY';

		$this->assertTrue( $cipher->is_legacy_format( $stored ) );

		$moved = (string) $cipher->reencrypt( $stored );

		$this->assertStringStartsWith( '__SHOP_ENCRYPTED__v3:', $moved );
		$this->assertFalse( $cipher->is_legacy_format( $moved ) );
		$this->assertSame( 'fixture secret', $cipher->decrypt( $moved ) );
	}

	/**
	 * Pins the derivation: a change to the HKDF label or the purpose
	 * default would stop every value already written from opening.
	 */
	public function test_a_value_written_under_a_purpose_key_still_reads(): void {
		$this->assertSame( 'fixture secret', ( new Cipher( 'shop', self::KEY ) )->decrypt( '__SHOP_ENCRYPTED__v3:RFFG911pZrlZ2YqqsO13nW9zixY+xTOVx8tt3OryYcP3apdhf1JB4MSm' ) );
		$this->assertSame( 'fixture secret', ( new Cipher( 'shop' ) )->decrypt( '__SHOP_ENCRYPTED__v3:efrmVh9lvOZQiVEmClJTpSY8qkcku/h6ZJtyaSoEyzHZfzhvL6qYY+Mu' ) );
	}

	/* ─── One key per purpose ──────────────────────────────────────── */

	/**
	 * The point of it: two plugins on one site's salts. Before, the prefix
	 * only labelled the value, so moving the payload under the other
	 * plugin's marker opened it.
	 */
	public function test_another_plugins_cipher_does_not_open_a_value(): void {
		$sealed  = (string) ( new Cipher( 'alpha' ) )->encrypt( 'secret' );
		$payload = substr( $sealed, strlen( '__ALPHA_ENCRYPTED__' ) );

		$this->assertInstanceOf( WP_Error::class, ( new Cipher( 'beta' ) )->decrypt( '__BETA_ENCRYPTED__' . $payload ) );
		$this->assertSame( 'secret', ( new Cipher( 'alpha' ) )->decrypt( $sealed ) );
	}

	public function test_two_purposes_under_one_prefix_and_key_are_apart(): void {
		$api      = new Cipher( 'shop', self::KEY, 'shop/api-keys' );
		$webhooks = new Cipher( 'shop', self::KEY, 'shop/webhooks' );

		$this->assertInstanceOf( WP_Error::class, $webhooks->decrypt( (string) $api->encrypt( 'secret' ) ) );
		$this->assertInstanceOf( WP_Error::class, $webhooks->open( (string) $api->seal( 'secret' ) ) );
		$this->assertSame( 'secret', $api->open( (string) $api->seal( 'secret' ) ) );
	}

	public function test_the_purpose_key_is_not_the_shared_key(): void {
		$cipher  = new Cipher( 'shop', self::KEY );
		$payload = substr( (string) $cipher->encrypt( 'secret' ), strlen( '__SHOP_ENCRYPTED__v3:' ) );

		$this->assertInstanceOf( WP_Error::class, $cipher->open( $payload ), 'open() without a purpose is on the shared key.' );
		$this->assertInstanceOf( WP_Error::class, $cipher->decrypt( '__SHOP_ENCRYPTED__v2:' . $payload ) );
	}

	/**
	 * A payload carries no version, so seal() stays where code with its
	 * own marker already reads it until that code names a purpose.
	 */
	public function test_sealing_without_a_purpose_stays_on_the_shared_key(): void {
		$payload = (string) ( new Cipher( 'fields' ) )->seal( 'secret' );

		$this->assertSame( 'secret', ( new Cipher( 'any' ) )->open( $payload ) );
	}

	public function test_a_purpose_value_opens_under_an_older_key_once_named(): void {
		$stored  = (string) ( new Cipher( 'shop', ts_key( 'older' ) ) )->encrypt( 'secret' );
		$current = new Cipher( 'shop', ts_key( 'current' ) );

		$this->assertInstanceOf( WP_Error::class, $current->decrypt( $stored ) );
		$this->assertSame( 'secret', $current->also_open( ts_key( 'older' ) )->decrypt( $stored ) );
	}

	public function test_the_purpose_is_shown_but_not_the_key(): void {
		$dump = print_r( new Cipher( 'shop', self::KEY, 'shop/api-keys' ), true );

		$this->assertStringContainsString( 'shop/api-keys', $dump );
		$this->assertStringNotContainsString( self::KEY, $dump );
	}

	public function test_an_empty_purpose_is_refused(): void {
		$this->expectException( InvalidArgumentException::class );

		new Cipher( 'shop', self::KEY, ' ' );
	}

	/* ─── A key of the caller's own ────────────────────────────────── */

	/**
	 * @return array<string, array{string}>
	 */
	public static function short_keys(): array {
		return array(
			'one byte'       => array( 'k' ),
			'a password'     => array( 'hunter2' ),
			'one byte short' => array( str_repeat( 'x', Cipher::MIN_KEY_BYTES - 1 ) ),
		);
	}

	#[DataProvider( 'short_keys' )]
	public function test_a_short_key_is_refused( string $key ): void {
		$this->expectException( InvalidArgumentException::class );

		new Cipher( 'shop', $key );
	}

	public function test_a_short_key_is_refused_by_secrets_and_change_key(): void {
		$cipher = new Cipher( 'shop', self::KEY );

		try {
			$cipher->change_key( 'short' );
			$this->fail( 'change_key() took a short key.' );
		} catch ( InvalidArgumentException ) {
			$this->assertSame( 'secret', $cipher->decrypt( (string) $cipher->encrypt( 'secret' ) ), 'The old key is kept.' );
		}

		$this->expectException( InvalidArgumentException::class );

		new Secrets( 'shop', 'short', false );
	}

	public function test_thirty_two_bytes_the_site_key_and_older_short_keys_are_taken(): void {
		$this->assertSame( 'x', ( new Cipher( 'shop', str_repeat( 'x', Cipher::MIN_KEY_BYTES ) ) )->decrypt( (string) ( new Cipher( 'shop', str_repeat( 'x', Cipher::MIN_KEY_BYTES ) ) )->encrypt( 'x' ) ) );
		$this->assertSame( 'x', ( new Cipher( 'shop', '' ) )->decrypt( (string) ( new Cipher( 'shop' ) )->encrypt( 'x' ) ), "'' is the site's key." );

		// Only to read what a short key wrote; nothing is written under it.
		$this->assertInstanceOf( Cipher::class, ( new Cipher( 'shop', self::KEY ) )->also_open( 'short' ) );
	}
}
