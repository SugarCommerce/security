<?php
/**
 * The site's own encryption key, and the placeholder salts.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\Encryption\Cipher;
use SugarCommerce\Security\Keys;
use WP_Error;

/**
 * Each test defines wp-config constants, which cannot be undefined again,
 * so each runs in a process of its own.
 */
final class SiteKeyTest extends TestCase {

	private const PLACEHOLDER = 'put your unique phrase here';

	/**
	 * Define the four `*_KEY` constants.
	 *
	 * @param array<string, string> $values Constant => value.
	 */
	private static function define_keys( array $values ): void {
		foreach ( $values as $name => $value ) {
			define( $name, $value );
		}
	}

	/**
	 * What wp_salt() gives for the two schemes the key is made from.
	 */
	private static function from_salts(): string {
		return hash( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), true );
	}

	/**
	 * A site with real keys keeps the key it has always had, so every value
	 * it already encrypted still opens.
	 */
	#[RunInSeparateProcess]
	public function test_a_site_with_real_keys_keeps_its_key(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => str_repeat( 'a', 64 ),
				'SECURE_AUTH_KEY' => str_repeat( 'b', 64 ),
				'LOGGED_IN_KEY'   => str_repeat( 'c', 64 ),
				'NONCE_KEY'       => str_repeat( 'd', 64 ),
			)
		);

		$this->assertSame(
			hash( 'sha256', str_repeat( 'a', 64 ) . str_repeat( 'b', 64 ) . str_repeat( 'c', 64 ) . str_repeat( 'd', 64 ), true ),
			Keys::encryption()
		);
		$this->assertSame( array(), Keys::previous_encryption() );
	}

	/**
	 * Partly defined, but real: still the constants that are there.
	 */
	#[RunInSeparateProcess]
	public function test_a_site_with_some_real_keys_keeps_its_key(): void {
		self::define_keys(
			array(
				'AUTH_KEY'  => str_repeat( 'a', 64 ),
				'NONCE_KEY' => str_repeat( 'd', 64 ),
			)
		);

		$this->assertSame( hash( 'sha256', str_repeat( 'a', 64 ) . str_repeat( 'd', 64 ), true ), Keys::encryption() );
	}

	/**
	 * The placeholders are printed in wp-config-sample.php, so a key made
	 * from them is public. wp_salt() swaps them for a stored random secret.
	 */
	#[RunInSeparateProcess]
	public function test_the_placeholder_keys_are_never_the_key(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => self::PLACEHOLDER,
				'SECURE_AUTH_KEY' => self::PLACEHOLDER,
				'LOGGED_IN_KEY'   => self::PLACEHOLDER,
				'NONCE_KEY'       => self::PLACEHOLDER,
			)
		);

		$this->assertNotSame( hash( 'sha256', str_repeat( self::PLACEHOLDER, 4 ), true ), Keys::encryption() );
		$this->assertSame( self::from_salts(), Keys::encryption() );
	}

	/**
	 * One placeholder among real keys is enough to stop trusting them.
	 */
	#[RunInSeparateProcess]
	public function test_one_placeholder_key_is_enough_to_use_the_salts(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => str_repeat( 'a', 64 ),
				'SECURE_AUTH_KEY' => str_repeat( 'b', 64 ),
				'LOGGED_IN_KEY'   => str_repeat( 'c', 64 ),
				'NONCE_KEY'       => self::PLACEHOLDER,
			)
		);

		$this->assertSame( self::from_salts(), Keys::encryption() );
	}

	/**
	 * A value pasted into two constants is one core no longer trusts either.
	 */
	#[RunInSeparateProcess]
	public function test_duplicated_keys_use_the_salts(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => str_repeat( 'a', 64 ),
				'SECURE_AUTH_KEY' => str_repeat( 'b', 64 ),
				'LOGGED_IN_KEY'   => str_repeat( 'c', 64 ),
				'NONCE_KEY'       => str_repeat( 'd', 64 ),
				'NONCE_SALT'      => str_repeat( 'd', 64 ),
			)
		);

		$this->assertSame( self::from_salts(), Keys::encryption() );
	}

	/**
	 * An empty constant is no secret either.
	 */
	#[RunInSeparateProcess]
	public function test_an_empty_key_uses_the_salts(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => str_repeat( 'a', 64 ),
				'SECURE_AUTH_KEY' => '',
			)
		);

		$this->assertSame( self::from_salts(), Keys::encryption() );
	}

	/**
	 * WP_ENCRYPTION_KEY still wins over everything.
	 */
	#[RunInSeparateProcess]
	public function test_the_encryption_constant_still_wins(): void {
		self::define_keys(
			array(
				'AUTH_KEY'          => self::PLACEHOLDER,
				'WP_ENCRYPTION_KEY' => 'mine',
			)
		);

		$this->assertSame( hash( 'sha256', 'mine', true ), Keys::encryption() );
		$this->assertSame( array(), Keys::previous_encryption() );
	}

	/**
	 * A site on the placeholders already has values encrypted under the old
	 * key. They still open, and saving them again moves them to the new one.
	 */
	#[RunInSeparateProcess]
	public function test_values_sealed_under_the_placeholder_key_still_open(): void {
		self::define_keys(
			array(
				'AUTH_KEY'        => self::PLACEHOLDER,
				'SECURE_AUTH_KEY' => self::PLACEHOLDER,
				'LOGGED_IN_KEY'   => self::PLACEHOLDER,
				'NONCE_KEY'       => self::PLACEHOLDER,
			)
		);

		// What the cipher wrote before: the key hashed from the constants.
		$old    = new Cipher( 'shop', str_repeat( self::PLACEHOLDER, 4 ) );
		$stored = (string) $old->encrypt( 'secret' );
		$site   = new Cipher( 'shop' );

		$this->assertSame( 'secret', $site->decrypt( $stored ) );

		$moved = (string) $site->reencrypt( $stored );

		$this->assertSame( 'secret', $site->decrypt( $moved ) );
		$this->assertInstanceOf( WP_Error::class, $old->decrypt( $moved ), 'Now under the secret key, not the public one.' );
	}

	/**
	 * The fallback is for that one case: on a site with real keys a value
	 * under any other key is still refused.
	 */
	#[RunInSeparateProcess]
	public function test_a_site_with_real_keys_opens_nothing_else(): void {
		self::define_keys( array( 'AUTH_KEY' => str_repeat( 'a', 64 ) ) );

		$stored = (string) ( new Cipher( 'shop', str_repeat( self::PLACEHOLDER, 4 ) ) )->encrypt( 'secret' );

		$this->assertInstanceOf( WP_Error::class, ( new Cipher( 'shop' ) )->decrypt( $stored ) );
	}
}
