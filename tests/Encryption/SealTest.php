<?php
/**
 * The payload without a marker, and values under a key made another way.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Encryption;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\Encryption\Cipher;
use WP_Error;

final class SealTest extends TestCase {

	protected function setUp(): void {
		ts_reset();
	}

	/**
	 * Sealed by the code before seal() and open() were split out of
	 * encrypt() and decrypt(): the stored format did not move.
	 */
	public function test_values_stored_before_the_split_still_decrypt(): void {
		$own  = '__SHOP_ENCRYPTED__v2:o1r4uC/72sdVDLUYPp6eo8+hIbX5Xl0J6DwuY3TUS/Lf0lNoVyIJmyI8hIwq6j8vu/j6HZs=';
		$site = '__SHOP_ENCRYPTED__v2:5oL7sMUVtynOXkRRM3vo2hcaoXS9SJYe/GOSmDMSjHXlE9dGVHDucgRmCjuUfb18k9x+RfA=';

		$this->assertSame( 'sk_example_cipher_fixture', ( new Cipher( 'shop', ts_key( 'any' ) ) )->also_open( 'fixture-key' )->decrypt( $own ) );
		$this->assertSame( 'sk_example_cipher_fixture', ( new Cipher( 'shop' ) )->decrypt( $site ) );
	}

	public function test_a_sealed_payload_carries_no_marker_and_opens(): void {
		$cipher  = new Cipher( 'shop', ts_key( 'k' ) );
		$payload = (string) $cipher->seal( 'secret' );

		$this->assertStringNotContainsString( 'ENCRYPTED', $payload );
		$this->assertNotFalse( base64_decode( $payload, true ) );
		$this->assertSame( 'secret', $cipher->open( $payload ) );
	}

	public function test_seal_is_what_encrypt_puts_after_its_marker_once_a_purpose_is_named(): void {
		$cipher = new Cipher( 'shop', ts_key( 'k' ), 'shop' );
		$sealed = (string) $cipher->encrypt( 'secret' );

		$this->assertSame( 'secret', $cipher->open( substr( $sealed, strlen( '__SHOP_ENCRYPTED__v3:' ) ) ) );
		$this->assertSame( 'secret', $cipher->decrypt( '__SHOP_ENCRYPTED__v3:' . $cipher->seal( 'secret' ) ) );
	}

	public function test_without_a_purpose_seal_is_the_shared_v2_payload(): void {
		$cipher = new Cipher( 'shop', ts_key( 'k' ) );

		$this->assertSame( 'secret', $cipher->decrypt( '__SHOP_ENCRYPTED__v2:' . $cipher->seal( 'secret' ) ) );
		$this->assertInstanceOf( WP_Error::class, $cipher->decrypt( '__SHOP_ENCRYPTED__v3:' . $cipher->seal( 'secret' ) ) );
	}

	/**
	 * Twelve bytes of nonce and a whole tag with no ciphertext is an empty
	 * value. One byte less is refused before OpenSSL, which would take a
	 * short tag.
	 */
	public function test_an_empty_value_seals_and_a_short_tag_does_not_open(): void {
		$cipher  = new Cipher( 'shop', ts_key( 'k' ) );
		$payload = (string) $cipher->seal( '' );

		$this->assertSame( 28, strlen( (string) base64_decode( $payload, true ) ) );
		$this->assertSame( '', $cipher->open( $payload ) );

		$short = base64_encode( substr( (string) base64_decode( $payload, true ), 0, 27 ) );

		$this->assertInstanceOf( WP_Error::class, $cipher->open( $short ) );
		$this->assertSame( 'Invalid encrypted data', $cipher->open( $short )->get_error_message() );
	}

	public function test_a_tampered_payload_does_not_open(): void {
		$cipher = new Cipher( 'shop', ts_key( 'k' ) );
		$raw    = (string) base64_decode( (string) $cipher->seal( 'secret' ), true );

		$raw[ strlen( $raw ) - 1 ] = chr( ord( $raw[ strlen( $raw ) - 1 ] ) ^ 1 );

		$this->assertInstanceOf( WP_Error::class, $cipher->open( base64_encode( $raw ) ) );
		$this->assertInstanceOf( WP_Error::class, $cipher->open( 'not base64!' ) );
	}

	/* ─── Older keys ───────────────────────────────────────────────── */

	public function test_a_value_under_an_older_key_opens_once_named(): void {
		$old     = (string) ( new Cipher( 'shop', ts_key( 'older-material' ) ) )->seal( 'secret' );
		$current = new Cipher( 'shop', ts_key( 'current' ) );

		$this->assertInstanceOf( WP_Error::class, $current->open( $old ) );

		$current->also_open( '', ts_key( 'older-material' ) );

		$this->assertSame( 'secret', $current->open( $old ) );
		$this->assertSame( 'secret', $current->decrypt( '__SHOP_ENCRYPTED__v2:' . $old ) );
	}

	public function test_nothing_is_written_under_an_older_key(): void {
		$current = ( new Cipher( 'shop', ts_key( 'current' ) ) )->also_open( ts_key( 'older-material' ) );
		$payload = (string) $current->seal( 'secret' );

		$this->assertInstanceOf( WP_Error::class, ( new Cipher( 'shop', ts_key( 'older-material' ) ) )->open( $payload ) );
		$this->assertSame( 'secret', ( new Cipher( 'shop', ts_key( 'current' ) ) )->open( $payload ) );
	}

	public function test_older_keys_survive_a_change_of_key(): void {
		$old    = (string) ( new Cipher( 'shop', ts_key( 'older-material' ) ) )->seal( 'secret' );
		$cipher = ( new Cipher( 'shop', ts_key( 'first' ) ) )->also_open( ts_key( 'older-material' ) );

		$cipher->change_key( ts_key( 'second' ) );

		$this->assertSame( 'secret', $cipher->open( $old ) );
	}

	public function test_the_first_failure_is_the_one_reported(): void {
		$cipher = ( new Cipher( 'shop', ts_key( 'k' ) ) )->also_open( ts_key( 'other' ) );

		$this->assertSame( 'Invalid encrypted data', $cipher->open( 'AAAA' )->get_error_message() );
	}
}
