<?php
/**
 * The cipher on its own, rotation, and where else secrets are kept.
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
use SugarCommerce\Security\Encryption\Secrets;
use WP_Error;

final class CipherTest extends TestCase {

	protected function setUp(): void {
		ts_reset();
		putenv( 'CIPHERPFX_FROM_ENV' );
	}

	protected function tearDown(): void {
		putenv( 'CIPHERPFX_FROM_ENV' );
		unset( $GLOBALS['ts_current_filter'] );
	}

	/* ─── The marker ───────────────────────────────────────────────── */

	public function test_values_are_marked_with_the_prefix(): void {
		$cipher = new Cipher( 'shop', ts_key( 'k' ) );

		$this->assertSame( '__SHOP_ENCRYPTED__', $cipher->marker() );
		$this->assertStringStartsWith( '__SHOP_ENCRYPTED__v3:', (string) $cipher->encrypt( 'x' ) );
	}

	public function test_another_prefix_does_not_read_as_encrypted(): void {
		$sealed = ( new Cipher( 'shop', ts_key( 'k' ) ) )->encrypt( 'secret' );

		$this->assertFalse( ( new Cipher( 'other', ts_key( 'k' ) ) )->is_encrypted( $sealed ) );
		$this->assertSame( $sealed, ( new Cipher( 'other', ts_key( 'k' ) ) )->decrypt( $sealed ), 'Passed through as a plain value.' );
	}

	public function test_a_wrong_key_does_not_open_a_value(): void {
		$sealed = ( new Cipher( 'shop', ts_key( 'right' ) ) )->encrypt( 'secret' );

		$this->assertInstanceOf( WP_Error::class, ( new Cipher( 'shop', ts_key( 'wrong' ) ) )->decrypt( $sealed ) );
	}

	public function test_nothing_but_the_site_key_is_needed(): void {
		$cipher = new Cipher( 'shop' );

		$this->assertSame( 'secret', $cipher->decrypt( (string) $cipher->encrypt( 'secret' ) ) );
	}

	public function test_dumping_it_does_not_print_the_key(): void {
		$this->assertStringNotContainsString( hash( 'sha256', ts_key( 'k' ), true ), print_r( new Cipher( 'shop', ts_key( 'k' ) ), true ) );
	}

	/* ─── Once, and again under a new key ──────────────────────────── */

	public function test_encrypt_once_never_seals_twice(): void {
		$cipher = new Cipher( 'shop', ts_key( 'k' ) );
		$sealed = (string) $cipher->encrypt( 'secret' );

		$this->assertSame( $sealed, $cipher->encrypt_once( $sealed ) );
		$this->assertSame( 'secret', $cipher->decrypt( (string) $cipher->encrypt_once( 'secret' ) ) );
	}

	public function test_reencrypt_moves_a_value_to_the_new_key(): void {
		$old    = new Cipher( 'shop', ts_key( 'old' ) );
		$new    = new Cipher( 'shop', ts_key( 'new' ) );
		$stored = (string) $old->encrypt( 'secret' );

		$moved = $new->reencrypt( $stored, $old );

		$this->assertNotNull( $moved );
		$this->assertSame( 'secret', $new->decrypt( $moved ) );
		$this->assertInstanceOf( WP_Error::class, $old->decrypt( $moved ) );
	}

	public function test_reencrypt_is_safe_to_run_twice(): void {
		$old   = new Cipher( 'shop', ts_key( 'old' ) );
		$new   = new Cipher( 'shop', ts_key( 'new' ) );
		$moved = (string) $new->reencrypt( (string) $old->encrypt( 'secret' ), $old );

		$this->assertSame( 'secret', $new->decrypt( (string) $new->reencrypt( $moved, $old ) ) );
	}

	public function test_reencrypt_seals_a_plain_value(): void {
		$new = new Cipher( 'shop', ts_key( 'new' ) );

		$this->assertSame( 'secret', $new->decrypt( (string) $new->reencrypt( 'secret' ) ) );
	}

	public function test_reencrypt_stops_on_a_value_no_key_opens(): void {
		$lost = (string) ( new Cipher( 'shop', ts_key( 'lost' ) ) )->encrypt( 'secret' );

		$this->assertNull( ( new Cipher( 'shop', ts_key( 'new' ) ) )->reencrypt( $lost, new Cipher( 'shop', ts_key( 'old' ) ) ) );
	}

	/* ─── Constants ────────────────────────────────────────────────── */

	public function test_a_constant_wins_over_everything(): void {
		define( 'CIPHERPFX_FROM_CONSTANT', 'from-constant' );
		putenv( 'CIPHERPFX_FROM_CONSTANT=from-env' );

		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ), false );

		$this->assertFalse( $secrets->update_option( 'from_constant', 'from-db' ) );
		$this->assertSame( 'from-constant', $secrets->get_option( 'from_constant' ) );
		$this->assertTrue( $secrets->is_constant_defined( 'from_constant' ) );
		$this->assertSame( 'CIPHERPFX_FROM_CONSTANT', $secrets->get_constant_name( 'from_constant' ) );
		$this->assertSame(
			array(
				'value'        => 'from-constant',
				'source'       => 'constant',
				'constant'     => 'CIPHERPFX_FROM_CONSTANT',
				'is_encrypted' => false,
			),
			$secrets->get_option_info( 'from_constant' )
		);
		$this->assertStringContainsString( 'Defined as constant:', $secrets->get_setting_description( 'from_constant', 'Key.' ) );

		putenv( 'CIPHERPFX_FROM_CONSTANT' );
	}

	public function test_the_description_says_where_the_value_comes_from(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ), false );

		$this->assertSame( 'Key. (stored encrypted in database)', $secrets->get_setting_description( 'from_env', 'Key.' ) );

		putenv( 'CIPHERPFX_FROM_ENV=x' );

		$this->assertSame( 'Key. <strong>Defined as environment variable:</strong> <code>CIPHERPFX_FROM_ENV</code>', $secrets->get_setting_description( 'from_env', 'Key.' ) );
		$this->assertSame( 'env', $secrets->get_option_info( 'from_env' )['source'] );
		$this->assertSame( 'CIPHERPFX_FROM_ENV', $secrets->get_option_info( 'from_env' )['env'] );
	}

	/* ─── Transients and meta ──────────────────────────────────────── */

	public function test_transients_and_meta_are_stored_encrypted(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ), false );

		$this->assertTrue( $secrets->set_transient( 'token', 'abc', 60 ) );
		$this->assertTrue( $secrets->update_user_meta( 7, 'key', 'user-secret' ) );
		$this->assertTrue( $secrets->update_post_meta( 9, 'key', 'post-secret' ) );

		$this->assertTrue( $secrets->is_encrypted( $GLOBALS['ts_transients']['token'] ) );
		$this->assertTrue( $secrets->is_encrypted( $GLOBALS['ts_meta']['user'][7]['key'] ) );
		$this->assertTrue( $secrets->is_encrypted( $GLOBALS['ts_meta']['post'][9]['key'] ) );

		$this->assertSame( 'abc', $secrets->get_transient( 'token' ) );
		$this->assertSame( 'user-secret', $secrets->get_user_meta( 7, 'key' ) );
		$this->assertSame( 'post-secret', $secrets->get_post_meta( 9, 'key' ) );
	}

	public function test_missing_or_unreadable_values_fall_back(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ), false );

		$GLOBALS['ts_transients']['broken']   = $secrets->cipher()->marker() . 'v2:!!!';
		$GLOBALS['ts_meta']['user'][7]['bad'] = $secrets->cipher()->marker() . 'v2:!!!';

		$this->assertFalse( $secrets->get_transient( 'missing' ) );
		$this->assertFalse( $secrets->get_transient( 'broken' ) );
		$this->assertSame( 'none', $secrets->get_user_meta( 7, 'bad', 'none' ) );
		$this->assertSame( 'plain', ( static function () use ( $secrets ) {
			$GLOBALS['ts_meta']['post'][1]['k'] = 'plain';

			return $secrets->get_post_meta( 1, 'k' );
		} )() );
	}

	/* ─── WordPress's get_option() ─────────────────────────────────── */

	public function test_a_saved_option_reads_decrypted_through_get_option(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ) );

		$this->assertTrue( $secrets->is_auto_intercept_enabled() );
		$secrets->update_option( 'api_key', 'sk_live_value' );

		$hook = 'pre_option_cipherpfx_api_key';

		$this->assertCount( 1, $GLOBALS['ts_hooks'][ $hook ] );
		$this->assertSame( 'sk_live_value', apply_filters( $hook, false, 'cipherpfx_api_key' ) );

		// Read from the current filter when WordPress passes no name.
		$GLOBALS['ts_current_filter'] = $hook;
		$this->assertSame( 'sk_live_value', $secrets->intercept_option_value( false ) );
		$this->assertCount( 1, $GLOBALS['ts_hooks'][ $hook ], 'Put back after reading, once.' );
	}

	public function test_interception_can_be_switched_off_and_on(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ) );
		$hook    = 'pre_option_cipherpfx_api_key';

		$secrets->update_option( 'api_key', 'value' );
		$secrets->disable_auto_interception();

		$this->assertFalse( $secrets->is_auto_intercept_enabled() );
		$this->assertEmpty( $GLOBALS['ts_hooks'][ $hook ] );

		$secrets->enable_auto_interception();

		$this->assertCount( 1, $GLOBALS['ts_hooks'][ $hook ] );
	}

	public function test_without_interception_nothing_is_hooked(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'k' ), false );

		$secrets->update_option( 'api_key', 'value' );

		$this->assertArrayNotHasKey( 'pre_option_cipherpfx_api_key', $GLOBALS['ts_hooks'] );
	}

	public function test_change_key_reads_under_the_new_one(): void {
		$secrets = new Secrets( 'cipherpfx', ts_key( 'old' ), false );

		$secrets->update_option( 'api_key', 'value' );
		$secrets->change_key( ts_key( 'new' ) );

		$this->assertSame( 'fallback', $secrets->get_option( 'api_key', 'fallback' ) );

		$secrets->change_key( ts_key( 'old' ) );

		$this->assertSame( 'value', $secrets->get_option( 'api_key' ) );
	}
}
