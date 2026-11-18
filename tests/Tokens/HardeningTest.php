<?php
/**
 * What the signer gained in the move: derived keys, checked retired
 * secrets, canonical expiries and secrets kept out of dumps.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Tokens;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\Tokens\Reason;
use SugarCommerce\Security\Tokens\Signer;

final class HardeningTest extends TestCase {

	private const SECRET  = 'a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1';
	private const SECRET2 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
	private const NOW     = 1700000000;

	private function signer(): Signer {
		return new Signer( self::SECRET, array(), self::NOW );
	}

	/* ─── Derived signers ──────────────────────────────────────────── */

	public function test_a_derived_signer_is_the_hex_hkdf_key(): void {
		$expected = new Signer( bin2hex( hash_hkdf( 'sha256', self::SECRET, 32, 'app/links/v1' ) ) );
		$derived  = Signer::derived( self::SECRET, 'app/links/v1' );
		$token    = $expected->sign_until( 'dl', array( 'o' => 1 ), 4_000_000_000 );

		$this->assertNotNull( $derived->verify( 'dl', $token ), 'tokens signed by the hand-derived key still verify' );
		$this->assertSame( $token, $derived->sign_until( 'dl', array( 'o' => 1 ), 4_000_000_000 ) );
	}

	public function test_a_derived_signer_keeps_the_fixed_time(): void {
		$signer = Signer::derived( self::SECRET, 'app/t', timestamp: 1_000 );

		$this->assertNull( $signer->verify( 'ns', $signer->sign_until( 'ns', array(), 999 ) ) );
		$this->assertNotNull( $signer->verify( 'ns', $signer->sign_until( 'ns', array(), 1_001 ) ) );
	}

	public function test_a_derived_signer_needs_a_context(): void {
		$this->expectException( \InvalidArgumentException::class );

		Signer::derived( self::SECRET, '' );
	}

	public function test_a_retired_shared_secret_still_verifies_through_derivation(): void {
		$old   = Signer::derived( self::SECRET2, 'app/links' )->sign( 'ns', array( 'x' => 1 ), 60 );
		$after = Signer::derived( self::SECRET, 'app/links', array( self::SECRET2 ) );

		$this->assertNotNull( $after->verify( 'ns', $old ) );
	}

	public function test_contexts_do_not_verify_each_other(): void {
		$token = Signer::derived( self::SECRET, 'app/a' )->sign( 'ns', array( 'x' => 1 ), 60 );

		$this->assertNull( Signer::derived( self::SECRET, 'app/b' )->verify( 'ns', $token ) );
		$this->assertNull( ( new Signer( self::SECRET ) )->verify( 'ns', $token ), 'nor does the bare secret' );
	}

	/* ─── Retired secrets ──────────────────────────────────────────── */

	public function test_a_non_string_retired_secret_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Signer( self::SECRET, array( 12345 ), self::NOW );
	}

	public function test_a_short_retired_secret_is_refused(): void {
		// A weak retired secret would let a forger brute-force it offline
		// and mint tokens the signer still accepts.
		$this->expectException( \InvalidArgumentException::class );

		new Signer( self::SECRET, array( 'old-weak-secret' ), self::NOW );
	}

	public function test_an_unset_retired_secret_is_skipped(): void {
		// getenv() of a variable that is not set is false.
		$signer = new Signer( self::SECRET, array( false, null, '', self::SECRET2 ), self::NOW );
		$old    = ( new Signer( self::SECRET2, array(), self::NOW ) )->sign( 'ns', array(), 60 );

		$this->assertNotNull( $signer->verify( 'ns', $old ) );
	}

	/* ─── Expiries spelled one way ─────────────────────────────────── */

	/** @return array<string, array{0: string}> */
	public static function respelled_expiries(): array {
		return array(
			'leading zero'  => array( '0%d' ),
			'leading zeros' => array( '000%d' ),
		);
	}

	#[DataProvider( 'respelled_expiries' )]
	public function test_a_respelled_expiry_is_malformed( string $respell ): void {
		$signer = $this->signer();
		$token  = $signer->sign_until( 'ns', array( 'u' => 1 ), self::NOW + 60 );

		[ $payload, , $signature ] = explode( '.', $token );

		$this->assertNotNull( $signer->verify( 'ns', $token ) );
		$this->assertSame( Reason::Malformed, $signer->inspect( 'ns', $payload . '.' . sprintf( $respell, self::NOW + 60 ) . '.' . $signature ) );
	}

	public function test_an_overflowing_expiry_is_malformed(): void {
		$this->assertSame(
			Reason::Malformed,
			$this->signer()->inspect( 'ns', 'YQ.99999999999999999999.' . str_repeat( 'a', 64 ) )
		);
	}

	/* ─── Dumps ────────────────────────────────────────────────────── */

	public function test_secrets_are_kept_out_of_debug_output(): void {
		$signer = new Signer( self::SECRET, array( self::SECRET2 ), self::NOW );

		$dumped = print_r( $signer, true );
		ob_start();
		var_dump( $signer );
		$dumped .= (string) ob_get_clean();

		$this->assertStringNotContainsString( self::SECRET, $dumped );
		$this->assertStringNotContainsString( self::SECRET2, $dumped );
		$this->assertStringContainsString( '[redacted]', $dumped );
	}

	/* ─── Links already emailed ────────────────────────────────────── */

	/**
	 * The signature is the one the earlier library made, so a link sent
	 * before the move still verifies after it.
	 */
	public function test_a_token_signed_before_the_move_still_verifies(): void {
		$encoded = rtrim( strtr( base64_encode( '{"user":42}' ), '+/', '-_' ), '=' );
		$expires = self::NOW + 900;
		$subkey  = hash_hmac( 'sha256', 'arraypress/wp-signed-tokens/v1/magic-link', self::SECRET, true );
		$token   = $encoded . '.' . $expires . '.' . hash_hmac( 'sha256', $encoded . '|' . $expires, $subkey );

		$this->assertSame( $token, $this->signer()->sign( 'magic-link', array( 'user' => 42 ), 900 ) );
		$this->assertSame( 42, $this->signer()->verify( 'magic-link', $token )?->int( 'user' ) );
	}
}
