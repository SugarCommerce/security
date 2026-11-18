<?php
/**
 * Site-derived secret tests.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use SugarCommerce\Security\Keys;
use SugarCommerce\Security\Tokens\Signer;
use PHPUnit\Framework\TestCase;

/**
 * The one part of this library that is WordPress's rather than the signer's:
 * where the 32 bytes come from.
 *
 * A site already has somewhere sensible to get them -- the salts in
 * wp-config.php, which every install has and which are not in the database.
 * The care is in not handing a salt straight to the signer.
 */
final class KeysTest extends TestCase {

	/**
	 * Give the site a healthy salt.
	 */
	protected function setUp(): void {
		$GLOBALS['st_salt'] = str_repeat( 'k', 64 );
	}

	/**
	 * Put it back.
	 */
	protected function tearDown(): void {
		unset( $GLOBALS['st_salt'] );
	}

	/**
	 * A derived secret is long enough for the signer to accept.
	 */
	public function test_a_derived_secret_satisfies_the_signer(): void {
		$secret = Keys::signing();

		$this->assertGreaterThanOrEqual( Signer::MIN_SECRET_BYTES, strlen( $secret ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $secret );
	}

	/**
	 * The salt is never the secret.
	 *
	 * wp_salt() hands the same value to every caller, so a token signed with
	 * it directly shares a key with session tokens and anything else that
	 * reaches for the same salt. A weakness in one would be a weakness in all
	 * of them.
	 */
	public function test_the_salt_is_not_used_as_the_secret(): void {
		$this->assertNotSame( $GLOBALS['st_salt'], Keys::signing() );
		$this->assertStringNotContainsString( $GLOBALS['st_salt'], Keys::signing() );
	}

	/**
	 * Two purposes give two unrelated keys.
	 *
	 * So a plugin does not have to share a signing key with the site, or with
	 * another plugin that had the same idea.
	 */
	public function test_each_purpose_gets_its_own_key(): void {
		$this->assertNotSame( Keys::signing( 'downloads' ), Keys::signing( 'magic-link' ) );
		$this->assertSame( Keys::signing( 'downloads' ), Keys::signing( 'downloads' ) );
	}

	/**
	 * A token signed for one purpose does not verify under another.
	 *
	 * The end-to-end version of the separation, through the signer rather than
	 * on the key itself.
	 */
	public function test_a_token_does_not_cross_between_purposes(): void {
		$token = Signer::site( 'downloads' )->sign( 'file', array( 'id' => 7 ), 300 );

		$this->assertNotNull( Signer::site( 'downloads' )->verify( 'file', $token ) );
		$this->assertNull( Signer::site( 'magic-link' )->verify( 'file', $token ) );
	}

	/**
	 * Rotating the site's salts invalidates the tokens.
	 *
	 * Which is correct rather than unfortunate: rotating the salts is how a
	 * WordPress site says "log everybody out", and a download link that
	 * outlived it would be a link that survived the revocation.
	 */
	public function test_rotating_the_salts_invalidates_tokens(): void {
		$token = Signer::site()->sign( 'file', array( 'id' => 7 ), 300 );

		$this->assertNotNull( Signer::site()->verify( 'file', $token ) );

		$GLOBALS['st_salt'] = str_repeat( 'z', 64 );

		$this->assertNull( Signer::site()->verify( 'file', $token ) );
	}

	/**
	 * A site with no real salt is refused rather than signed weakly.
	 *
	 * The failure mode this guards is the quiet one: an install whose
	 * wp-config still carries the placeholder would otherwise sign every
	 * token in the site with a string that is printed in the documentation.
	 *
	 * @param string $salt What the site has.
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'uselessSaltProvider' )]
	public function test_a_site_without_a_real_salt_is_refused( string $salt ): void {
		$GLOBALS['st_salt'] = $salt;

		$this->expectException( \RuntimeException::class );

		Keys::signing();
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function uselessSaltProvider(): array {
		return array(
			'empty'           => array( '' ),
			'too short'       => array( 'abcdef' ),
			'the placeholder' => array( 'put your unique phrase here put your unique phrase here' ),
		);
	}

	/**
	 * The derivation is the one links were first signed with, so a link
	 * emailed before the move verifies after it.
	 */
	public function test_the_signing_key_is_the_one_links_were_first_signed_with(): void {
		$this->assertSame(
			hash_hmac( 'sha256', 'arraypress/wp-signed-tokens/secret/v1/downloads', $GLOBALS['st_salt'] ),
			Keys::signing( 'downloads' )
		);
	}

	/**
	 * A key derived for anything else is never a signing key.
	 */
	public function test_a_derived_key_is_not_a_signing_key(): void {
		$this->assertNotSame( Keys::signing( 'x' ), Keys::derive( 'x' ) );
		$this->assertNotSame( Keys::derive( 'hash/a' ), Keys::derive( 'hash/b' ) );
		$this->assertSame( hash_hmac( 'sha256', 'sugarcommerce/security/hash/a', $GLOBALS['st_salt'] ), Keys::derive( 'hash/a' ) );
	}

	/**
	 * Deriving refuses a useless salt too.
	 */
	public function test_deriving_refuses_a_placeholder_salt(): void {
		$GLOBALS['st_salt'] = 'put your unique phrase here put your unique phrase here';

		$this->expectException( \RuntimeException::class );

		Keys::derive( 'hash/a' );
	}

	/**
	 * An encryption key of the caller's own is hashed to 32 bytes; without
	 * one it comes from the site, the same way every time.
	 */
	public function test_an_encryption_key_is_32_bytes_and_stable(): void {
		$this->assertSame( hash( 'sha256', 'mine', true ), Keys::encryption( 'mine' ) );
		$this->assertSame( 32, strlen( Keys::encryption() ) );
		$this->assertSame( Keys::encryption(), Keys::encryption( null ) );
		$this->assertSame( Keys::encryption(), Keys::encryption( '' ) );
		$this->assertNotSame( Keys::encryption(), Keys::encryption( 'mine' ) );
	}

	/**
	 * Without the wp-config constants, the key comes from the salts the way
	 * it always has, so values already stored still decrypt.
	 */
	public function test_the_site_encryption_key_is_the_one_values_were_stored_under(): void {
		$this->assertSame( hash( 'sha256', wp_salt() . wp_salt( 'secure_auth' ), true ), Keys::encryption() );
	}
}
