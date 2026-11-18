<?php
/**
 * Keys a WordPress site already has.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

/**
 * Class Keys
 *
 * A signer and a cipher each need a secret, and neither cares where it
 * comes from. On a WordPress site there is already somewhere sensible: the
 * keys and salts in wp-config.php, which every install has and which are
 * not in the database. This is the one place they are turned into keys.
 *
 * Each key is derived for its job rather than being a salt used directly.
 * `wp_salt()` returns the same value to every caller, so handing it straight
 * to a signer would mean this library, a session token and anything else
 * reaching for the same salt were all keyed identically -- and a weakness in
 * one becomes a weakness in all of them.
 *
 * Both derivations are fixed: changing either would stop every token
 * already emailed from verifying, or every value already stored from
 * decrypting.
 *
 * @since 1.0.0
 */
final class Keys {

	/**
	 * Domain separation for a signing key.
	 *
	 * Versioned, and still named for the library that first signed with
	 * it, so links signed before the move keep verifying after it.
	 *
	 * @since 1.0.0
	 */
	private const SIGNING_CONTEXT = 'arraypress/wp-signed-tokens/secret/v1/';

	/**
	 * The constant that, when defined, is the encryption key.
	 *
	 * @since 1.0.0
	 */
	public const ENCRYPTION_CONSTANT = 'WP_ENCRYPTION_KEY';

	/**
	 * A signing secret derived from this site's salts.
	 *
	 * @since 1.0.0
	 *
	 * @param string $purpose What the key is for. Two callers passing
	 *                        different purposes get unrelated keys, so a
	 *                        plugin does not have to share one with the site.
	 *
	 * @return string 64 hex characters.
	 *
	 * @throws \RuntimeException When the site has no usable salt.
	 */
	public static function signing( string $purpose = 'default' ): string {
		return hash_hmac( 'sha256', self::SIGNING_CONTEXT . $purpose, self::salt() );
	}

	/**
	 * The site's auth salt, when it is one worth deriving from.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 *
	 * @throws \RuntimeException When the site has no usable salt.
	 */
	private static function salt(): string {
		$salt = wp_salt( 'auth' );

		// A site left on the placeholder salts, or one where wp-config was
		// generated without them, has nothing secret to derive from. Failing
		// loudly beats signing every token in the installation with the
		// string "put your unique phrase here".
		if ( strlen( $salt ) < 32 || str_contains( $salt, 'put your unique phrase here' ) ) {
			throw new \RuntimeException(
				'This site has no usable AUTH_SALT. Define the salts in wp-config.php '
				. '-- https://api.wordpress.org/secret-key/1.1/salt/ -- or pass a secret '
				. 'of your own.'
			);
		}

		return $salt;
	}

	/**
	 * A key for anything else, derived from this site's salts.
	 *
	 * For a keyed hash, say ({@see Hash::site()}). Separate from the
	 * signing keys: no context given here produces a key a signer uses.
	 *
	 * @since 1.0.0
	 *
	 * @param string $context What the key is for, such as `hash/visitors`.
	 *
	 * @return string 64 hex characters.
	 *
	 * @throws \RuntimeException When the site has no usable salt.
	 */
	public static function derive( string $context ): string {
		return hash_hmac( 'sha256', 'sugarcommerce/security/' . $context, self::salt() );
	}

	/**
	 * A 32-byte encryption key.
	 *
	 * A key of the caller's own is hashed to length. Otherwise the
	 * `WP_ENCRYPTION_KEY` constant when it is defined, which lets a site
	 * keep the key out of its salts and rotate one without the other. Then
	 * the four `*_KEY` constants of wp-config.php, and `wp_salt()` as a last
	 * resort for a site that defines them some other way.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $key A key of the caller's own, or null for the site's.
	 *
	 * @return string 32 raw bytes.
	 *
	 * @throws \RuntimeException When the site has no key material at all.
	 */
	public static function encryption( #[\SensitiveParameter] ?string $key = null ): string {
		if ( null !== $key && '' !== $key ) {
			return hash( 'sha256', $key, true );
		}

		if ( defined( self::ENCRYPTION_CONSTANT ) && ! empty( constant( self::ENCRYPTION_CONSTANT ) ) ) {
			return hash( 'sha256', (string) constant( self::ENCRYPTION_CONSTANT ), true );
		}

		$combined = '';

		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ) as $name ) {
			$combined .= defined( $name ) ? (string) constant( $name ) : '';
		}

		if ( '' === $combined && function_exists( 'wp_salt' ) ) {
			$combined = wp_salt() . wp_salt( 'secure_auth' );
		}

		if ( '' === $combined ) {
			throw new \RuntimeException( 'Cannot make an encryption key: the WordPress salts are not available. Define WP_ENCRYPTION_KEY.' );
		}

		return hash( 'sha256', $combined, true );
	}
}
