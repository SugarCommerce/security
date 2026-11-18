<?php
/**
 * Authenticated encryption for values at rest.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Encryption;

use Exception;
use RuntimeException;
use SugarCommerce\Security\Keys;
use WP_Error;

/**
 * Class Cipher
 *
 * Encrypts a string on the way into the database and decrypts it on the
 * way out, so a leaked dump or a backup on somebody's laptop holds
 * ciphertext where the API key was.
 *
 * AES-256-GCM, which authenticates as well as encrypts. An earlier version
 * used AES-256-CBC with no MAC, so ciphertext sitting in wp_options could be
 * altered by anyone with database access -- or through SQL injection in any
 * other plugin on the site -- and decrypt to plaintext of the attacker's
 * choosing without anything noticing. Values written that way are still
 * read, so nothing stored is lost, and are written back authenticated the
 * next time they are saved.
 *
 * A stored value is marked: `__PREFIX_ENCRYPTED__v2:` and base64 of
 * nonce, tag and ciphertext. The mark is how decrypt() tells a sealed value
 * from a plain one, so a column can be encrypted gradually: plain values
 * pass through decrypt() untouched.
 *
 *     $cipher = new Cipher( 'myplugin' );
 *     $stored = $cipher->encrypt( $key );
 *     $key    = $cipher->decrypt( $stored );
 *
 * @since 1.0.0
 */
final class Cipher {

	/**
	 * Authenticated cipher used for everything written.
	 *
	 * @since 1.0.0
	 */
	private const ALGORITHM = 'aes-256-gcm';

	/**
	 * Unauthenticated cipher, kept only to read values written by the
	 * first version.
	 *
	 * @since 1.0.0
	 */
	private const LEGACY_ALGORITHM = 'aes-256-cbc';

	/**
	 * Marker distinguishing the authenticated format from the legacy one.
	 *
	 * Base64 never produces ':', so a payload starting with this cannot be
	 * mistaken for a legacy IV.
	 *
	 * @since 1.0.0
	 */
	private const FORMAT = 'v2:';

	/**
	 * GCM nonce length in bytes. 96 bits is the length GCM is specified
	 * around; other lengths take a slower, weaker construction.
	 *
	 * @since 1.0.0
	 */
	private const IV_LENGTH = 12;

	/**
	 * GCM authentication tag length in bytes.
	 *
	 * @since 1.0.0
	 */
	private const TAG_LENGTH = 16;

	/**
	 * The 32-byte key.
	 *
	 * @var string
	 */
	private string $key;

	/**
	 * What every encrypted value starts with.
	 *
	 * @var string
	 */
	private string $marker;

	/**
	 * @since 1.0.0
	 *
	 * @param string      $prefix What marks this plugin's values, such as
	 *                            `myplugin`: they are stored as
	 *                            `__MYPLUGIN_ENCRYPTED__…`.
	 * @param string|null $key    A key of the caller's own. Null derives one
	 *                            from the site ({@see Keys::encryption()}).
	 *
	 * @throws RuntimeException When OpenSSL or AES-256-GCM is missing, or
	 *                          the site has no key material.
	 */
	public function __construct( string $prefix, #[\SensitiveParameter] ?string $key = null ) {
		if ( ! extension_loaded( 'openssl' ) || ! in_array( self::ALGORITHM, openssl_get_cipher_methods(), true ) ) {
			throw new RuntimeException( 'Encryption needs the OpenSSL extension with ' . self::ALGORITHM . '.' );
		}

		$this->marker = '__' . strtoupper( $prefix ) . '_ENCRYPTED__';
		$this->key    = Keys::encryption( $key );
	}

	/**
	 * Keep the key out of var_dump() and print_r().
	 *
	 * @since 1.0.0
	 *
	 * @return array{marker: string, key: string}
	 */
	public function __debugInfo(): array {
		return array(
			'marker' => $this->marker,
			'key'    => '[redacted]',
		);
	}

	/**
	 * What every encrypted value starts with.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function marker(): string {
		return $this->marker;
	}

	/**
	 * Use another key from now on.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $key A key of the caller's own, or null for the site's.
	 *
	 * @return void
	 */
	public function change_key( #[\SensitiveParameter] ?string $key = null ): void {
		$this->key = Keys::encryption( $key );
	}

	/**
	 * Encrypt a value.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value The plain value. '' stays '': there is nothing
	 *                      to hide, and an empty setting stays empty.
	 *
	 * @return string|WP_Error The marked ciphertext, or why not.
	 */
	public function encrypt( #[\SensitiveParameter] string $value ): string|WP_Error {
		if ( '' === $value ) {
			return $value;
		}

		try {
			$iv = random_bytes( self::IV_LENGTH );
		} catch ( Exception $e ) {
			return new WP_Error( 'encryption_error', 'Failed to generate IV: ' . $e->getMessage() );
		}

		$tag       = '';
		$encrypted = openssl_encrypt( $value, self::ALGORITHM, $this->key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH );

		if ( false === $encrypted ) {
			return new WP_Error( 'encryption_error', 'Encryption failed: ' . openssl_error_string() );
		}

		return $this->marker . self::FORMAT . base64_encode( $iv . $tag . $encrypted );
	}

	/**
	 * Encrypt a value unless it already is.
	 *
	 * For code that is handed a value that may have come back from the
	 * database as it was stored: encrypting it again would store
	 * ciphertext of ciphertext, which decrypts to the marked value and not
	 * to the secret.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Plain, or already encrypted.
	 *
	 * @return string|WP_Error
	 */
	public function encrypt_once( #[\SensitiveParameter] string $value ): string|WP_Error {
		return $this->is_encrypted( $value ) ? $value : $this->encrypt( $value );
	}

	/**
	 * Decrypt a value.
	 *
	 * Reads both the authenticated format and the legacy one. A value
	 * without the marker is returned as it is, so plain values stored
	 * before encryption was switched on keep working.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return string|WP_Error The plain value, or why not -- never anything
	 *                         derived from ciphertext that failed its check.
	 */
	public function decrypt( string $value ): string|WP_Error {
		if ( '' === $value || ! $this->is_encrypted( $value ) ) {
			return $value;
		}

		$payload = substr( $value, strlen( $this->marker ) );

		if ( str_starts_with( $payload, self::FORMAT ) ) {
			return $this->decrypt_authenticated( substr( $payload, strlen( self::FORMAT ) ) );
		}

		return $this->decrypt_legacy( $payload );
	}

	/**
	 * Re-encrypt a value under this cipher's key.
	 *
	 * For moving to a new key: pass the ciphers the value may have been
	 * written under. A plain value is encrypted; one any of them (or this
	 * one) opens is encrypted again under this key. Safe to run twice, so a
	 * rotation that stops part-way is finished by running it again.
	 *
	 *     $stored = $new->reencrypt( $stored, $old );
	 *
	 * @since 1.0.0
	 *
	 * @param string $value   Stored value.
	 * @param Cipher ...$from Ciphers it may be under.
	 *
	 * @return string|null Under this key, or null when no key opens it --
	 *                     stop rather than overwrite it.
	 */
	public function reencrypt( string $value, Cipher ...$from ): ?string {
		if ( ! $this->is_encrypted( $value ) ) {
			$sealed = $this->encrypt( $value );

			return is_string( $sealed ) ? $sealed : null;
		}

		foreach ( array( $this, ...$from ) as $cipher ) {
			$plain = $cipher->decrypt( $value );

			if ( is_string( $plain ) ) {
				$sealed = $this->encrypt( $plain );

				return is_string( $sealed ) ? $sealed : null;
			}
		}

		return null;
	}

	/**
	 * Whether a value carries this cipher's marker.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public function is_encrypted( string $value ): bool {
		return str_starts_with( $value, $this->marker );
	}

	/**
	 * Whether a stored value is still in the unauthenticated format.
	 *
	 * For a one-off migration: read each value, and when this is true write
	 * it straight back to re-encrypt it under AES-256-GCM.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public function is_legacy_format( string $value ): bool {
		return $this->is_encrypted( $value )
			&& ! str_starts_with( substr( $value, strlen( $this->marker ) ), self::FORMAT );
	}

	/**
	 * Decrypt an AES-256-GCM payload.
	 *
	 * @since 1.0.0
	 *
	 * @param string $payload Base64 of nonce, tag and ciphertext.
	 *
	 * @return string|WP_Error
	 */
	private function decrypt_authenticated( string $payload ): string|WP_Error {
		$data = base64_decode( $payload, true );

		if ( false === $data || strlen( $data ) <= self::IV_LENGTH + self::TAG_LENGTH ) {
			return new WP_Error( 'decryption_error', 'Invalid encrypted data' );
		}

		$iv         = substr( $data, 0, self::IV_LENGTH );
		$tag        = substr( $data, self::IV_LENGTH, self::TAG_LENGTH );
		$ciphertext = substr( $data, self::IV_LENGTH + self::TAG_LENGTH );
		$decrypted  = openssl_decrypt( $ciphertext, self::ALGORITHM, $this->key, OPENSSL_RAW_DATA, $iv, $tag );

		// False means the tag did not verify: the ciphertext was cut short,
		// corrupted, or deliberately changed. Report it rather than return
		// anything derived from it.
		if ( false === $decrypted ) {
			return new WP_Error( 'decryption_error', 'Decryption failed: data failed authentication' );
		}

		return $decrypted;
	}

	/**
	 * Decrypt a legacy AES-256-CBC payload.
	 *
	 * These carry no authentication tag, so tampering cannot be detected.
	 * Re-save them to upgrade them.
	 *
	 * @since 1.0.0
	 *
	 * @param string $payload Base64 of IV and ciphertext.
	 *
	 * @return string|WP_Error
	 */
	private function decrypt_legacy( string $payload ): string|WP_Error {
		$data      = base64_decode( $payload, true );
		$iv_length = (int) openssl_cipher_iv_length( self::LEGACY_ALGORITHM );

		if ( false === $data || strlen( $data ) <= $iv_length ) {
			return new WP_Error( 'decryption_error', 'Invalid encrypted data' );
		}

		$decrypted = openssl_decrypt( substr( $data, $iv_length ), self::LEGACY_ALGORITHM, $this->key, OPENSSL_RAW_DATA, substr( $data, 0, $iv_length ) );

		if ( false === $decrypted ) {
			return new WP_Error( 'decryption_error', 'Decryption failed: ' . openssl_error_string() );
		}

		return $decrypted;
	}
}
