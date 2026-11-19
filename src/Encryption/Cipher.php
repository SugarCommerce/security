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
use InvalidArgumentException;
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
 * A stored value is marked: `__PREFIX_ENCRYPTED__v3:` and base64 of
 * nonce, tag and ciphertext. The mark is how decrypt() tells a sealed value
 * from a plain one, so a column can be encrypted gradually: plain values
 * pass through decrypt() untouched.
 *
 * **Each purpose has its own key.** The key a value is written under is
 * derived from the site's (or the caller's) with HKDF-SHA256 and a purpose
 * label -- the prefix, unless one is named -- so a value one plugin
 * encrypted does not open under another plugin's cipher, even though both
 * start from the same salts. `v2:` values, written under the shared key
 * before that, are still read and move to their purpose's key the next
 * time they are saved ({@see self::is_legacy_format()}).
 *
 * **A key of the caller's own is at least 32 bytes.** A short one is
 * refused rather than stretched: `sha256( 'k' )` is 32 bytes anyone can
 * guess. To read values written under a short key, pass it to also_open().
 *
 *     $cipher = new Cipher( 'myplugin' );
 *     $stored = $cipher->encrypt( $key );
 *     $key    = $cipher->decrypt( $stored );
 *
 * Code with a marker of its own -- one already in its stored values, say --
 * keeps the marker and has this class do the encryption: seal() and open()
 * are the same AES-256-GCM payload without any marker, and also_open() lets
 * values made under a key derived some other way still be read. A payload
 * carries no version, so seal() stays on the shared key unless a purpose is
 * named in the constructor; name one for new code.
 *
 *     $payload = $cipher->seal( $json );          // base64 of nonce, tag, ciphertext
 *     $json    = $cipher->open( $payload );       // or a WP_Error
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
	private const FORMAT = 'v3:';

	/**
	 * Marker of the authenticated format written under the shared key,
	 * before each purpose had its own. Read, never written.
	 *
	 * @since 1.0.0
	 */
	private const SHARED_FORMAT = 'v2:';

	/**
	 * The shortest key of the caller's own, in bytes.
	 *
	 * @since 1.0.0
	 */
	public const MIN_KEY_BYTES = 32;

	/**
	 * HKDF info a purpose key is derived with, before the purpose label.
	 *
	 * Fixed: changing it would stop every `v3:` value from decrypting.
	 *
	 * @since 1.0.0
	 */
	private const PURPOSE_CONTEXT = 'sugarcommerce/security/cipher/v3/';

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
	 * Keys values may still be under, tried only when the key fails.
	 *
	 * @var string[]
	 */
	private array $previous = array();

	/**
	 * Keys the caller said its older values are under ({@see self::also_open()}).
	 *
	 * Kept apart from the site's previous keys so a change of key keeps them.
	 *
	 * @var string[]
	 */
	private array $older = array();

	/**
	 * What every encrypted value starts with.
	 *
	 * @var string
	 */
	private string $marker;

	/**
	 * The label this cipher's keys are derived with.
	 *
	 * @var string
	 */
	private string $purpose;

	/**
	 * Whether the caller named the purpose, which puts seal() on it too.
	 *
	 * @var bool
	 */
	private bool $named;

	/**
	 * @since 1.0.0
	 *
	 * @param string      $prefix What marks this plugin's values, such as
	 *                            `myplugin`: they are stored as
	 *                            `__MYPLUGIN_ENCRYPTED__…`.
	 * @param string|null $key     A key of the caller's own, at least
	 *                             {@see self::MIN_KEY_BYTES} bytes. Null
	 *                             derives one from the site
	 *                             ({@see Keys::encryption()}).
	 * @param string|null $purpose What the values are, such as
	 *                             `myplugin/api-keys`: each purpose gets
	 *                             its own key. Null uses the prefix for
	 *                             encrypt() and leaves seal() on the
	 *                             shared key, as payloads sealed before
	 *                             purposes existed are under it.
	 *
	 * @throws RuntimeException         When OpenSSL or AES-256-GCM is
	 *                                  missing, or the site has no key
	 *                                  material.
	 * @throws InvalidArgumentException When the key is too short or the
	 *                                  purpose is empty.
	 */
	public function __construct( string $prefix, #[\SensitiveParameter] ?string $key = null, ?string $purpose = null ) {
		if ( ! extension_loaded( 'openssl' ) || ! in_array( self::ALGORITHM, openssl_get_cipher_methods(), true ) ) {
			throw new RuntimeException( 'Encryption needs the OpenSSL extension with ' . self::ALGORITHM . '.' );
		}

		if ( null !== $purpose && '' === trim( $purpose ) ) {
			throw new InvalidArgumentException( 'A purpose cannot be empty: pass null to use the prefix.' );
		}

		$this->marker   = '__' . strtoupper( $prefix ) . '_ENCRYPTED__';
		$this->purpose  = $purpose ?? strtolower( $prefix );
		$this->named    = null !== $purpose;
		$this->key      = Keys::encryption( self::checked( $key ) );
		$this->previous = Keys::previous_encryption( $key );
	}

	/**
	 * Refuse a key of the caller's own that is too short to be one.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $key A key of the caller's own, or null/'' for the site's.
	 *
	 * @return string|null The key, unchanged.
	 *
	 * @throws InvalidArgumentException When it is shorter than {@see self::MIN_KEY_BYTES}.
	 */
	private static function checked( #[\SensitiveParameter] ?string $key ): ?string {
		if ( null !== $key && '' !== $key && strlen( $key ) < self::MIN_KEY_BYTES ) {
			throw new InvalidArgumentException( sprintf( 'An encryption key must be at least %d bytes: try base64_encode( random_bytes( 32 ) ).', self::MIN_KEY_BYTES ) );
		}

		return $key;
	}

	/**
	 * The key for this cipher's purpose, from a 32-byte key.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key 32 raw bytes.
	 *
	 * @return string 32 raw bytes.
	 */
	private function derive( #[\SensitiveParameter] string $key ): string {
		return hash_hkdf( 'sha256', $key, 32, self::PURPOSE_CONTEXT . $this->purpose );
	}

	/**
	 * Keep the key out of var_dump() and print_r().
	 *
	 * @since 1.0.0
	 *
	 * @return array{marker: string, purpose: string, key: string}
	 */
	public function __debugInfo(): array {
		return array(
			'marker'  => $this->marker,
			'purpose' => $this->purpose,
			'key'     => '[redacted]',
		);
	}

	/**
	 * Also read values sealed under these keys.
	 *
	 * For values written before this cipher was used, by code that made its
	 * key some other way: each key is tried, after this cipher's own, only
	 * when that one fails. GCM authenticates, so a wrong key fails cleanly
	 * and trying another gives nothing away. Nothing is ever written under
	 * them -- save a value again to move it to this cipher's key.
	 *
	 * @since 1.0.0
	 *
	 * @param string ...$keys Key material, hashed to length as a key of the
	 *                        caller's own is ({@see Keys::encryption()}).
	 *                        Empty ones are skipped.
	 *
	 * @return static
	 */
	public function also_open( #[\SensitiveParameter] string ...$keys ): static {
		foreach ( $keys as $key ) {
			if ( '' !== $key ) {
				$this->older[] = Keys::encryption( $key );
			}
		}

		return $this;
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
	 * @param string|null $key A key of the caller's own, at least
	 *                         {@see self::MIN_KEY_BYTES} bytes, or null for
	 *                         the site's.
	 *
	 * @return void
	 *
	 * @throws InvalidArgumentException When the key is too short.
	 */
	public function change_key( #[\SensitiveParameter] ?string $key = null ): void {
		$this->key      = Keys::encryption( self::checked( $key ) );
		$this->previous = Keys::previous_encryption( $key );
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

		$sealed = $this->seal_under( $value, $this->derive( $this->key ) );

		return is_string( $sealed ) ? $this->marker . self::FORMAT . $sealed : $sealed;
	}

	/**
	 * Encrypt a value, without the marker.
	 *
	 * For code that marks its stored values its own way. The payload is
	 * the shape encrypt() puts after its marker: base64 of a 12-byte nonce,
	 * the 16-byte tag and the ciphertext, under AES-256-GCM. It is under the
	 * purpose's key when the constructor named a purpose, and under the
	 * shared key when it did not.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value The plain value. '' is sealed too: the caller
	 *                      decides whether emptiness is worth hiding.
	 *
	 * @return string|WP_Error Base64, or why not.
	 */
	public function seal( #[\SensitiveParameter] string $value ): string|WP_Error {
		return $this->seal_under( $value, $this->named ? $this->derive( $this->key ) : $this->key );
	}

	/**
	 * Seal a value under one key.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value The plain value.
	 * @param string $key   32 raw bytes.
	 *
	 * @return string|WP_Error Base64, or why not.
	 */
	private function seal_under( #[\SensitiveParameter] string $value, #[\SensitiveParameter] string $key ): string|WP_Error {
		try {
			$iv = random_bytes( self::IV_LENGTH );
		} catch ( Exception $e ) {
			return new WP_Error( 'encryption_error', 'Failed to generate IV: ' . $e->getMessage() );
		}

		$tag       = '';
		$encrypted = openssl_encrypt( $value, self::ALGORITHM, $key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH );

		if ( false === $encrypted ) {
			return new WP_Error( 'encryption_error', 'Encryption failed: ' . openssl_error_string() );
		}

		return base64_encode( $iv . $tag . $encrypted );
	}

	/**
	 * Decrypt a payload made by seal().
	 *
	 * Tried under this cipher's key, then the site's previous one, then any
	 * given to also_open() -- the purpose's keys first when a purpose was
	 * named, then the shared ones a payload sealed before that is under.
	 *
	 * @since 1.0.0
	 *
	 * @param string $payload Base64 of nonce, tag and ciphertext.
	 *
	 * @return string|WP_Error The plain value, or why not -- never anything
	 *                         derived from a payload that failed its check.
	 */
	public function open( string $payload ): string|WP_Error {
		return $this->open_under( $payload, $this->named ? array( ...$this->purpose_keys(), ...$this->keys() ) : $this->keys() );
	}

	/**
	 * Decrypt a payload under the first of several keys that opens it.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $payload Base64 of nonce, tag and ciphertext.
	 * @param string[] $keys    32 raw bytes each.
	 *
	 * @return string|WP_Error The plain value, or the first failure.
	 */
	private function open_under( string $payload, #[\SensitiveParameter] array $keys ): string|WP_Error {
		$result = null;

		foreach ( $keys as $key ) {
			$plain = $this->decrypt_authenticated( $payload, $key );

			if ( is_string( $plain ) ) {
				return $plain;
			}

			$result ??= $plain;
		}

		return $result;
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
	 * Reads the purpose's format (`v3:`), the shared-key one before it
	 * (`v2:`) and the unauthenticated legacy one. A value without the
	 * marker is returned as it is, so plain values stored before encryption
	 * was switched on keep working. A value the key does
	 * not open is tried under the key a site on the placeholder salts used
	 * before ({@see Keys::previous_encryption()}), so it can be read and
	 * saved again under the new one.
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
			return $this->open_under( substr( $payload, strlen( self::FORMAT ) ), $this->purpose_keys() );
		}

		if ( str_starts_with( $payload, self::SHARED_FORMAT ) ) {
			return $this->open_under( substr( $payload, strlen( self::SHARED_FORMAT ) ), $this->keys() );
		}

		$result = null;

		foreach ( $this->keys() as $key ) {
			$plain = $this->decrypt_legacy( $payload, $key );

			if ( is_string( $plain ) ) {
				return $plain;
			}

			$result ??= $plain;
		}

		return $result;
	}

	/**
	 * Every key a value may be under, this cipher's first.
	 *
	 * @since 1.0.0
	 *
	 * @return string[] 32 raw bytes each.
	 */
	private function keys(): array {
		return array( $this->key, ...$this->previous, ...$this->older );
	}

	/**
	 * Every key a value may be under, derived for this cipher's purpose.
	 *
	 * @since 1.0.0
	 *
	 * @return string[] 32 raw bytes each.
	 */
	private function purpose_keys(): array {
		return array_map( $this->derive( ... ), $this->keys() );
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
	 * Whether a stored value is in an older format.
	 *
	 * The unauthenticated CBC one, or `v2:` under the key every purpose
	 * shared. For a one-off migration: read each value, and when this is
	 * true write it straight back to re-encrypt it under this purpose's key.
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
	 * @param string $key     32 raw bytes.
	 *
	 * @return string|WP_Error
	 */
	private function decrypt_authenticated( string $payload, #[\SensitiveParameter] string $key ): string|WP_Error {
		$data = base64_decode( $payload, true );

		// Shorter than a nonce and a whole tag is refused before OpenSSL sees
		// it, because OpenSSL would accept a shorter tag -- a weaker check.
		// Exactly that long is an empty value, which seal() can make.
		if ( false === $data || strlen( $data ) < self::IV_LENGTH + self::TAG_LENGTH ) {
			return new WP_Error( 'decryption_error', 'Invalid encrypted data' );
		}

		$iv         = substr( $data, 0, self::IV_LENGTH );
		$tag        = substr( $data, self::IV_LENGTH, self::TAG_LENGTH );
		$ciphertext = substr( $data, self::IV_LENGTH + self::TAG_LENGTH );
		$decrypted  = openssl_decrypt( $ciphertext, self::ALGORITHM, $key, OPENSSL_RAW_DATA, $iv, $tag );

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
	 * @param string $key     32 raw bytes.
	 *
	 * @return string|WP_Error
	 */
	private function decrypt_legacy( string $payload, #[\SensitiveParameter] string $key ): string|WP_Error {
		$data      = base64_decode( $payload, true );
		$iv_length = (int) openssl_cipher_iv_length( self::LEGACY_ALGORITHM );

		if ( false === $data || strlen( $data ) <= $iv_length ) {
			return new WP_Error( 'decryption_error', 'Invalid encrypted data' );
		}

		$decrypted = openssl_decrypt( substr( $data, $iv_length ), self::LEGACY_ALGORITHM, $key, OPENSSL_RAW_DATA, substr( $data, 0, $iv_length ) );

		if ( false === $decrypted ) {
			return new WP_Error( 'decryption_error', 'Decryption failed: ' . openssl_error_string() );
		}

		return $decrypted;
	}
}
