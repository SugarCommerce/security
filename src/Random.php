<?php
/**
 * Random strings for secrets and identifiers.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

/**
 * Class Random
 *
 * Opaque secrets -- session identifiers, nonces, one-time references, a
 * cart's cookie -- and short identifiers for naming things in a log.
 * {@see ApiKey} for keys that are shown once and stored hashed.
 *
 * Everything here draws from the CSPRNG. Nothing draws from `rand()`,
 * `mt_rand()`, `uniqid()`, or a hash of the current time — all of which
 * appear in this role regularly and are all predictable enough to
 * enumerate.
 *
 * @since 1.0.0
 */
final readonly class Random {

	/**
	 * Alphanumeric, no ambiguity concerns — these are copy-pasted, not read.
	 */
	private const string ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	/**
	 * A hexadecimal token.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Entropy in bytes. 32 is a good default.
	 *
	 * @return string Twice `$bytes` in length.
	 *
	 * @throws \InvalidArgumentException Below 16 bytes.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function hex( int $bytes = 32 ): string {
		self::assert_entropy( $bytes );

		return bin2hex( random_bytes( $bytes ) );
	}

	/**
	 * A hexadecimal token as it was given, or nothing.
	 *
	 * The other half of hex(): a token read back from a cookie, a link or a
	 * form is exactly twice `$bytes` hex characters and nothing else, or it
	 * is thrown away -- so a value a lookup is keyed on never reaches a query
	 * unvalidated. Upper-case letters are accepted and lowered, since hex()
	 * writes lower case and a copied token may have been retyped.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value Whatever arrived.
	 * @param int   $bytes The entropy the token was made with.
	 *
	 * @return string The token in lower case, or '' when it is not one.
	 */
	public static function sanitize_hex( mixed $value, int $bytes = 32 ): string {
		if ( ! is_string( $value ) || $bytes < 1 ) {
			return '';
		}

		$value = strtolower( trim( $value ) );

		return 1 === preg_match( '/^[a-f0-9]{' . ( 2 * $bytes ) . '}$/D', $value ) ? $value : '';
	}

	/**
	 * Whether a value is a hexadecimal token of the given entropy.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value Whatever arrived.
	 * @param int   $bytes The entropy the token was made with.
	 *
	 * @return bool
	 */
	public static function is_hex( mixed $value, int $bytes = 32 ): bool {
		return '' !== self::sanitize_hex( $value, $bytes );
	}

	/**
	 * A URL-safe base64 token.
	 *
	 * Shorter than hex for the same entropy — 32 bytes is 43 characters
	 * rather than 64.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Entropy in bytes.
	 *
	 * @return string Unpadded, `-` and `_` for `+` and `/`.
	 *
	 * @throws \InvalidArgumentException Below 16 bytes.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function url_safe( int $bytes = 32 ): string {
		self::assert_entropy( $bytes );

		return Base64Url::encode( random_bytes( $bytes ) );
	}

	/**
	 * An alphanumeric token of an exact length.
	 *
	 * @since 1.0.0
	 *
	 * @param int $length Characters. Each carries ~5.95 bits.
	 *
	 * @return string
	 *
	 * @throws \InvalidArgumentException Below 22 characters (~128 bits).
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function alphanumeric( int $length = 40 ): string {
		if ( $length < 22 ) {
			throw new \InvalidArgumentException(
				'An alphanumeric token needs at least 22 characters for 128 bits of entropy.'
			);
		}

		$max   = strlen( self::ALPHABET ) - 1;
		$token = '';

		for ( $i = 0; $i < $length; $i++ ) {
			$token .= self::ALPHABET[ random_int( 0, $max ) ];
		}

		return $token;
	}

	/**
	 * A short random identifier, optionally prefixed: `evt_9f2c41d0a7b3e655`.
	 *
	 * For naming a thing -- a delivery, an event, a request -- so a log line
	 * and a support ticket can point at the same one. Not a secret: 64 bits
	 * by default is plenty never to collide in practice and too few to be
	 * an authenticator, so never use one as a token. {@see self::hex()} is
	 * for that, and refuses anything under 128 bits.
	 *
	 * The prefix says what kind of thing it is, the way Stripe's `evt_` and
	 * `cus_` do, so an id pasted into the wrong field is recognisably wrong.
	 *
	 * @since 1.0.0
	 *
	 * @param string $prefix Kind, without the underscore. '' for none.
	 * @param int    $bytes  Randomness in bytes; the id has twice as many
	 *                       hex characters.
	 *
	 * @return string
	 *
	 * @throws \InvalidArgumentException Below 4 bytes.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function id( string $prefix = '', int $bytes = 8 ): string {
		if ( $bytes < 4 ) {
			throw new \InvalidArgumentException( 'An identifier needs at least 4 bytes of randomness.' );
		}

		return ( '' === $prefix ? '' : $prefix . '_' ) . bin2hex( random_bytes( $bytes ) );
	}

	/**
	 * Refuse dangerously short tokens.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Requested entropy.
	 *
	 * @return void
	 *
	 * @throws \InvalidArgumentException Below 16 bytes.
	 */
	private static function assert_entropy( int $bytes ): void {
		if ( $bytes < 16 ) {
			throw new \InvalidArgumentException( 'A token needs at least 16 bytes (128 bits) of entropy.' );
		}
	}
}
