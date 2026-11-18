<?php
/**
 * Single-use recovery codes for when the authenticator is unavailable.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\TwoFactor;

use SugarCommerce\Security\Code;

/**
 * Class RecoveryCodes
 *
 * The fallback for a user whose phone is lost, wiped, or simply not to
 * hand. Nothing in RFC 6238 covers these — they are a product concern,
 * and the details are where implementations go wrong:
 *
 *   - **They are password-equivalent.** A recovery code bypasses the
 *     second factor entirely, so it is hashed at rest, never stored in
 *     plaintext, and shown to the user exactly once.
 *   - **They are single-use.** Consumption is the caller's job, because
 *     only the caller has the database. {@see self::verify()} returns
 *     the *index* of the code that matched so you can mark that one used
 *     and reject it next time.
 *   - **They are independent of the TOTP secret.** Deriving them from it
 *     would mean one leak compromises both factors.
 *
 * Codes are {@see Code}s: Crockford base32, with no `I`, `L`, `O` or
 * `U`, because these get written on paper and read back later, and a
 * person who reads `O` for `0` still gets in.
 *
 * Typical enrolment:
 *
 *   $codes  = RecoveryCodes::generate();          // show these once
 *   $hashes = RecoveryCodes::hash_all( $codes );  // store these
 *
 * Typical use:
 *
 *   $index = RecoveryCodes::verify( $submitted, $user->recovery_hashes );
 *
 *   if ( null !== $index ) {
 *       $user->consume_recovery_code( $index );   // single-use
 *   }
 *
 * @since 1.0.0
 */
final readonly class RecoveryCodes {

	/**
	 * Generate a fresh set of plaintext recovery codes.
	 *
	 * The default shape is ten `XXXXX-XXXXX` codes — roughly 49 bits of
	 * entropy each, which is ample given they are stored under a slow
	 * hash and rate-limited at the login form.
	 *
	 * Show these to the user once, then keep only the hashes.
	 *
	 * @since 1.0.0
	 *
	 * @param int $count  How many codes to issue.
	 * @param int $groups Hyphen-separated groups per code.
	 * @param int $length Characters per group.
	 *
	 * @return list<string> Plaintext codes.
	 *
	 * @throws \InvalidArgumentException When asked for a degenerate set.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function generate( int $count = 10, int $groups = 2, int $length = 5 ): array {
		if ( $count < 1 || $groups < 1 || $length < 1 ) {
			throw new \InvalidArgumentException( 'Recovery code count, groups and length must all be positive.' );
		}

		if ( $groups * $length < 8 ) {
			throw new \InvalidArgumentException( 'A recovery code must be at least 8 characters to resist guessing.' );
		}

		$codes = array();

		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = Code::make( $groups, $length );
		}

		return $codes;
	}

	/**
	 * Normalise a code as typed by a user.
	 *
	 * Uppercases, strips whitespace and separators, then folds the
	 * handwriting-ambiguous letters onto the digits they resemble, per
	 * Crockford. Someone copying a code off paper will read `O` for `0`
	 * sooner or later; this makes that harmless rather than a lockout.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code Raw user input.
	 *
	 * @return string Comparable form.
	 */
	public static function normalize( string $code ): string {
		return Code::normalize( $code );
	}

	/**
	 * Hash a single code for storage.
	 *
	 * Deliberately a slow hash. Recovery codes are only ever verified on
	 * the recovery path, which is rare, so the cost is invisible in
	 * normal use and meaningful to an attacker with a stolen database.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code Plaintext code.
	 *
	 * @return string Hash suitable for storage.
	 */
	public static function hash( #[\SensitiveParameter] string $code ): string {
		return password_hash( self::normalize( $code ), PASSWORD_DEFAULT );
	}

	/**
	 * Hash a whole set.
	 *
	 * @since 1.0.0
	 *
	 * @param array<int, string> $codes Plaintext codes.
	 *
	 * @return array<int, string> Hashes, in the same order and under the
	 *                            same keys.
	 */
	public static function hash_all( #[\SensitiveParameter] array $codes ): array {
		return array_map( static fn( string $code ): string => self::hash( $code ), $codes );
	}

	/**
	 * Check a submitted code against a set of stored hashes.
	 *
	 * Returns the index of the hash that matched, so the caller can mark
	 * exactly that code as consumed. A `null` return means no match.
	 *
	 * **This does not enforce single use.** Nothing here knows which
	 * codes have already been spent — pass only the unconsumed hashes,
	 * or consume the returned index immediately.
	 *
	 * @since 1.0.0
	 *
	 * @param string                  $submitted Code as typed by the user.
	 * @param array<int, string|null> $hashes    Stored hashes of unconsumed
	 *                                           codes. Null or empty
	 *                                           entries (a cleared slot)
	 *                                           are skipped.
	 *
	 * @return int|null Index into `$hashes`, or null when nothing matched.
	 */
	public static function verify( #[\SensitiveParameter] string $submitted, array $hashes ): ?int {
		$candidate = self::normalize( $submitted );

		if ( '' === $candidate ) {
			return null;
		}

		foreach ( $hashes as $index => $hash ) {
			if ( is_string( $hash ) && '' !== $hash && password_verify( $candidate, $hash ) ) {
				return (int) $index;
			}
		}

		return null;
	}

	/**
	 * Whether a stored hash should be upgraded.
	 *
	 * PHP's default algorithm changes between releases; re-hash on next
	 * successful use to keep older entries current.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Stored hash.
	 *
	 * @return bool
	 */
	public static function needs_rehash( string $hash ): bool {
		return password_needs_rehash( $hash, PASSWORD_DEFAULT );
	}
}
