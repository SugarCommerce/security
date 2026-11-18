<?php
/**
 * API keys that are shown once and stored hashed.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

/**
 * Class ApiKey
 *
 * A key somebody pastes into another system, the pattern GitHub and Stripe
 * use: a recognisable prefix, 256 random bits, shown once, and only its
 * hash stored. A short visible part is stored beside the hash so a row can
 * be found without a full table scan and a person can tell their keys
 * apart in a list.
 *
 *     [ 'key' => $key, 'prefix' => $prefix, 'hash' => $hash ] = ApiKey::make( 'sk' );
 *
 *     // Show $key once. Store $prefix and $hash. Verify with ApiKey::matches().
 *
 * @since 1.0.0
 */
final readonly class ApiKey {

	/**
	 * Make a key.
	 *
	 * @since 1.0.0
	 *
	 * @param string $prefix Product prefix, e.g. `sk`.
	 * @param int    $shown  Characters of the secret kept in the stored
	 *                       prefix. Each one shown is one fewer to guess,
	 *                       so keep it short.
	 *
	 * @return array{key: string, prefix: string, hash: string}
	 *
	 * @throws \InvalidArgumentException When `$shown` is negative or above 12.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public static function make( string $prefix = 'sk', int $shown = 8 ): array {
		if ( $shown < 0 || $shown > 12 ) {
			throw new \InvalidArgumentException( 'An API key prefix may show between 0 and 12 characters of the secret.' );
		}

		$key = $prefix . '_' . Random::url_safe( 32 );

		return array(
			'key'    => $key,
			'prefix' => substr( $key, 0, strlen( $prefix ) + 1 + $shown ),
			'hash'   => self::digest( $key ),
		);
	}

	/**
	 * The stored form of a key.
	 *
	 * Public because three callers need it: a key is hashed when it is
	 * made, when it is verified, and -- in a store that looks a key up
	 * rather than iterating -- when it is found. That third caller is the
	 * application, which would otherwise write its own and let the two
	 * drift.
	 *
	 * Unkeyed on purpose. The lookup happens by hash, so it must be
	 * derivable from the key alone. The key's own entropy is what makes
	 * that safe: see matches() for why a fast hash is right here.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key The key, as issued.
	 *
	 * @return string 64-character hex digest.
	 */
	public static function digest( #[\SensitiveParameter] string $key ): string {
		return hash( 'sha256', $key );
	}

	/**
	 * Whether a submitted key matches a stored hash.
	 *
	 * Constant-time.
	 *
	 * A fast hash is correct here, unlike for passwords: the key has 256
	 * bits of entropy, so there is no dictionary to run and nothing for a
	 * slow hash to buy. It also keeps verification cheap enough to run on
	 * every API request.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key  Submitted key.
	 * @param string $hash Stored hash.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the key is wrong.' )]
	public static function matches( #[\SensitiveParameter] string $key, string $hash ): bool {
		return hash_equals( $hash, self::digest( $key ) );
	}
}
