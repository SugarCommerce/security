<?php
/**
 * Countries a fraud or compliance rule treats with caution.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

/**
 * Class CountryRisk
 *
 * Two point-in-time lists of two-letter country codes, kept as data in
 * `data/country-risk.php`: territories with elevated payment-fraud rates,
 * and territories under comprehensive sanctions. Policy rather than
 * geography -- sugarcommerce/geo names the countries; this says which ones
 * a rule should look at twice.
 *
 *     CountryRisk::is_high_risk( 'ng' );   // true: a signal to weigh, never a reason to refuse on its own
 *     CountryRisk::is_sanctioned( 'KP' );  // true: a coarse first gate, not a compliance product
 *     CountryRisk::sanctioned();           // [ 'CU', 'IR', 'KP', 'RU', 'SY', 'VE' ]
 *
 * For names, ask geo: `array_intersect_key( Countries::all(), array_flip( CountryRisk::high_risk() ) )`.
 *
 * @since 1.1.0
 */
final class CountryRisk {

	/**
	 * The lists, once read.
	 *
	 * @var array{high_risk: list<string>, sanctioned: list<string>}|null
	 */
	private static ?array $lists = null;

	/**
	 * Whether a country has elevated payment-fraud rates. One signal among
	 * several: blocking on it alone refuses a lot of genuine customers.
	 *
	 * @since 1.1.0
	 *
	 * @param string $code Country code, in either case.
	 *
	 * @return bool
	 */
	public static function is_high_risk( string $code ): bool {
		return in_array( self::normalize( $code ), self::high_risk(), true );
	}

	/**
	 * The countries with elevated payment-fraud rates.
	 *
	 * @since 1.1.0
	 *
	 * @return list<string> Two-letter codes.
	 */
	public static function high_risk(): array {
		return self::lists()['high_risk'];
	}

	/**
	 * Whether a country is under comprehensive sanctions. Indicative only:
	 * sanctions change without notice and vary by jurisdiction.
	 *
	 * @since 1.1.0
	 *
	 * @param string $code Country code, in either case.
	 *
	 * @return bool
	 */
	public static function is_sanctioned( string $code ): bool {
		return in_array( self::normalize( $code ), self::sanctioned(), true );
	}

	/**
	 * The countries under comprehensive sanctions.
	 *
	 * @since 1.1.0
	 *
	 * @return list<string> Two-letter codes.
	 */
	public static function sanctioned(): array {
		return self::lists()['sanctioned'];
	}

	/**
	 * The lists, read from the data file once a request.
	 *
	 * @return array{high_risk: list<string>, sanctioned: list<string>}
	 */
	private static function lists(): array {
		if ( null === self::$lists ) {
			$data = require dirname( __DIR__ ) . '/data/country-risk.php';

			self::$lists = [
				'high_risk'  => array_values( array_map( 'strval', (array) ( $data['high_risk'] ?? [] ) ) ),
				'sanctioned' => array_values( array_map( 'strval', (array) ( $data['sanctioned'] ?? [] ) ) ),
			];
		}

		return self::$lists;
	}

	/**
	 * A code trimmed and upper-cased.
	 *
	 * @param string $code Raw code.
	 *
	 * @return string
	 */
	private static function normalize( string $code ): string {
		return strtoupper( trim( $code ) );
	}
}
