<?php
/**
 * Country lists for fraud and compliance rules.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\CountryRisk;

/**
 * Each list is two-letter codes, once each, and a code is on it in either
 * case and with stray space -- and nothing else is.
 */
final class CountryRiskTest extends TestCase {

	/**
	 * A list and its question.
	 *
	 * @param string $list      The list.
	 * @param string $predicate Its question.
	 */
	#[DataProvider( 'lists' )]
	public function test_a_list_holds_codes_once_each( string $list, string $predicate ): void {
		$codes = CountryRisk::$list();

		$this->assertNotEmpty( $codes );
		$this->assertSame( array_values( array_unique( $codes ) ), $codes, 'A code is listed twice.' );

		foreach ( $codes as $code ) {
			$this->assertMatchesRegularExpression( '/^[A-Z]{2}$/', $code );
			$this->assertTrue( CountryRisk::$predicate( $code ) );
			$this->assertTrue( CountryRisk::$predicate( ' ' . strtolower( $code ) . ' ' ) );
		}

		$this->assertFalse( CountryRisk::$predicate( 'GB' ) );
		$this->assertFalse( CountryRisk::$predicate( 'ZZ' ) );
		$this->assertFalse( CountryRisk::$predicate( '' ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function lists(): array {
		return [
			'high risk'  => [ 'high_risk', 'is_high_risk' ],
			'sanctioned' => [ 'sanctioned', 'is_sanctioned' ],
		];
	}

	/**
	 * The lists as they stand.
	 */
	public function test_the_lists_as_they_stand(): void {
		$this->assertSame( [ 'CU', 'IR', 'KP', 'RU', 'SY', 'VE' ], CountryRisk::sanctioned() );
		$this->assertCount( 20, CountryRisk::high_risk() );
		$this->assertTrue( CountryRisk::is_high_risk( 'ng' ) );
		$this->assertFalse( CountryRisk::is_sanctioned( 'NG' ) );
	}
}
