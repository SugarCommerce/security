<?php
/**
 * Rules test suite.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\RateLimit\Decision;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Rules;
use SugarCommerce\Security\RateLimit\Stores\Memory;

final class RulesTest extends TestCase {

	private const int NOW = 1_800_000_000;

	private function rules(): Rules {
		return new Rules(
			new Limiter( new Memory( self::NOW ), 'secret', self::NOW ),
			array( 'lookup' => array( 2, 3600 ), 'login' => array( 5, 60 ) )
		);
	}

	/* ─── Counting by name ──────────────────────────────────────────── */

	public function test_a_named_action_is_limited_by_its_rule(): void {
		$rules = $this->rules();

		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->allowed );
		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->allowed );
		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->denied() );
		$this->assertTrue( $rules->hit( 'lookup', 'b@example.com' )->allowed, 'Each key counts on its own.' );
	}

	public function test_the_decision_carries_the_rule_in_its_headers(): void {
		$headers = $this->rules()->hit( 'login', '1.2.3.4' )->headers();

		$this->assertSame( '5', $headers['X-RateLimit-Limit'] );
		$this->assertSame( '4', $headers['X-RateLimit-Remaining'] );
	}

	public function test_checking_does_not_count(): void {
		$rules = $this->rules();

		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertTrue( $rules->allows( 'lookup', 'a@example.com' ) );
		}

		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->limited );
		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->limited );

		$this->assertFalse( $rules->allows( 'lookup', 'a@example.com' ) );
		$this->assertTrue( $rules->check( 'lookup', 'a@example.com' )->denied() );
	}

	/* ─── What is never limited ─────────────────────────────────────── */

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function unlimited(): array {
		return array(
			'unknown action' => array( 'nope', '1.2.3.4' ),
			'empty key'      => array( 'lookup', '' ),
			'blank key'      => array( 'lookup', '   ' ),
		);
	}

	#[DataProvider( 'unlimited' )]
	public function test_nothing_to_count_is_never_limited( string $action, string $key ): void {
		$rules = $this->rules();

		for ( $i = 0; $i < 10; $i++ ) {
			$decision = $rules->hit( $action, $key );

			$this->assertTrue( $decision->allowed );
			$this->assertSame( array(), $decision->headers() );
		}

		$this->assertTrue( $rules->allows( $action, $key ) );
	}

	public function test_has_names_the_rules_that_exist(): void {
		$this->assertTrue( $this->rules()->has( 'lookup' ) );
		$this->assertFalse( $this->rules()->has( 'nope' ) );
	}

	public function test_a_malformed_rule_is_refused_up_front(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rules( new Limiter( new Memory( self::NOW ), 'secret', self::NOW ), array( 'x' => array( 5, 0 ) ) );
	}

	public function test_a_rule_is_read_by_its_keys_not_its_order(): void {
		// [ 1 => 60, 0 => 5 ] is 5 in 60 seconds. Reordered, it was 60 in 5.
		$rules = new Rules( new Limiter( new Memory( self::NOW ), 'secret', self::NOW ), array( 'x' => array( 1 => 60, 0 => 5 ) ) );

		$this->assertSame( 5, $rules->hit( 'x', 'k' )->limit );
	}

	public function test_a_rule_without_its_two_positions_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rules( new Limiter( new Memory( self::NOW ), 'secret', self::NOW ), array( 'x' => array( 'limit' => 5, 'window' => 60 ) ) );
	}

	/* ─── Decisions with no limit ───────────────────────────────────── */

	public function test_an_unlimited_decision_allows_and_sends_no_headers(): void {
		$decision = Decision::unlimited();

		$this->assertFalse( $decision->denied() );
		$this->assertFalse( $decision->limited );
		$this->assertSame( array(), $decision->headers() );
	}

	/* ─── Switching off, and starting again ─────────────────────────── */

	public function test_a_rule_of_nought_is_no_limit(): void {
		$rules = new Rules( new Limiter( new Memory( self::NOW ), 'secret', self::NOW ), array( 'x' => array( 0, 60 ) ) );

		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertFalse( $rules->hit( 'x', 'k' )->limited );
		}
	}

	public function test_a_negative_limit_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rules( new Limiter( new Memory( self::NOW ), 'secret', self::NOW ), array( 'x' => array( -1, 60 ) ) );
	}

	public function test_reset_starts_the_window_again_for_one_caller(): void {
		$rules = $this->rules();

		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->limited );
		$this->assertTrue( $rules->hit( 'lookup', 'a@example.com' )->limited );
		$this->assertTrue( $rules->hit( 'lookup', 'b@example.com' )->limited );
		$this->assertTrue( $rules->hit( 'lookup', 'b@example.com' )->limited );

		$rules->reset( 'lookup', 'a@example.com' );

		$this->assertTrue( $rules->allows( 'lookup', 'a@example.com' ) );
		$this->assertFalse( $rules->allows( 'lookup', 'b@example.com' ), 'Only the one caller starts again.' );

		$rules->reset( 'nope', 'a@example.com' ); // No rule, nothing to do.
		$this->assertTrue( $rules->allows( 'lookup', 'a@example.com' ) );
	}
}
