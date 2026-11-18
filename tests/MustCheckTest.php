<?php
/**
 * Results that must not be ignored.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Security\ApiKey;
use SugarCommerce\Security\FormGuard;
use SugarCommerce\Security\Hash;
use SugarCommerce\Security\RateLimit\Rules;
use SugarCommerce\Security\Tokens\Signer;
use SugarCommerce\Security\Turnstile\Verifier;
use SugarCommerce\Security\TwoFactor\Totp;

/**
 * Class MustCheckTest
 *
 * These answer "did it work?" or "is it allowed?", and code that ignores the
 * answer behaves as though it were yes. #[\NoDiscard] makes PHP 8.5 warn
 * where a result is dropped (earlier versions read the attribute and do
 * nothing); this keeps it from being lost in a refactor.
 */
final class MustCheckTest extends TestCase {

	/**
	 * @return array<string, array{0: class-string, 1: string}>
	 */
	public static function methods(): array {
		$methods = array(
			array( Signer::class, 'verify' ),
			array( Signer::class, 'inspect' ),
			array( Signer::class, 'verify_detached' ),
			array( ApiKey::class, 'matches' ),
			array( Hash::class, 'matches' ),
			array( FormGuard::class, 'human' ),
			array( FormGuard::class, 'trapped' ),
			array( Rules::class, 'hit' ),
			array( Rules::class, 'check' ),
			array( Rules::class, 'allows' ),
			array( Verifier::class, 'passes' ),
			array( Totp::class, 'verify_after' ),
		);

		$named = array();

		foreach ( $methods as $method ) {
			$named[ $method[0] . '::' . $method[1] ] = $method;
		}

		return $named;
	}

	#[DataProvider( 'methods' )]
	public function test_the_result_must_be_used( string $class, string $method ): void {
		$attributes = ( new \ReflectionMethod( $class, $method ) )->getAttributes( 'NoDiscard' );

		$this->assertCount( 1, $attributes, $class . '::' . $method . ' lost #[\NoDiscard].' );
		$this->assertNotSame( '', (string) ( $attributes[0]->getArguments()[0] ?? '' ), 'Say why it matters.' );
	}
}
