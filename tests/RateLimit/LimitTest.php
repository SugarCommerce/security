<?php
/**
 * The form of an identity that is counted.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit;

use SugarCommerce\Security\RateLimit\Limit;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Stores\Memory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LimitTest extends TestCase {

	public static function identities(): array {
		return array(
			'IPv4 as it is'                => array( '203.0.113.9', '203.0.113.9' ),
			'IPv4 with space'              => array( " 203.0.113.9\n", '203.0.113.9' ),
			'IPv4-mapped IPv6'             => array( '::ffff:192.0.2.1', '192.0.2.1' ),
			'IPv6 to its /64'              => array( '2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64' ),
			'IPv6 case and zeros'          => array( '2001:DB8:0:0::1', '2001:db8::/64' ),
			'email lower case'             => array( 'Buyer@Example.COM', 'buyer@example.com' ),
			'email beyond ASCII'           => array( 'JÖRG@example.com', 'jörg@example.com' ),
			'an id is left alone'          => array( '12:1700000000', '12:1700000000' ),
			'already lower case unchanged' => array( 'buyer@example.com', 'buyer@example.com' ),
		);
	}

	#[DataProvider( 'identities' )]
	public function test_identity( string $given, string $counted ): void {
		$this->assertSame( $counted, Limit::identity( $given ) );
	}

	public function test_every_address_in_one_64_is_one_caller(): void {
		$limiter = new Limiter( new Memory( 1800000000 ), 'secret', 1800000000 );

		$this->assertTrue( $limiter->for( 'login', '2001:db8::1' )->hit( 1, 60 )->allowed );
		$this->assertTrue( $limiter->for( 'login', '2001:db8::ffff:2' )->hit( 1, 60 )->denied() );
		$this->assertTrue( $limiter->for( 'login', '2001:db8:0:1::1' )->hit( 1, 60 )->allowed, 'The next /64 is another caller.' );
	}

	public function test_an_ipv4_or_lower_case_email_names_the_same_counter_as_before(): void {
		// A host that used to count `checkout_ip:<ip>` and
		// `checkout_email:<lower-case email>` by hand keeps its rows.
		$this->assertSame( 'checkout_ip:203.0.113.9', ( new Limit( new Limiter( new Memory(), 's' ), 'checkout_ip', '203.0.113.9' ) )->name() );
		$this->assertSame( 'checkout_email:buyer@example.com', ( new Limit( new Limiter( new Memory(), 's' ), 'checkout_email', 'buyer@example.com' ) )->name() );
	}
}
