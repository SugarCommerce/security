<?php
/**
 * The one clock everything here reads.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\FormGuard;
use SugarCommerce\Security\Models\Tokens\Reason;
use SugarCommerce\Security\RateLimit\Limiter;
use SugarCommerce\Security\RateLimit\Stores\Memory;
use SugarCommerce\Security\Tokens\Signer;
use SugarCommerce\Security\Turnstile\Record;
use SugarCommerce\Security\TwoFactor\Totp;

/**
 * A test that has to see a link expire should not have to wait for it.
 *
 * The signers, limiters and checks that matter are built by production code
 * -- through Signer::site(), say -- where a test cannot hand them a time. So
 * every one of them reads `SugarCommerce\Dates\Clock`, which can be stopped
 * and moved from outside, and which every other SugarCommerce package reads
 * too.
 */
final class ClockTest extends TestCase {

	private const SECRET = 'a-thirty-two-byte-secret-for-tests-only-xx';

	private const AT = 1_800_000_000;

	protected function setUp(): void {
		$GLOBALS['st_salt'] = str_repeat( 'k', 64 );
		ts_reset();
		Clock::reset();
	}

	protected function tearDown(): void {
		Clock::reset();
		unset( $GLOBALS['st_salt'] );
	}

	/**
	 * A signer production code builds sees a link expire without a sleep.
	 */
	public function test_a_site_signer_reads_the_clock(): void {
		Clock::freeze( self::AT );

		$token = Signer::site( 'downloads' )->sign( 'file', array( 'id' => 7 ), 60 );

		Clock::advance( 59 );
		$this->assertNotNull( Signer::site( 'downloads' )->verify( 'file', $token ) );
		$this->assertSame( 1, Signer::site( 'downloads' )->verify( 'file', $token )->seconds_remaining() );

		Clock::advance( 1 );
		$this->assertNull( Signer::site( 'downloads' )->verify( 'file', $token ) );
		$this->assertSame( Reason::Expired, Signer::site( 'downloads' )->inspect( 'file', $token ) );
	}

	/**
	 * A detached signature reads it too.
	 */
	public function test_a_detached_signature_reads_the_clock(): void {
		Clock::freeze( self::AT );

		$signer    = new Signer( self::SECRET );
		$signature = $signer->sign_detached( 'file', array( 'id' => 7 ), self::AT + 10 );

		$this->assertTrue( $signer->verify_detached( 'file', array( 'id' => 7 ), self::AT + 10, $signature ) );

		Clock::advance( 10 );
		$this->assertFalse( $signer->verify_detached( 'file', array( 'id' => 7 ), self::AT + 10, $signature ) );
	}

	/**
	 * A fixed time given to a signer wins over the clock.
	 */
	public function test_a_fixed_time_wins_over_the_clock(): void {
		Clock::freeze( self::AT );

		$fixed = new Signer( self::SECRET, array(), self::AT - 1000 );
		$token = $fixed->sign( 'file', array(), 60 );

		$this->assertSame( self::AT - 940, $fixed->verify( 'file', $token )->expires_at );
		$this->assertNull( ( new Signer( self::SECRET ) )->verify( 'file', $token ) );

		// And Signer::site() can be given one.
		$site = Signer::site( 'downloads', self::AT - 1000 );
		$this->assertNotNull( $site->verify( 'file', $site->sign( 'file', array(), 60 ) ) );
		$this->assertNull( Signer::site( 'downloads' )->verify( 'file', $site->sign( 'file', array(), 60 ) ) );
	}

	/**
	 * A limiter's window moves with the clock.
	 */
	public function test_a_limiter_reads_the_clock(): void {
		Clock::freeze( self::AT - ( self::AT % 600 ) );

		$limiter = new Limiter( new Memory(), 'secret' );

		$this->assertTrue( $limiter->hit( 'login:a', 1, 600 )->allowed );
		$this->assertFalse( $limiter->hit( 'login:a', 1, 600 )->allowed );

		Clock::advance( 600 );
		$this->assertTrue( $limiter->hit( 'login:a', 1, 600 )->allowed );
	}

	/**
	 * A two-factor code is the clock's.
	 */
	public function test_a_totp_code_reads_the_clock(): void {
		$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

		Clock::freeze( 59 );
		$this->assertSame( '287082', ( new Totp() )->code( $secret ) );
		$this->assertSame( 1, ( new Totp() )->seconds_remaining() );
	}

	/**
	 * A form drawn now is too fresh to send now, and fine a minute later.
	 */
	public function test_a_form_stamp_reads_the_clock(): void {
		Clock::freeze( self::AT );

		$guard = new FormGuard( new Signer( self::SECRET ), 'contact' );
		$stamp = $guard->stamp();

		$this->assertFalse( $guard->human( $stamp ) );

		Clock::advance( 60 );
		$this->assertTrue( $guard->human( $stamp ) );
	}

	/**
	 * When Turnstile last worked is the clock's time.
	 */
	public function test_the_turnstile_record_reads_the_clock(): void {
		Clock::freeze( self::AT );

		$record = new Record( 'demo_record' );
		$record->answered();

		$this->assertSame( self::AT, $record->last_answered() );
	}
}
