<?php
/**
 * Record: the last success and the last problem.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Turnstile\Record;
use PHPUnit\Framework\TestCase;

final class RecordTest extends TestCase {

	private const T = 1_800_000_000;

	protected function setUp(): void {
		ts_reset();
	}

	public function test_a_working_check_is_written_at_most_once_a_minute(): void {
		( new Record( 'rec', self::T ) )->answered();
		( new Record( 'rec', self::T + 59 ) )->answered();

		$this->assertSame( self::T, ( new Record( 'rec' ) )->last_answered() );

		( new Record( 'rec', self::T + 60 ) )->answered();

		$this->assertSame( self::T + 60, ( new Record( 'rec' ) )->last_answered() );
	}

	public function test_a_working_check_straight_after_a_problem_ends_it(): void {
		( new Record( 'rec', self::T ) )->answered();
		( new Record( 'rec', self::T + 5 ) )->problem( 'unavailable', 'signup', array( 'unreachable' ), 'secret' );
		( new Record( 'rec', self::T + 10 ) )->answered();

		$record  = new Record( 'rec' );
		$problem = $record->last_problem();

		$this->assertSame( self::T + 10, $record->last_answered(), 'Written within the minute, because it is news.' );
		$this->assertTrue( $problem['over'] );
		$this->assertSame( self::T + 5, $problem['time'], 'Kept, as the last time it happened.' );
	}

	public function test_a_problem_keeps_no_secret_and_no_more_than_five_codes(): void {
		( new Record( 'rec', self::T ) )->problem( 'misconfigured', 'Sign Up!', array( 'A', 'b', 'c', 'd', 'e', 'f' ), '0x4AAAAAAAsecret' );

		$stored = $GLOBALS['ts_options']['rec']['problem'];

		$this->assertSame( 'signup', $stored['place'] );
		$this->assertSame( array( 'a', 'b', 'c', 'd', 'e' ), $stored['codes'] );
		$this->assertSame( 12, strlen( $stored['key'] ) );
		$this->assertStringNotContainsString( 'secret', serialize( $GLOBALS['ts_options'] ) );
	}

	public function test_a_refused_secret_is_reported_until_another_key_is_saved_or_a_check_works(): void {
		$record = new Record( 'rec', self::T );

		$this->assertFalse( $record->secret_refused( 'old' ) );

		$record->problem( 'misconfigured', 'signup', array( 'invalid-input-secret' ), 'old' );

		$this->assertTrue( $record->secret_refused( 'old' ) );
		$this->assertFalse( $record->secret_refused( 'new' ), 'Another key is saved.' );
		$this->assertFalse( $record->secret_refused( '' ) );

		$record->answered();

		$this->assertFalse( $record->secret_refused( 'old' ), 'A check worked.' );
	}

	public function test_cloudflare_being_down_is_not_a_refused_secret(): void {
		$record = new Record( 'rec', self::T );
		$record->problem( 'unavailable', 'signup', array( 'unreachable' ), 'old' );

		$this->assertFalse( $record->secret_refused( 'old' ) );
	}

	public function test_nothing_on_record_and_forget(): void {
		$record = new Record( 'rec', self::T );

		$this->assertSame( 0, $record->last_answered() );
		$this->assertNull( $record->last_problem() );

		$GLOBALS['ts_options']['rec'] = 'garbage';

		$this->assertNull( $record->last_problem() );

		$record->answered();
		$record->forget();

		$this->assertArrayNotHasKey( 'rec', $GLOBALS['ts_options'] );
	}
}
