<?php
/**
 * Turnstile: configuration, policy and verify().
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Turnstile\Turnstile;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class TurnstileTest extends TestCase {

	protected function setUp(): void {
		ts_reset();
	}

	/**
	 * Switched on, with keys and two places.
	 *
	 * @param array<string, mixed> $config Changes.
	 */
	private function turnstile( array $config = array() ): Turnstile {
		return new Turnstile(
			array_merge(
				array(
					'id'         => 'demo',
					'enabled'    => true,
					'site_key'   => '0x4AAAAAAAsitekey',
					'secret_key' => '0x4AAAAAAAsecret',
					'places'     => array(
						'signup' => 'Sign-up',
						'login'  => 'Log-in',
					),
				),
				$config
			)
		);
	}

	public function test_it_needs_an_id(): void {
		$this->expectException( InvalidArgumentException::class );

		new Turnstile( array( 'id' => '  !! ' ) );
	}

	public function test_names_follow_the_id_so_two_plugins_never_share_one(): void {
		$turnstile = new Turnstile( array( 'id' => 'sugarcart' ) );

		$this->assertSame( 'sugarcart_turnstile_places', $turnstile->hook( 'places' ) );
		$this->assertSame( 'sugarcart_turnstile_record', $turnstile->record()->option() );
		$this->assertSame( 'sugarcart-turnstile-api', $turnstile->option( 'script_handle' ) );
		$this->assertSame( 'sugarcart-turnstile', $turnstile->option( 'module_id' ) );
		$this->assertSame( 'sugarcart-turnstile', $turnstile->option( 'class' ) );
		$this->assertSame( 'sugarcart_turnstile', $turnstile->option( 'health_test' ) );
		$this->assertSame( 'sugarcart-key-test', $turnstile->option( 'key_test_token' ) );
		$this->assertSame( array( 'incomplete' => 'sugarcart_turnstile_incomplete', 'failed' => 'sugarcart_turnstile_failed' ), $turnstile->option( 'codes' ) );

		$other = new Turnstile( array( 'id' => 'my-members' ) );

		$this->assertSame( 'my_members_turnstile_shown', $other->hook( 'shown' ) );
		$this->assertSame( 'my-members-turnstile-api', $other->option( 'script_handle' ) );
		$this->assertSame( 'custom_failed', ( new Turnstile( array( 'id' => 'x', 'prefix' => 'custom' ) ) )->hook( 'failed' ) );
	}

	public function test_unknown_options_are_ignored(): void {
		$this->assertNull( ( new Turnstile( array( 'id' => 'x', 'nonsense' => 1 ) ) )->option( 'nonsense' ) );
	}

	public function test_registered_instances_can_be_found_again(): void {
		$turnstile = Turnstile::register( array( 'id' => 'found', 'notice' => false, 'site_health' => false, 'privacy' => false ) );

		$this->assertSame( $turnstile, Turnstile::get( 'found' ) );
		$this->assertNull( Turnstile::get( 'missing' ) );
		$this->assertSame( array(), $GLOBALS['ts_hooks'], 'Nothing listens that was switched off.' );
	}

	public function test_register_hooks_up_the_notice_site_health_and_privacy_text(): void {
		Turnstile::register( array( 'id' => 'listens' ) );

		$this->assertArrayHasKey( 'admin_notices', $GLOBALS['ts_hooks'] );
		$this->assertArrayHasKey( 'debug_information', $GLOBALS['ts_hooks'] );
		$this->assertArrayHasKey( 'site_status_tests', $GLOBALS['ts_hooks'] );
		$this->assertArrayHasKey( 'admin_init', $GLOBALS['ts_hooks'] );
	}

	public function test_places_are_filtered_and_their_keys_made_safe(): void {
		add_filter( 'demo_turnstile_places', static fn( array $places ): array => $places + array( 'Contact Form!' => 'Contact', '???' => 'Nothing' ) );

		$this->assertSame( array( 'signup' => 'Sign-up', 'login' => 'Log-in', 'contactform' => 'Contact' ), $this->turnstile()->places() );
		$this->assertSame( str_repeat( 'a', 32 ), Turnstile::place( str_repeat( 'A', 40 ) ) );
	}

	public function test_in_use_means_switched_on_with_both_keys(): void {
		$this->assertTrue( $this->turnstile()->enabled() );
		$this->assertFalse( $this->turnstile( array( 'enabled' => false ) )->enabled() );
		$this->assertFalse( $this->turnstile( array( 'site_key' => ' ' ) )->enabled() );
		$this->assertFalse( $this->turnstile( array( 'secret_key' => '' ) )->enabled() );
		$this->assertTrue( $this->turnstile( array( 'secret_key' => '' ) )->switched_on() );
	}

	public function test_options_may_be_callables(): void {
		$turnstile = $this->turnstile(
			array(
				'enabled'    => static fn(): bool => true,
				'site_key'   => static fn(): string => ' site ',
				'secret_key' => static fn(): string => 'secret',
				'places'     => static fn(): array => array( 'signup' => 'Sign-up' ),
			)
		);

		$this->assertTrue( $turnstile->enabled( 'signup' ) );
		$this->assertSame( 'site', $turnstile->site_key() );
	}

	public function test_a_plain_string_is_never_called_as_a_function(): void {
		$this->assertSame( 'date', $this->turnstile( array( 'site_key' => 'date' ) )->site_key() );
	}

	public function test_a_place_is_in_use_only_when_chosen(): void {
		$this->assertTrue( $this->turnstile()->enabled( 'signup' ), 'Never chosen: every place.' );
		$this->assertTrue( $this->turnstile( array( 'chosen' => array( 'login' ) ) )->enabled( 'LOGIN' ) );
		$this->assertFalse( $this->turnstile( array( 'chosen' => array( 'login' ) ) )->enabled( 'signup' ) );
		$this->assertFalse( $this->turnstile( array( 'chosen' => array( 'gone' ) ) )->enabled( 'gone' ), 'A place no longer offered is not chosen.' );
		$this->assertSame( array( 'login' ), $this->turnstile( array( 'default_places' => array( 'login' ) ) )->chosen() );
		$this->assertSame( array(), $this->turnstile( array( 'chosen' => array() ) )->chosen(), 'Saved as none is none.' );
	}

	public function test_the_enabled_filter_has_the_last_word(): void {
		add_filter( 'demo_turnstile_enabled', static fn( bool $on, string $place ): bool => 'login' === $place ? false : $on, 10, 2 );

		$this->assertFalse( $this->turnstile()->enabled( 'login' ) );
		$this->assertTrue( $this->turnstile()->enabled( 'signup' ) );
	}

	public function test_by_default_only_somebody_signed_out_has_to_pass(): void {
		$this->assertTrue( $this->turnstile()->required( 'signup' ) );

		$GLOBALS['ts_logged_in'] = true;

		$this->assertFalse( $this->turnstile()->required( 'signup' ) );
		$this->assertFalse( $this->turnstile( array( 'enabled' => false ) )->required( 'signup' ), 'Nobody, where it is not in use.' );
	}

	public function test_who_has_to_pass_is_configurable_and_filtered(): void {
		$rule      = static fn( string $place, array $who ): bool => 'form' === ( $who['source'] ?? 'form' );
		$turnstile = $this->turnstile( array( 'required' => $rule ) );

		$this->assertTrue( $turnstile->required( 'signup', array() ) );
		$this->assertFalse( $turnstile->required( 'signup', array( 'source' => 'api' ) ) );

		add_filter( 'demo_turnstile_required', static fn(): bool => true );

		$this->assertTrue( $turnstile->required( 'signup', array( 'source' => 'api' ) ) );
	}

	public function test_nothing_is_asked_where_turnstile_is_not_in_use(): void {
		$this->assertTrue( $this->turnstile( array( 'enabled' => false ) )->verify( '', 'signup' ) );
		$this->assertTrue( $this->turnstile( array( 'chosen' => array( 'login' ) ) )->verify( '', 'signup' ) );
		$this->assertSame( array(), $GLOBALS['ts_requests'] );
	}

	public function test_no_token_is_incomplete_and_names_the_field(): void {
		$error = $this->turnstile()->verify( '  ', 'signup' );

		$this->assertInstanceOf( WP_Error::class, $error );
		$this->assertSame( 'demo_turnstile_incomplete', $error->get_error_code() );
		$this->assertSame( array( 'status' => 400, 'field' => 'turnstile' ), $error->get_error_data() );
		$this->assertSame( array(), $GLOBALS['ts_requests'] );
	}

	public function test_a_good_token_passes_and_is_written_down(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'hostname' => 'example.com', 'action' => 'signup' ) );

		$this->assertTrue( $this->turnstile()->verify( 'tok', 'signup', array( 'ip' => '198.51.100.7' ) ) );
		$this->assertSame( '198.51.100.7', $GLOBALS['ts_requests'][0][1]['body']['remoteip'] );
		$this->assertGreaterThan( 0, $GLOBALS['ts_options']['demo_turnstile_record']['ok'] ?? 0 );
	}

	public function test_a_token_is_asked_about_once_a_request(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'hostname' => 'example.com', 'action' => 'signup' ) );

		$turnstile = $this->turnstile();

		$this->assertTrue( $turnstile->verify( 'tok', 'signup' ) );
		$this->assertTrue( $turnstile->verify( ' tok ', 'signup' ), 'The second asking would be refused as a duplicate.' );
		$this->assertCount( 1, $GLOBALS['ts_requests'] );

		$turnstile->reset();
		$turnstile->verify( 'tok', 'signup' );

		$this->assertCount( 2, $GLOBALS['ts_requests'] );
	}

	public function test_the_place_is_the_action_and_the_sites_hostnames_are_held_to(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'action' => 'login' ) ),
			ts_answer( array( 'success' => true, 'hostname' => 'elsewhere.example' ) ),
		);

		$turnstile = $this->turnstile();

		$this->assertSame( 'demo_turnstile_failed', $turnstile->verify( 'a', 'signup' )->get_error_code() );
		$this->assertSame( 'demo_turnstile_failed', $turnstile->verify( 'b', 'signup' )->get_error_code() );
	}

	public function test_an_answer_without_the_hostname_or_action_fails(): void {
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => true, 'hostname' => 'example.com' ) ),
			ts_answer( array( 'success' => true, 'action' => 'signup' ) ),
		);

		$turnstile = $this->turnstile();

		$this->assertSame( 'demo_turnstile_failed', $turnstile->verify( 'a', 'signup' )->get_error_code(), 'A widget without data-action is not this place.' );
		$this->assertSame( 'demo_turnstile_failed', $turnstile->verify( 'b', 'signup' )->get_error_code(), 'No hostname is not this site.' );
	}

	public function test_the_sites_own_hostnames_with_and_without_www(): void {
		$this->assertSame( array( 'example.com', 'www.example.com' ), $this->turnstile()->hostnames() );
		$this->assertSame( array( 'a.example' ), $this->turnstile( array( 'hostnames' => array( 'a.example' ) ) )->hostnames() );

		add_filter( 'demo_turnstile_hostnames', static fn(): array => array() );

		$this->assertSame( array(), $this->turnstile()->hostnames(), 'Empty accepts any.' );
	}

	public function test_a_rejected_token_fails_with_403(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) );

		$error = $this->turnstile()->verify( 'tok', 'signup' );

		$this->assertSame( 'demo_turnstile_failed', $error->get_error_code() );
		$this->assertSame( array( 'status' => 403 ), $error->get_error_data() );
		$this->assertGreaterThan( 0, $GLOBALS['ts_options']['demo_turnstile_record']['ok'] ?? 0, 'Cloudflare answered, so the check works.' );
		$this->assertArrayNotHasKey( 'problem', $GLOBALS['ts_options']['demo_turnstile_record'] );
	}

	public function test_a_spent_token_is_incomplete_not_failed(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'timeout-or-duplicate' ) ) );

		$this->assertSame( 'demo_turnstile_incomplete', $this->turnstile()->verify( 'tok', 'signup' )->get_error_code() );
	}

	public function test_a_token_older_than_max_age_is_incomplete(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => true, 'hostname' => 'example.com', 'action' => 'signup', 'challenge_ts' => '2001-01-01T00:00:00Z' ) );

		$this->assertSame( 'demo_turnstile_incomplete', $this->turnstile( array( 'max_age' => 120 ) )->verify( 'tok', 'signup' )->get_error_code() );
	}

	public function test_fails_closed_by_default_when_cloudflare_is_down_and_says_so(): void {
		$error = $this->turnstile()->verify( 'tok', 'signup' );

		$this->assertSame( 'demo_turnstile_failed', $error->get_error_code() );

		$problem = $GLOBALS['ts_options']['demo_turnstile_record']['problem'];

		$this->assertSame( 'unavailable', $problem['kind'] );
		$this->assertSame( 'signup', $problem['place'] );
		$this->assertSame( array( 'unreachable' ), $problem['codes'] );
		$this->assertArrayNotHasKey( 'ok', $GLOBALS['ts_options']['demo_turnstile_record'], 'Nothing was learnt about the check working.' );
	}

	public function test_fail_open_lets_the_visitor_through_and_still_says_so(): void {
		$this->assertTrue( $this->turnstile( array( 'fail_open' => true ) )->verify( 'tok', 'signup' ) );
		$this->assertSame( 'unavailable', $GLOBALS['ts_options']['demo_turnstile_record']['problem']['kind'] );
	}

	public function test_fail_open_by_kind(): void {
		$policy = array( 'unavailable' => true, 'misconfigured' => false );

		$this->assertTrue( $this->turnstile( array( 'fail_open' => $policy ) )->verify( 'down', 'signup' ) );

		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-secret' ) ) );

		$this->assertSame( 'demo_turnstile_failed', $this->turnstile( array( 'fail_open' => $policy ) )->verify( 'bad-key', 'signup' )->get_error_code() );
		$this->assertSame( 'misconfigured', $GLOBALS['ts_options']['demo_turnstile_record']['problem']['kind'] );
	}

	public function test_fail_open_as_a_callable_is_told_the_kind_place_and_who(): void {
		$seen      = array();
		$turnstile = $this->turnstile(
			array(
				'fail_open' => static function ( string $kind, string $place, array $who ) use ( &$seen ): bool {
					$seen = array( $kind, $place, $who );

					return true;
				},
			)
		);

		$this->assertTrue( $turnstile->verify( 'tok', 'login', array( 'email' => 'a@example.com' ) ) );
		$this->assertSame( array( 'unavailable', 'login', array( 'email' => 'a@example.com' ) ), $seen );
	}

	public function test_the_fail_open_filter_has_the_last_word(): void {
		add_filter( 'demo_turnstile_fail_open', static fn( bool $open, string $place, string $kind ): bool => 'misconfigured' !== $kind, 10, 3 );

		$this->assertTrue( $this->turnstile()->verify( 'down', 'signup' ), 'Closed by policy, opened by the filter.' );
	}

	public function test_a_genuine_rejection_is_never_let_through_by_fail_open(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) );

		$this->assertInstanceOf( WP_Error::class, $this->turnstile( array( 'fail_open' => true ) )->verify( 'tok', 'signup' ) );
	}

	public function test_a_request_cloudflare_refused_is_never_let_through_by_fail_open(): void {
		// The request carries the visitor's token, so a 4xx may be theirs to
		// cause: it is a refusal, not Cloudflare being down.
		$GLOBALS['ts_responses'] = array(
			ts_answer( array( 'success' => false, 'error-codes' => array( 'bad-request' ) ), 400 ),
			array( 'response' => array( 'code' => 429 ), 'body' => '' ),
		);

		$this->assertSame( 'demo_turnstile_failed', $this->turnstile( array( 'fail_open' => true ) )->verify( 'crafted', 'signup' )->get_error_code() );
		$this->assertSame( 'demo_turnstile_failed', $this->turnstile( array( 'fail_open' => true ) )->verify( 'flood', 'signup' )->get_error_code() );
	}

	public function test_the_failed_action_says_what_happened_and_whether_they_got_through(): void {
		$this->turnstile( array( 'fail_open' => true ) )->verify( 'tok', 'signup', array( 'ip' => '192.0.2.1' ) );

		$this->assertSame( array( 'demo_turnstile_failed', array( 'signup', array( 'unreachable' ), array( 'ip' => '192.0.2.1' ), true ) ), $GLOBALS['ts_fired'][0] );
	}

	public function test_no_failed_action_for_a_form_sent_without_a_token(): void {
		$this->turnstile()->verify( '', 'signup' );

		$this->assertSame( array(), $GLOBALS['ts_fired'] );
	}

	public function test_the_address_comes_from_who_then_the_option_then_the_connection(): void {
		$GLOBALS['ts_responses'] = array_fill( 0, 3, ts_answer( array( 'success' => true ) ) );
		$_SERVER['REMOTE_ADDR']  = '192.0.2.50';

		$this->turnstile( array( 'visitor_ip' => static fn(): string => '192.0.2.99' ) )->verify( 'a', 'signup', array( 'ip' => '192.0.2.1' ) );
		$this->turnstile( array( 'visitor_ip' => static fn(): string => '192.0.2.99' ) )->verify( 'b', 'signup' );
		$this->turnstile()->verify( 'c', 'signup' );

		$this->assertSame( array( '192.0.2.1', '192.0.2.99', '192.0.2.50' ), array_map( static fn( array $request ): string => $request[1]['body']['remoteip'], $GLOBALS['ts_requests'] ) );
	}

	public function test_error_codes_field_and_wording_are_configurable(): void {
		$turnstile = $this->turnstile(
			array(
				'codes'    => array( 'incomplete' => 'shop_check_incomplete' ),
				'field'    => 'captcha',
				'messages' => array( 'incomplete' => static fn(): string => 'Tick the box.' ),
			)
		);

		$error = $turnstile->verify( '', 'signup' );

		$this->assertSame( 'shop_check_incomplete', $error->get_error_code() );
		$this->assertSame( 'Tick the box.', $error->get_error_message() );
		$this->assertSame( 'captcha', $error->get_error_data()['field'] );
		$this->assertSame( 'demo_turnstile_failed', $turnstile->option( 'codes' )['failed'], 'The other code keeps its default.' );
	}

	public function test_status_for_a_settings_card(): void {
		$this->assertSame( 'neutral', $this->turnstile( array( 'enabled' => false ) )->status()['tone'] );
		$this->assertSame( 'Keys missing', $this->turnstile( array( 'secret_key' => '' ) )->status()['label'] );
		$this->assertSame( 'Not used anywhere', $this->turnstile( array( 'chosen' => array() ) )->status()['label'] );
		$this->assertSame( 'On with test keys', $this->turnstile( array( 'secret_key' => '1x0000000000000000000000000000000AA' ) )->status()['label'] );
		$this->assertSame( array( 'label' => 'On', 'tone' => 'success' ), $this->turnstile()->status() );

		$this->turnstile()->record()->problem( 'misconfigured', 'signup', array( 'invalid-input-secret' ), '0x4AAAAAAAsecret' );

		$this->assertSame( array( 'label' => 'Key not accepted', 'tone' => 'error' ), $this->turnstile()->status() );
	}

	public function test_clean_key_keeps_only_what_a_key_is_made_of(): void {
		$this->assertSame( '0x4AAA-_bscript', Turnstile::clean_key( " 0x4AAA-_b\n<script>" ) );
		$this->assertSame( '', Turnstile::clean_key( array( 'x' ) ) );
		$this->assertSame( 100, strlen( Turnstile::clean_key( str_repeat( 'a', 150 ) ) ) );
	}
}
