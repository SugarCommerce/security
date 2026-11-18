<?php
/**
 * The owner's side: the notice, Site Health, the key test, the privacy text.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Turnstile\Messages;
use SugarCommerce\Security\Turnstile\Notice;
use SugarCommerce\Security\Turnstile\PrivacyText;
use SugarCommerce\Security\Turnstile\SiteHealth;
use SugarCommerce\Security\Turnstile\Turnstile;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class AdminTest extends TestCase {

	private const SECRET = '0x4AAAAAAAsecret';

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
					'id'           => 'demo',
					'label'        => 'Demo Plugin',
					'enabled'      => true,
					'site_key'     => '0x4AAAAAAAsitekey',
					'secret_key'   => self::SECRET,
					'places'       => array(
						'signup' => 'Sign-up',
						'login'  => 'Log-in',
					),
					'settings_url' => 'https://example.com/wp-admin/admin.php?page=demo-settings',
				),
				$config
			)
		);
	}

	private function refuse_the_secret( Turnstile $turnstile ): void {
		$turnstile->record()->problem( 'misconfigured', 'signup', array( 'invalid-input-secret' ), self::SECRET );
	}

	private function notice( Turnstile $turnstile ): string {
		ob_start();
		( new Notice( $turnstile ) )->render();

		return (string) ob_get_clean();
	}

	/* Notice */

	public function test_no_notice_until_the_secret_is_refused(): void {
		$this->assertSame( '', $this->notice( $this->turnstile() ) );

		$this->turnstile()->record()->problem( 'unavailable', 'signup', array( 'unreachable' ), self::SECRET );

		$this->assertSame( '', $this->notice( $this->turnstile() ), 'Cloudflare being down mends itself.' );
	}

	public function test_the_notice_says_what_is_happening_by_the_policy(): void {
		$turnstile = $this->turnstile();
		$this->refuse_the_secret( $turnstile );

		$closed = $this->notice( $turnstile );

		$this->assertStringContainsString( 'class="notice notice-warning demo-turnstile-notice"', $closed );
		$this->assertStringContainsString( Messages::get( 'refused' ), $closed );
		$this->assertStringContainsString( 'Every visitor is being refused', $closed );
		$this->assertStringContainsString( 'href="https://example.com/wp-admin/admin.php?page=demo-settings"', $closed );

		$this->assertStringContainsString( 'let through', $this->notice( $this->turnstile( array( 'fail_open' => true ) ) ) );
	}

	public function test_the_notice_is_for_whoever_can_change_it_where_the_plugin_says(): void {
		$this->refuse_the_secret( $this->turnstile() );

		$GLOBALS['ts_caps'] = array();
		$this->assertSame( '', $this->notice( $this->turnstile() ) );

		$GLOBALS['ts_caps'] = array( 'manage_options' );
		$this->assertSame( '', $this->notice( $this->turnstile( array( 'notice_screen' => static fn(): bool => false ) ) ) );
		$this->assertNotSame( '', $this->notice( $this->turnstile( array( 'notice_screen' => static fn(): bool => true ) ) ) );
	}

	public function test_no_button_on_the_settings_screen_itself_or_without_a_url(): void {
		$this->refuse_the_secret( $this->turnstile() );

		$GLOBALS['ts_screen'] = 'demo_page_demo-settings';

		$this->assertStringNotContainsString( 'class="button"', $this->notice( $this->turnstile( array( 'settings_page' => 'demo-settings' ) ) ) );
		$this->assertStringNotContainsString( 'class="button"', $this->notice( $this->turnstile( array( 'settings_url' => '' ) ) ) );
		$this->assertStringContainsString( 'class="button"', $this->notice( $this->turnstile( array( 'settings_page' => 'other' ) ) ) );
	}

	/* Site Health */

	public function test_info_when_off_is_one_line(): void {
		$fields = ( new SiteHealth( $this->turnstile( array( 'enabled' => false ) ) ) )->info( array() );

		$this->assertSame( array( 'turnstile' ), array_keys( $fields ) );
		$this->assertSame( 'Off', $fields['turnstile']['value'] );
		$this->assertSame( 'off', $fields['turnstile']['debug'] );
	}

	public function test_info_says_where_when_it_last_worked_and_the_last_problem(): void {
		$turnstile = $this->turnstile( array( 'chosen' => array( 'login' ) ) );
		$health    = new SiteHealth( $turnstile );
		$fields    = $health->info( array( 'other' => array() ) );

		$this->assertArrayHasKey( 'other', $fields, 'Added to, not replaced.' );
		$this->assertSame( 'On: Log-in', $fields['turnstile']['value'] );
		$this->assertSame( 'on: login', $fields['turnstile']['debug'] );
		$this->assertSame( 'Not yet', $fields['turnstile_checked']['value'] );
		$this->assertArrayNotHasKey( 'turnstile_problem', $fields );

		$turnstile->record()->problem( 'unavailable', 'login', array( 'unreachable' ), self::SECRET );
		$fields = $health->info( array() );

		$this->assertStringContainsString( 'Cloudflare could not be reached', $fields['turnstile_problem']['value'] );
		$this->assertStringContainsString( 'unavailable (unreachable) at login', $fields['turnstile_problem']['debug'] );
		$this->assertSame( 'On, but keys are missing', ( new SiteHealth( $this->turnstile( array( 'site_key' => '' ) ) ) )->info( array() )['turnstile']['value'] );
		$this->assertSame( 'On, but not used anywhere', ( new SiteHealth( $this->turnstile( array( 'chosen' => array() ) ) ) )->info( array() )['turnstile']['value'] );
	}

	public function test_info_goes_into_the_plugins_section_or_a_section_of_its_own(): void {
		( new SiteHealth( $this->turnstile( array( 'info_filter' => 'demo_site_info' ) ) ) )->init();

		$this->assertArrayHasKey( 'demo_site_info', $GLOBALS['ts_hooks'] );
		$this->assertArrayNotHasKey( 'debug_information', $GLOBALS['ts_hooks'] );

		$sections = ( new SiteHealth( $this->turnstile() ) )->section( array() );

		$this->assertSame( 'Demo Plugin: Cloudflare Turnstile', $sections['demo_turnstile']['label'] );
		$this->assertArrayHasKey( 'turnstile_checked', $sections['demo_turnstile']['fields'] );
	}

	public function test_the_status_test_is_registered_only_once_switched_on(): void {
		$this->assertSame( array(), ( new SiteHealth( $this->turnstile( array( 'enabled' => false ) ) ) )->register( array() ) );

		$tests = ( new SiteHealth( $this->turnstile() ) )->register( array() );

		$this->assertSame( 'Demo Plugin', $tests['direct']['demo_turnstile']['label'] );
	}

	public function test_the_status_test_warns_about_missing_and_refused_keys(): void {
		$missing = ( new SiteHealth( $this->turnstile( array( 'secret_key' => '' ) ) ) )->check();

		$this->assertSame( 'recommended', $missing['status'] );
		$this->assertSame( Messages::get( 'health_test_no_keys' ), $missing['label'] );
		$this->assertStringContainsString( 'page=demo-settings', $missing['actions'] );
		$this->assertSame( 'demo_turnstile', $missing['test'] );
		$this->assertSame( 'Demo Plugin', $missing['badge']['label'] );

		$turnstile = $this->turnstile();
		$good      = ( new SiteHealth( $turnstile ) )->check();

		$this->assertSame( 'good', $good['status'] );
		$this->assertSame( '', $good['actions'] );

		$this->refuse_the_secret( $turnstile );
		$refused = ( new SiteHealth( $turnstile ) )->check();

		$this->assertSame( 'recommended', $refused['status'] );
		$this->assertSame( Messages::get( 'refused' ), $refused['label'] );
	}

	/* Key test */

	public function test_the_key_test_wants_both_keys_and_a_site_key_shaped_like_one(): void {
		$this->assertSame( array( 'success' => false, 'message' => Messages::get( 'test_save_first' ) ), $this->turnstile( array( 'secret_key' => '' ) )->key_test()->run() );
		$this->assertSame( Messages::get( 'test_site_key' ), $this->turnstile( array( 'site_key' => 'short' ) )->key_test()->run()['message'] );
		$this->assertSame( array(), $GLOBALS['ts_requests'] );
	}

	public function test_the_key_test_asks_about_a_token_that_is_not_one(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) );

		$result = $this->turnstile()->key_test()->run();

		$this->assertTrue( $result['success'] );
		$this->assertSame( Messages::get( 'test_accepted' ), $result['message'] );
		$this->assertSame( 'demo-key-test', $GLOBALS['ts_requests'][0][1]['body']['response'] );
		$this->assertGreaterThan( 0, $GLOBALS['ts_options']['demo_turnstile_record']['ok'] );
	}

	public function test_the_key_test_records_a_refused_secret(): void {
		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-secret' ) ) );

		$turnstile = $this->turnstile();
		$result    = $turnstile->key_test()->run();

		$this->assertFalse( $result['success'] );
		$this->assertSame( Messages::get( 'test_refused' ), $result['message'] );
		$this->assertTrue( $turnstile->record()->secret_refused( self::SECRET ) );
		$this->assertSame( 'test', $turnstile->record()->last_problem()['place'] );
	}

	public function test_the_key_test_when_cloudflare_is_down_or_the_keys_are_test_keys(): void {
		$GLOBALS['ts_responses'][] = new WP_Error( 'http_request_failed', 'down' );

		$this->assertSame( Messages::get( 'test_unreachable' ), $this->turnstile()->key_test()->run()['message'] );
		$this->assertNull( $this->turnstile()->record()->last_problem(), 'Not the keys\' fault.' );

		$GLOBALS['ts_responses'][] = ts_answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) );

		$result = $this->turnstile( array( 'secret_key' => '2x0000000000000000000000000000000AA' ) )->key_test()->run();

		$this->assertTrue( $result['success'] );
		$this->assertSame( Messages::get( 'test_test_keys' ), $result['message'] );
	}

	/* Privacy text */

	public function test_the_privacy_paragraph_is_offered_under_the_plugins_name(): void {
		( new PrivacyText( $this->turnstile() ) )->register();

		$content = $GLOBALS['ts_privacy']['Demo Plugin'];

		$this->assertStringContainsString( 'in Demo Plugin', $content );
		$this->assertStringContainsString( 'href="' . PrivacyText::POLICY . '"', $content );
		$this->assertStringContainsString( 'href="' . PrivacyText::ADDENDUM . '"', $content );
		$this->assertStringContainsString( 'class="privacy-policy-tutorial"', $content );
	}

	public function test_the_privacy_wording_is_configurable(): void {
		$content = ( new PrivacyText( $this->turnstile( array( 'messages' => array( 'privacy_title' => 'Bot protection at checkout' ) ) ) ) )->content();

		$this->assertStringStartsWith( '<h2>Bot protection at checkout</h2>', $content );
	}

	/* Messages */

	public function test_every_message_has_words_and_none_is_about_a_shop(): void {
		foreach ( Messages::keys() as $key ) {
			$text = Messages::get( $key, 'Demo' );

			$this->assertNotSame( '', $text, $key );
			$this->assertDoesNotMatchRegularExpression( '/\b(shop|buyer|checkout|cart|sugarcart)\b/i', $text, $key );
		}

		$this->assertSame( '', Messages::get( 'nonsense' ) );
	}
}
