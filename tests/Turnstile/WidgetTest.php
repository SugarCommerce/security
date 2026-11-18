<?php
/**
 * Widget: the slot, the scripts and what the script is given.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\Turnstile;

use SugarCommerce\Security\Turnstile\Turnstile;
use SugarCommerce\Security\Turnstile\Widget;
use PHPUnit\Framework\TestCase;

final class WidgetTest extends TestCase {

	protected function setUp(): void {
		ts_reset();
	}

	/**
	 * Switched on, with keys and one place.
	 *
	 * @param array<string, mixed> $config Changes.
	 */
	private function widget( array $config = array() ): Widget {
		return ( new Turnstile(
			array_merge(
				array(
					'id'         => 'demo',
					'enabled'    => true,
					'site_key'   => '0x4AAAAAAAsitekey',
					'secret_key' => '0x4AAAAAAAsecret',
					'places'     => array( 'signup' => 'Sign-up' ),
					'module_url' => 'https://example.com/turnstile.js',
				),
				$config
			)
		) )->widget();
	}

	public function test_nothing_is_drawn_or_loaded_where_the_check_is_not_shown(): void {
		$this->assertSame( '', $this->widget( array( 'enabled' => false ) )->slot( 'signup' ) );
		$this->assertSame( '', $this->widget()->slot( 'elsewhere' ) );
		$this->assertNull( $this->widget()->config( 'elsewhere' ) );

		$GLOBALS['ts_logged_in'] = true;

		$this->assertSame( '', $this->widget()->slot( 'signup' ), 'Somebody signed in is not shown it.' );
		$this->assertSame( array(), $GLOBALS['ts_enqueued'] );
	}

	public function test_who_is_shown_it_is_configurable_and_filtered(): void {
		$GLOBALS['ts_logged_in'] = true;

		$this->assertTrue( $this->widget( array( 'shown' => static fn(): bool => true ) )->shown( 'signup' ) );

		add_filter( 'demo_turnstile_shown', static fn(): bool => false );

		$this->assertFalse( $this->widget( array( 'shown' => static fn(): bool => true ) )->shown( 'signup' ) );
	}

	public function test_the_slot_is_an_empty_named_box_with_its_scripts_asked_for(): void {
		$html = $this->widget()->slot( 'SignUp' );

		$this->assertSame(
			'<div class="demo-turnstile" role="group" aria-label="Security check" data-place="signup" data-turnstile-slot><div class="demo-turnstile__widget" data-turnstile-widget></div></div>',
			$html
		);

		$script = $GLOBALS['ts_enqueued']['scripts']['demo-turnstile-api'];

		$this->assertSame( Widget::SCRIPT, $script[0] );
		$this->assertNull( $script[1], 'Cloudflare\'s to version.' );
		$this->assertSame( array( 'strategy' => 'defer', 'in_footer' => true ), $script[2] );
		$this->assertSame( array( 'https://example.com/turnstile.js', Turnstile::VERSION ), $GLOBALS['ts_enqueued']['modules']['demo-turnstile'] );
		$this->assertTrue( $GLOBALS['ts_enqueued']['styles']['demo-turnstile']['enqueued'] );
		$this->assertStringContainsString( '[data-turnstile-slot].is-visible', $GLOBALS['ts_enqueued']['styles']['demo-turnstile']['inline'] );
	}

	public function test_the_inline_styles_are_added_once_and_can_be_left_out(): void {
		$widget = $this->widget();
		$widget->slot( 'signup' );
		$widget->slot( 'signup' );

		$this->assertSame( 1, substr_count( $GLOBALS['ts_enqueued']['styles']['demo-turnstile']['inline'], '.is-visible' ) );

		ts_reset();
		$this->widget( array( 'styles' => false ) )->slot( 'signup' );

		$this->assertArrayNotHasKey( 'styles', $GLOBALS['ts_enqueued'] );
	}

	public function test_a_template_of_the_plugins_own_draws_the_slot(): void {
		$html = $this->widget(
			array(
				'class'    => 'shop-turnstile',
				'template' => static fn( array $args ): string => '<p data-place="' . $args['place'] . '" class="' . $args['class'] . '">' . $args['label'] . '</p>',
			)
		)->slot( 'signup' );

		$this->assertSame( '<p data-place="signup" class="shop-turnstile">Security check</p>', $html );
		$this->assertArrayHasKey( 'demo-turnstile-api', $GLOBALS['ts_enqueued']['scripts'], 'A template enqueues nothing, so the slot does.' );
	}

	public function test_the_script_is_given_the_key_the_action_and_the_words(): void {
		$config = $this->widget( array( 'theme' => 'dark' ) )->config( 'signup' );

		$this->assertSame(
			array(
				'sitekey'    => '0x4AAAAAAAsitekey',
				'action'     => 'signup',
				'theme'      => 'dark',
				'size'       => 'flexible',
				'appearance' => 'interaction-only',
			),
			$config['params']
		);
		$this->assertSame( 'demo-turnstile-api-js', $config['script'] );
		$this->assertSame( array( 'incomplete', 'failed', 'blocked' ), array_keys( $config['messages'] ) );
	}

	public function test_an_unknown_theme_is_auto_and_widget_options_and_the_filter_apply(): void {
		$this->assertSame( 'auto', $this->widget( array( 'theme' => static fn(): string => 'purple' ) )->config( 'signup' )['params']['theme'] );
		$this->assertSame( 'always', $this->widget( array( 'widget' => array( 'appearance' => 'always' ) ) )->config( 'signup' )['params']['appearance'] );

		add_filter( 'demo_turnstile_widget', static fn( array $params ): array => array( 'language' => 'fr' ) + $params );

		$this->assertSame( 'fr', $this->widget()->config( 'signup' )['params']['language'] );
	}

	public function test_messages_for_the_script_are_configurable(): void {
		$config = $this->widget( array( 'messages' => array( 'widget_blocked' => 'Blocked.' ) ) )->config( 'signup' );

		$this->assertSame( 'Blocked.', $config['messages']['blocked'] );
	}

	public function test_the_markup_escapes_what_it_is_given(): void {
		$this->assertStringContainsString( 'aria-label="&quot;&gt;"', Widget::markup( array( 'label' => '">' ) ) );
	}
}
