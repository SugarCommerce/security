<?php
/**
 * The Turnstile widget in a form.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

use SugarCommerce\Plugin\Assets;

/**
 * Where the check sits in a form, and Cloudflare's script for it.
 *
 * **Cloudflare is only ever contacted from a page that shows a protected
 * form.** The script is asked for by slot(), which a form calls as it is
 * drawn, and by nothing else: not on any other page, never in wp-admin,
 * and not at all until the owner has switched Turnstile on with both
 * keys. Somebody signed in is not shown it either, by default -- they
 * are not asked to pass it (see Turnstile::required()).
 *
 * **Drawn by the library's script, not Cloudflare's.** The script is
 * loaded with `render=explicit` ("Explicit rendering",
 * developers.cloudflare.com/turnstile/get-started/client-side-rendering),
 * because a form may not be on the page when it loads -- a step shown
 * when a button is pressed -- and a widget has to be drawn then, and drawn
 * again after a token has been spent. assets/js/turnstile.js, a script
 * module the form's own script imports, does that.
 *
 * **Most visitors never see it.** `appearance` is `interaction-only`:
 * "the widget becomes visible only when visitor interaction is required".
 * The slot takes up no room until then, so a form with Turnstile on looks
 * exactly as it does with it off, and nothing moves when the check passes
 * by itself. `size` is `flexible` ("100% width with a 300px minimum"),
 * and the script swaps it for `compact` (150px wide) in a form narrower
 * than 300px, so it fits whatever it is put in.
 *
 * @since 1.0.0
 */
final readonly class Widget {

	/**
	 * Cloudflare's script, asked not to draw anything by itself.
	 *
	 * @since 1.0.0
	 */
	public const string SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

	/**
	 * The slot's rules: no room until there is something to show.
	 *
	 * Attribute selectors, so they apply whatever the slot's class is
	 * called. A plugin with its own stylesheet turns them off (`styles`).
	 *
	 * @since 1.0.0
	 */
	private const string STYLES = '[data-turnstile-slot]{height:0;overflow:hidden;pointer-events:none;position:absolute;left:0;top:0;width:100%}'
		. '[data-turnstile-slot].is-visible{height:auto;min-height:65px;overflow:visible;pointer-events:auto;position:static}'
		. '[data-turnstile-widget]{max-width:25em}';

	/**
	 * The widget for one plugin's Turnstile.
	 *
	 * @param Turnstile $turnstile Its configuration and policy.
	 *
	 * @since 1.0.0
	 */
	public function __construct( private Turnstile $turnstile ) {
	}

	/**
	 * Whether this visitor is shown the check in a place.
	 *
	 * @param string $place The place.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function shown( string $place ): bool {
		$rule  = $this->turnstile->option( 'shown' );
		$shown = $this->turnstile->enabled( $place ) && ( is_callable( $rule ) ? (bool) $rule( $place ) : ! is_user_logged_in() );

		/**
		 * Filter whether a visitor is shown the Turnstile check.
		 *
		 * False by default for somebody signed in, who is not asked to
		 * pass it. A plugin that requires it of them shows it here.
		 *
		 * @param bool   $shown Whether it is shown.
		 * @param string $place The place.
		 *
		 * @since 1.0.0
		 */
		return (bool) apply_filters( $this->turnstile->hook( 'shown' ), $shown, $place );
	}

	/**
	 * The place in a form where the check goes, with its scripts asked for.
	 *
	 * Empty, and nothing is loaded, wherever the check is not shown. The
	 * slot is an empty box the library's script draws the widget into;
	 * the `template` option draws it instead, for a plugin whose theme
	 * templates can be overridden.
	 *
	 * @param string $place The place.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function slot( string $place ): string {
		$args = $this->slot_args( $place );

		if ( array() === $args ) {
			return '';
		}

		$template = $this->turnstile->option( 'template' );

		if ( is_callable( $template ) ) {
			return (string) $template( $args );
		}

		return self::markup( $args );
	}

	/**
	 * What a slot is drawn from, with the scripts asked for.
	 *
	 * For a form drawn from a template, which includes the slot itself.
	 * The scripts are enqueued here, before the markup is drawn, because a
	 * template enqueues nothing.
	 *
	 * @param string $place The place.
	 *
	 * @return array{place?: string, class?: string, label?: string} Empty
	 *         wherever the check is not shown.
	 * @since 1.0.0
	 */
	public function slot_args( string $place ): array {
		if ( ! $this->shown( $place ) ) {
			return array();
		}

		$this->enqueue();

		return array(
			'place' => Turnstile::place( $place ),
			'class' => (string) $this->turnstile->option( 'class' ),
			'label' => $this->turnstile->message( 'slot_label' ),
		);
	}

	/**
	 * The slot's markup.
	 *
	 * Named for screen readers: the widget is a frame of its own and says
	 * only what it is, not what it is for. The script finds the slot by
	 * `data-place` and the box inside it by `data-turnstile-widget` (or,
	 * in a template of a plugin's own, its first child).
	 *
	 * @param array{place?: string, class?: string, label?: string} $args From slot_args().
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public static function markup( array $args ): string {
		$class = (string) ( $args['class'] ?? 'turnstile' );

		return sprintf(
			'<div class="%1$s" role="group" aria-label="%2$s" data-place="%3$s" data-turnstile-slot><div class="%1$s__widget" data-turnstile-widget></div></div>',
			esc_attr( $class ),
			esc_attr( (string) ( $args['label'] ?? '' ) ),
			esc_attr( (string) ( $args['place'] ?? '' ) )
		);
	}

	/**
	 * What the script needs to draw the widget in a place.
	 *
	 * Handed to the page by the plugin (in its own state or data
	 * attribute), and given to the script's `mount()`.
	 *
	 * @param string $place The place.
	 *
	 * @return array{params: array<string, mixed>, script: string, messages: array<string, string>}|null
	 *         Null wherever it is not shown.
	 * @since 1.0.0
	 */
	public function config( string $place ): ?array {
		if ( ! $this->shown( $place ) ) {
			return null;
		}

		$theme = (string) Turnstile::resolve( $this->turnstile->option( 'theme' ) );

		$params = array_merge(
			array(
				'sitekey'    => $this->turnstile->site_key(),

				// Comes back from Cloudflare with the token, so one made
				// for one form cannot be sent to another.
				'action'     => Turnstile::place( $place ),

				// `auto` follows the visitor's own light or dark setting.
				'theme'      => in_array( $theme, array( 'auto', 'light', 'dark' ), true ) ? $theme : 'auto',
				'size'       => 'flexible',
				'appearance' => 'interaction-only',
			),
			(array) $this->turnstile->option( 'widget' )
		);

		/**
		 * Filter how the Turnstile widget is drawn.
		 *
		 * Cloudflare's own names and values
		 * (developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations):
		 * `theme` (auto, light, dark), `size` (normal, flexible, compact),
		 * `appearance` (always, execute, interaction-only), `language`.
		 *
		 * @param array<string, mixed> $params What turnstile.render() is given.
		 * @param string               $place  The place.
		 *
		 * @since 1.0.0
		 */
		$params = (array) apply_filters( $this->turnstile->hook( 'widget' ), $params, $place );

		return array(
			'params'   => $params,
			'script'   => $this->turnstile->option( 'script_handle' ) . '-js',
			'messages' => array(
				'incomplete' => $this->turnstile->message( 'widget_incomplete' ),
				'failed'     => $this->turnstile->message( 'widget_failed' ),
				'blocked'    => $this->turnstile->message( 'widget_blocked' ),
			),
		);
	}

	/**
	 * Ask for Cloudflare's script, the module and the slot's rules on this page.
	 *
	 * Cloudflare's is deferred and goes in the footer, so it never holds
	 * the page up, and carries no version: it is Cloudflare's to version,
	 * and they ask for it to be loaded from its exact address.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function enqueue(): void {
		$this->register_module();

		wp_enqueue_script(
			(string) $this->turnstile->option( 'script_handle' ),
			self::SCRIPT,
			array(),
			null, // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- Cloudflare's script, at Cloudflare's address.
			array(
				'strategy'  => 'defer',
				'in_footer' => true,
			)
		);

		if ( $this->turnstile->option( 'styles' ) ) {
			$handle = (string) $this->turnstile->option( 'module_id' );

			if ( ! wp_style_is( $handle, 'registered' ) ) {
				wp_register_style( $handle, false, array(), (string) $this->turnstile->option( 'module_version' ) );
				wp_add_inline_style( $handle, self::STYLES );
			}

			wp_enqueue_style( $handle );
		}
	}

	/**
	 * Make the module known, so a form's script can import it.
	 *
	 * Registering loads nothing: a module is fetched when something
	 * imports it, which a form's script does only when a widget is to be
	 * drawn.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function register_module(): void {
		if ( ! function_exists( 'wp_register_script_module' ) ) {
			return;
		}

		$url = $this->module_url();

		if ( '' !== $url ) {
			wp_register_script_module( (string) $this->turnstile->option( 'module_id' ), $url, array(), (string) $this->turnstile->option( 'module_version' ) );
		}
	}

	/**
	 * Where the module is: the `module_url` option, or the library's own copy.
	 *
	 * The copy's URL comes from Plugin\Assets, which finds this package
	 * wherever the host put it: a vendor/ folder, a Strauss copy, a
	 * symlinked plugin.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function module_url(): string {
		$given = $this->turnstile->option( 'module_url' );

		if ( is_string( $given ) && '' !== $given ) {
			return $given;
		}

		return Assets::url( __FILE__, 'js/turnstile.js' ) ?? '';
	}
}
