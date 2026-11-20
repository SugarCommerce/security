<?php
/**
 * Telling the owner that Turnstile is on and not working.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * One notice, for one situation: Cloudflare has refused the secret key.
 *
 * Every visitor is then either let through unchecked or refused,
 * depending on the plugin's fail-open policy, and without this nobody
 * would find out until somebody complained -- or nobody would at all.
 * Shown to whoever can change the setting (the `capability` option), on
 * the screens the `notice_screen` option allows, from the first refusal
 * until another key is saved or a check works. Not dismissible: it goes
 * when the thing it describes does.
 *
 * Cloudflare being unreachable is not a notice. It mends itself and there
 * is nothing for the owner to do; Site Health has the time it last
 * happened.
 *
 * @since 1.0.0
 */
final readonly class Notice {

	/**
	 * The notice for one plugin's Turnstile.
	 *
	 * @param Turnstile $turnstile Its configuration.
	 *
	 * @since 1.0.0
	 */
	public function __construct( private Turnstile $turnstile ) {
	}

	/**
	 * Listen.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function init(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
	}

	/**
	 * Whether there is something to say.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function due(): bool {
		return $this->turnstile->enabled() && $this->turnstile->record()->secret_refused( $this->turnstile->secret() );
	}

	/**
	 * What it says. Site Health says the same.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function message(): string {
		return $this->turnstile->message( 'refused' );
	}

	/**
	 * What it says next: what is happening to visitors, and what to do.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function detail(): string {
		return $this->turnstile->message( $this->turnstile->fails_open( 'misconfigured' ) ? 'refused_open' : 'refused_closed' );
	}

	/**
	 * Print it.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function render(): void {
		$screen = $this->turnstile->option( 'notice_screen' );

		if ( ( is_callable( $screen ) && ! $screen() ) || ! current_user_can( (string) $this->turnstile->option( 'capability' ) ) || ! $this->due() ) {
			return;
		}

		$url  = (string) $this->turnstile->option( 'settings_url' );
		$page = (string) $this->turnstile->option( 'settings_page' );

		// On the settings screen the button would lead to where the
		// reader already is.
		$current = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$there   = '' !== $page && $current && str_contains( (string) $current->id, $page );

		// Core's markup and wp_kses_post(), and its wp_admin_notice_args and
		// _markup filters. Two paragraphs, so core does not wrap it in one.
		wp_admin_notice(
			sprintf(
				'<p><strong>%1$s</strong> %2$s</p>%3$s',
				esc_html( $this->message() ),
				esc_html( $this->detail() ),
				$there || '' === $url
					? ''
					: sprintf(
						'<p><a class="button" href="%1$s">%2$s</a></p>',
						esc_url( $url ),
						esc_html( $this->turnstile->message( 'settings_button' ) )
					)
			),
			array(
				'type'               => 'warning',
				'additional_classes' => array( esc_attr( $this->turnstile->option( 'class' ) . '-notice' ) ),
				'paragraph_wrap'     => false,
			)
		);
	}
}
