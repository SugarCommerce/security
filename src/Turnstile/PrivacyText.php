<?php
/**
 * What a site using Turnstile should say in its privacy policy.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * A suggested paragraph, offered in WordPress's privacy policy guide.
 *
 * Turnstile talks to a company the visitor may not expect: their browser
 * loads a script from Cloudflare, and the site then sends Cloudflare the
 * result with the visitor's IP address. The owner is the one who has to
 * say so, and this hands them the words (Settings > Privacy > the policy
 * guide). It is offered whether or not Turnstile is on, as the guide is
 * read once, usually before anything is switched on, and says when it
 * applies.
 *
 * What Cloudflare does with it is taken from its Turnstile Privacy
 * Addendum (cloudflare.com/turnstile-privacy-policy, June 2025): it
 * processes "client IP address, TLS Fingerprint, User-Agent Header and
 * Sitekey and associated origin", and "the purpose of collecting these
 * Signals is not to identify, profile or target any individuals but
 * solely to detect and block bots", and to improve Turnstile. The
 * suggested text claims no more than that.
 *
 * @since 1.0.0
 */
final class PrivacyText {

	/**
	 * Cloudflare's privacy policy.
	 *
	 * @since 1.0.0
	 */
	public const POLICY = 'https://www.cloudflare.com/privacypolicy/';

	/**
	 * Cloudflare's Turnstile privacy addendum.
	 *
	 * @since 1.0.0
	 */
	public const ADDENDUM = 'https://www.cloudflare.com/turnstile-privacy-policy/';

	/**
	 * The paragraph for one plugin's Turnstile.
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
		add_action( 'admin_init', array( $this, 'register' ) );
	}

	/**
	 * Offer the paragraph, under the plugin's name.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function register(): void {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
			wp_add_privacy_policy_content( (string) $this->turnstile->option( 'label' ), wp_kses_post( $this->content() ) );
		}
	}

	/**
	 * The paragraph.
	 *
	 * @return string Markup, in the guide's own classes.
	 * @since 1.0.0
	 */
	public function content(): string {
		return '<h2>' . esc_html( $this->turnstile->message( 'privacy_title' ) ) . '</h2>'
			. '<p class="privacy-policy-tutorial">' . esc_html( $this->turnstile->message( 'privacy_tutorial' ) ) . '</p>'
			. '<p><strong class="privacy-policy-tutorial">' . esc_html( $this->turnstile->message( 'privacy_suggested' ) ) . '</strong> '
			. sprintf(
				esc_html( $this->turnstile->message( 'privacy_text' ) ),
				'<a href="' . esc_url( self::POLICY ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $this->turnstile->message( 'privacy_policy_link' ) ) . '</a>',
				'<a href="' . esc_url( self::ADDENDUM ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $this->turnstile->message( 'privacy_addendum' ) ) . '</a>'
			)
			. '</p>';
	}
}
