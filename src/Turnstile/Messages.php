<?php
/**
 * The library's own wording.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * Every sentence a visitor or an owner can see, by key.
 *
 * A plugin replaces any of them with its `messages` option, as a string
 * or a callable returning one; these are what it gets otherwise. Written
 * for any form, so they say "visitors" and "forms" and nothing about what
 * the form is for.
 *
 * Translated when asked for, not when the plugin is configured, so
 * configuring Turnstile early loads no translations early.
 *
 * @since 1.0.0
 */
final class Messages {

	/**
	 * One message.
	 *
	 * @param string $key   The message.
	 * @param string $label The plugin's name, for the few that say it.
	 *
	 * @return string '' for a key that is not one.
	 * @since 1.0.0
	 */
	public static function get( string $key, string $label = '' ): string {
		return match ( $key ) {
			// Visitors: the server's answers, and the widget's.
			'incomplete'           => __( 'Please confirm you are not a robot and try again.', 'sugarcommerce' ),
			'failed'               => __( 'The security check did not pass. Please try again.', 'sugarcommerce' ),
			'widget_incomplete'    => __( 'Please confirm you are not a robot and try again.', 'sugarcommerce' ),
			'widget_failed'        => __( 'The security check did not pass. Reload the page and try again.', 'sugarcommerce' ),
			'widget_blocked'       => __( 'The security check could not load. Turn off content blockers for this site and reload.', 'sugarcommerce' ),
			'slot_label'           => __( 'Security check', 'sugarcommerce' ),

			// The settings card's status.
			'status_off'           => __( 'Off', 'sugarcommerce' ),
			'status_no_keys'       => __( 'Keys missing', 'sugarcommerce' ),
			'status_refused'       => __( 'Key not accepted', 'sugarcommerce' ),
			'status_nowhere'       => __( 'Not used anywhere', 'sugarcommerce' ),
			'status_test_keys'     => __( 'On with test keys', 'sugarcommerce' ),
			'status_on'            => __( 'On', 'sugarcommerce' ),

			// The admin notice, and Site Health's warning, when the secret
			// key is refused. Which detail depends on the fail-open policy.
			'refused'              => __( 'Turnstile is switched on but its secret key is not accepted, so it is not protecting your forms.', 'sugarcommerce' ),
			'refused_open'         => __( 'Visitors are being let through without the check. Copy the secret key again from your Cloudflare dashboard and save it.', 'sugarcommerce' ),
			'refused_closed'       => __( 'Every visitor is being refused. Copy the secret key again from your Cloudflare dashboard and save it.', 'sugarcommerce' ),
			'settings_button'      => __( 'Open Turnstile settings', 'sugarcommerce' ),

			// Site Health.
			'health_title'         => __( 'Cloudflare Turnstile', 'sugarcommerce' ),
			'health_off'           => __( 'Off', 'sugarcommerce' ),
			'health_no_keys'       => __( 'On, but keys are missing', 'sugarcommerce' ),
			'health_nowhere'       => __( 'On, but not used anywhere', 'sugarcommerce' ),
			/* translators: %s: a list of places, such as "Sign-up, Log-in". */
			'health_on'            => __( 'On: %s', 'sugarcommerce' ),
			'health_checked'       => __( 'Turnstile last checked a visitor', 'sugarcommerce' ),
			'health_never'         => __( 'Not yet', 'sugarcommerce' ),
			'health_problem'       => __( 'Turnstile last could not check a visitor', 'sugarcommerce' ),
			'health_problem_key'   => __( 'Cloudflare did not accept the secret key', 'sugarcommerce' ),
			'health_problem_down'  => __( 'Cloudflare could not be reached', 'sugarcommerce' ),
			/* translators: 1: a date and time, 2: what went wrong. */
			'health_problem_value' => __( '%1$s: %2$s', 'sugarcommerce' ),
			'health_test_no_keys'  => __( 'Turnstile is switched on but has no keys', 'sugarcommerce' ),
			'health_test_add_keys' => __( 'Nothing is being checked. Paste the site key and the secret key from your Cloudflare dashboard, or switch Turnstile off.', 'sugarcommerce' ),
			'health_test_good'     => __( 'Turnstile is protecting your forms', 'sugarcommerce' ),
			'health_test_in_place' => __( 'Cloudflare Turnstile is switched on and its keys are in place.', 'sugarcommerce' ),
			'health_action'        => __( 'Open Turnstile settings', 'sugarcommerce' ),

			// The Test Keys button.
			'test_save_first'      => __( 'Save both keys first, then test them.', 'sugarcommerce' ),
			'test_site_key'        => __( 'The site key does not look right. Copy it again from your Cloudflare dashboard.', 'sugarcommerce' ),
			'test_refused'         => __( 'Cloudflare does not accept the secret key. Copy it again from your Cloudflare dashboard and save it.', 'sugarcommerce' ),
			'test_unreachable'     => __( 'Could not reach Cloudflare. Your keys may be fine: try again in a minute.', 'sugarcommerce' ),
			'test_test_keys'       => __( 'These are Cloudflare’s test keys. They work, but they do not check anybody. Replace them before you rely on this.', 'sugarcommerce' ),
			'test_accepted'        => __( 'Cloudflare accepts your secret key. The site key can only be checked in a browser: open your site in a private window and try a protected form.', 'sugarcommerce' ),

			// The privacy policy guide.
			'privacy_title'        => __( 'Bot protection (Cloudflare Turnstile)', 'sugarcommerce' ),
			'privacy_tutorial'     => sprintf(
				/* translators: %s: the plugin's name. */
				__( 'This applies only if you have switched on Cloudflare Turnstile in %s. If you have, visitors’ browsers load a script from Cloudflare on the pages with a protected form, and your site sends Cloudflare each visitor’s IP address with the result of the check. Your policy should say so.', 'sugarcommerce' ),
				$label
			),
			'privacy_suggested'    => __( 'Suggested text:', 'sugarcommerce' ),
			/* translators: 1: a link to Cloudflare's privacy policy, 2: a link to Cloudflare's Turnstile privacy addendum. */
			'privacy_text'         => __( 'To keep automated programs out of our forms we use Cloudflare Turnstile. When you use a form it protects, your browser contacts Cloudflare, which looks at technical details of your connection and browser, including your IP address, to tell a person from a program. We then send Cloudflare your IP address and the result of that check so that it can be confirmed. Cloudflare says it uses this only to detect and block bots and to improve the service, not to identify you. See %1$s and %2$s.', 'sugarcommerce' ),
			'privacy_policy_link'  => __( 'Cloudflare’s privacy policy', 'sugarcommerce' ),
			'privacy_addendum'     => __( 'its Turnstile privacy addendum', 'sugarcommerce' ),

			default                => '',
		};
	}

	/**
	 * Every key there is.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	public static function keys(): array {
		return array(
			'incomplete',
			'failed',
			'widget_incomplete',
			'widget_failed',
			'widget_blocked',
			'slot_label',
			'status_off',
			'status_no_keys',
			'status_refused',
			'status_nowhere',
			'status_test_keys',
			'status_on',
			'refused',
			'refused_open',
			'refused_closed',
			'settings_button',
			'health_title',
			'health_off',
			'health_no_keys',
			'health_nowhere',
			'health_on',
			'health_checked',
			'health_never',
			'health_problem',
			'health_problem_key',
			'health_problem_down',
			'health_problem_value',
			'health_test_no_keys',
			'health_test_add_keys',
			'health_test_good',
			'health_test_in_place',
			'health_action',
			'test_save_first',
			'test_site_key',
			'test_refused',
			'test_unreachable',
			'test_test_keys',
			'test_accepted',
			'privacy_title',
			'privacy_tutorial',
			'privacy_suggested',
			'privacy_text',
			'privacy_policy_link',
			'privacy_addendum',
		);
	}
}
