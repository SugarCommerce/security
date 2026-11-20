<?php
/**
 * Turnstile: where it is in use, for whom, and what a failure lets through.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Traits\Turnstile;

use SugarCommerce\Security\Turnstile\Verifier;

/**
 * Where Turnstile is in use, who has to pass it, which hostnames a token
 * may come from, and what the owner is shown. For {@see \SugarCommerce\Security\Turnstile\Turnstile}.
 *
 * @since 1.0.0
 */
trait Policy {

	/**
	 * The forms Turnstile can protect.
	 *
	 * @return array<string, string> Place => what the owner calls it.
	 * @since 1.0.0
	 */
	public function places(): array {
		/**
		 * Filter the forms Cloudflare Turnstile can protect.
		 *
		 * Add a place and the owner can tick it. The other plugin then
		 * prints the slot for it and verifies its token. A key is
		 * lower-case letters, digits, `_` and `-`, at most 32 characters:
		 * it is sent to Cloudflare as the widget's action.
		 *
		 * @param array<string, string> $places Place => label.
		 *
		 * @since 1.0.0
		 */
		$places = (array) apply_filters( $this->hook( 'places' ), (array) self::resolve( $this->config['places'] ) );
		$clean  = array();

		foreach ( $places as $place => $label ) {
			$place = self::place( (string) $place );

			if ( '' !== $place ) {
				$clean[ $place ] = (string) $label;
			}
		}

		return $clean;
	}

	/**
	 * Whether Turnstile is in use, at all or for one place.
	 *
	 * In use means switched on with both keys saved. Switched on without
	 * them is off: there is nothing to draw and nothing to ask.
	 *
	 * @param string $place A place, or '' for anywhere.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function enabled( string $place = '' ): bool {
		$enabled = $this->switched_on() && '' !== $this->site_key() && '' !== $this->secret();

		if ( $enabled && '' !== $place ) {
			$enabled = in_array( self::place( $place ), $this->chosen(), true );
		}

		/**
		 * Filter whether Cloudflare Turnstile is in use.
		 *
		 * @param bool   $enabled Whether it is.
		 * @param string $place   The place asked about, or '' for anywhere.
		 *
		 * @since 1.0.0
		 */
		return (bool) apply_filters( $this->hook( 'enabled' ), $enabled, $place );
	}

	/**
	 * Whether the owner has thrown the switch, keys or no keys.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function switched_on(): bool {
		return (bool) self::resolve( $this->config['enabled'] );
	}

	/**
	 * The places the owner has ticked.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	public function chosen(): array {
		$chosen = self::resolve( $this->config['chosen'] );
		$places = array_keys( $this->places() );

		// Never saved: what the setting shows ticked.
		if ( ! is_array( $chosen ) ) {
			$chosen = is_array( $this->config['default_places'] ) ? $this->config['default_places'] : $places;
		}

		return array_values( array_intersect( array_map( 'strval', $chosen ), $places ) );
	}

	/**
	 * The widget's site key. Public: it is printed in the page.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function site_key(): string {
		return trim( (string) self::resolve( $this->config['site_key'] ) );
	}

	/**
	 * The widget's secret key. Never printed, logged or returned by anything else.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function secret(): string {
		return trim( (string) self::resolve( $this->config['secret_key'] ) );
	}

	/**
	 * Whether somebody has to pass the check.
	 *
	 * @param string               $place The place.
	 * @param array<string, mixed> $who   Who is asking, as the plugin
	 *                                    describes them (`email`, `ip`…).
	 *
	 * @return bool False wherever Turnstile is not in use.
	 * @since 1.0.0
	 */
	public function required( string $place, array $who = array() ): bool {
		if ( ! $this->enabled( $place ) ) {
			return false;
		}

		$rule     = $this->config['required'];
		$required = is_callable( $rule ) ? (bool) $rule( $place, $who ) : ! is_user_logged_in();

		/**
		 * Filter whether somebody has to pass Cloudflare Turnstile.
		 *
		 * Only asked where Turnstile is in use. Return false to let
		 * somebody off, or true to hold a request to it that would not
		 * have been.
		 *
		 * @param bool                 $required Whether they have to.
		 * @param string               $place    The place.
		 * @param array<string, mixed> $who      Who is asking.
		 *
		 * @since 1.0.0
		 */
		return (bool) apply_filters( $this->hook( 'required' ), $required, $place, $who );
	}

	/**
	 * Whether a check that could not be made lets the visitor through,
	 * by the configured policy and before the filter.
	 *
	 * @param string               $kind  `unavailable` or `misconfigured`.
	 * @param string               $place The place, or ''.
	 * @param array<string, mixed> $who   Who sent the token.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function fails_open( string $kind, string $place = '', array $who = array() ): bool {
		$policy = $this->config['fail_open'];

		if ( is_callable( $policy ) ) {
			return (bool) $policy( $kind, $place, $who );
		}

		if ( is_array( $policy ) ) {
			return ! empty( $policy[ $kind ] );
		}

		return (bool) $policy;
	}

	/**
	 * The hostnames a token may have been made on.
	 *
	 * By default the site's own, from its two addresses and with and
	 * without `www`, and never from the request: a Host header is
	 * whatever the sender wrote.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	public function hostnames(): array {
		$given = self::resolve( $this->config['hostnames'] );
		$hosts = is_array( $given ) ? $given : self::own_hostnames();

		/**
		 * Filter the hostnames a Turnstile token may come from.
		 *
		 * Add the address of a front end on another domain that draws the
		 * widget with this site key. Return an empty array to accept a
		 * token from any hostname the widget itself allows.
		 *
		 * @param string[] $hosts Hostnames, lower case.
		 *
		 * @since 1.0.0
		 */
		$hosts = (array) apply_filters( $this->hook( 'hostnames' ), $hosts );

		return array_values( array_unique( array_map( 'strval', $hosts ) ) );
	}

	/**
	 * Where the owner stands, in a word and a tone, for a settings card.
	 *
	 * Off; keys missing; key not accepted; not used anywhere; on with
	 * Cloudflare's test keys (which pass everybody); on.
	 *
	 * @return array{label: string, tone: string} Tone is `neutral`,
	 *                                            `warning`, `error` or
	 *                                            `success`.
	 * @since 1.0.0
	 */
	public function status(): array {
		if ( ! $this->switched_on() ) {
			return array(
				'label' => $this->message( 'status_off' ),
				'tone'  => 'neutral',
			);
		}

		if ( '' === $this->site_key() || '' === $this->secret() ) {
			return array(
				'label' => $this->message( 'status_no_keys' ),
				'tone'  => 'warning',
			);
		}

		if ( $this->record()->secret_refused( $this->secret() ) ) {
			return array(
				'label' => $this->message( 'status_refused' ),
				'tone'  => 'error',
			);
		}

		if ( array() === $this->chosen() ) {
			return array(
				'label' => $this->message( 'status_nowhere' ),
				'tone'  => 'warning',
			);
		}

		// Cloudflare's published test keys pass everybody. On, and not
		// protecting anything: said, so they are not left in by mistake.
		if ( Verifier::is_test_secret( $this->secret() ) ) {
			return array(
				'label' => $this->message( 'status_test_keys' ),
				'tone'  => 'warning',
			);
		}

		return array(
			'label' => $this->message( 'status_on' ),
			'tone'  => 'success',
		);
	}

	/**
	 * The site's own hostnames, with and without `www`.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	private static function own_hostnames(): array {
		$hosts = array();

		foreach ( array( home_url(), site_url() ) as $url ) {
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );

			if ( '' === $host ) {
				continue;
			}

			$bare    = str_starts_with( $host, 'www.' ) ? substr( $host, 4 ) : $host;
			$hosts[] = $bare;
			$hosts[] = 'www.' . $bare;
		}

		return $hosts;
	}
}
