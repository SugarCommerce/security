<?php
/**
 * What Site Health says about Turnstile.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * Turnstile on both tabs of Site Health.
 *
 * **Info**: whether it is on and where, when a check last worked, and the
 * last time one could not be made. These are the lines somebody helping
 * the owner asks for first, and they are how the owner learns that
 * Cloudflare could not be reached. Added to the plugin's own Info section
 * when it has one (`info_filter`: a filter that passes that section's
 * fields), or as a section of their own.
 *
 * **Status**: one check, only once Turnstile is switched on. A warning
 * when the keys are missing or the secret key has been refused; good
 * otherwise.
 *
 * Neither key is ever written here. The site key is public and the secret
 * is not, and a line saying "set" is all anybody needs of either.
 *
 * @since 1.0.0
 */
final readonly class SiteHealth {

	/**
	 * Site Health for one plugin's Turnstile.
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
		$filter = $this->turnstile->option( 'info_filter' );

		if ( is_string( $filter ) && '' !== $filter ) {
			add_filter( $filter, array( $this, 'info' ) );
		} else {
			add_filter( 'debug_information', array( $this, 'section' ) );
		}

		add_filter( 'site_status_tests', array( $this, 'register' ) );
	}

	/**
	 * A section of its own on the Info tab.
	 *
	 * @param array<string, array<string, mixed>> $sections The sections so far.
	 *
	 * @return array<string, array<string, mixed>>
	 * @since 1.0.0
	 */
	public function section( mixed $sections ): array {
		$sections = (array) $sections;

		$sections[ $this->turnstile->option( 'prefix' ) ] = array(
			'label'  => sprintf( '%s: %s', $this->turnstile->option( 'label' ), $this->turnstile->message( 'health_title' ) ),
			'fields' => $this->info( array() ),
		);

		return $sections;
	}

	/**
	 * The lines, added to a section's fields.
	 *
	 * @param array<string, array<string, mixed>> $fields The lines so far.
	 *
	 * @return array<string, array<string, mixed>>
	 * @since 1.0.0
	 */
	public function info( mixed $fields ): array {
		$fields = (array) $fields;

		$fields['turnstile'] = array(
			'label' => $this->turnstile->message( 'health_title' ),
			'value' => $this->state(),
			'debug' => $this->state( false ),
		);

		// Nothing more to say about something that has never been on.
		if ( ! $this->turnstile->switched_on() ) {
			return $fields;
		}

		$record   = $this->turnstile->record();
		$answered = $record->last_answered();

		$fields['turnstile_checked'] = array(
			'label' => $this->turnstile->message( 'health_checked' ),
			'value' => $answered > 0 ? self::moment( $answered ) : $this->turnstile->message( 'health_never' ),
			'debug' => $answered > 0 ? gmdate( 'Y-m-d H:i:s', $answered ) . ' UTC' : 'never',
		);

		$problem = $record->last_problem();

		if ( null !== $problem ) {
			$what = 'misconfigured' === $problem['kind']
				? $this->turnstile->message( 'health_problem_key' )
				: $this->turnstile->message( 'health_problem_down' );

			$fields['turnstile_problem'] = array(
				'label' => $this->turnstile->message( 'health_problem' ),
				'value' => sprintf( $this->turnstile->message( 'health_problem_value' ), self::moment( $problem['time'] ), $what ),
				'debug' => sprintf( '%s UTC, %s (%s) at %s', gmdate( 'Y-m-d H:i:s', $problem['time'] ), $problem['kind'], implode( ', ', $problem['codes'] ), $problem['place'] ),
			);
		}

		return $fields;
	}

	/**
	 * Add the check to WordPress's list, once Turnstile is switched on.
	 *
	 * @param array<string, array<string, mixed>> $tests The tests.
	 *
	 * @return array<string, array<string, mixed>>
	 * @since 1.0.0
	 */
	public function register( mixed $tests ): array {
		$tests = (array) $tests;

		if ( $this->turnstile->switched_on() ) {
			$tests['direct'][ $this->turnstile->option( 'health_test' ) ] = array(
				'label' => (string) $this->turnstile->option( 'label' ),
				'test'  => array( $this, 'check' ),
			);
		}

		return $tests;
	}

	/**
	 * Whether Turnstile is doing what the owner switched it on to do.
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	public function check(): array {
		if ( ! $this->turnstile->enabled() ) {
			return $this->result( 'recommended', $this->turnstile->message( 'health_test_no_keys' ), $this->turnstile->message( 'health_test_add_keys' ) );
		}

		$notice = new Notice( $this->turnstile );

		if ( $notice->due() ) {
			return $this->result( 'recommended', $notice->message(), $notice->detail() );
		}

		return $this->result( 'good', $this->turnstile->message( 'health_test_good' ), $this->turnstile->message( 'health_test_in_place' ) );
	}

	/**
	 * Off, on and where, or on without its keys.
	 *
	 * @param bool $translated False for the copied text, which is English.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private function state( bool $translated = true ): string {
		if ( ! $this->turnstile->switched_on() ) {
			return $translated ? $this->turnstile->message( 'health_off' ) : 'off';
		}

		if ( ! $this->turnstile->enabled() ) {
			return $translated ? $this->turnstile->message( 'health_no_keys' ) : 'on, keys missing';
		}

		$chosen = $this->turnstile->chosen();

		if ( ! $translated ) {
			return 'on: ' . ( array() === $chosen ? 'no places' : implode( ', ', $chosen ) );
		}

		if ( array() === $chosen ) {
			return $this->turnstile->message( 'health_nowhere' );
		}

		return sprintf( $this->turnstile->message( 'health_on' ), implode( ', ', array_intersect_key( $this->turnstile->places(), array_flip( $chosen ) ) ) );
	}

	/**
	 * A moment, in the site's own time and format.
	 *
	 * @param int $time A Unix time.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private static function moment( int $time ): string {
		return (string) wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $time );
	}

	/**
	 * A result in the shape Site Health wants.
	 *
	 * @param string $status good or recommended.
	 * @param string $label  The headline.
	 * @param string $detail The explanation.
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	private function result( string $status, string $label, string $detail ): array {
		$url = (string) $this->turnstile->option( 'settings_url' );

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => (string) $this->turnstile->option( 'label' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html( $detail ) . '</p>',
			'actions'     => 'good' === $status || '' === $url
				? ''
				: sprintf(
					'<a href="%1$s">%2$s</a>',
					esc_url( $url ),
					esc_html( $this->turnstile->message( 'health_action' ) )
				),
			'test'        => (string) $this->turnstile->option( 'health_test' ),
		);
	}
}
