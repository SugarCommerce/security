<?php
/**
 * Secrets: WordPress's get_option() answered decrypted.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Traits\Secrets;

/**
 * Answering WordPress's own get_option() with the decrypted value, through
 * `pre_option_{name}`. For {@see \SugarCommerce\Security\Encryption\Secrets}.
 *
 * @since 1.0.0
 */
trait Interception {

	/**
	 * Have WordPress's get_option() answer an option decrypted.
	 *
	 * Through its `pre_option_{name}` filter. Done for every option saved
	 * through this class while interception is on.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return void
	 */
	public function track_option( string $option ): void {
		if ( in_array( $option, $this->tracked, true ) ) {
			return;
		}

		$this->tracked[] = $option;

		if ( $this->auto_intercept ) {
			add_filter( 'pre_option_' . $this->option_name( $option ), array( $this, 'intercept_option_value' ), 10, 2 );
		}
	}

	/**
	 * The `pre_option_{name}` filter: the option, decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed  $value  What the filter was given.
	 * @param string $option The full option name. Read from the current
	 *                       filter when not given.
	 *
	 * @return string
	 */
	public function intercept_option_value( mixed $value, string $option = '' ): string {
		$hook   = 'pre_option_' . ( '' === $option ? substr( current_filter(), strlen( 'pre_option_' ) ) : $option );
		$option = substr( $hook, strlen( 'pre_option_' ) );
		$base   = str_starts_with( $option, $this->option_prefix ) ? substr( $option, strlen( $this->option_prefix ) ) : $option;

		// Off while the option is read, or reading it would call this again.
		remove_filter( $hook, array( $this, 'intercept_option_value' ), 10 );

		$decrypted = $this->get_option( $base, '' );

		add_filter( $hook, array( $this, 'intercept_option_value' ), 10, 2 );

		return $decrypted;
	}

	/**
	 * Start answering get_option() decrypted, for every tracked option.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function enable_auto_interception(): void {
		$this->auto_intercept = true;

		foreach ( $this->tracked as $option ) {
			add_filter( 'pre_option_' . $this->option_name( $option ), array( $this, 'intercept_option_value' ), 10, 2 );
		}
	}

	/**
	 * Stop answering get_option() decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function disable_auto_interception(): void {
		$this->auto_intercept = false;

		foreach ( $this->tracked as $option ) {
			remove_filter( 'pre_option_' . $this->option_name( $option ), array( $this, 'intercept_option_value' ), 10 );
		}
	}

	/**
	 * Whether get_option() is answered decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_auto_intercept_enabled(): bool {
		return $this->auto_intercept;
	}
}
