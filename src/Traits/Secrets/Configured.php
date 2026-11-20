<?php
/**
 * Secrets: values a constant or an environment variable supplies.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Traits\Secrets;

/**
 * Where a secret comes from when it is not the database: a constant in
 * wp-config.php, then an environment variable. For {@see \SugarCommerce\Security\Encryption\Secrets}.
 *
 * @since 1.0.0
 */
trait Configured {

	/**
	 * Whether a constant supplies an option.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return bool
	 */
	public function is_constant_defined( string $option ): bool {
		return null !== $this->constant( $option );
	}

	/**
	 * The constant that would supply an option: `MYPLUGIN_{NAME}`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string
	 */
	public function get_constant_name( string $option ): string {
		return $this->constant_name( $option );
	}

	/**
	 * Whether an environment variable supplies an option.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return bool
	 */
	public function is_env_defined( string $option ): bool {
		return null !== $this->env( $option );
	}

	/**
	 * The environment variable that would supply an option. The same name
	 * as the constant.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string
	 */
	public function get_env_name( string $option ): string {
		return $this->constant_name( $option );
	}

	/**
	 * Whether configuration rather than the database supplies an option.
	 *
	 * A settings screen then shows the field read-only: saving it would
	 * have no effect.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return bool
	 */
	public function is_externally_defined( string $option ): bool {
		return null !== $this->configured( $option );
	}

	/**
	 * A settings field's description, saying where its value comes from.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option    Name without the prefix.
	 * @param string $base_desc The field's own description.
	 *
	 * @return string Markup: the description and a note of the source.
	 */
	public function get_setting_description( string $option, string $base_desc ): string {
		if ( $this->is_constant_defined( $option ) ) {
			return $base_desc . sprintf( ' <strong>%s</strong> <code>%s</code>', __( 'Defined as constant:', 'sugarcommerce' ), $this->constant_name( $option ) );
		}

		// Said, or the field looks editable while saves do nothing.
		if ( $this->is_env_defined( $option ) ) {
			return $base_desc . sprintf( ' <strong>%s</strong> <code>%s</code>', __( 'Defined as environment variable:', 'sugarcommerce' ), $this->constant_name( $option ) );
		}

		return $base_desc . ' ' . __( '(stored encrypted in database)', 'sugarcommerce' );
	}

	/**
	 * The constant, and environment variable, that would supply an option.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string
	 */
	private function constant_name( string $option ): string {
		return strtoupper( $this->option_name( $option ) );
	}

	/**
	 * A constant's value, when it is defined and not empty.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string|null
	 */
	private function constant( string $option ): ?string {
		$name = $this->constant_name( $option );

		return defined( $name ) && ! empty( constant( $name ) ) ? (string) constant( $name ) : null;
	}

	/**
	 * An environment variable's value, when it is set and not empty.
	 *
	 * getenv() rather than $_ENV: PHP's default variables_order has no E,
	 * so $_ENV is empty on most installs. Under PHP-FPM the default pool
	 * setting `clear_env = yes` strips the environment before workers start,
	 * so a variable exported in a shell or Dockerfile does not arrive until
	 * the pool passes it (`env[NAME] = $NAME`) -- the usual reason a correct
	 * configuration appears to be ignored.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string|null
	 */
	private function env( string $option ): ?string {
		$value = getenv( $this->constant_name( $option ) );

		return false === $value || '' === $value ? null : $value;
	}

	/**
	 * The configured value and its source, constant first.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return array{value: string, source: string}|null
	 */
	private function configured( string $option ): ?array {
		$constant = $this->constant( $option );

		if ( null !== $constant ) {
			return array(
				'value'  => $constant,
				'source' => 'constant',
			);
		}

		$env = $this->env( $option );

		return null === $env ? null : array(
			'value'  => $env,
			'source' => 'env',
		);
	}
}
