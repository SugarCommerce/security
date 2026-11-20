<?php
/**
 * A plugin's secrets, kept encrypted in WordPress.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Encryption;

use SugarCommerce\Security\Traits\Secrets\Configured;
use SugarCommerce\Security\Traits\Secrets\Interception;
use SugarCommerce\Security\Traits\Secrets\Stored;
use WP_Error;

/**
 * Class Secrets
 *
 * Where a plugin keeps an API key: a constant in wp-config.php when the site
 * defines one, an environment variable when the host injects one, and
 * otherwise an option stored encrypted. Read it the same way whichever it is.
 *
 *     $secrets = new Secrets( 'myplugin' );
 *
 *     $secrets->update_option( 'stripe_secret_key', $key ); // stored as ciphertext
 *     $key = $secrets->get_option( 'stripe_secret_key' );   // the key
 *
 * **Precedence.** A constant, then an environment variable, then the
 * database. The option `myplugin_stripe_secret_key` is overridden by the
 * constant or variable `MYPLUGIN_STRIPE_SECRET_KEY`. Constants win because
 * they are explicit and local to the site; an environment variable is more
 * easily exposed by phpinfo(), a stack trace or a debugging plugin, so it is
 * the fallback for hosts where wp-config.php cannot be written. While either
 * supplies the value, saving the option is refused: the write would succeed
 * and the read would keep returning the configured value, which reads as
 * data loss.
 *
 * **Reading through get_option().** An option saved through this class in
 * the current request -- or named with track_option() -- is also decrypted
 * when other code reads it with WordPress's own get_option().
 *
 * The key comes from the site's salts, which are in wp-config.php. This
 * protects against a leaked database dump, not against somebody who already
 * has the filesystem. That is the threat worth defending here: database
 * backups travel far more freely than wp-config.php does.
 *
 * Constants and variables are in {@see Configured}, transients and meta
 * in {@see Stored}, and get_option() in {@see Interception}.
 *
 * @since 1.0.0
 */
class Secrets {

	use Configured;
	use Interception;
	use Stored;

	/**
	 * The cipher.
	 *
	 * @var Cipher
	 */
	private Cipher $cipher;

	/**
	 * What every option name starts with: the prefix and an underscore.
	 *
	 * @var string
	 */
	private string $option_prefix;

	/**
	 * Whether WordPress's get_option() is answered with the decrypted value.
	 *
	 * @var bool
	 */
	private bool $auto_intercept;

	/**
	 * Options read through get_option() decrypted.
	 *
	 * @var string[]
	 */
	private array $tracked = array();

	/**
	 * @since 1.0.0
	 *
	 * @param string      $prefix         The plugin's prefix, such as
	 *                                    `myplugin`: options are
	 *                                    `myplugin_{name}`, constants and
	 *                                    variables `MYPLUGIN_{NAME}`.
	 * @param string|null $key            A key of the caller's own. Null
	 *                                    derives one from the site.
	 * @param bool        $auto_intercept Decrypt saved options for
	 *                                    WordPress's get_option() too.
	 *
	 * @throws \RuntimeException When OpenSSL is missing or the site has no
	 *                           key material.
	 */
	public function __construct( string $prefix, #[\SensitiveParameter] ?string $key = null, bool $auto_intercept = true ) {
		$this->cipher         = new Cipher( $prefix, $key );
		$this->option_prefix  = $prefix . '_';
		$this->auto_intercept = $auto_intercept;
	}

	/**
	 * The cipher, for a value that is not an option, meta or a transient.
	 *
	 * @since 1.0.0
	 *
	 * @return Cipher
	 */
	public function cipher(): Cipher {
		return $this->cipher;
	}

	/* ─── Values ──────────────────────────────────────────────────── */

	/**
	 * Encrypt a value. See {@see Cipher::encrypt()}.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value The plain value.
	 *
	 * @return string|WP_Error
	 */
	public function encrypt( #[\SensitiveParameter] string $value ): string|WP_Error {
		return $this->cipher->encrypt( $value );
	}

	/**
	 * Decrypt a value. See {@see Cipher::decrypt()}.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return string|WP_Error
	 */
	public function decrypt( string $value ): string|WP_Error {
		return $this->cipher->decrypt( $value );
	}

	/**
	 * Whether a value is encrypted. See {@see Cipher::is_encrypted()}.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public function is_encrypted( string $value ): bool {
		return $this->cipher->is_encrypted( $value );
	}

	/**
	 * Whether a value is in the unauthenticated format. See
	 * {@see Cipher::is_legacy_format()}.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public function is_legacy_format( string $value ): bool {
		return $this->cipher->is_legacy_format( $value );
	}

	/**
	 * Use another key from now on.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $key A key of the caller's own, or null for the site's.
	 *
	 * @return void
	 */
	public function change_key( #[\SensitiveParameter] ?string $key = null ): void {
		$this->cipher->change_key( $key );
	}

	/* ─── Options ─────────────────────────────────────────────────── */

	/**
	 * Save an option, encrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 * @param string $value  The plain value.
	 *
	 * @return bool False when a constant or variable supplies it, or the
	 *              value could not be encrypted.
	 */
	public function update_option( string $option, #[\SensitiveParameter] string $value ): bool {
		if ( $this->is_externally_defined( $option ) ) {
			return false;
		}

		$encrypted = $this->cipher->encrypt( $value );

		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		if ( $this->auto_intercept ) {
			$this->track_option( $option );
		}

		return update_option( $this->option_name( $option ), $encrypted );
	}

	/**
	 * Read an option: the constant, the variable, or the decrypted option.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option  Name without the prefix.
	 * @param string $default What to return when there is none, or it will
	 *                        not decrypt.
	 *
	 * @return string
	 */
	public function get_option( string $option, string $default = '' ): string {
		$configured = $this->configured( $option );

		if ( null !== $configured ) {
			return $configured['value'];
		}

		$value = get_option( $this->option_name( $option ), $default );

		if ( ! is_string( $value ) ) {
			return $default;
		}

		$decrypted = $this->cipher->decrypt( $value );

		return is_wp_error( $decrypted ) ? $default : $decrypted;
	}

	/**
	 * Delete an option.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 * @param bool   $force  Delete it even while a constant or variable
	 *                       supplies the value.
	 *
	 * @return bool
	 */
	public function delete_option( string $option, bool $force = false ): bool {
		if ( ! $force && $this->is_externally_defined( $option ) ) {
			return false;
		}

		return delete_option( $this->option_name( $option ) );
	}

	/**
	 * An option's value and where it came from, for a settings screen.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option  Name without the prefix.
	 * @param string $default What to return when there is none.
	 *
	 * @return array{value: string, source: string, is_encrypted: bool, constant?: string, env?: string, option?: string}
	 *         Source is `constant`, `env`, `database` or `default`.
	 */
	public function get_option_info( string $option, string $default = '' ): array {
		$configured = $this->configured( $option );

		if ( null !== $configured ) {
			return array(
				'value'              => $configured['value'],
				'source'             => $configured['source'],
				$configured['source'] => $this->constant_name( $option ),
				'is_encrypted'       => false,
			);
		}

		$name   = $this->option_name( $option );
		$stored = get_option( $name, null );

		if ( is_string( $stored ) ) {
			$decrypted = $this->cipher->decrypt( $stored );

			if ( ! is_wp_error( $decrypted ) ) {
				return array(
					'value'        => $decrypted,
					'source'       => 'database',
					'option'       => $name,
					'is_encrypted' => $this->cipher->is_encrypted( $stored ),
				);
			}
		}

		return array(
			'value'        => $default,
			'source'       => 'default',
			'is_encrypted' => false,
		);
	}

	/* ─── Internals ───────────────────────────────────────────────── */

	/**
	 * An option's full name.
	 *
	 * @since 1.0.0
	 *
	 * @param string $option Name without the prefix.
	 *
	 * @return string
	 */
	private function option_name( string $option ): string {
		return $this->option_prefix . $option;
	}
}
