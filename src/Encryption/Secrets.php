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
 * @since 1.0.0
 */
class Secrets {

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

	/* ─── Constants and environment variables ─────────────────────── */

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
			return $base_desc . sprintf( ' <strong>%s</strong> <code>%s</code>', __( 'Defined as constant:', 'arraypress' ), $this->constant_name( $option ) );
		}

		// Said, or the field looks editable while saves do nothing.
		if ( $this->is_env_defined( $option ) ) {
			return $base_desc . sprintf( ' <strong>%s</strong> <code>%s</code>', __( 'Defined as environment variable:', 'arraypress' ), $this->constant_name( $option ) );
		}

		return $base_desc . ' ' . __( '(stored encrypted in database)', 'arraypress' );
	}

	/* ─── Transients and meta ─────────────────────────────────────── */

	/**
	 * Set a transient, encrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param string $transient  Name.
	 * @param string $value      The plain value.
	 * @param int    $expiration Seconds, or 0 for none.
	 *
	 * @return bool
	 */
	public function set_transient( string $transient, #[\SensitiveParameter] string $value, int $expiration = 0 ): bool {
		$encrypted = $this->cipher->encrypt( $value );

		return ! is_wp_error( $encrypted ) && set_transient( $transient, $encrypted, $expiration );
	}

	/**
	 * Read a transient, decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param string $transient Name.
	 *
	 * @return string|false False when there is none, or it will not decrypt.
	 */
	public function get_transient( string $transient ): string|false {
		$value = get_transient( $transient );

		return is_string( $value ) ? $this->opened( $value, false ) : false;
	}

	/**
	 * Save user meta, encrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param int    $user_id    User.
	 * @param string $meta_key   Key.
	 * @param string $meta_value The plain value.
	 *
	 * @return int|bool Meta id on a new row, true on an update, false otherwise.
	 */
	public function update_user_meta( int $user_id, string $meta_key, #[\SensitiveParameter] string $meta_value ): int|bool {
		$encrypted = $this->cipher->encrypt( $meta_value );

		return is_wp_error( $encrypted ) ? false : update_user_meta( $user_id, $meta_key, $encrypted );
	}

	/**
	 * Read user meta, decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param int    $user_id  User.
	 * @param string $meta_key Key.
	 * @param string $default  What to return when there is none.
	 *
	 * @return string
	 */
	public function get_user_meta( int $user_id, string $meta_key, string $default = '' ): string {
		$value = get_user_meta( $user_id, $meta_key, true );

		return is_string( $value ) ? (string) $this->opened( $value, $default ) : $default;
	}

	/**
	 * Save post meta, encrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param int    $post_id    Post.
	 * @param string $meta_key   Key.
	 * @param string $meta_value The plain value.
	 *
	 * @return int|bool Meta id on a new row, true on an update, false otherwise.
	 */
	public function update_post_meta( int $post_id, string $meta_key, #[\SensitiveParameter] string $meta_value ): int|bool {
		$encrypted = $this->cipher->encrypt( $meta_value );

		return is_wp_error( $encrypted ) ? false : update_post_meta( $post_id, $meta_key, $encrypted );
	}

	/**
	 * Read post meta, decrypted.
	 *
	 * @since 1.0.0
	 *
	 * @param int    $post_id  Post.
	 * @param string $meta_key Key.
	 * @param string $default  What to return when there is none.
	 *
	 * @return string
	 */
	public function get_post_meta( int $post_id, string $meta_key, string $default = '' ): string {
		$value = get_post_meta( $post_id, $meta_key, true );

		return is_string( $value ) ? (string) $this->opened( $value, $default ) : $default;
	}

	/* ─── WordPress's get_option() ────────────────────────────────── */

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

	/**
	 * A stored value decrypted, or a fallback when it will not decrypt.
	 *
	 * @since 1.0.0
	 *
	 * @param string       $value    Stored value.
	 * @param string|false $fallback What to return instead.
	 *
	 * @return string|false
	 */
	private function opened( string $value, string|false $fallback ): string|false {
		$decrypted = $this->cipher->decrypt( $value );

		return is_wp_error( $decrypted ) ? $fallback : $decrypted;
	}
}
