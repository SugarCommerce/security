<?php
/**
 * Secrets: transients and user and post meta, encrypted.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Traits\Secrets;

/**
 * Transients and meta kept encrypted. For {@see \SugarCommerce\Security\Encryption\Secrets}.
 *
 * @since 1.0.0
 */
trait Stored {

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
