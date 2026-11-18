<?php
/**
 * PHPUnit bootstrap.
 *
 * A library, not a plugin. The WordPress functions it calls are stubbed
 * over globals a test can set and read:
 *
 *  - $GLOBALS['st_salt']       what wp_salt() answers; unset, a healthy 64 characters;
 *  - $GLOBALS['ts_hooks']      callbacks added with add_filter/add_action, run by apply_filters/do_action;
 *  - $GLOBALS['ts_fired']      every do_action, with its arguments;
 *  - $GLOBALS['ts_options']    the options table;
 *  - $GLOBALS['ts_transients'] transients, and $GLOBALS['ts_meta'] user and post meta;
 *  - $GLOBALS['ts_responses']  what wp_remote_post answers, in order (an array, or a WP_Error);
 *  - $GLOBALS['ts_requests']   what was posted, and where;
 *  - $GLOBALS['ts_logged_in']  whether somebody is signed in;
 *  - $GLOBALS['ts_caps']       the current user's capabilities;
 *  - $GLOBALS['ts_screen']     the current admin screen's id;
 *  - $GLOBALS['ts_enqueued']   scripts, styles and modules asked for;
 *  - $GLOBALS['ts_privacy']    what was offered to the privacy policy guide;
 *  - $GLOBALS['rl_ext_cache']  whether a persistent object cache is in use, and
 *    $GLOBALS['rl_cache'] what is in it ($GLOBALS['rl_cache_broken'] makes it refuse).
 *
 * $wpdb is a fake that understands the few statements the rate-limit table
 * store sends (tests/RateLimit/Support/FakeWpdb.php).
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

// The folder this package sits in stands for wp-content, so an asset's URL
// can be worked out from where the file is.
if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', dirname( __DIR__, 2 ) );
}

if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public array $errors     = array();
		public array $error_data = array();

		public function __construct( $code = '', $message = '', $data = '' ) {
			if ( '' !== $code ) {
				$this->errors[ $code ][] = $message;

				if ( '' !== $data ) {
					$this->error_data[ $code ] = $data;
				}
			}
		}

		public function get_error_code() {
			return array_key_first( $this->errors ) ?? '';
		}

		public function get_error_message() {
			return $this->errors[ $this->get_error_code() ][0] ?? '';
		}

		public function get_error_data() {
			return $this->error_data[ $this->get_error_code() ] ?? null;
		}
	}
}

/**
 * Forget everything a test may have left behind.
 *
 * @return void
 */
function ts_reset(): void {
	$GLOBALS['ts_hooks']      = array();
	$GLOBALS['ts_fired']      = array();
	$GLOBALS['ts_options']    = array();
	$GLOBALS['ts_transients'] = array();
	$GLOBALS['ts_meta']       = array();
	$GLOBALS['ts_responses']  = array();
	$GLOBALS['ts_requests']   = array();
	$GLOBALS['ts_logged_in']  = false;
	$GLOBALS['ts_caps']       = array( 'manage_options' );
	$GLOBALS['ts_screen']     = 'toplevel_page_demo';
	$GLOBALS['ts_enqueued']   = array();
	$GLOBALS['ts_privacy']    = array();
	$GLOBALS['ts_home']       = 'https://www.example.com';
	$GLOBALS['ts_site']       = 'https://example.com/wp';
	unset( $_SERVER['REMOTE_ADDR'] );
}

/**
 * A siteverify answer.
 *
 * @param array<string, mixed> $body The JSON body.
 * @param int                  $code The HTTP status.
 *
 * @return array<string, mixed>
 */
function ts_answer( array $body, int $code = 200 ): array {
	return array(
		'response' => array( 'code' => $code ),
		'body'     => json_encode( $body ),
	);
}

ts_reset();

function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}

function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	$GLOBALS['ts_hooks'][ $hook ][] = $callback;

	return true;
}

function remove_filter( $hook, $callback, $priority = 10 ) {
	foreach ( $GLOBALS['ts_hooks'][ $hook ] ?? array() as $i => $added ) {
		if ( $added === $callback ) {
			unset( $GLOBALS['ts_hooks'][ $hook ][ $i ] );

			return true;
		}
	}

	return false;
}

function current_filter() {
	return $GLOBALS['ts_current_filter'] ?? '';
}

function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	return add_filter( $hook, $callback, $priority, $args );
}

function apply_filters( $hook, $value, ...$args ) {
	foreach ( $GLOBALS['ts_hooks'][ $hook ] ?? array() as $callback ) {
		$value = $callback( $value, ...$args );
	}

	return $value;
}

function do_action( $hook, ...$args ) {
	$GLOBALS['ts_fired'][] = array( $hook, $args );

	foreach ( $GLOBALS['ts_hooks'][ $hook ] ?? array() as $callback ) {
		$callback( ...$args );
	}
}

function __( $text, $domain = 'default' ) {
	return $text;
}

function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES );
}

function esc_attr( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES );
}

function esc_url( $url ) {
	return (string) $url;
}

function wp_kses_post( $html ) {
	return (string) $html;
}

function sanitize_key( $key ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
}

function sanitize_text_field( $text ) {
	return trim( (string) $text );
}

function wp_unslash( $value ) {
	return $value;
}

function get_option( $name, $fallback = false ) {
	return $GLOBALS['ts_options'][ $name ] ?? $fallback;
}

function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['ts_options'][ $name ] = $value;

	return true;
}

function delete_option( $name ) {
	$had = isset( $GLOBALS['ts_options'][ $name ] );

	unset( $GLOBALS['ts_options'][ $name ] );

	return $had;
}

function set_transient( $name, $value, $expiration = 0 ) {
	$GLOBALS['ts_transients'][ $name ] = $value;

	return true;
}

function get_transient( $name ) {
	return $GLOBALS['ts_transients'][ $name ] ?? false;
}

function update_user_meta( $id, $key, $value ) {
	$GLOBALS['ts_meta']['user'][ $id ][ $key ] = $value;

	return true;
}

function get_user_meta( $id, $key, $single = false ) {
	return $GLOBALS['ts_meta']['user'][ $id ][ $key ] ?? '';
}

function update_post_meta( $id, $key, $value ) {
	$GLOBALS['ts_meta']['post'][ $id ][ $key ] = $value;

	return true;
}

function get_post_meta( $id, $key, $single = false ) {
	return $GLOBALS['ts_meta']['post'][ $id ][ $key ] ?? '';
}

/**
 * Core's salt accessor: $GLOBALS['st_salt'] for the auth salt when a test
 * sets one, so a suite can exercise a site still on the placeholder salts.
 */
function wp_salt( $scheme = 'auth' ) {
	if ( 'auth' === $scheme && isset( $GLOBALS['st_salt'] ) ) {
		return $GLOBALS['st_salt'];
	}

	return str_repeat( 'a', 64 ) . '-' . $scheme;
}

function wp_generate_uuid4() {
	return '6f9619ff-8b86-4d01-b42d-00cf4fc964ff';
}

function wp_remote_post( $url, $args = array() ) {
	$GLOBALS['ts_requests'][] = array( $url, $args );

	return array_shift( $GLOBALS['ts_responses'] ) ?? new WP_Error( 'http_request_failed', 'No answer queued.' );
}

function wp_remote_retrieve_body( $response ) {
	return is_array( $response ) ? (string) ( $response['body'] ?? '' ) : '';
}

function wp_remote_retrieve_response_code( $response ) {
	return is_array( $response ) ? ( $response['response']['code'] ?? '' ) : '';
}

function home_url() {
	return $GLOBALS['ts_home'];
}

function site_url() {
	return $GLOBALS['ts_site'];
}

function content_url() {
	return 'https://example.com/wp-content';
}

function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component );
}

function is_user_logged_in() {
	return (bool) $GLOBALS['ts_logged_in'];
}

function current_user_can( $capability ) {
	return in_array( $capability, $GLOBALS['ts_caps'], true );
}

function get_current_screen() {
	return (object) array( 'id' => $GLOBALS['ts_screen'] );
}

function wp_enqueue_script( $handle, $src = '', $deps = array(), $ver = false, $args = array() ) {
	$GLOBALS['ts_enqueued']['scripts'][ $handle ] = array( $src, $ver, $args );
}

function wp_register_script_module( $id, $src, $deps = array(), $version = false ) {
	$GLOBALS['ts_enqueued']['modules'][ $id ] = array( $src, $version );
}

function wp_style_is( $handle, $status = 'enqueued' ) {
	return isset( $GLOBALS['ts_enqueued']['styles'][ $handle ] );
}

// As core's: a handle already registered is left as it is.
function wp_register_style( $handle, $src, $deps = array(), $ver = false ) {
	if ( isset( $GLOBALS['ts_enqueued']['styles'][ $handle ] ) ) {
		return false;
	}

	$GLOBALS['ts_enqueued']['styles'][ $handle ] = array( 'src' => $src, 'inline' => '', 'enqueued' => false );

	return true;
}

function wp_add_inline_style( $handle, $css ) {
	$GLOBALS['ts_enqueued']['styles'][ $handle ]['inline'] .= $css;
}

function wp_enqueue_style( $handle ) {
	$GLOBALS['ts_enqueued']['styles'][ $handle ]['enqueued'] = true;
}

function wp_date( $format, $time ) {
	return gmdate( 'Y-m-d H:i', (int) $time );
}

function wp_add_privacy_policy_content( $name, $content ) {
	$GLOBALS['ts_privacy'][ $name ] = $content;
}

/**
 * Whether a persistent object cache is in use: $GLOBALS['rl_ext_cache'].
 */
function wp_using_ext_object_cache() {
	return ! empty( $GLOBALS['rl_ext_cache'] );
}

function wp_cache_add( $key, $data, $group = '', $expire = 0 ) {
	if ( isset( $GLOBALS['rl_cache'][ $group ][ $key ] ) ) {
		return false;
	}

	$GLOBALS['rl_cache'][ $group ][ $key ]     = $data;
	$GLOBALS['rl_cache_ttl'][ $group ][ $key ] = $expire;

	return true;
}

/**
 * Add to a number in the cache. False when the key is missing, as core's
 * is -- or always, when a test sets $GLOBALS['rl_cache_broken'].
 */
function wp_cache_incr( $key, $offset = 1, $group = '' ) {
	if ( ! empty( $GLOBALS['rl_cache_broken'] ) || ! isset( $GLOBALS['rl_cache'][ $group ][ $key ] ) ) {
		return false;
	}

	$GLOBALS['rl_cache'][ $group ][ $key ] += $offset;

	return $GLOBALS['rl_cache'][ $group ][ $key ];
}

function wp_cache_get( $key, $group = '' ) {
	return $GLOBALS['rl_cache'][ $group ][ $key ] ?? false;
}

function wp_cache_delete( $key, $group = '' ) {
	unset( $GLOBALS['rl_cache'][ $group ][ $key ] );

	return true;
}

/**
 * Core's transliteration, abbreviated.
 *
 * Enough of the table to exercise the branch. The real one is several
 * hundred characters; the point of the test is that this path is taken at
 * all, not that the stub is complete.
 */
function remove_accents( string $text ): string {
	return strtr(
		$text,
		array(
			'á' => 'a', 'à' => 'a', 'â' => 'a', 'ä' => 'a', 'å' => 'a', 'ã' => 'a',
			'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
			'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i',
			'ó' => 'o', 'ò' => 'o', 'ô' => 'o', 'ö' => 'o', 'õ' => 'o', 'ø' => 'o',
			'ú' => 'u', 'ù' => 'u', 'û' => 'u', 'ü' => 'u',
			'ñ' => 'n', 'ç' => 'c', 'ß' => 'ss', 'æ' => 'ae',

			// Upper case as well. Leaving it out was a stub deficiency that
			// read as a library bug: "Übungsstück" lost its first character,
			// because the Ü survived transliteration and was then stripped by
			// the a-z filter.
			'Á' => 'A', 'À' => 'A', 'Â' => 'A', 'Ä' => 'A', 'Å' => 'A', 'Ã' => 'A',
			'É' => 'E', 'È' => 'E', 'Ê' => 'E', 'Ë' => 'E',
			'Í' => 'I', 'Ì' => 'I', 'Î' => 'I', 'Ï' => 'I',
			'Ó' => 'O', 'Ò' => 'O', 'Ô' => 'O', 'Ö' => 'O', 'Õ' => 'O', 'Ø' => 'O',
			'Ú' => 'U', 'Ù' => 'U', 'Û' => 'U', 'Ü' => 'U',
			'Ñ' => 'N', 'Ç' => 'C', 'Æ' => 'AE',
		)
	);
}
