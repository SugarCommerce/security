<?php
/**
 * Cloudflare Turnstile for one plugin's forms.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

use InvalidArgumentException;
use SugarCommerce\Security\Traits\Turnstile\Policy;
use SugarCommerce\Security\Traits\Turnstile\Verifying;
use WP_Error;

/**
 * Whether Turnstile is in use, who has to pass it, and what a failure means.
 *
 * Turnstile is Cloudflare's free check that a person, and not a script,
 * is at a form. It is off until the owner switches it on and pastes two
 * keys, and until then nothing here contacts Cloudflare and nothing of
 * Cloudflare's is put on any page.
 *
 * Verifier does the asking and knows nothing about a site. This is
 * everything that is the plugin's to decide, all of it configuration:
 *
 * **Where.** A place is a form (`checkout`, `login`, `signup`…). The
 * owner ticks the ones to protect; another plugin adds its own with the
 * `{prefix}_places` filter.
 *
 * **Who.** required() -- by default whoever is not signed in. Somebody
 * signed in has already proved more than a widget can. The `required`
 * option and the `{prefix}_required` filter change it per visitor.
 *
 * **What a failure means.** verify() answers true, or one of two errors:
 *
 *  - `{prefix}_incomplete`, 400, against the field `turnstile`: there
 *    was no token, or it had gone stale. This is the visitor's to put
 *    right and they are told how. It says nothing a visitor cannot see
 *    for themselves by looking at the page.
 *  - `{prefix}_failed`, 403: Cloudflare said the token is not real, or
 *    it was made for another site or another form. A person using the
 *    form does not get here.
 *
 * **When Cloudflare cannot be asked** -- a timeout, a server error there,
 * a name that does not resolve -- or does not accept the secret key, is
 * the plugin's policy (`fail_open`). Closed by default: the visitor is
 * told the check did not pass. A shop may rather let the buyer through
 * than stop selling because a third party is having a bad hour. Either
 * way it is written down (Record) and the owner is told (Notice,
 * SiteHealth).
 *
 *     $turnstile = Turnstile::register( [
 *         'id'         => 'my_plugin',
 *         'label'      => 'My Plugin',
 *         'enabled'    => fn() => (bool) get_option( 'my_plugin_turnstile' ),
 *         'site_key'   => fn() => (string) get_option( 'my_plugin_site_key' ),
 *         'secret_key' => fn() => (string) get_option( 'my_plugin_secret_key' ),
 *         'places'     => [ 'signup' => __( 'Sign-up form', 'my-plugin' ) ],
 *     ] );
 *
 * The policy is in {@see Policy} and the checking in {@see Verifying}; this
 * class is the configuration they both read.
 *
 * @since 1.0.0
 */
final class Turnstile {

	use Policy;
	use Verifying;

	/**
	 * The library's version, for its script module.
	 *
	 * @since 1.0.0
	 */
	public const string VERSION = '1.0.0';

	/**
	 * Every instance registered, by id.
	 *
	 * @var array<string, self>
	 */
	private static array $registered = array();

	/**
	 * The configuration, with every default filled in.
	 *
	 * @var array<string, mixed>
	 */
	private array $config;

	/**
	 * What each token came to, for the length of this request.
	 *
	 * A token is single use: asking Cloudflare about one twice gets
	 * `timeout-or-duplicate` the second time, and a visitor who passed
	 * would be refused by the site asking again. Not a cache -- it is
	 * gone with the request.
	 *
	 * @var array<string, true|WP_Error>
	 */
	private array $asked = array();

	/**
	 * The record of the last success and the last problem.
	 *
	 * @var Record|null
	 */
	private ?Record $record = null;

	/**
	 * The widget.
	 *
	 * @var Widget|null
	 */
	private ?Widget $widget = null;

	/**
	 * Turnstile for one plugin.
	 *
	 * @param array<string, mixed> $config See the README. `id` is required.
	 *
	 * @throws InvalidArgumentException Without an id.
	 * @since 1.0.0
	 */
	public function __construct( array $config ) {
		$id = strtolower( (string) preg_replace( '/[^A-Za-z0-9_-]/', '', (string) ( $config['id'] ?? '' ) ) );

		if ( '' === $id ) {
			throw new InvalidArgumentException( 'Turnstile needs an id: the plugin it belongs to, such as "my_plugin".' );
		}

		$this->config = self::defaults( $id, $config );
	}

	/**
	 * Configure Turnstile for a plugin and hook up the parts that listen.
	 *
	 * @param array<string, mixed> $config See the README.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public static function register( array $config ): self {
		$turnstile = new self( $config );

		self::$registered[ $turnstile->id() ] = $turnstile;

		$turnstile->init();

		return $turnstile;
	}

	/**
	 * A registered instance.
	 *
	 * @param string $id The plugin's id.
	 *
	 * @return self|null
	 * @since 1.0.0
	 */
	public static function get( string $id ): ?self {
		return self::$registered[ strtolower( $id ) ] ?? null;
	}

	/**
	 * Hook up the notice, Site Health and the privacy guide's paragraph.
	 *
	 * Each only when its option is on.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function init(): void {
		if ( $this->config['notice'] ) {
			( new Notice( $this ) )->init();
		}

		if ( $this->config['site_health'] ) {
			( new SiteHealth( $this ) )->init();
		}

		if ( $this->config['privacy'] ) {
			( new PrivacyText( $this ) )->init();
		}
	}

	/* ─── Configuration ───────────────────────────────────────────── */

	/**
	 * The plugin's id.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function id(): string {
		return $this->config['id'];
	}

	/**
	 * A configuration value, resolved.
	 *
	 * @param string $key The option.
	 *
	 * @return mixed
	 * @since 1.0.0
	 */
	public function option( string $key ): mixed {
		return $this->config[ $key ] ?? null;
	}

	/**
	 * The name of one of this instance's hooks: `{prefix}_{name}`.
	 *
	 * @param string $name `places`, `enabled`, `required`, `failed`,
	 *                     `fail_open`, `hostnames`, `shown` or `widget`.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function hook( string $name ): string {
		return $this->config['prefix'] . '_' . $name;
	}

	/**
	 * Words, from the configuration or the library's own.
	 *
	 * A configured value may be a string or a callable returning one, so
	 * a plugin can hand over its translations without loading them early.
	 *
	 * @param string $key The message.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function message( string $key ): string {
		$given = $this->config['messages'][ $key ] ?? null;

		if ( is_callable( $given ) ) {
			return (string) $given();
		}

		if ( is_string( $given ) ) {
			return $given;
		}

		return Messages::get( $key, $this->config['label'] );
	}

	/**
	 * The record of the last success and the last problem.
	 *
	 * @return Record
	 * @since 1.0.0
	 */
	public function record(): Record {
		$this->record ??= new Record( $this->config['record_option'] );

		return $this->record;
	}

	/**
	 * The widget.
	 *
	 * @return Widget
	 * @since 1.0.0
	 */
	public function widget(): Widget {
		$this->widget ??= new Widget( $this );

		return $this->widget;
	}

	/**
	 * The Test Keys check.
	 *
	 * @return KeyTest
	 * @since 1.0.0
	 */
	public function key_test(): KeyTest {
		return new KeyTest( $this );
	}

	/**
	 * A place's key, as it is stored and as Cloudflare takes an action.
	 *
	 * "This can only contain up to 32 alphanumeric characters including
	 * `_` and `-`" (developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations).
	 *
	 * @param string $place What was given.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public static function place( string $place ): string {
		return substr( (string) preg_replace( '/[^a-z0-9_-]/', '', strtolower( $place ) ), 0, 32 );
	}

	/**
	 * A key as pasted, without the space that came with it.
	 *
	 * Cloudflare's keys are letters, digits, `_` and `-`. Anything else
	 * was not part of one, and the site key is printed into the page. For
	 * a settings field's sanitize callback.
	 *
	 * @param mixed $key What was pasted.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public static function clean_key( mixed $key ): string {
		return substr( (string) preg_replace( '/[^A-Za-z0-9_-]/', '', is_scalar( $key ) ? (string) $key : '' ), 0, 100 );
	}

	/**
	 * Forget what this request has asked. Tests.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function reset(): void {
		$this->asked = array();
	}

	/**
	 * A value that may be given as a callable.
	 *
	 * A closure, an array callable or a `Class::method` string is called;
	 * anything else, a plain string included, is the value itself -- a key
	 * is never mistaken for the name of a function.
	 *
	 * @param mixed $value The value, or a callable returning it.
	 *
	 * @return mixed
	 * @since 1.0.0
	 */
	public static function resolve( mixed $value ): mixed {
		return $value instanceof \Closure || ( is_array( $value ) && is_callable( $value ) ) || ( is_string( $value ) && str_contains( $value, '::' ) && is_callable( $value ) )
			? $value()
			: $value;
	}

	/**
	 * The configuration, with every default filled in.
	 *
	 * @param string               $id     The plugin's id.
	 * @param array<string, mixed> $config As given.
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	private static function defaults( string $id, array $config ): array {
		$snake  = str_replace( '-', '_', $id );
		$kebab  = str_replace( '_', '-', $id );
		$prefix = (string) ( $config['prefix'] ?? $snake . '_turnstile' );

		$defaults = array(
			'id'             => $id,
			'prefix'         => $prefix,
			'label'          => $id,
			'enabled'        => false,
			'site_key'       => '',
			'secret_key'     => '',
			'places'         => array(),
			'chosen'         => null,
			'default_places' => null,
			'theme'          => 'auto',
			'required'       => null,
			'shown'          => null,
			'fail_open'      => false,
			'hostnames'      => null,
			'max_age'        => 0,
			'timeout'        => Verifier::TIMEOUT,
			'visitor_ip'     => null,
			'record_option'  => $prefix . '_record',
			'codes'          => array(),
			'field'          => 'turnstile',
			'script_handle'  => $kebab . '-turnstile-api',
			'module_id'      => $kebab . '-turnstile',
			'module_url'     => null,
			'module_version' => self::VERSION,
			'class'          => $kebab . '-turnstile',
			'styles'         => true,
			'template'       => null,
			'widget'         => array(),
			'settings_url'   => '',
			'capability'     => 'manage_options',
			'notice'         => true,
			'notice_screen'  => null,
			'settings_page'  => '',
			'site_health'    => true,
			'info_filter'    => null,
			'health_test'    => $prefix,
			'privacy'        => true,
			'key_test_token' => $kebab . '-key-test',
			'messages'       => array(),
		);

		$config          = array_merge( $defaults, array_intersect_key( $config, $defaults ) );
		$config['id']    = $id;
		$config['codes'] = array_merge(
			array(
				'incomplete' => $prefix . '_incomplete',
				'failed'     => $prefix . '_failed',
			),
			(array) $config['codes']
		);

		return $config;
	}
}
