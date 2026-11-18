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
 * @since 1.0.0
 */
final class Turnstile {

	/**
	 * The library's version, for its script module.
	 *
	 * @since 1.0.0
	 */
	public const VERSION = '1.0.0';

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

	/* ─── Policy ──────────────────────────────────────────────────── */

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
	 * The error for a check that has not been completed.
	 *
	 * @return WP_Error
	 * @since 1.0.0
	 */
	public function incomplete(): WP_Error {
		return new WP_Error(
			$this->config['codes']['incomplete'],
			$this->message( 'incomplete' ),
			array(
				'status' => 400,
				'field'  => $this->config['field'],
			)
		);
	}

	/**
	 * Check a token.
	 *
	 * True where Turnstile is not in use for the place: there is nothing
	 * to pass. Whether this person has to pass it at all is required(),
	 * which the caller asks first.
	 *
	 * @param string               $token What the widget produced.
	 * @param string               $place The place it was produced for.
	 * @param array<string, mixed> $who   Who sent it, for the hooks. The
	 *                                    address sent to Cloudflare is
	 *                                    `ip` when given, and otherwise
	 *                                    the `visitor_ip` option's.
	 *
	 * @return true|WP_Error
	 * @since 1.0.0
	 */
	public function verify( string $token, string $place, array $who = array() ): true|WP_Error {
		$place = self::place( $place );

		if ( ! $this->enabled( $place ) ) {
			return true;
		}

		$token = trim( $token );

		if ( '' === $token ) {
			return $this->incomplete();
		}

		$key = hash( 'sha256', $place . '|' . $token );

		if ( ! isset( $this->asked[ $key ] ) ) {
			$this->asked[ $key ] = $this->ask( $token, $place, $who );
		}

		return $this->asked[ $key ];
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

	/* ─── Asking ──────────────────────────────────────────────────── */

	/**
	 * Ask Cloudflare, and turn its answer into the plugin's.
	 *
	 * @param string               $token The token.
	 * @param string               $place The place.
	 * @param array<string, mixed> $who   Who sent it.
	 *
	 * @return true|WP_Error
	 * @since 1.0.0
	 */
	private function ask( string $token, string $place, array $who ): true|WP_Error {
		$secret = $this->secret();
		$ip     = (string) ( $who['ip'] ?? '' );

		$verifier = new Verifier( $secret, $this->hostnames(), $place, (int) $this->config['timeout'], (int) $this->config['max_age'] );

		// The address itself, not whatever the plugin stores: it is sent
		// and not kept.
		$answer = $verifier->verify( $token, '' !== $ip ? $ip : $this->visitor_ip(), wp_generate_uuid4() );

		if ( $answer->success ) {
			$this->record()->answered();

			return true;
		}

		$passed = $this->let_through( $answer, $place, $who, $secret );

		/**
		 * Fires when a Cloudflare Turnstile check does not pass.
		 *
		 * For a token Cloudflare refused, and for a check that could not
		 * be made. Not for a form sent with no token at all.
		 *
		 * @param string               $place  The place.
		 * @param string[]             $codes  Cloudflare's error codes, or, when
		 *                                     it gave none, why the answer was
		 *                                     refused: `unreachable`, `http_error`,
		 *                                     `unreadable`, `wrong_hostname`,
		 *                                     `wrong_action`, `expired`,
		 *                                     `token_too_long`.
		 * @param array<string, mixed> $who    Who sent it.
		 * @param bool                 $passed Whether they were let through
		 *                                     all the same, by the fail-open
		 *                                     policy.
		 *
		 * @since 1.0.0
		 */
		do_action( $this->hook( 'failed' ), $place, $answer->summary(), $who, $passed );

		if ( $passed ) {
			return true;
		}

		// Cloudflare answered about the token, so the check itself works.
		if ( ! $answer->misconfigured() && ! $answer->unavailable() ) {
			$this->record()->answered();
		}

		if ( $answer->stale() ) {
			return $this->incomplete();
		}

		return new WP_Error(
			$this->config['codes']['failed'],
			$this->message( 'failed' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Whether a check that could not be made lets the visitor through.
	 *
	 * The problem is written down whichever way it goes, so the owner is
	 * told either way.
	 *
	 * @param Verification         $answer What came back.
	 * @param string               $place  The place.
	 * @param array<string, mixed> $who    Who sent the token.
	 * @param string               $secret The secret key that was used.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function let_through( Verification $answer, string $place, array $who, string $secret ): bool {
		$kind = '';

		if ( $answer->misconfigured() ) {
			$kind = 'misconfigured';
		} elseif ( $answer->unavailable() ) {
			$kind = 'unavailable';
		}

		if ( '' === $kind ) {
			return false;
		}

		$this->record()->problem( $kind, $place, $answer->summary(), $secret );

		/**
		 * Filter whether a visitor is let through when Turnstile cannot be asked.
		 *
		 * The default is the plugin's `fail_open` policy.
		 *
		 * @param bool                 $open  Whether to let them through.
		 * @param string               $place The place.
		 * @param string               $kind  `unavailable` (no answer from
		 *                                    Cloudflare, or a server error
		 *                                    there) or `misconfigured` (the
		 *                                    secret key is missing or not
		 *                                    accepted).
		 * @param array<string, mixed> $who   Who sent the token.
		 *
		 * @since 1.0.0
		 */
		return (bool) apply_filters( $this->hook( 'fail_open' ), $this->fails_open( $kind, $place, $who ), $place, $kind, $who );
	}

	/**
	 * The visitor's address, when the caller gave none.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private function visitor_ip(): string {
		$given = $this->config['visitor_ip'];

		if ( is_callable( $given ) ) {
			return (string) $given();
		}

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		return false === filter_var( $ip, FILTER_VALIDATE_IP ) ? '' : $ip;
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
