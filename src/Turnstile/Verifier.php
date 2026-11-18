<?php
/**
 * Cloudflare Turnstile, checked on the server.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

use SensitiveParameter;

/**
 * Asks Cloudflare whether a token is real, and checks what it leaves to us.
 *
 * The widget on the page proves nothing by itself: it hands the browser a
 * token, and only Cloudflare's siteverify endpoint can say whether that
 * token is real, unspent and recent
 * (developers.cloudflare.com/turnstile/get-started/server-side-validation).
 * This asks, through WordPress's HTTP API, and then checks the things
 * siteverify reports and does not enforce:
 *
 *  - **A token is for one site.** Cloudflare accepts a good token from
 *    any page that carries the site key. Given hostnames, a token minted
 *    anywhere else is refused.
 *  - **A token is for one form.** Given an action, a token solved on one
 *    form cannot be sent to another. Checked when Cloudflare returns an
 *    action, which it does for a widget that was given one.
 *  - **A token is for a moment**, when asked (within()). Cloudflare
 *    honours one for five minutes; a form that wants less says so.
 *
 * None of them is checked for one of Cloudflare's published test
 * secrets, whose answer "always returns example.com as the hostname" and
 * "doesn't include action"
 * (developers.cloudflare.com/turnstile/troubleshooting/testing).
 *
 * Nothing is remembered: a token is single use ("Tokens are intended for
 * single use"), so an answer is good for the one request that asked.
 *
 * Knows nothing about a site, a setting or a place, and always refuses
 * when Cloudflare cannot be reached. Whether a visitor is let through then
 * is policy, and lives in Turnstile.
 *
 * @since 1.0.0
 */
final class Verifier {

	/**
	 * Cloudflare's siteverify endpoint.
	 *
	 * @since 1.0.0
	 */
	public const ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

	/**
	 * The form field Cloudflare's own widget puts its token in.
	 *
	 * For a form drawn with Cloudflare's implicit rendering. The library's
	 * widget hands the token to the form's script instead.
	 *
	 * @since 1.0.0
	 */
	public const FIELD = 'cf-turnstile-response';

	/**
	 * The most of an answer that is read, in bytes.
	 *
	 * A siteverify answer is a few hundred bytes. Anything that runs past
	 * this is not one, and is refused rather than read into memory.
	 *
	 * @since 1.0.0
	 */
	public const MAX_ANSWER = 65536;

	/**
	 * The longest token Cloudflare issues: "Maximum token length: 2048 characters".
	 *
	 * @since 1.0.0
	 */
	public const MAX_TOKEN = 2048;

	/**
	 * Seconds to wait for Cloudflare. Short, because somebody is waiting.
	 *
	 * @since 1.0.0
	 */
	public const TIMEOUT = 5;

	/**
	 * Lower-cased hostnames a token may come from. Empty for any.
	 *
	 * @var string[]
	 */
	private array $hostnames;

	/**
	 * A verifier for one widget.
	 *
	 * @param string   $secret    The widget's secret key.
	 * @param string[] $hostnames Hostnames a token may come from. Empty for any.
	 * @param string   $action    The action a token must carry when it carries one. '' for any.
	 * @param int      $timeout   Seconds to wait for Cloudflare. At least one.
	 * @param int      $max_age   Seconds since the challenge was solved. 0 for
	 *                            Cloudflare's own five minutes.
	 * @param int|null $now       A fixed clock, for tests.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		#[SensitiveParameter] private string $secret,
		array $hostnames = array(),
		private string $action = '',
		private int $timeout = self::TIMEOUT,
		private int $max_age = 0,
		private ?int $now = null
	) {
		$this->hostnames = self::hostnames( $hostnames );
	}

	/**
	 * Keep the secret out of var_dump() and print_r().
	 *
	 * The attribute above keeps it out of a stack trace; a dumped object,
	 * pasted into a log or a support ticket, would print it anyway.
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	public function __debugInfo(): array {
		return array(
			'secret'    => '' === $this->secret ? '' : '[redacted]',
			'hostnames' => $this->hostnames,
			'action'    => $this->action,
			'timeout'   => $this->timeout,
			'max_age'   => $this->max_age,
		);
	}

	/**
	 * This verifier, accepting tokens only from these hostnames.
	 *
	 * Compared without regard to case; no wildcards, so name each one.
	 *
	 * @param string ...$hostnames Hostnames, such as `shop.example.com`.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public function for_hostnames( string ...$hostnames ): self {
		$copy            = clone $this;
		$copy->hostnames = self::hostnames( $hostnames );

		return $copy;
	}

	/**
	 * This verifier, accepting tokens only from a widget with this action.
	 *
	 * @param string $action The action, exactly as the widget has it.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public function for_action( string $action ): self {
		$copy         = clone $this;
		$copy->action = $action;

		return $copy;
	}

	/**
	 * This verifier, refusing a challenge solved more than so long ago.
	 *
	 * @param int $seconds Seconds. 0 for no limit of our own.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public function within( int $seconds ): self {
		$copy          = clone $this;
		$copy->max_age = max( 0, $seconds );

		return $copy;
	}

	/**
	 * Whether a secret key is set.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function configured(): bool {
		return '' !== $this->secret;
	}

	/**
	 * Ask Cloudflare about a token.
	 *
	 * A form-encoded POST of `secret` and `response`, with `remoteip` when
	 * the address is one and `idempotency_key` when one is given -- the
	 * four parameters siteverify takes. No token and a token longer than
	 * Cloudflare issues are refused here, without a request.
	 *
	 * @param string $token           What the widget produced.
	 * @param string $ip              The visitor's address, or ''.
	 * @param string $idempotency_key A UUID that makes the request safe
	 *                                to repeat, or ''.
	 *
	 * @return Verification
	 * @since 1.0.0
	 */
	public function verify( #[SensitiveParameter] string $token, string $ip = '', string $idempotency_key = '' ): Verification {
		if ( '' === $this->secret ) {
			return Verification::unanswered( Reason::NoSecret );
		}

		if ( '' === $token ) {
			return Verification::unanswered( Reason::NoToken );
		}

		if ( strlen( $token ) > self::MAX_TOKEN ) {
			return Verification::unanswered( Reason::TokenTooLong );
		}

		$response = wp_remote_post(
			self::ENDPOINT,
			array(
				'timeout'             => max( 1, $this->timeout ),
				'redirection'         => 0,
				'limit_response_size' => self::MAX_ANSWER,
				'headers'             => array( 'Accept' => 'application/json' ),
				'body'                => array_filter(
					array(
						'secret'          => $this->secret,
						'response'        => $token,
						'remoteip'        => false === filter_var( $ip, FILTER_VALIDATE_IP ) ? '' : $ip,
						'idempotency_key' => $idempotency_key,
					),
					static fn( string $value ): bool => '' !== $value
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return Verification::unanswered( Reason::Unreachable );
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			// Whatever error codes came with it are kept, for the log.
			return is_array( $body )
				? Verification::from_siteverify( $body )->refused( Reason::HttpError )
				: Verification::unanswered( Reason::HttpError );
		}

		if ( ! is_array( $body ) || ! is_bool( $body['success'] ?? null ) ) {
			return Verification::unanswered( Reason::Unreadable );
		}

		return $this->hold( Verification::from_siteverify( $body ) );
	}

	/**
	 * Whether a token passes. verify(), for when the reason does not matter.
	 *
	 * @param string $token What the widget produced.
	 * @param string $ip    The visitor's address, or ''.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	#[\NoDiscard( 'False means the token was refused.' )]
	public function passes( #[SensitiveParameter] string $token, string $ip = '' ): bool {
		return $this->verify( $token, $ip )->success;
	}

	/**
	 * Whether a secret is one of Cloudflare's test secrets.
	 *
	 * `1x` always passes, `2x` always fails, `3x` always answers "already
	 * spent". By default only the published shape counts: a digit, an x, a
	 * run of noughts and `AA`. `$any_prefix` counts any secret starting
	 * `1x`, `2x` or `3x`, for a check that would rather refuse a test key
	 * Cloudflare reshapes later than let it through: no real secret starts
	 * that way.
	 *
	 * @param string $secret     A secret key.
	 * @param bool   $any_prefix Count every `1x`/`2x`/`3x` secret.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public static function is_test_secret( #[SensitiveParameter] string $secret, bool $any_prefix = false ): bool {
		return 1 === preg_match( $any_prefix ? '/^[123]x/' : '/^[123]x0{20,}AA$/D', $secret );
	}

	/**
	 * Refuse an accepted token that is not for this site, form or moment.
	 *
	 * @param Verification $answer What Cloudflare said.
	 *
	 * @return Verification
	 * @since 1.0.0
	 */
	private function hold( Verification $answer ): Verification {
		if ( ! $answer->success || self::is_test_secret( $this->secret ) ) {
			return $answer;
		}

		// Each only when Cloudflare said which: an answer without a
		// hostname or an action has nothing to compare.
		if ( array() !== $this->hostnames && '' !== $answer->hostname && ! in_array( strtolower( $answer->hostname ), $this->hostnames, true ) ) {
			return $answer->refused( Reason::WrongHostname );
		}

		if ( '' !== $this->action && '' !== $answer->action && $answer->action !== $this->action ) {
			return $answer->refused( Reason::WrongAction );
		}

		// An age limit was asked for, so an answer that does not say when
		// the challenge was solved cannot be shown to be within it.
		if ( $this->max_age > 0 && ( $answer->age( $this->now ) ?? PHP_INT_MAX ) > $this->max_age ) {
			return $answer->refused( Reason::Expired );
		}

		return $answer;
	}

	/**
	 * Hostnames, lower-cased, without blanks or repeats.
	 *
	 * @param array<mixed> $hostnames As given.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	private static function hostnames( array $hostnames ): array {
		return array_values(
			array_unique(
				array_filter(
					array_map( static fn( $host ): string => strtolower( trim( (string) $host ) ), $hostnames ),
					static fn( string $host ): bool => '' !== $host
				)
			)
		);
	}
}
