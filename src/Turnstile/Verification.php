<?php
/**
 * What came of checking one Turnstile token.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

use DateTimeImmutable;
use SugarCommerce\Dates\Clock;
use Exception;

/**
 * The answer to "is this token good?", and when it is not, whose fault.
 *
 * A refusal is one of three kinds, and what a site does about each is
 * different, so the answer says which:
 *
 *  - **The token.** Made up, spent, or too old. Whoever sent it is shown
 *    the check again. stale() picks out the kind an honest form can
 *    produce: a token that sat too long or was sent twice.
 *  - **The configuration.** misconfigured(): no secret key, or one
 *    Cloudflare does not accept. Every visitor would fail until somebody
 *    fixes it, so it is the owner who needs telling, not the visitor.
 *  - **Cloudflare.** unavailable(): no answer, a server error, an answer
 *    that is not one. Nothing was learnt about the visitor either way.
 *
 * This says what happened. Whether a visitor is let through when
 * Cloudflare is down is the site's policy (see Turnstile's `fail_open`),
 * and not this class's.
 *
 * @since 1.0.0
 */
final class Verification {

	/**
	 * An answer.
	 *
	 * @param bool                   $success       Whether the token is good.
	 * @param Reason|null            $reason        Why not. Null when it is.
	 * @param string[]               $codes         Cloudflare's `error-codes`.
	 * @param string                 $hostname      The hostname the challenge was served on.
	 * @param string                 $action        The widget's `data-action`.
	 * @param DateTimeImmutable|null $challenged_at When the challenge was solved (`challenge_ts`).
	 *
	 * @since 1.0.0
	 */
	private function __construct(
		public readonly bool $success,
		public readonly ?Reason $reason = null,
		public readonly array $codes = array(),
		public readonly string $hostname = '',
		public readonly string $action = '',
		public readonly ?DateTimeImmutable $challenged_at = null
	) {
	}

	/**
	 * A refusal Cloudflare was never asked about, or did not answer.
	 *
	 * @param Reason $reason Why.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public static function unanswered( Reason $reason ): self {
		return new self( false, $reason );
	}

	/**
	 * From the JSON siteverify answers with.
	 *
	 * `success`, `error-codes`, `hostname`, `action` and `challenge_ts` are
	 * the fields Cloudflare documents; anything of the wrong type is read
	 * as absent.
	 *
	 * @param array<string, mixed> $body The decoded answer.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public static function from_siteverify( array $body ): self {
		$success = true === ( $body['success'] ?? null );
		$codes   = is_array( $body['error-codes'] ?? null ) ? $body['error-codes'] : array();

		return new self(
			$success,
			$success ? null : Reason::Rejected,
			array_values( array_filter( $codes, 'is_string' ) ),
			is_string( $body['hostname'] ?? null ) ? $body['hostname'] : '',
			is_string( $body['action'] ?? null ) ? $body['action'] : '',
			self::moment( is_string( $body['challenge_ts'] ?? null ) ? $body['challenge_ts'] : '' )
		);
	}

	/**
	 * This answer, refused for a reason of the verifier's own.
	 *
	 * @param Reason $reason Why.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public function refused( Reason $reason ): self {
		return new self( false, $reason, $this->codes, $this->hostname, $this->action, $this->challenged_at );
	}

	/**
	 * Whether the site's own keys are what is wrong.
	 *
	 * No secret key, or a code Cloudflare gives about the secret or the
	 * widget ({@see ErrorCode::misconfigured()}). The last two of those are
	 * from an earlier version of Cloudflare's page; counting them costs
	 * nothing and a site is never locked because of one.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function misconfigured(): bool {
		if ( Reason::NoSecret === $this->reason ) {
			return true;
		}

		foreach ( $this->errors() as $error ) {
			if ( $error->misconfigured() ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Cloudflare's error codes, named.
	 *
	 * @return ErrorCode[] A code this library does not know is ErrorCode::Unknown.
	 * @since 1.0.0
	 */
	public function errors(): array {
		return array_map( array( ErrorCode::class, 'from_cloudflare' ), $this->codes );
	}

	/**
	 * Whether Cloudflare gave an error code.
	 *
	 * @param ErrorCode $code The code.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function has( ErrorCode $code ): bool {
		return in_array( $code, $this->errors(), true );
	}

	/**
	 * Whether Cloudflare could not be asked, or could not answer.
	 *
	 * `internal-error` is Cloudflare saying so itself ("An internal error
	 * occurred"). `bad-request` is not counted: if a token could be
	 * written to make Cloudflare call the request malformed, counting it
	 * would be a way round the check.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function unavailable(): bool {
		return in_array( $this->reason, array( Reason::Unreachable, Reason::HttpError, Reason::Unreadable ), true )
			|| $this->has( ErrorCode::InternalError );
	}

	/**
	 * Whether the token was real once and is now spent or too old.
	 *
	 * `timeout-or-duplicate`: "The token has expired or was already
	 * validated". What a form left open over lunch sends, and what
	 * pressing the button twice sends. A token older than the verifier's
	 * own limit (Reason::Expired) is the same thing, sooner.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function stale(): bool {
		return Reason::Expired === $this->reason || $this->has( ErrorCode::TimeoutOrDuplicate );
	}

	/**
	 * Seconds since the challenge was solved.
	 *
	 * @param int|null $now Unix time to measure against. Null reads the clock.
	 *
	 * @return int|null Null when Cloudflare did not say. Never negative: a
	 *                  timestamp a little ahead of this server's clock is
	 *                  nought seconds old.
	 * @since 1.0.0
	 */
	public function age( ?int $now = null ): ?int {
		return null === $this->challenged_at ? null : max( 0, ( $now ?? Clock::time() ) - $this->challenged_at->getTimestamp() );
	}

	/**
	 * What to write down: Cloudflare's codes, or the reason when it gave none.
	 *
	 * @return string[]
	 * @since 1.0.0
	 */
	public function summary(): array {
		if ( array() !== $this->codes ) {
			return $this->codes;
		}

		return null === $this->reason ? array() : array( $this->reason->value );
	}

	/**
	 * An ISO 8601 timestamp, such as `2026-10-22T15:14:30.096Z`.
	 *
	 * Only that shape: the date parser would otherwise take "now" or
	 * "+1 year" as a time, and an age check would believe it.
	 *
	 * @param string $value The timestamp.
	 *
	 * @return DateTimeImmutable|null Null when it is not one.
	 * @since 1.0.0
	 */
	private static function moment( string $value ): ?DateTimeImmutable {
		if ( 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/D', $value ) ) {
			return null;
		}

		try {
			return new DateTimeImmutable( $value );
		} catch ( Exception ) {
			return null;
		}
	}
}
