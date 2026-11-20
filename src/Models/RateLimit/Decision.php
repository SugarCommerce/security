<?php
/**
 * What a rate-limit check came to.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Models\RateLimit;

/**
 * Allowed or not, how much is left, and when the window starts again.
 *
 * Fixed windows tell a client exactly when to come back, and that is what
 * the headers say: the moment the current window ends.
 *
 * @since 1.0.0
 */
final readonly class Decision {

	/**
	 * `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`,
	 * the reset as a Unix time. The form most clients already read.
	 *
	 * @since 1.0.0
	 */
	public const string LEGACY = 'legacy';

	/**
	 * `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (seconds
	 * until the window ends) and `RateLimit-Policy`, after the IETF
	 * httpapi draft "RateLimit header fields for HTTP".
	 *
	 * @since 1.0.0
	 */
	public const string STANDARD = 'standard';

	/**
	 * A decision.
	 *
	 * @param bool $allowed    Whether the attempt may go ahead.
	 * @param int  $limit      Attempts allowed in one window.
	 * @param int  $count      Attempts counted in this window, this one
	 *                         included when it was counted.
	 * @param int  $remaining  Attempts left in this window. Never below 0.
	 * @param int  $reset      Unix time the window ends.
	 * @param int  $window     The window's length, in seconds.
	 * @param int  $checked_at Unix time the decision was made.
	 * @param bool $limited    Whether a limit applied at all. False only
	 *                         for {@see self::unlimited()}.
	 * @param bool $failed     Whether the store could not count, so
	 *                         `$allowed` is the failure policy's answer
	 *                         and not the count's.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		public bool $allowed,
		public int $limit,
		public int $count,
		public int $remaining,
		public int $reset,
		public int $window,
		public int $checked_at,
		public bool $limited = true,
		public bool $failed = false
	) {
	}

	/**
	 * The answer when nothing limits the attempt.
	 *
	 * A limit of nought (switched off), or nothing to count against.
	 * Allowed, and with no headers: `X-RateLimit-Limit: 0` would tell a
	 * client it may make no requests at all, the opposite of the truth.
	 *
	 * @return self
	 * @since 1.0.0
	 */
	public static function unlimited(): self {
		return new self( true, 0, 0, 0, 0, 0, 0, false );
	}

	/**
	 * The decision worth reporting, of several made for one request.
	 *
	 * A request counted against more than one limit -- every request, and
	 * the ones that move money a second time against a much smaller limit
	 * -- sends one set of headers. A refusal wins, since it is what the
	 * client has to act on (of two, the one that ends later: that is how
	 * long the client really has to wait). Otherwise the limit with the
	 * least left, which is the one the client will run into first.
	 *
	 * @param Decision ...$decisions The decisions.
	 *
	 * @return self Unlimited when none of them was limited.
	 * @since 1.0.0
	 */
	public static function tightest( Decision ...$decisions ): self {
		$tightest = null;

		foreach ( $decisions as $decision ) {
			if ( ! $decision->limited ) {
				continue;
			}

			if ( null === $tightest || self::tighter( $decision, $tightest ) ) {
				$tightest = $decision;
			}
		}

		return $tightest ?? self::unlimited();
	}

	/**
	 * Whether the attempt was refused.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function denied(): bool {
		return ! $this->allowed;
	}

	/**
	 * Seconds until the window ends. At least one, while a limit applies.
	 *
	 * @return int 0 for an unlimited decision.
	 * @since 1.0.0
	 */
	public function retry_after(): int {
		return $this->limited ? max( 1, $this->reset - $this->checked_at ) : 0;
	}

	/**
	 * The response headers this decision asks for.
	 *
	 * `Retry-After` goes with a refusal, which is where RFC 9110 gives it a
	 * meaning. `$when_spent` sends it as well on an allowed response that
	 * has used the last of the allowance, telling the client before its
	 * next request is refused.
	 *
	 * @param string $format     self::LEGACY or self::STANDARD.
	 * @param bool   $when_spent Send Retry-After when nothing remains, too.
	 *
	 * @return array<string, string> Header name => value. Empty when
	 *                               unlimited.
	 * @since 1.0.0
	 */
	public function headers( string $format = self::LEGACY, bool $when_spent = false ): array {
		if ( ! $this->limited ) {
			return array();
		}

		if ( self::STANDARD === $format ) {
			$headers = array(
				'RateLimit-Limit'     => (string) $this->limit,
				'RateLimit-Remaining' => (string) $this->remaining,
				'RateLimit-Reset'     => (string) $this->retry_after(),
				'RateLimit-Policy'    => $this->limit . ';w=' . $this->window,
			);
		} else {
			$headers = array(
				'X-RateLimit-Limit'     => (string) $this->limit,
				'X-RateLimit-Remaining' => (string) $this->remaining,
				'X-RateLimit-Reset'     => (string) $this->reset,
			);
		}

		if ( $this->denied() || ( $when_spent && 0 === $this->remaining ) ) {
			$headers['Retry-After'] = (string) $this->retry_after();
		}

		return $headers;
	}

	/**
	 * Whether one decision is more worth reporting than another.
	 *
	 * @param Decision $one   A decision.
	 * @param Decision $other The one to beat.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private static function tighter( Decision $one, Decision $other ): bool {
		if ( $one->denied() !== $other->denied() ) {
			return $one->denied();
		}

		if ( $one->denied() ) {
			return $one->reset > $other->reset;
		}

		return $one->remaining < $other->remaining;
	}
}
