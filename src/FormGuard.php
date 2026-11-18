<?php
/**
 * Bot resistance for a public form, without a captcha.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

use SugarCommerce\Dates\Clock;
use SugarCommerce\Security\Tokens\Signer;
use SugarCommerce\Security\Tokens\Token;

/**
 * Class FormGuard
 *
 * For the form anybody can submit — a contact form, an abuse report — where
 * a third-party captcha would send every visitor's address to somebody
 * else, and lock out the people a screen reader or a strict browser leaves
 * unable to solve one. Two cheap checks catch most of what a captcha does:
 *
 * - **A trap.** A field people never see, hidden from screen readers too,
 *   which form-filling bots complete because it is there.
 * - **A signed stamp of when the form was drawn.** A submission seconds
 *   after the page loaded is a script, not somebody typing; one a day later
 *   is a replayed page. The stamp is signed, so it cannot be backdated, and
 *   namespaced per form, so a stamp from one form is no use on another.
 *
 * Neither is a rate limit, and neither stops a person. Put the form behind
 * one as well.
 *
 * The stamp is a signed token rather than a bare HMAC: the signature is
 * checked before anything is read from it, and what is signed is
 * namespaced.
 *
 * @since 1.0.0
 */
final readonly class FormGuard {

	/**
	 * Field that carries the stamp.
	 */
	public const string STAMP = '_started';

	/**
	 * Field people never see.
	 */
	public const string TRAP = 'website';

	/**
	 * Seconds a person needs, at least, between opening a form and sending it.
	 */
	public const int MIN = 3;

	/**
	 * Seconds after which a drawn form is stale.
	 */
	public const int MAX = 86400;

	/**
	 * @since 1.0.0
	 *
	 * @param Signer      $signer Signs the stamp. `Signer::site( 'forms' )`
	 *                            needs no secret of your own.
	 * @param string      $form   Which form: letters, digits, `-`, `_`, `.`.
	 *                            A stamp drawn for one form fails on another.
	 * @param int         $min    Seconds a person needs at least.
	 * @param int         $max    Seconds after which the form is stale.
	 * @param int|null    $now    Fixed clock, for tests. Null reads the clock.
	 */
	public function __construct(
		private Signer $signer,
		private string $form,
		private int $min = self::MIN,
		private int $max = self::MAX,
		private ?int $now = null,
	) {}

	/**
	 * A stamp for a form being drawn now. Put it in a hidden field.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function stamp(): string {
		return $this->signer->sign( $this->ns(), array( 't' => $this->now() ), max( 1, $this->max ) );
	}

	/**
	 * Whether a stamp is ours, for this form, and old enough that a person
	 * could have filled it in — but not so old the page was replayed.
	 *
	 * @since 1.0.0
	 *
	 * @param string $stamp The submitted stamp.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the form was sent too fast, too late, or not drawn by us.' )]
	public function human( string $stamp ): bool {
		$token = '' === $stamp ? null : $this->signer->inspect( $this->ns(), $stamp );

		if ( ! $token instanceof Token || ! $token->has( 't' ) ) {
			return false;
		}

		$age = $this->now() - $token->int( 't' );

		return $age >= $this->min && $age < $this->max;
	}

	/**
	 * Whether the trap was filled in.
	 *
	 * Answer a trapped submission as if it worked: a bot told it failed
	 * learns which field gave it away.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value The trap field's value.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'True means a bot sent this.' )]
	public static function trapped( string $value ): bool {
		return '' !== trim( $value );
	}

	/**
	 * The namespace this form's stamps are signed under.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	private function ns(): string {
		return 'form-guard.' . $this->form;
	}

	/**
	 * The time.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	private function now(): int {
		return $this->now ?? Clock::time();
	}
}
