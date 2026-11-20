<?php
/**
 * What happened the last time Turnstile was asked.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

use SugarCommerce\Dates\Clock;

use SensitiveParameter;

/**
 * Two moments, kept so the owner can be told: when a check last worked,
 * and when one last could not be made and why.
 *
 * A site that lets visitors through when Cloudflare cannot be reached, or
 * does not accept the secret key, keeps working and would otherwise keep
 * the owner in the dark: a check that silently protects nothing. A site
 * that refuses them instead has every visitor turned away. Either way the
 * failure is written down here, and the admin notice and Site Health
 * read it.
 *
 * One small option that is not autoloaded. A working check is written at
 * most once a minute, because a busy site does not need a database write
 * per form to know that Turnstile is fine -- except straight after a
 * problem, when it is what says the problem is over. A problem is always
 * written. Nothing about a visitor is kept: no address, no token, no
 * email.
 *
 * A problem with the keys carries a fingerprint of the secret it was
 * about, so it stops being reported the moment a different key is saved,
 * without anything having to listen for the save.
 *
 * @since 1.0.0
 */
final readonly class Record {

	/**
	 * A record kept in one option.
	 *
	 * @param string   $option The option's name.
	 * @param int|null $now    A fixed clock, for tests.
	 *
	 * @since 1.0.0
	 */
	public function __construct(
		private string $option,
		private ?int $now = null
	) {
	}

	/**
	 * The option's name.
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function option(): string {
		return $this->option;
	}

	/**
	 * A check was made and Cloudflare answered about the token.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function answered(): void {
		$record = $this->read();
		$open   = isset( $record['problem'] ) && empty( $record['problem']['over'] );

		// Unless there is a problem on record that this ends: that is
		// news, and is what takes the notice down.
		if ( ! $open && $this->now() - (int) ( $record['ok'] ?? 0 ) < MINUTE_IN_SECONDS ) {
			return;
		}

		$record['ok'] = $this->now();

		// Kept, as the last time it happened, and marked as over. Said
		// outright and not worked out from the two times, which are
		// often the same second.
		if ( $open ) {
			$record['problem']['over'] = true;
		}

		update_option( $this->option, $record, false );
	}

	/**
	 * A check could not be made.
	 *
	 * @param string   $kind   `misconfigured` (the keys) or `unavailable` (Cloudflare).
	 * @param string   $place  Where it was asked for.
	 * @param string[] $codes  Cloudflare's codes, or the verifier's reason.
	 * @param string   $secret The secret key it was asked with. Only a
	 *                         fingerprint of it is kept.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function problem( string $kind, string $place, array $codes, #[SensitiveParameter] string $secret ): void {
		$record = $this->read();

		$record['problem'] = array(
			'time'  => $this->now(),
			'kind'  => $kind,
			'place' => Turnstile::place( $place ),
			'codes' => array_slice( array_map( 'sanitize_key', $codes ), 0, 5 ),
			'key'   => self::fingerprint( $secret ),
		);

		update_option( $this->option, $record, false );
	}

	/**
	 * When a check last worked, as a Unix time. Nought for never.
	 *
	 * @return int
	 * @since 1.0.0
	 */
	public function last_answered(): int {
		return (int) ( $this->read()['ok'] ?? 0 );
	}

	/**
	 * The last problem, when there has been one.
	 *
	 * @return array{time: int, kind: string, place: string, codes: string[], key: string, over: bool}|null
	 * @since 1.0.0
	 */
	public function last_problem(): ?array {
		$problem = $this->read()['problem'] ?? null;

		if ( ! is_array( $problem ) || empty( $problem['time'] ) ) {
			return null;
		}

		return array(
			'time'  => (int) $problem['time'],
			'kind'  => (string) ( $problem['kind'] ?? '' ),
			'place' => (string) ( $problem['place'] ?? '' ),
			'codes' => array_map( 'strval', (array) ( $problem['codes'] ?? array() ) ),
			'key'   => (string) ( $problem['key'] ?? '' ),
			'over'  => ! empty( $problem['over'] ),
		);
	}

	/**
	 * Whether the secret key now saved is one Cloudflare has refused.
	 *
	 * True from the first refusal until a check works or another key is
	 * saved. This is what the notice and the Site Health warning ask.
	 *
	 * @param string $secret The secret key now saved.
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	public function secret_refused( #[SensitiveParameter] string $secret ): bool {
		$problem = $this->last_problem();

		return null !== $problem
			&& 'misconfigured' === $problem['kind']
			&& '' !== $secret
			&& hash_equals( $problem['key'], self::fingerprint( $secret ) )
			&& ! $problem['over'];
	}

	/**
	 * Forget everything. An uninstaller, and tests.
	 *
	 * @return void
	 * @since 1.0.0
	 */
	public function forget(): void {
		delete_option( $this->option );
	}

	/**
	 * The option, as an array.
	 *
	 * @return array<string, mixed>
	 * @since 1.0.0
	 */
	private function read(): array {
		$record = get_option( $this->option, array() );

		return is_array( $record ) ? $record : array();
	}

	/**
	 * Now.
	 *
	 * @return int
	 * @since 1.0.0
	 */
	private function now(): int {
		return $this->now ?? Clock::time();
	}

	/**
	 * A secret key, as something that can be compared and not read back.
	 *
	 * @param string $secret A secret key.
	 *
	 * @return string Twelve characters of a keyed hash.
	 * @since 1.0.0
	 */
	private static function fingerprint( #[SensitiveParameter] string $secret ): string {
		// Core's wp_hash() with sha256 is hash_hmac( 'sha256', $secret,
		// wp_salt( 'auth' ) ): the same twelve characters as before.
		return substr( wp_hash( $secret, 'auth', 'sha256' ), 0, 12 );
	}
}
