<?php
/**
 * A $wpdb that understands the table store's statements.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests\RateLimit\Support;

use RuntimeException;

/**
 * Rows held in an array, keyed by table and bucket, with MySQL's meaning
 * for each statement the store sends. Anything else throws, so a statement
 * that changes shape fails a test instead of quietly doing nothing.
 */
final class FakeWpdb {

	/**
	 * Rows: table => bucket => row.
	 *
	 * @var array<string, array<string, array{hits: int, date_expires: string|null, date_created: string, date_modified: string}>>
	 */
	public array $rows = array();

	/**
	 * Every statement run, prepared.
	 *
	 * @var string[]
	 */
	public array $log = array();

	/**
	 * The table prefix.
	 *
	 * @var string
	 */
	public string $prefix = 'wp_';

	/**
	 * Fill placeholders the way wpdb::prepare() does, near enough.
	 *
	 * @param string $query The query.
	 * @param mixed  ...$args Values.
	 *
	 * @return string
	 */
	public function prepare( string $query, ...$args ): string {
		return (string) preg_replace_callback(
			'/%([isd])/',
			static function ( array $match ) use ( &$args ): string {
				$value = array_shift( $args );

				return match ( $match[1] ) {
					'i'     => '`' . str_replace( '`', '``', (string) $value ) . '`',
					'd'     => (string) (int) $value,
					default => "'" . addslashes( (string) $value ) . "'",
				};
			},
			$query
		);
	}

	/**
	 * Run a statement.
	 *
	 * @param string $sql The statement.
	 *
	 * @return int|false Rows affected.
	 */
	public function query( string $sql ) {
		$this->log[] = $sql;
		$flat        = (string) preg_replace( '/\s+/', ' ', trim( $sql ) );

		if ( preg_match( "/^INSERT INTO `([^`]+)` \( bucket, hits, date_expires, date_created, date_modified \) VALUES \( '([^']*)', 1, '([^']*)', '([^']*)', '([^']*)' \) ON DUPLICATE KEY UPDATE hits = hits \+ 1, date_modified = VALUES\( date_modified \)$/", $flat, $m ) ) {
			[ , $table, $bucket, $expires, $created, $modified ] = $m;

			if ( isset( $this->rows[ $table ][ $bucket ] ) ) {
				++$this->rows[ $table ][ $bucket ]['hits'];
				$this->rows[ $table ][ $bucket ]['date_modified'] = $modified;

				return 2;
			}

			$this->rows[ $table ][ $bucket ] = array(
				'hits'          => 1,
				'date_expires'  => $expires,
				'date_created'  => $created,
				'date_modified' => $modified,
			);

			return 1;
		}

		if ( preg_match( '/^DELETE FROM `([^`]+)`(?: WHERE (.+))?$/', $flat, $m ) ) {
			$table   = $m[1];
			$where   = $m[2] ?? '';
			$removed = 0;

			foreach ( $this->rows[ $table ] ?? array() as $bucket => $row ) {
				if ( $this->matches( $row, $where ) ) {
					unset( $this->rows[ $table ][ $bucket ] );
					++$removed;
				}
			}

			return $removed;
		}

		throw new RuntimeException( 'FakeWpdb does not understand: ' . $flat );
	}

	/**
	 * Read one value.
	 *
	 * @param string $sql The statement.
	 *
	 * @return string|null
	 */
	public function get_var( string $sql ): ?string {
		$this->log[] = $sql;
		$flat        = (string) preg_replace( '/\s+/', ' ', trim( $sql ) );

		if ( preg_match( "/^SELECT hits FROM `([^`]+)` WHERE bucket = '([^']*)'$/", $flat, $m ) ) {
			return isset( $this->rows[ $m[1] ][ $m[2] ] ) ? (string) $this->rows[ $m[1] ][ $m[2] ]['hits'] : null;
		}

		throw new RuntimeException( 'FakeWpdb does not understand: ' . $flat );
	}

	/**
	 * Delete by column values.
	 *
	 * @param string               $table The table.
	 * @param array<string, mixed> $where Column => value. Only `bucket`.
	 *
	 * @return int
	 */
	public function delete( string $table, array $where ): int {
		$bucket = (string) ( $where['bucket'] ?? '' );

		if ( ! isset( $this->rows[ $table ][ $bucket ] ) ) {
			return 0;
		}

		unset( $this->rows[ $table ][ $bucket ] );

		return 1;
	}

	/**
	 * Whether a row matches a WHERE of ANDed date_expires conditions.
	 *
	 * @param array<string, mixed> $row   The row.
	 * @param string               $where The clause, '' for every row.
	 *
	 * @return bool
	 */
	private function matches( array $row, string $where ): bool {
		if ( '' === $where ) {
			return true;
		}

		foreach ( preg_split( '/ AND /', $where ) as $condition ) {
			if ( 'date_expires IS NOT NULL' === $condition ) {
				if ( null === $row['date_expires'] ) {
					return false;
				}
			} elseif ( preg_match( "/^date_expires < '([^']*)'$/", $condition, $m ) ) {
				if ( null === $row['date_expires'] || strcmp( $row['date_expires'], $m[1] ) >= 0 ) {
					return false;
				}
			} else {
				throw new RuntimeException( 'FakeWpdb does not understand the condition: ' . $condition );
			}
		}

		return true;
	}
}
