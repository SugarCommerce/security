<?php
/**
 * Country lists for fraud and compliance rules.
 *
 * Read by CountryRisk, once a request. Policy, not geography: tuned per
 * business, and point-in-time.
 *
 * @package   SugarCommerce\Security
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

return [

	/*
	 * Territories with elevated payment-fraud rates.
	 *
	 * A signal to weigh, never a reason to block on its own -- plenty of
	 * genuine customers live in every one of them. Not exhaustive, and worth
	 * tuning per business.
	 */
	'high_risk'  => [
		'BY',
		'BD',
		'BR',
		'CN',
		'CO',
		'EG',
		'GH',
		'ID',
		'IN',
		'MX',
		'MY',
		'NG',
		'PH',
		'PK',
		'RO',
		'RU',
		'TH',
		'UA',
		'VE',
		'VN',
	],

	/*
	 * Territories under comprehensive sanctions (US Treasury OFAC).
	 *
	 * Indicative only. Sanctions change without notice and vary by
	 * jurisdiction; a business relying on this for compliance verifies it
	 * against its own legal advice rather than a list in a library. A coarse
	 * first gate for "should this checkout go ahead at all", not a screening
	 * product: it knows nothing of names, sectors or entities.
	 */
	'sanctioned' => [
		'CU',
		'IR',
		'KP',
		'RU',
		'SY',
		'VE',
	],
];
