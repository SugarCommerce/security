<?php
/**
 * Why a Turnstile token was not accepted.
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Turnstile;

/**
 * Every refusal has exactly one.
 *
 * Most are the verifier's own: it never got as far as asking, Cloudflare
 * could not be asked, the answer could not be read, or Cloudflare said
 * yes to a token that was not for this site, this form or this moment.
 * Rejected is the one where Cloudflare itself said no, and its error
 * codes say why.
 *
 * The values are what is written to a log, and what the `_failed` action
 * passes when Cloudflare gave no code, so they never change.
 *
 * @since 1.0.0
 */
enum Reason: string {

	/**
	 * There is no secret key, so nothing can be verified.
	 */
	case NoSecret = 'no_secret';

	/**
	 * The form came back without a token.
	 */
	case NoToken = 'no_token';

	/**
	 * The token is longer than Cloudflare ever issues.
	 */
	case TokenTooLong = 'token_too_long';

	/**
	 * Cloudflare could not be reached, or did not answer in time.
	 */
	case Unreachable = 'unreachable';

	/**
	 * Cloudflare answered with something other than 200.
	 */
	case HttpError = 'http_error';

	/**
	 * Cloudflare's answer was not the JSON siteverify sends.
	 */
	case Unreadable = 'unreadable';

	/**
	 * Cloudflare said no; see the error codes.
	 */
	case Rejected = 'rejected';

	/**
	 * Cloudflare said yes, for a token issued on another hostname.
	 */
	case WrongHostname = 'wrong_hostname';

	/**
	 * Cloudflare said yes, for a token issued to another form's action.
	 */
	case WrongAction = 'wrong_action';

	/**
	 * Cloudflare said yes, for a challenge solved longer ago than allowed.
	 */
	case Expired = 'expired';
}
