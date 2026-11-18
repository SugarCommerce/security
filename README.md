# Security

Signed links that expire, secrets kept encrypted, licence and API keys, rate
limits that hold under a burst, Cloudflare Turnstile on forms, and two-factor
codes — for a WordPress plugin.

## What it does

A shop or a membership plugin needs the same handful of security pieces every
time: a download link that stops working after an hour, a Stripe key that is
not sitting in `wp_options` in plain text, a licence key a customer can read
down the phone, a sign-in form that refuses the twentieth try in a second, a
check that a person and not a script sent the form, and a code from an
authenticator app.

Each is easy to write and easy to get subtly wrong. This is all of them done
once, keyed from the site's own salts so nothing has to be configured, and
read against one clock a test can stop.

## Features

* Email a link that expires and cannot be edited or used for another purpose — with no database row
* Keep an API key encrypted in the database, overridable from `wp-config.php` or the environment
* Issue licence keys, discount codes and API keys, and check one back however it was typed
* Limit attempts per caller atomically — even twenty requests at once count as twenty
* Put Cloudflare Turnstile on a form, and tell the owner when it stops working
* Add two-factor sign-in with any authenticator app, with recovery codes
* Stop form bots without a captcha, and count visitors without keeping their addresses

## Installation

```bash
composer require sugarcommerce/security
```

## Quick start

A download link that works for an hour:

```php
use SugarCommerce\Security\Tokens\Signer;
use SugarCommerce\Security\Tokens\Ttl;

$token = Signer::site( 'downloads' )->sign( 'file', [ 'order' => 42, 'file' => 3 ], Ttl::HOUR );
$url   = add_query_arg( 'download', $token, home_url( '/' ) );

// When it comes back:
$link = Signer::site( 'downloads' )->inspect( 'file', $_GET['download'] ?? '' );

if ( $link instanceof \SugarCommerce\Security\Tokens\Token ) {
	serve_file( $link->int( 'order' ), $link->int( 'file' ) );
} else {
	wp_die( esc_html( $link->public_message() ) ); // "This link has expired. Please request a new one."
}
```

The key comes from the site's salts, one per purpose. `new Signer( $secret, $retired )`
takes a secret of your own and rotates it without breaking links already sent;
`Signer::derived( $secret, 'shop/links/v1' )` gives each purpose its own key from
one shared secret. A forged token is always `InvalidSignature`, never `Expired`.

## Secrets at rest

```php
use SugarCommerce\Security\Encryption\Secrets;

$secrets = new Secrets( 'myplugin' );

$secrets->update_option( 'stripe_secret_key', $key ); // ciphertext in wp_options
$key = $secrets->get_option( 'stripe_secret_key' );   // the key
```

A constant `MYPLUGIN_STRIPE_SECRET_KEY` in `wp-config.php` wins, then an
environment variable of that name, then the encrypted option — and while either
supplies it, saving is refused. `get_setting_description()` and
`get_option_info()` tell a settings screen which. Transients and user and post
meta work the same way. AES-256-GCM, so a value altered in the database fails to
decrypt instead of decrypting to something else.

`Encryption\Cipher` is the cipher on its own, for a column of your own.
`$new->reencrypt( $stored, $old )` moves a value to a new key and is safe to
run twice.

This protects a leaked dump or backup, not a server whose files are taken: the
key comes from `wp-config.php` (or `WP_ENCRYPTION_KEY`).

## Keys and codes

```php
use SugarCommerce\Security\{ApiKey, Code, Random, Uuid};

$licence = Code::license( 'ACME' );   // ACME-83FMD-Z7QHQ-G03P2-H061J
$coupon  = Code::discount( 'SPRING' ); // SPRING-A3K9M2
Code::matches( 'acme 83fmd-z7qhq-go3p2-ho61j', $licence ); // true: case, spaces, O for 0

[ 'key' => $key, 'prefix' => $prefix, 'hash' => $hash ] = ApiKey::make( 'sk' );
// Show $key once. Store $prefix and $hash. ApiKey::matches( $submitted, $hash ).

$cart  = Random::hex();                                   // 64 hex characters
$cart  = Random::sanitize_hex( $_COOKIE['cart'] ?? '' );  // the token, or ''
$event = Random::id( 'evt' );                             // evt_9f2c41d0a7b3e655, for a log
$id    = Uuid::v7();                                      // sorts by time
```

`Slug::make( 'Naïve Café' )` gives `naive-cafe`, `Slug::unique()` asks your own
callback what is taken, and `Slug::clean( $typed, 3, 30, [ 'admin' ] )` takes a
handle somebody typed as it is or not at all.

## Rate limits

```php
use SugarCommerce\Security\RateLimit\Limiter;

global $wpdb;

$limiter  = Limiter::auto( $wpdb->prefix . 'myplugin_rate_limits' );
$decision = $limiter->for( 'sign_in', $ip )->hit( 5, 10 * MINUTE_IN_SECONDS );

if ( $decision->denied() ) {
	return new WP_Error( 'too_many', 'Too many tries.', [ 'status' => 429, 'retry_after' => $decision->retry_after() ] );
}
```

One atomic step per attempt: the object cache's own increment where there is a
persistent cache, `INSERT … ON DUPLICATE KEY UPDATE` on your table otherwise
(`Table::schema()` writes it), or `Stores\Apcu`. Windows are fixed, so a client
is told exactly when to come back (`$decision->headers()`); an IPv6 caller
counts as its /64; counters hold a salted hash, never an address. Nothing to
count against is never limited, and a store that cannot count lets the attempt
through — a limit must never become the outage.

`Rules` keeps every limit in one table, so a call site names the action:

```php
use SugarCommerce\Security\RateLimit\Rules;

$rules = new Rules( $limiter, [ 'sign_in' => [ 5, 600 ], 'reset_mail' => [ 3, 3600 ] ] );
$rules->hit( 'sign_in', $ip );   // counts
$rules->allows( 'reset_mail', $email ); // looks
```

## Turnstile

```php
use SugarCommerce\Security\Turnstile\Turnstile;

$turnstile = Turnstile::register( [
	'id'         => 'members',
	'label'      => 'Members',
	'enabled'    => fn() => (bool) get_option( 'members_turnstile' ),
	'site_key'   => fn() => (string) get_option( 'members_turnstile_site_key' ),
	'secret_key' => fn() => (string) get_option( 'members_turnstile_secret' ),
	'places'     => [ 'signup' => __( 'Sign-up form', 'members' ) ],
] );

echo $turnstile->widget()->slot( 'signup' );              // in the form

$passed = $turnstile->verify( $token, 'signup' );        // true, or a 400/403 WP_Error
```

Nothing of Cloudflare's is loaded until the owner switches it on with both
keys, and then only on a page with a protected form. A token is held to the
site's hostnames, the form it was made for, and once per request. `fail_open`
decides what a Cloudflare outage or a refused key does; either way the owner is
told by an admin notice and Site Health. `status()` gives a settings card its
word and tone, `key_test()->run()` backs a Test Keys button, `clean_key()` is a
settings field's sanitize callback, and a paragraph is offered to the privacy
policy guide. The form's script draws the widget with `mount()` from the
library's script module (`assets/js/turnstile.js`). Hooks are named from
`{id}_turnstile`, and every sentence can be replaced through `messages`.

`Verifier` is the server check on its own:
`( new Verifier( $secret ) )->for_hostnames( 'shop.example.com' )->passes( $token, $ip )`.

## Two-factor codes

```php
use SugarCommerce\Security\TwoFactor\{Totp, RecoveryCodes};

$totp   = new Totp();
$secret = $totp->generate_secret();                                   // store against the user
$uri    = $totp->enrolment_uri( $secret, $user->user_email, 'My Shop' ); // show as a QR code

$step = $totp->verify_after( $code, $secret, (int) $last_step );     // null: wrong, or replayed

$codes  = RecoveryCodes::generate();          // show once
$hashes = RecoveryCodes::hash_all( $codes );  // store these
$index  = RecoveryCodes::verify( $typed, $hashes ); // consume that one
```

RFC 6238, checked against its reference vectors. Leave the algorithm on SHA-1:
several apps ignore anything else.

## Forms and visitors

```php
use SugarCommerce\Security\{FormGuard, Hash};
use SugarCommerce\Security\Tokens\Signer;

$guard = new FormGuard( Signer::site( 'forms' ), 'contact' );
// Draw hidden FormGuard::STAMP => $guard->stamp(), and an empty, hidden FormGuard::TRAP.
if ( FormGuard::trapped( $_POST[ FormGuard::TRAP ] ?? '' ) || ! $guard->human( $_POST[ FormGuard::STAMP ] ?? '' ) ) { … }

$visitor = Hash::site( 'visitors' )->ip( $ip ); // keyed: comparable, not reversible
```

## Freezing the clock

Everything here that asks the time reads `SugarCommerce\Dates\Clock`, so a test
can see a link expire, a window roll over or a code change without waiting:
`Clock::freeze( 1_800_000_000 )`, `Clock::advance( 61 )`, `Clock::reset()`.

## Moving from arraypress/wp-*

From `arraypress/wp-signed-tokens`, `wp-encryption-utils`, `wp-generate-utils`,
`wp-rate-limit` and `wp-turnstile`. Tokens already emailed, values already
encrypted and counters already kept carry on working: the key derivations and
stored formats are unchanged.

| Old | New |
|---|---|
| `ArrayPress\SignedTokens\TokenSigner` | `SugarCommerce\Security\Tokens\Signer` — same methods |
| `ArrayPress\SignedTokens\{Token, Reason, Ttl}` | `SugarCommerce\Security\Tokens\{Token, Reason, Ttl}` |
| `ArrayPress\SignedTokens\Base64Url` | `SugarCommerce\Security\Base64Url` |
| `Secret::from_salts( $purpose )` | `Keys::signing( $purpose )` |
| `Secret::signer( $purpose, $timestamp )` | `Signer::site( $purpose, $timestamp )` |
| `ArrayPress\SignedTokens\Clock::now()` | `SugarCommerce\Dates\Clock::time()`; `freeze`, `advance`, `use`, `reset` as they were |
| `new TokenSigner( $secret, $previous )` | unchanged, but a retired secret under 32 bytes now throws, and an expiry with a leading zero is `Malformed` |
| `ArrayPress\EncryptionUtils\Manager` | `SugarCommerce\Security\Encryption\Secrets` — same constructor and methods |
| `Manager::encrypt()` / `decrypt()` / `is_encrypted()` | unchanged on `Secrets`, and on `Encryption\Cipher` alone |
| `Manager::encrypt( '0' )` | now encrypted; it was returned as it was |
| `ArrayPress\Generate\{Code, Slug, Uuid}` | `SugarCommerce\Security\{Code, Slug, Uuid}` |
| `Token::hex()`, `url_safe()`, `alphanumeric()`, `sanitize_hex()`, `is_hex()` | `Random::…` |
| `Token::api_key( $prefix )` | `ApiKey::make( $prefix )` |
| `Token::matches( $key, $hash )` | `ApiKey::matches( $key, $hash )` |
| `Uuid::is_valid( $uuid, $version )` | unchanged; a version outside 1–8 is false, and a trailing newline is refused |
| `ArrayPress\RateLimit\*` | `SugarCommerce\Security\RateLimit\*` — `Limiter`, `Limit`, `Decision`, `Store`, `Stores\*` |
| `ArrayPress\Turnstile\*` | `SugarCommerce\Security\Turnstile\*` — every class, option and hook name |
| `arraypress/wp-composer-assets` (Turnstile's module URL) | not needed: the library works out its own |

New: `Signer::derived()`, `Keys::derive()`, `Cipher::encrypt_once()` and
`reencrypt()`, `Secrets::cipher()`, `Random::id()`, `ApiKey::digest()` and its
`$shown`, `Slug::clean()`, `RateLimit\Rules`, `Stores\Apcu`, Turnstile's
`ErrorCode`, `Verification::errors()` and `has()`, `Verifier::passes()`,
`for_hostnames()`, `for_action()` and `is_test_secret( $secret, true )`, and
from the retired SugarCommerce packages `TwoFactor\{Totp, Algorithm,
RecoveryCodes}`, `Base32`, `Hash` and `FormGuard`.

Not brought over from those packages: the sliding-window limiter (fixed windows
tell a client exactly when to come back), the SQLite and file rate-limit stores
(WordPress has the table), and web-security's cookie sessions, CSRF tokens,
flash messages and magic-link sessions (WordPress has nonces and auth cookies),
and its libsodium sealer and file sealing (the cipher here covers values).

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later
* The OpenSSL extension

## License

GPL-2.0-or-later
