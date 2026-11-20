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
* Print an SVG somebody else wrote -- an icon, a logo -- with nothing in it that runs

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

if ( $link instanceof \SugarCommerce\Security\Models\Tokens\Token ) {
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

Each purpose has its own key: the one a value is written under is derived from
the site's (or yours) with HKDF-SHA256 and a purpose label — the prefix, or the
third argument — so a value one plugin encrypted does not open under another
plugin's `Cipher`, though both start from the same salts:

```php
$keys  = new Cipher( 'myplugin', null, 'myplugin/api-keys' );
$hooks = new Cipher( 'myplugin', null, 'myplugin/webhooks' ); // cannot read $keys' values
```

Values are written as `__PREFIX_ENCRYPTED__v3:`. The `v2:` values written
before, under the key every purpose shared, still decrypt; `is_legacy_format()`
says so and saving them again moves them. A key of your own must be at least 32
bytes (`Cipher::MIN_KEY_BYTES`) — a shorter one throws rather than being
stretched into a guessable key; pass an old short key to `also_open()` to read
what it wrote.

This is the family's one copy of encryption: other packages call it rather than
carry their own (`sugarcommerce/fields` encrypts its `encrypted` fields here).
Code whose stored values already carry a marker of its own keeps the marker and
uses the unmarked payload, the same AES-256-GCM nonce, tag and ciphertext that
follows the marker:

```php
$cipher = ( new Cipher( 'myplugin', null, 'myplugin/columns' ) )->also_open( $material_of_the_old_key );

$stored = 'mine:' . $cipher->seal( $value );           // under the purpose's key
$value  = $cipher->open( substr( $stored, 5 ) );        // or a WP_Error
```

A payload carries no version, so without a named purpose `seal()` stays on the
shared site key that payloads sealed before purposes are under; name one for new
code. `open()` with a purpose tries the purpose's key, then the shared one.
`also_open()` takes the key material an older copy hashed into its key, so its
values still read; nothing is written under it.

This protects a leaked dump or backup, not a server whose files are taken: the
key comes from `wp-config.php` (or `WP_ENCRYPTION_KEY`).

Where the key comes from, in order: a key passed to the `Cipher`, then
`WP_ENCRYPTION_KEY`, then the four `*_KEY` constants of `wp-config.php`. Those
are used only when they are secret. A site still on the "put your unique phrase
here" placeholders, with an empty one, or with one value pasted into two keys or
salts would get a key anyone can work out, so it uses `wp_salt( 'auth' )` and
`wp_salt( 'secure_auth' )` instead: core swaps such values for a random secret it
keeps in the database. A site with real keys keeps the key it has always had.
Values a placeholder site encrypted before still decrypt (under the old, public
key), and `$cipher->reencrypt( $stored )` or saving them again moves them to the
new one.

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
counts as its /64; counters hold a salted hash, never an address.

Nothing to count against is the visitor's address, never no limit:
`for( 'reset_mail', '' )` counts against the address the request came from
(`REMOTE_ADDR`, as `sugarcommerce/network`'s `ClientIp::resolve()` gives it with
no proxy trusted). A site behind a proxy says who the visitor is with
`$limiter->client( fn() => ClientIp::resolve( null, $its_trusted_proxies ) )`. An
empty action, or no identity and no address (a command line), throws.

A store that cannot count — the table not installed, the database refusing —
refuses the attempt by default.
`$limit->hit( 5, 600, fail_open: true )` lets it through for one call, and
`$limiter->fail_open()` for every call, where an outage of the counter must not
be an outage of what it protects. Either way it is reported (`error_log()`, or
your own `$limiter->on_failure( fn( $key, $allowed ) => … )`) and
`$decision->failed` is true.

`Rules` keeps every limit in one table, so a call site names the action:

```php
use SugarCommerce\Security\RateLimit\Rules;

$rules = new Rules( $limiter, [ 'sign_in' => [ 5, 600 ], 'reset_mail' => [ 3, 3600 ] ] );
$rules->hit( 'sign_in', $ip );   // counts
$rules->allows( 'reset_mail', $email ); // looks
$rules->hit( 'sign_in', $ip, fail_open: true ); // let through if the store is down
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
site's hostnames, the form it was made for, and once per request; an answer
from Cloudflare that leaves out the hostname or the action is refused like a
wrong one (a widget rendered without `data-action` is not your form). `fail_open`
decides what a Cloudflare outage or a refused key does; either way the owner is
told by an admin notice (core's `wp_admin_notice()`) and Site Health. `status()` gives a settings card its
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

## SVG somebody else wrote

An SVG inlined into a page runs its scripts and event handlers with the page's
privileges -- in the admin, an administrator's. `Svg` parses it as XML (no
network, no entities, no DOCTYPE, 64 KB at most) and rebuilds it from an
allow-list of shapes and presentation attributes: scripts, event handlers,
`<style>`, `<foreignObject>`, links, images, animation and text are dropped,
and a `href` or `url()` may only point inside the SVG. sugarcommerce/fields'
icon sets print every icon through it.

```php
use SugarCommerce\Security\Svg;

$clean = Svg::sanitize( $markup );                       // '' when it is not an SVG worth drawing
echo Svg::render( $clean, [ 'size' => 20 ] );            // decorative: aria-hidden
echo Svg::render( $clean, [ 'label' => 'Cart' ] );       // an image named "Cart"
```

## Freezing the clock

Everything here that asks the time reads `SugarCommerce\Dates\Clock`, so a test
can see a link expire, a window roll over or a code change without waiting:
`Clock::freeze( 1_800_000_000 )`, `Clock::advance( 61 )`, `Clock::reset()`.

## Security

What each part defends against:

* **A forged or edited link** — HMAC-SHA256 under a key derived per purpose, compared in constant time; a forged token is never reported as `Expired`.
* **A link used for another purpose** — the namespace is mixed into the key, so a `password-reset` token never verifies as a `magic-link`.
* **A guessable secret** — a signing secret, a retired one, a derived signer's shared secret or a cipher key of your own under 32 bytes throws; placeholder salts are never used as key material.
* **A leaked database dump** — AES-256-GCM, so a value altered in the database fails to decrypt instead of decrypting to something else; each purpose has its own key.
* **Secrets in logs and bug reports** — `var_dump()` and `print_r()` show `[redacted]`, and every secret argument is a `#[\SensitiveParameter]`.
* **A burst of attempts** — one atomic increment per attempt; an IPv6 caller counts as its /64; a caller with nothing to count against counts against their address; a counter that cannot count refuses by default.
* **A script at a form** — a Turnstile token is held to the site's hostnames, its form and one use; a 4xx from Cloudflare is a refusal, so a visitor cannot make the check "unavailable" and slip through a policy that fails open.
* **A replayed or guessed two-factor code** — compared in constant time across the whole window; `verify_after()` refuses a step already used; recovery codes are stored with `password_hash()`.
* **A hostile SVG** — rebuilt from an allow-list after an XML parse that fetches nothing and refuses a DOCTYPE (so no entity expansion or external entity); event handlers, scripts, styles and outside links are dropped, not escaped.
* **A stolen key table** — API keys are stored as digests, compared in constant time; visitor addresses are kept as keyed hashes.

## Layout

`Tokens/` signed links, `Encryption/` the cipher and `Secrets`, `RateLimit/`
the limiter and its stores, `Turnstile/` Cloudflare Turnstile, `TwoFactor/`
TOTP and recovery codes, and at the top the small pieces (`Keys`, `Random`,
`Code`, `ApiKey`, `Uuid`, `Slug`, `Hash`, `FormGuard`, `Svg`). `Models/` holds the data
shapes and nothing that does work, by the same areas: a rate-limit `Decision`, a
verified `Token` and why one was refused (`Tokens/Reason`), a Turnstile
`Verification` with its `Reason` and Cloudflare `ErrorCode`, and the TOTP
`Algorithm`. `Traits/<Class>/` holds the jobs a larger class is split into.

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later
* The OpenSSL extension

## License

GPL-2.0-or-later
