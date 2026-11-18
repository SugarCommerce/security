/**
 * Cloudflare Turnstile in a form: drawing the widget, and handing its
 * token over when the form is sent.
 *
 * Cloudflare's script is on the page already, put there by PHP and asked
 * not to draw anything by itself (`render=explicit`). This draws a widget
 * into a slot when a form wants one -- which may be long after the page
 * loaded, for a step shown when a button is pressed -- and looks after it
 * from then on.
 *
 * A widget is in one of six states, and a form only has to ask for the
 * token to find out which:
 *
 *   - `loading`     Cloudflare's script has not arrived yet.
 *   - `working`     The check is running. Usually about a second.
 *   - `solved`      There is a token. It is good for five minutes, once.
 *   - `interactive` The visitor has been asked to tick a box.
 *   - `failed`      Cloudflare could not check this visitor.
 *   - `blocked`     Cloudflare's script never arrived: a content blocker,
 *                   or no connection.
 *
 * The slot takes up no room until the widget has something to show (see the
 * `is-visible` class, and the library's inline styles), so a check that passes by itself moves nothing.
 */

/**
 * How long a form waits for a check that is still running, in
 * milliseconds, before telling the visitor to try again.
 */
const PATIENCE = 12000;

/**
 * How long Cloudflare's script is waited for after the page has finished
 * loading, in milliseconds. It is deferred, so by then it has either run
 * or failed; the margin is for a browser that reports the two out of
 * order.
 */
const GRACE = 1500;

let arriving = null;

/**
 * Cloudflare's script, once it has run.
 *
 * It tells nobody when it fails to load, so this watches for it: an error
 * on the script element when that is seen, and otherwise a page that has
 * finished loading without it.
 *
 * @param {string} id The id of the script element.
 * @return {Promise<Object>} `window.turnstile`. Rejects when it is not coming.
 */
function api( id ) {
	if ( window.turnstile ) {
		return Promise.resolve( window.turnstile );
	}

	if ( arriving ) {
		return arriving;
	}

	arriving = new Promise( ( resolve, reject ) => {
		const tag = document.getElementById( id );
		const started = Date.now();
		let loaded = 0;
		let done = false;

		const give = ( found ) => {
			if ( done ) {
				return;
			}

			done = true;

			if ( found ) {
				resolve( window.turnstile );
			} else {
				// Asked again by the next widget: the visitor may have
				// come back on line.
				arriving = null;
				reject( new Error( 'blocked' ) );
			}
		};

		if ( tag ) {
			tag.addEventListener( 'error', () => give( false ) );
		}

		const look = () => {
			if ( window.turnstile ) {
				give( true );

				return;
			}

			if ( document.readyState === 'complete' && ! loaded ) {
				loaded = Date.now();
			}

			if (
				! tag ||
				( loaded && Date.now() - loaded > GRACE ) ||
				Date.now() - started > PATIENCE
			) {
				give( false );

				return;
			}

			window.setTimeout( look, 100 );
		};

		look();
	} );

	return arriving;
}

/**
 * Draw a widget in a slot.
 *
 * @param {Element}                slot       The slot: the element with `data-place`.
 * @param {Object}                 config     From PHP: `params`, `script`, `messages`.
 * @param {function(string): void} [onChange] Called with the new state whenever it changes.
 * @return {Object} `take()`, `reset()`, `remove()`, `focus()` and `message()`.
 */
export function mount( slot, config, onChange = () => {} ) {
	// The box inside the slot: marked as such by the library's markup, or
	// the first child of a plugin's own template.
	const box =
		slot.querySelector( '[data-turnstile-widget]' ) || slot.firstElementChild || slot;
	const always = config.params.appearance === 'always';

	let status = 'loading';
	let token = '';
	let id = null;
	let gone = false;
	let waiting = [];

	// Whether the widget has something on show. Once it has asked the
	// visitor for anything it stays, so the form does not jump twice.
	// A check that failed shows nothing -- Cloudflare draws nothing for
	// it unless the widget is always on show -- so no room is made.
	let shown = false;

	const set = ( next, value = '' ) => {
		if ( gone ) {
			return;
		}

		status = next;
		token = value;
		shown =
			shown ||
			( always && next !== 'loading' && next !== 'blocked' ) ||
			next === 'interactive';

		slot.classList.toggle( 'is-visible', shown );

		// Whoever is waiting for a token is told as soon as there is an
		// answer either way.
		if ( next !== 'loading' && next !== 'working' ) {
			const told = waiting;

			waiting = [];
			told.forEach( ( { resolve, reject, timer } ) => {
				window.clearTimeout( timer );

				if ( next === 'solved' ) {
					resolve( value );
				} else {
					reject( next );
				}
			} );
		}

		onChange( next );
	};

	api( config.script ).then(
		( turnstile ) => {
			if ( gone ) {
				return;
			}

			// A form in a column too narrow for the usual widget gets
			// the small one: 150px wide where the other needs 300.
			const room = slot.parentElement
				? slot.parentElement.clientWidth
				: 300;

			id = turnstile.render( box, {
				...config.params,
				size: room && room < 300 ? 'compact' : config.params.size,

				// The token goes with the form's own request, not in a
				// hidden field of Cloudflare's making.
				'response-field': false,

				// Expiry is handled here and only here: the token is
				// thrown away and a new check started.
				'refresh-expired': 'never',

				callback: ( value ) => set( 'solved', value ),
				'expired-callback': () => {
					set( 'working' );
					turnstile.reset( id );
				},
				'timeout-callback': () => {
					set( 'working' );
					turnstile.reset( id );
				},
				'error-callback': () => set( 'failed' ),
				'unsupported-callback': () => set( 'failed' ),
				'before-interactive-callback': () => set( 'interactive' ),
				'after-interactive-callback': () => {
					if ( status === 'interactive' ) {
						set( 'working' );
					}
				},
			} );

			if ( status === 'loading' ) {
				set( 'working' );
			}
		},
		() => set( 'blocked' )
	);

	return {
		/**
		 * The token, as soon as there is one.
		 *
		 * @return {Promise<string>} Rejects with the state when there
		 *                           will not be one without the visitor
		 *                           doing something.
		 */
		take() {
			if ( status === 'solved' ) {
				return Promise.resolve( token );
			}

			if ( status !== 'loading' && status !== 'working' ) {
				return Promise.reject( status );
			}

			return new Promise( ( resolve, reject ) => {
				const entry = { resolve, reject, timer: 0 };

				entry.timer = window.setTimeout( () => {
					waiting = waiting.filter( ( other ) => other !== entry );
					reject( 'slow' );
				}, PATIENCE );

				waiting.push( entry );
			} );
		},

		/**
		 * Throw the token away and check again. A token is single use,
		 * so this follows every request that carried one.
		 */
		reset() {
			if ( gone || id === null || ! window.turnstile ) {
				return;
			}

			set( 'working' );
			window.turnstile.reset( id );
		},

		/**
		 * Take the widget off the page.
		 */
		remove() {
			if ( id !== null && window.turnstile ) {
				window.turnstile.remove( id );
			}

			waiting.forEach( ( { reject, timer } ) => {
				window.clearTimeout( timer );
				reject( 'removed' );
			} );

			waiting = [];
			gone = true;
			slot.classList.remove( 'is-visible' );
		},

		/**
		 * Put the keyboard at the widget, when it is asking for something.
		 */
		focus() {
			// Cloudflare keeps its frame where a page's script cannot
			// reach it, so the keyboard is put on the slot, which is
			// named "Security check": the box to tick is the next
			// press of Tab.
			if ( shown ) {
				slot.setAttribute( 'tabindex', '-1' );
				slot.focus();
			}
		},

		/**
		 * What to tell the visitor when there is no token.
		 *
		 * @param {string} why The state take() rejected with.
		 * @return {string} A sentence.
		 */
		message( why ) {
			if ( why === 'blocked' ) {
				return config.messages.blocked;
			}

			// Nothing for the visitor to tick: say so, and what to do.
			if ( why === 'failed' ) {
				return config.messages.failed;
			}

			return config.messages.incomplete;
		},
	};
}
