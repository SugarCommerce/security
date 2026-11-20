<?php
/**
 * SVG cleaning tests.
 *
 * @package SugarCommerce\Security
 */

declare( strict_types=1 );

namespace SugarCommerce\Security\Tests;

use SugarCommerce\Security\Svg;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * An icon is somebody else's markup printed into an admin screen.
 *
 * A theme's folder, a plugin's callback, a file dropped in by whoever had
 * FTP: inlined, an SVG runs its scripts and its event handlers with the
 * page's privileges -- in the admin, an administrator's. So every icon is
 * rebuilt from an allow-list before it is printed, and these are the things
 * that list exists to stop.
 */
final class SvgTest extends TestCase {

	/**
	 * The fixtures.
	 *
	 * @return string
	 */
	private static function fixtures(): string {
		return __DIR__ . '/fixtures/svg';
	}

	/**
	 * Nothing that runs survives, from a file built to try every way.
	 */
	public function test_a_malicious_icon_is_defanged(): void {
		$clean = Svg::sanitize( (string) file_get_contents( self::fixtures() . '/evil.svg' ) );

		$this->assertNotSame( '', $clean, 'The shapes in it are still an icon.' );

		foreach ( [ 'script', 'alert', 'javascript', 'onload', 'onclick', 'onmouseover', 'onerror', 'foreignObject', '<style', '<a ', 'evil.example', 'data:', 'expression', '<animate', '<set', '<image', '<text', 'background', 'CDATA' ] as $needle ) {
			$this->assertStringNotContainsStringIgnoringCase( $needle, $clean, "\"$needle\" survived." );
		}

		// What is left is what an icon is made of.
		$this->assertStringContainsString( '<path d="M4 4h16v16H4z"/>', $clean );
		$this->assertStringContainsString( '<use href="#ok"/>', $clean );
		$this->assertStringContainsString( '<circle fill="red" cx="12" cy="12" r="4"/>', $clean );
	}

	/**
	 * What an editor leaves in a file is stripped: the XML declaration, the
	 * comment, the title (a hover tooltip on a decorative icon), the class
	 * and id (a page's stylesheet would reach in), the fixed size.
	 */
	public function test_editor_furniture_is_dropped(): void {
		$clean = Svg::sanitize( (string) file_get_contents( self::fixtures() . '/star.svg' ) );

		$this->assertSame(
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z"/></svg>',
			$clean
		);
	}

	/**
	 * Presentation written as style is kept as the attributes it means, and
	 * nothing else in the style is.
	 *
	 * WordPress's own icons are written `style="fill: none"`; dropping the
	 * style whole would fill every outline icon solid black.
	 */
	public function test_presentational_style_becomes_attributes(): void {
		$clean = Svg::sanitize( (string) file_get_contents( self::fixtures() . '/moon.svg' ) );

		$this->assertStringContainsString( '<path fill="none" stroke="currentColor" stroke-width="1.5" d=', $clean );
		$this->assertStringNotContainsString( 'style', $clean );
		$this->assertStringNotContainsString( 'behavior', $clean );

		// No viewBox, but a width and a height: the viewBox they imply.
		$this->assertStringContainsString( 'viewBox="0 0 20 20"', $clean );
	}

	/**
	 * Anything that is not an icon is nothing.
	 *
	 * @param string $markup The markup.
	 */
	#[DataProvider( 'notAnIconProvider' )]
	public function test_not_an_icon_is_nothing( string $markup ): void {
		$this->assertSame( '', Svg::sanitize( $markup ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function notAnIconProvider(): array {
		return [
			'empty'                => [ '' ],
			'not xml'              => [ 'not an svg at all' ],
			'html'                 => [ '<div><svg viewBox="0 0 1 1"><path d="M0 0"/></svg></div>' ],
			'a script'             => [ '<script>alert(1)</script>' ],
			'no size at all'       => [ '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1v1z"/></svg>' ],
			'nothing drawn'        => [ '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><script>alert(1)</script></svg>' ],
			// A billion laughs: entities declared in a DOCTYPE. Refused
			// before the parser can expand anything.
			'an entity'            => [ '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><path d="&b;"/></svg>' ],
			// An external entity, which would read a file off the server.
			'an external entity'   => [ '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><path d="&x;"/></svg>' ],
			'far too big'          => [ '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><path d="' . str_repeat( 'M0 0', 20000 ) . '"/></svg>' ],
		];
	}

	/**
	 * A sprite's symbol is drawn as an svg, and takes the text's colour.
	 *
	 * Dashicons' symbols have bare paths, which would draw black on any
	 * background without a fill on the outer element.
	 */
	public function test_a_symbol_becomes_an_svg_in_the_texts_colour(): void {
		$clean = Svg::sanitize( '<symbol viewBox="0 0 20 20" id="cart"><title>cart</title><g><path d="M1 1h18v18H1z"/></g></symbol>' );

		$this->assertSame( '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><g><path d="M1 1h18v18H1z"/></g></svg>', $clean );
	}

	/**
	 * An outline icon is not filled: it said how to draw itself.
	 */
	public function test_an_outline_icon_keeps_its_stroke(): void {
		$clean = Svg::sanitize( '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path d="M1 1h2"/></svg>' );

		$this->assertStringContainsString( 'fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"', $clean );
		$this->assertStringNotContainsString( 'fill="currentColor"', $clean );
	}

	/**
	 * SVG's mixed-case names are spelled as SVG spells them.
	 *
	 * Inline in HTML, `lineargradient` is an unknown element and draws
	 * nothing; the parser hands back lower case, so it is put back.
	 */
	public function test_case_sensitive_names_survive(): void {
		$clean = Svg::sanitize(
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><linearGradient id="g" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fff"/></linearGradient><clipPath id="c"><rect width="24" height="24"/></clipPath></defs><path fill="url(#g)" clip-path="url(#c)" d="M0 0h24v24H0z"/></svg>'
		);

		$this->assertStringContainsString( '<linearGradient id="g" gradientUnits="userSpaceOnUse">', $clean );
		$this->assertStringContainsString( '<clipPath id="c">', $clean );
		$this->assertStringContainsString( 'fill="url(#g)" clip-path="url(#c)"', $clean );
	}

	/**
	 * Drawn decorative by default, or as a named image when labelled.
	 */
	public function test_render_is_decorative_unless_named(): void {
		$svg = Svg::sanitize( '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h1v1z"/></svg>' );

		$this->assertStringStartsWith( '<svg aria-hidden="true" focusable="false" xmlns=', Svg::render( $svg ) );

		$named = Svg::render( $svg, [ 'label' => 'Cart "quoted"', 'size' => 32, 'class' => 'a b' ] );

		$this->assertStringStartsWith( '<svg width="32" height="32" class="a b" role="img" aria-label="Cart &quot;quoted&quot;" focusable="false" xmlns=', $named );
		$this->assertStringNotContainsString( 'aria-hidden', $named );

		// Only cleaned markup is drawn at all.
		$this->assertSame( '', Svg::render( '<script>alert(1)</script>' ) );
	}

	/**
	 * A DOCTYPE is refused on its own, entity or not.
	 */
	public function test_an_icon_with_a_doctype_is_refused(): void {
		$this->assertSame( '', Svg::sanitize( '<!DOCTYPE svg><svg viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>' ) );
	}

	/**
	 * Only an svg or a symbol is an icon.
	 */
	public function test_only_an_svg_or_a_symbol_is_an_icon(): void {
		$this->assertSame( '', Svg::sanitize( '<g viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></g>' ) );
		$this->assertNotSame( '', Svg::sanitize( '<symbol viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></symbol>' ) );
		$this->assertNotSame( '', Svg::sanitize( '<SVG viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></SVG>' ) );
	}

	/**
	 * Without a viewBox, a width and a height make one -- both of them, and
	 * both above zero.
	 */
	public function test_a_viewbox_is_made_from_a_size(): void {
		$this->assertStringContainsString( 'viewBox="0 0 1 1"', Svg::sanitize( '<svg width="1" height="1"><path d="M0 0h1v1H0z"/></svg>' ) );
		$this->assertSame( '', Svg::sanitize( '<svg width="0" height="24"><path d="M0 0h24v24H0z"/></svg>' ) );
		$this->assertSame( '', Svg::sanitize( '<svg width="24" height="0"><path d="M0 0h24v24H0z"/></svg>' ) );
		$this->assertSame( '', Svg::sanitize( '<svg><path d="M0 0h24v24H0z"/></svg>' ) );
	}

	/**
	 * An icon that strokes is not also filled.
	 */
	public function test_a_stroked_icon_is_not_given_a_fill(): void {
		$svg = Svg::sanitize( '<svg viewBox="0 0 24 24" stroke="currentColor"><path d="M0 0h24"/></svg>' );

		$this->assertStringNotContainsString( 'fill="currentColor"', $svg );
		$this->assertStringContainsString( 'fill="currentColor"', Svg::sanitize( '<svg viewBox="0 0 24 24"><path d="M0 0h24"/></svg>' ) );
	}

	/**
	 * The size limit is inclusive: exactly the limit is read, a byte more
	 * is not.
	 */
	public function test_the_size_limit_is_inclusive(): void {
		$head = '<svg viewBox="0 0 24 24"';
		$tail = '><path d="M0 0h24"/></svg>';
		$fill = 65536 - strlen( $head ) - strlen( $tail );

		$this->assertNotSame( '', Svg::sanitize( $head . str_repeat( ' ', $fill ) . $tail ) );
		$this->assertSame( '', Svg::sanitize( $head . str_repeat( ' ', $fill + 1 ) . $tail ) );
	}
}
