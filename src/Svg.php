<?php
/**
 * SVG Markup, Cleaned
 *
 * @package     SugarCommerce\Security
 * @copyright   Copyright (c) 2026, ArrayPress Limited
 * @license     GPL-2.0-or-later
 * @since       1.5.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Security;

use DOMDocument;
use DOMElement;
use DOMNode;

/**
 * Class Svg
 *
 * The family's one SVG cleaner: sugarcommerce/fields' icon sets and
 * anything else that prints an SVG it did not write go through it.
 *
 * An icon is markup somebody else wrote, printed straight into an admin
 * screen and a shop's front end. A theme's folder of icons, a plugin's
 * callback, a file dropped into a directory by whoever had FTP: any of
 * them can hold a `<script>`, an `onload`, or a link to `javascript:`, and
 * an SVG inlined into a page runs every one of those with the page's own
 * privileges -- in the admin, an administrator's.
 *
 * So nothing is printed as it came. The markup is parsed as XML and rebuilt
 * from an allow-list: the shapes an icon is drawn with, the presentation
 * attributes that style them, and nothing else. What is not on the list is
 * dropped rather than escaped -- an event handler is not made safe by
 * quoting it, it is made safe by not being there.
 *
 * The allow-list is deliberately narrow. Text, images, links, animation,
 * `foreignObject` and `<style>` are all things an icon can do without, and
 * each is a way to run something or to fetch something.
 *
 * @since 1.5.0
 */
final class Svg {

	/**
	 * The elements an icon may be drawn with, by lower-case name.
	 *
	 * `use` is here for sprites that reference their own symbols; its link
	 * is held to a fragment within the icon (see clean_value()).
	 *
	 * @var array<string, true>
	 */
	private const array ELEMENTS = [
		'svg'            => true,
		'g'              => true,
		'path'           => true,
		'circle'         => true,
		'ellipse'        => true,
		'line'           => true,
		'polyline'       => true,
		'polygon'        => true,
		'rect'           => true,
		'defs'           => true,
		'clippath'       => true,
		'mask'           => true,
		'lineargradient' => true,
		'radialgradient' => true,
		'stop'           => true,
		'use'            => true,
		'symbol'         => true,
	];

	/**
	 * The attributes an element may keep, by lower-case name.
	 *
	 * Geometry and presentation. No `style` (see style_attributes(), which
	 * turns the presentational part of one into these), no `class` (a
	 * stylesheet on the page would reach into the icon), and nothing
	 * beginning `on`.
	 *
	 * @var array<string, true>
	 */
	private const array ATTRIBUTES = [
		'viewbox'             => true,
		'xmlns'               => true,
		'id'                  => true,
		'd'                   => true,
		'cx'                  => true,
		'cy'                  => true,
		'r'                   => true,
		'rx'                  => true,
		'ry'                  => true,
		'x'                   => true,
		'y'                   => true,
		'x1'                  => true,
		'y1'                  => true,
		'x2'                  => true,
		'y2'                  => true,
		'width'               => true,
		'height'              => true,
		'points'              => true,
		'transform'           => true,
		'offset'              => true,
		'fill'                => true,
		'fill-rule'           => true,
		'fill-opacity'        => true,
		'clip-rule'           => true,
		'clip-path'           => true,
		'mask'                => true,
		'stroke'              => true,
		'stroke-width'        => true,
		'stroke-linecap'      => true,
		'stroke-linejoin'     => true,
		'stroke-miterlimit'   => true,
		'stroke-dasharray'    => true,
		'stroke-dashoffset'   => true,
		'stroke-opacity'      => true,
		'opacity'             => true,
		'stop-color'          => true,
		'stop-opacity'        => true,
		'gradientunits'       => true,
		'gradienttransform'   => true,
		'clippathunits'       => true,
		'maskunits'           => true,
		'preserveaspectratio' => true,
		'vector-effect'       => true,
		'shape-rendering'     => true,
		'href'                => true,
		'xlink:href'          => true,
	];

	/**
	 * What the outer `<svg>` keeps.
	 *
	 * Its size is the caller's to set when it is drawn, so `width` and
	 * `height` go: an icon file that says 24 would otherwise refuse to be
	 * drawn at 16. The viewBox is what keeps its proportions.
	 *
	 * @var array<string, true>
	 */
	private const array ROOT_ATTRIBUTES = [
		'viewbox'           => true,
		'fill'              => true,
		'fill-rule'         => true,
		'clip-rule'         => true,
		'stroke'            => true,
		'stroke-width'      => true,
		'stroke-linecap'    => true,
		'stroke-linejoin'   => true,
		'stroke-miterlimit' => true,
	];

	/**
	 * Attributes that name a URL, and so may only point inside the icon.
	 *
	 * @var array<string, true>
	 */
	private const array LINKS = [
		'href'       => true,
		'xlink:href' => true,
	];

	/**
	 * The largest file worth parsing.
	 *
	 * An icon is a few hundred bytes. A file of hundreds of kilobytes in an
	 * icon folder is not an icon, and parsing it on every page that draws one
	 * is a cost somebody else chose.
	 */
	private const int MAX_BYTES = 65536;

	/**
	 * Clean icon markup into a self-contained `<svg>`.
	 *
	 * Accepts an `<svg>` or a `<symbol>` (a sprite's entry) and returns an
	 * `<svg>` either way, with the namespace, the viewBox and nothing that
	 * runs. When the outer element says neither how to fill nor how to
	 * stroke, it is given `fill="currentColor"`, which is what makes an icon
	 * take the colour of the text around it -- a sprite's bare paths
	 * otherwise draw black on any background.
	 *
	 * @param string $markup Markup as it came from a file or a callback.
	 *
	 * @return string The cleaned `<svg>`, or '' when it is not one -- not XML,
	 *                not an svg, too large, or carrying a DOCTYPE.
	 * @since 1.5.0
	 */
	public static function sanitize( string $markup ): string {
		$markup = trim( $markup );

		if ( '' === $markup || strlen( $markup ) > self::MAX_BYTES || ! class_exists( DOMDocument::class ) ) {
			return '';
		}

		// A DOCTYPE is how an entity is declared, and an entity is how a
		// few hundred bytes become gigabytes. An icon has no use for one.
		if ( false !== stripos( $markup, '<!DOCTYPE' ) || false !== stripos( $markup, '<!ENTITY' ) ) {
			return '';
		}

		$document = new DOMDocument();
		$previous = libxml_use_internal_errors( true );

		// LIBXML_NONET: nothing is fetched while parsing. No LIBXML_NOENT,
		// which would substitute entities rather than refuse them.
		$loaded = $document->loadXML( $markup, LIBXML_NONET | LIBXML_COMPACT );

		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		$root = $document->documentElement; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM's own names.

		if ( ! $loaded || ! $root instanceof DOMElement || ! in_array( strtolower( $root->localName ), [ 'svg', 'symbol' ], true ) ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM's own names.
			return '';
		}

		$attributes = self::attributes( $root, true );

		// A viewBox is what lets the icon be drawn at any size. An icon
		// with only a width and a height still has one, implied.
		if ( ! isset( $attributes['viewBox'] ) ) {
			$width  = (float) $root->getAttribute( 'width' );
			$height = (float) $root->getAttribute( 'height' );

			if ( $width <= 0 || $height <= 0 ) {
				return '';
			}

			$attributes = [ 'viewBox' => sprintf( '0 0 %s %s', self::number( $width ), self::number( $height ) ) ] + $attributes;
		}

		if ( ! isset( $attributes['fill'] ) && ! isset( $attributes['stroke'] ) ) {
			$attributes['fill'] = 'currentColor';
		}

		$inner = self::children( $root );

		if ( '' === $inner ) {
			return '';
		}

		return sprintf(
			'<svg xmlns="http://www.w3.org/2000/svg"%s>%s</svg>',
			self::render_attributes( $attributes ),
			$inner
		);
	}

	/**
	 * Draw cleaned markup with the attributes a page needs on it.
	 *
	 * Decorative unless told otherwise: an icon beside a word is announced
	 * as the word, and an icon announced as "image" first is noise. Given a
	 * `label`, it is an image with that name instead.
	 *
	 * @param string               $svg   Markup from sanitize().
	 * @param array<string, mixed> $attrs `size` (pixels, both sides), `width`,
	 *                                    `height`, `class`, `label`, `style`.
	 *
	 * @return string
	 * @since 1.5.0
	 */
	public static function render( string $svg, array $attrs = [] ): string {
		if ( ! str_starts_with( $svg, '<svg ' ) ) {
			return '';
		}

		$extra = [];
		$size  = isset( $attrs['size'] ) ? (int) $attrs['size'] : 0;
		$label = trim( (string) ( $attrs['label'] ?? '' ) );

		foreach ( [ 'width', 'height' ] as $side ) {
			$length = isset( $attrs[ $side ] ) ? (int) $attrs[ $side ] : $size;

			if ( $length > 0 ) {
				$extra[ $side ] = (string) $length;
			}
		}

		if ( '' !== trim( (string) ( $attrs['class'] ?? '' ) ) ) {
			$extra['class'] = trim( (string) $attrs['class'] );
		}

		if ( '' !== trim( (string) ( $attrs['style'] ?? '' ) ) ) {
			$extra['style'] = trim( (string) $attrs['style'] );
		}

		if ( '' !== $label ) {
			$extra['role']       = 'img';
			$extra['aria-label'] = $label;
		} else {
			$extra['aria-hidden'] = 'true';
		}

		// Old Edge and IE put an SVG in the tab order; it costs nothing to
		// say it is not a stop.
		$extra['focusable'] = 'false';

		return '<svg' . self::render_attributes( $extra ) . substr( $svg, 4 );
	}

	/**
	 * The allowed attributes of one element, cleaned.
	 *
	 * @param DOMElement $element The element.
	 * @param bool       $root    Whether it is the outer element.
	 *
	 * @return array<string, string> By the attribute's own spelling.
	 */
	private static function attributes( DOMElement $element, bool $root = false ): array {
		$allowed = $root ? self::ROOT_ATTRIBUTES : self::ATTRIBUTES;
		$kept    = [];

		// Presentation written as a style attribute -- `style="fill: none"`,
		// which is how WordPress's own icons are written -- is kept as the
		// attributes it means, and the rest of the style is not.
		$from_style = self::style_attributes( $element->getAttribute( 'style' ) );

		foreach ( $from_style as $name => $value ) {
			if ( isset( $allowed[ $name ] ) ) {
				$kept[ $name ] = $value;
			}
		}

		foreach ( $element->attributes ?? [] as $attribute ) {
			$name = $attribute->prefix ? $attribute->prefix . ':' . $attribute->localName : $attribute->localName; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM's own names.
			$key  = strtolower( (string) $name );

			if ( 'xmlns' === $key || ! isset( $allowed[ $key ] ) ) {
				continue;
			}

			$value = self::clean_value( $key, (string) $attribute->value );

			if ( null === $value ) {
				continue;
			}

			// The spelling SVG uses, which is case-sensitive in a page.
			$kept[ 'viewbox' === $key ? 'viewBox' : self::spelling( $key ) ] = $value;
		}

		return $kept;
	}

	/**
	 * Every allowed child of an element, rebuilt.
	 *
	 * @param DOMNode $node The element.
	 *
	 * @return string Markup.
	 */
	private static function children( DOMNode $node ): string {
		$markup = '';

		foreach ( $node->childNodes as $child ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM's own names.
			// Text, comments, CDATA and processing instructions are all
			// dropped: an icon's shapes are elements, and a `<script>` hid
			// inside CDATA is still a script.
			if ( ! $child instanceof DOMElement ) {
				continue;
			}

			$name = strtolower( $child->localName ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM's own names.

			if ( ! isset( self::ELEMENTS[ $name ] ) || 'svg' === $name ) {
				continue;
			}

			$attributes = self::attributes( $child );

			// A `use` whose link was refused points at nothing.
			if ( 'use' === $name && ! isset( $attributes['href'] ) && ! isset( $attributes['xlink:href'] ) ) {
				continue;
			}

			$inner = self::children( $child );

			// Self-closed when empty, which is most of an icon: a path is
			// all attributes. Inline SVG in HTML reads `/>` as closing.
			$markup .= '' === $inner
				? sprintf( '<%s%s/>', self::spelling( $name ), self::render_attributes( $attributes ) )
				: sprintf( '<%1$s%2$s>%3$s</%1$s>', self::spelling( $name ), self::render_attributes( $attributes ), $inner );
		}

		return $markup;
	}

	/**
	 * A value, if it is safe to keep.
	 *
	 * A link may only be a fragment within the icon. Anything that could
	 * reach outside it -- a scheme, `url()` to anything but a fragment,
	 * a CSS expression, an escape that could spell either -- is dropped.
	 *
	 * @param string $name  The attribute, lower-case.
	 * @param string $value Its value.
	 *
	 * @return string|null Null to drop it.
	 */
	private static function clean_value( string $name, string $value ): ?string {
		$value = trim( $value );

		if ( isset( self::LINKS[ $name ] ) ) {
			return 1 === preg_match( '/^#[A-Za-z][\w.-]*$/', $value ) ? $value : null;
		}

		$lower = strtolower( $value );

		if ( str_contains( $lower, ':' ) || str_contains( $lower, '\\' ) || str_contains( $lower, 'expression' ) || str_contains( $value, '<' ) ) {
			return null;
		}

		// url() only to a gradient, clip or mask inside the icon.
		if ( str_contains( $lower, 'url(' ) && 1 !== preg_match( '/^url\(\s*#[A-Za-z][\w.-]*\s*\)$/', $value ) ) {
			return null;
		}

		return $value;
	}

	/**
	 * The presentation attributes a style attribute sets.
	 *
	 * @param string $style The style attribute.
	 *
	 * @return array<string, string> Attribute by lower-case name; only safe values.
	 */
	private static function style_attributes( string $style ): array {
		$found = [];

		foreach ( explode( ';', $style ) as $declaration ) {
			$parts = explode( ':', $declaration, 2 );

			if ( 2 !== count( $parts ) ) {
				continue;
			}

			$name  = strtolower( trim( $parts[0] ) );
			$value = self::clean_value( $name, $parts[1] );

			if ( '' !== $name && null !== $value && '' !== $value && isset( self::ATTRIBUTES[ $name ] ) && ! isset( self::LINKS[ $name ] ) ) {
				$found[ $name ] = $value;
			}
		}

		return $found;
	}

	/**
	 * The case-sensitive spelling of an element or attribute.
	 *
	 * XML is case-sensitive and so is an SVG inlined into HTML for these
	 * few: `linearGradient` written in lower case is an unknown element and
	 * draws nothing.
	 *
	 * @param string $name Lower-case name.
	 *
	 * @return string
	 */
	private static function spelling( string $name ): string {
		return [
			'clippath'            => 'clipPath',
			'lineargradient'      => 'linearGradient',
			'radialgradient'      => 'radialGradient',
			'gradientunits'       => 'gradientUnits',
			'gradienttransform'   => 'gradientTransform',
			'clippathunits'       => 'clipPathUnits',
			'maskunits'           => 'maskUnits',
			'preserveaspectratio' => 'preserveAspectRatio',
			'viewbox'             => 'viewBox',
		][ $name ] ?? $name;
	}

	/**
	 * Attributes as markup, each escaped.
	 *
	 * @param array<string, string> $attributes By name.
	 *
	 * @return string With a leading space, or empty.
	 */
	private static function render_attributes( array $attributes ): string {
		$markup = '';

		foreach ( $attributes as $name => $value ) {
			$markup .= sprintf( ' %s="%s"', $name, htmlspecialchars( $value, ENT_QUOTES | ENT_XML1, 'UTF-8' ) );
		}

		return $markup;
	}

	/**
	 * A number as an SVG writes it: no trailing zeros.
	 *
	 * @param float $number The number.
	 *
	 * @return string
	 */
	private static function number( float $number ): string {
		return rtrim( rtrim( sprintf( '%.3F', $number ), '0' ), '.' );
	}
}
