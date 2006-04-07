# $Id$

use strict;
use HTML::Sanitizer;
use HTML::Element;
use Test::More;

plan tests => 20;

our %AllowedTags = map { $_ => 1 } qw(
  a abbr acronym address area b bdo big blockquote br caption center cite code
  col colgroup dd del dfn dir div dl dt em font h1 h2 h3 h4 h5 h6 hr i img ins
  legend li map menu ol p pre q s samp small span strike strong sub
  sup table tbody td tfoot th thead tr tt u ul
);

our %AllowedAttr = map { $_ => 1 } qw(
  align alt background bgcolor char charoff charset cite class color colspan
  coords dir face height href hreflang id lang longdesc name nohref
  noshade rel rev rowspan shape size src style target title type usemap valign
  width xml:lang
);

sub is_cleaned ($$;$) {
    my($dirty, $clean, $name) = @_;
    my $xhtml = sanitizer()->sanitize(\$dirty);
    #my $xhtml = sanitizer()->filter_xml_fragment($dirty);
    $xhtml =~ s/\s$//;
    is $xhtml, $clean, $name;
}

my $html;

$html = <<HTML;
<style type="text/css"> BAD { background: #666; color: #666;}</style>
HTML
is_cleaned $html, '', 'style tag is stripped';

$html = <<HTML;
<script language="javascript"> alert("Hello, I am EVIL!");</script>
HTML
is_cleaned $html, '', 'script tag is stripped';

is_cleaned '<center>Hi!</center>', '<div style="text-align: center">Hi!</div>', 'center => div';

is_cleaned '<i>italic</i>', '<em>italic</em>', 'i => em';

is_cleaned '<hr>', '<hr />', 'hr => hr /';

is_cleaned '<br>', '<br />', 'br => br /';

is_cleaned '<b>bold</b>', '<strong>bold</strong>', 'b => strong';

is_cleaned '<p background="foo.gif">Paragraph</p>', '<p style="background-image: url(foo.gif)">Paragraph</p>', 'background => style: background-image';

is_cleaned '<p bgcolor="#F0F0F0">Paragraph</p>', '<p style="background-color: #f0f0f0">Paragraph</p>', 'bgcolor => style: background-color';

is_cleaned '<font color="#EEE">Font</font>', '<span style="color: #eee">Font</span>', 'color => style: color';

is_cleaned '<font face="Verdana, sans-serif">Font</font>', '<span style="font-family: verdana, sans-serif">Font</span>', 'face => style: font-family';

is_cleaned '<font size="5">Font</font>', '<span style="font-size: x-large">Font</span>', 'size => style: font-size';

is_cleaned '<font size="9">Font</font>', '<span style="font-size: 7.45em">Font</span>', 'size => style: font-size with em';

is_cleaned '<font face="Verdana" style="line-height: 1.1em">Font</font>', '<span style="font-family: verdana; line-height: 1.1em">Font</span>', 'existing style is merged with new';

is_cleaned '<div width="100">Big div</div>', '<div style="width: 100px">Big div</div>', 'width => style: width with px';

is_cleaned '<div height="200">Big div</div>', '<div style="height: 200px">Big div</div>', 'height => style: height with px';

is_cleaned '<p align="right">This is a right-aligned paragraph.</p>', '<p style="text-align: right">This is a right-aligned paragraph.</p>', 'align => style: text-align';

is_cleaned '<strip>Hi</strip>', 'Hi', 'single element is stripped';

is_cleaned '<rmnode>Hi</rmnode>', '', 'entire node is removed';

is_cleaned '<foo>Hi</foo>', '<bar />', 'foo node is replaced with string';

sub sanitizer {
    my $safe = HTML::Sanitizer->new(
            %AllowedTags,

            strip  => 0,
            rmnode => undef,

            foo => sub { \'<bar />' },

            applet => HTML::Element->new('object'),
            b      => HTML::Element->new('strong'),
            center => HTML::Element->new('div', style => 'text-align: center'),
            font   => HTML::Element->new('span'),
            i      => HTML::Element->new('em'),
            menu   => HTML::Element->new('ul'),
            s      => HTML::Element->new('del'),
            strike => HTML::Element->new('del'),
            xmp    => HTML::Element->new('pre'),

            _      => {
                %AllowedAttr,

                align => sub {
                    my($elem, $attr, $value) = @_;
                    add_style($elem, 'text-align: ' . lc($value));
                    return 0;
                },

                face => sub {
                    my($elem, $attr, $value) = @_;
                    add_style($elem, 'font-family: ' . lc($value));
                    return 0;
                },

                size => sub {
                    my($elem, $attr, $value) = @_;
                    my %map = (
                        0 => 'xx-small',
                        1 => 'x-small',
                        2 => 'small',
                        3 => 'medium',
                        4 => 'large',
                        5 => 'x-large',
                        6 => 'xx-large',
                        7 => 'xx-large',
                    );
                    $value = $map{$value} || sprintf "%.02fem", 1.25 ** $value;
                    add_style($elem, 'font-size: ' . $value);
                    return 0;
                },

                color => sub {
                    my($elem, $attr, $value) = @_;
                    add_style($elem, 'color: ' . lc($value));
                    return 0;
                },

                bgcolor => sub {
                    my($elem, $attr, $value) = @_;
                    add_style($elem, 'background-color: ' . lc($value));
                    return 0;
                },

                background => sub {
                    my($elem, $attr, $value) = @_;
                    add_style($elem, 'background-image: url(' . lc($value) . ')');
                    return 0;
                },

                width => sub {
                    my($elem, $attr, $value) = @_;
                    $value .= 'px' unless $value =~ /%\s*$/;
                    add_style($elem, 'width: ' . $value);
                    return 0;
                },

                height => sub {
                    my($elem, $attr, $value) = @_;
                    $value .= 'px' unless $value =~ /%\s*$/;
                    add_style($elem, 'height: ' . $value);
                    return 0;
                },

                '*'    => 0,
            },
        );
    $safe;
}

sub add_style {
    my($elem, $new) = @_;
    if (my $style = $elem->[2]{style}) {
        $new .= '; ' . $style;
    }
    $elem->[2]{style} = $new;
}
