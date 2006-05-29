# $Id$

use strict;
use HTML::Sanitizer;
use HTML::Element;
use Test::More tests => 42;

my $safe = HTML::Sanitizer->new(
    p     => 1,
    div   => 0,
    span  => undef,
    b     => HTML::Element->new('strong'),
    i     => HTML::Element->new('em', attr => 'new_value'),
    u     => HTML::Element->new('address')->push_content('new content'),
    sup   => HTML::Element->new('sub')->push_content(''),
    a     => {
        attr1 => 1,
        attr2 => 0,
        attr3 => qr/ok_value/,
        attr4 => sub { s/sub_value/new_value/ },
    },
    '_'   => {
        attr_ok  => 1,
        attr_bad => undef,
        '*'      => undef,
    },
    '*'   => undef,
);

is $safe->filter_xml_fragment('<p>content p</p>'), '<p>content p</p>',"'permit' rule";

is $safe->filter_xml_fragment('<p>foo &amp; bar</p>'), '<p>foo &amp; bar</p>', "HTML entities in a tag content";

is $safe->filter_xml_fragment('<a attr1="http://example/?foo=bar&amp;baz=quox">foo &amp; bar</a>'), '<a attr1="http://example/?foo=bar&amp;baz=quox">foo &amp; bar</a>', "HTML entities in a tag content and attributes";

is $safe->filter_xml_fragment('<p attr_ok="attr value">content p</p>'), '<p attr_ok="attr value">content p</p>', "'permit' rule, checking OK attributes";

is $safe->filter_xml_fragment('<p attr_bad="attr value">content p</p>'), '<p>content p</p>', "'permit' rule, checking bad attributes";

is $safe->filter_xml_fragment('<p attr_unk="attr value">content p</p>'), '<p>content p</p>', "'permit' rule, checking unknown attributes";

is $safe->filter_xml_fragment('<p>ok</p><div>content div</div>'), '<p>ok</p>content div', "'ignore' rule";

is $safe->filter_xml_fragment('<p>ok</p><div>content div</div><span>content span</span>'), '<p>ok</p>content div', "'deny' rule";

is $safe->filter_xml_fragment('<p>ok</p><b>content b</b>'), '<p>ok</p><strong>content b</strong>', "HTML::Element rule";

is $safe->filter_xml_fragment('<p>ok</p><i attr="old_value">content i</i>'), '<p>ok</p><em attr="new_value">content i</em>', "HTML::Element rule, attribute overlay";

is $safe->filter_xml_fragment('<p>ok</p><i attr_ok="attr value" attr="old_value">content i</i>'), '<p>ok</p><em attr="new_value" attr_ok="attr value">content i</em>', "HTML::Element rule, attribute overlay with existing OK attribute";

is $safe->filter_xml_fragment('<p>ok</p><i attr_bad="attr value" attr="old_value">content i</i>'), '<p>ok</p><em attr="new_value">content i</em>', "HTML::Element rule, attribute overlay with existing bad attribute";

is $safe->filter_xml_fragment('<p>ok</p><sup>content sup</sup>'), '<p>ok</p><sub></sub>', "HTML::Element rule with empty replacement content";

is $safe->filter_xml_fragment('<p>ok</p><u>content u</u>'), '<p>ok</p><address>new content</address>', "HTML::Element rule with replacement content";

is $safe->filter_xml_fragment('<a>content a</a>'), '<a>content a</a>', "Attribute rules imply tag permit";

is $safe->filter_xml_fragment('<a attr1="attr value">content a</a>'), '<a attr1="attr value">content a</a>', "Attribute OK rule";

is $safe->filter_xml_fragment('<a attr2="attr value">content a</a>'), '<a>content a</a>', "Attribute deny rule";

is $safe->filter_xml_fragment('<a attr3="xyz ok_value xyz">content a</a>'), '<a attr3="xyz ok_value xyz">content a</a>', "Attribute OK regex rule";

is $safe->filter_xml_fragment('<a attr3="xyz bad_value xyz">content a</a>'), '<a>content a</a>', "Attribute failed regex rule";

is $safe->filter_xml_fragment('<a attr4="xyz sub_value xyz">content a</a>'), '<a attr4="xyz new_value xyz">content a</a>', "Attribute OK code rule";

is $safe->filter_xml_fragment('<a attr4="xyz bad_value xyz">content a</a>'), '<a>content a</a>', "Attribute failed code rule";

is $safe->filter_xml_fragment('<p>content p</p><blockquote attr4="xyz bad_value xyz">content blockquote</blockquote>'), '<p>content p</p>', "Unknown element should be stripped";

$safe->ignore('*');

is $safe->filter_xml_fragment('<p>content p</p><blockquote attr4="xyz bad_value xyz">content <blockquote>blockquote</blockquote></blockquote>'), '<p>content p</p>content blockquote', "Unknown element should be removed with child elements promoted";

$safe = HTML::Sanitizer->new;

is $safe->filter_xml_fragment('<p>content</p>'), '', "default should be filtered";

$safe->permit('p', 'i');

is $safe->filter_xml_fragment('<p>content</p><em>content</em>'), '<p>content</p>', "'permit' function";

$safe->ignore('em');

is $safe->filter_xml_fragment('<p>content</p><em>content</em>'), '<p>content</p>content', "'ignore' function";

$safe->deny('p');

is $safe->filter_xml_fragment('<p>content one</p><i>content two</i>'), '<i>content two</i>', "'deny' function";

$safe->deny_only('i');

is $safe->filter_xml_fragment('<p>content one</p><i>content two</i>'), '<p>content one</p>', "'deny_only' function";

$safe->ignore_only('p');

is $safe->filter_xml_fragment('<p>content one</p><i>content two</i>'), 'content one<i>content two</i>', "'ignore_only' function";

$safe->permit_only('p');

is $safe->filter_xml_fragment('<p>content one</p><i>content two</i>'), '<p>content one</p>', "'permit_only' function";

is $safe->filter_xml('<p>content one</p><i>content two</i>'), '<html><body><p>content one</p></body></html>', "'filter_xml' function";

is $safe->filter_html('<p>content one</p><i>content two</i>'), '<html><body><p>content one</p></body></html>', "'filter_html' function";

is $safe->filter_html_fragment('<p>content one</p><i>content two</i>'), '<p>content one</p>', "'filter_html_fragment' function";

$safe = HTML::Sanitizer->new;

is $safe->sanitize(\'foo'), 'foo';

$safe->ignore_only('code');
is $safe->sanitize(\'<code>code</code>'), 'code';

$safe->permit_only('b');
is $safe->sanitize(\'<b>bold</b>'), '<b>bold</b>';

$safe->ignore_only('b');
is $safe->sanitize(\'<b>not bold</b>'), 'not bold';

$safe->permit_only('b', '*' => [ 'style' ]);
is $safe->sanitize(\'<b style="color: red;">red bold</b>'), '<b style="color: red;">red bold</b>';

$safe->permit_only('br');
is $safe->sanitize(\'Some text<br />with a line break'), 'Some text<br />with a line break';
is $safe->sanitize(\'Some text<br>with a line break'), 'Some text<br />with a line break';

$safe->permit_only('br', 'p');
is $safe->sanitize(\'<p>Paragraphs<br />with line breaks</p>'), '<p>Paragraphs<br />with line breaks</p>';

$safe->permit_only('p');
is $safe->sanitize(\'<p>The pièce de résistance. A veritable tongue bath to those who sign the cheques. </p>'), '<p>The pièce de résistance. A veritable tongue bath to those who sign the cheques. </p>';
