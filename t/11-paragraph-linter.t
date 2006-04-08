# $Id$

use strict;
use HTML::Sanitizer;
use HTML::TokeParser;
use Test::More tests => 13;

is _lint('<p>First</p><p>Second</p>'), '<p>First</p><p>Second</p>', 'Already properly formed';

is _lint('First<br /><br />Second'), '<p>First</p><p>Second</p>', 'No paragraph tags, double br';

is _lint('<p>Fi<br />rst</p><p>Second</p>'), '<p>Fi<br />rst</p><p>Second</p>', 'properly formed: br in the middle does not cause a new paragraph';

is _lint('Fi<br />rst<br /><br />Second'), '<p>Fi<br />rst</p><p>Second</p>', 'transform: br in the middle does not cause a new paragraph';

is _lint('<p>First<br /><br />Second</p>'), '<p>First</p><p>Second</p>', 'transform: paragraph around two br tags causes two paragraphs';

is _lint('<strong>First</strong><br /><br />Second'), '<p><strong>First</strong></p><p>Second</p>', 'transform: strong works with paragraphs';

is _lint('Fi<strong>r</strong>st<br /><br />Second'), '<p>Fi<strong>r</strong>st</p><p>Second</p>', 'transform: strong works with paragraphs, part 2';

is _lint('This is some text outside of <b>anything</b>.'), '<p>This is some text outside of <b>anything</b>.</p>', 'Single paragraph with b tag';

is _lint('<blockquote>This is some bare text inside a blockquote. It should be in a paragraph, like with bare text in body.</blockquote>'), '<blockquote><p>This is some bare text inside a blockquote. It should be in a paragraph, like with bare text in body.</p></blockquote>', 'Simple paragraph inside blockquote';

is _lint('<blockquote><br />Text with a break inside a blockquote. The entire contents of the blockquote should be placed inside a paragraph.</blockquote>'), '<blockquote><p><br />Text with a break inside a blockquote. The entire contents of the blockquote should be placed inside a paragraph.</p></blockquote>', 'Paragraph with a break inside blockquote';

is _lint('<blockquote><img src="foo.gif" width="100" height="100" />Text with an image inside a blockquote. The text and image should be placed inside a paragraph.</blockquote>'), '<blockquote><p><img height="100" src="foo.gif" width="100" />Text with an image inside a blockquote. The text and image should be placed inside a paragraph.</p></blockquote>', 'Paragraph with an image inside blockquote';

is _lint('<blockquote>This blockquote should be split into two paragraphs.<br /><br />This is the 2nd paragraph.<br /><br /></blockquote>'), '<blockquote><p>This blockquote should be split into two paragraphs.</p><p>This is the 2nd paragraph.</p></blockquote>', 'Two paragraphs inside blockquote';

is _lint('<div>First</div>'), '<div>First</div>', 'Text inside div does not get changed';

sub _lint {
    my($html) = @_;

    my $parser = HTML::TokeParser->new(\$html);

    my $safe = HTML::Sanitizer->new;
    $safe->permit(qw( p br strong b blockquote div ),
        img => {
            src => 1,
            width => 1,
            height => 1,
        });

    my $out = '';
    my @block_stack = ('body');
    my %no_inline_content = map { $_ => 1 } qw( body blockquote );

    while (my $token = $parser->get_token) {
        ## If we found an end tag for a block-level tag that isn't a
        ## paragraph tag, and we're currently inside of a paragraph tag,
        ## that means we must have inserted the <p> tag. Close it.
        if ($block_stack[-1] eq 'p' &&
            $token->[0] eq 'E' &&
            $token->[1] ne 'p' &&
            !$HTML::Tagset::isPhraseMarkup{ $token->[1] }) {
            $out .= '</p>';
            pop @block_stack;
        }

        ## Manage a stack of block-level tags (don't bother with inline).
        if (!$HTML::Tagset::isPhraseMarkup{ $token->[1] }) {
            if ($token->[0] eq 'S') {
                push @block_stack, $token->[1];
            } elsif ($token->[0] eq 'E') {
                pop @block_stack;
            }
        }

        ## If the current block tag context doesn't allow inline content,
        ## and if we've found inline content (either a text token or an
        ## inline tag), wrap it in a <p> tag.
        if ($no_inline_content{ $block_stack[-1] } &&
            ($token->[0] eq 'T' ||
            ($token->[0] eq 'S' &&
             $HTML::Tagset::isPhraseMarkup{ $token->[1] }))) {
            $out .= '<p>';
            push @block_stack, 'p';
        }

        ## Now for the <br /> handling: if we're in a <p> tag, and we
        ## find a <br /> tag, check the next token. Is it also a <br />
        ## tag? If so, we should end this paragraph.
        if ($block_stack[-1] eq 'p' && $token->[0] eq 'S' && $token->[1] eq 'br') {
            my $next = $parser->get_token;
            if ($next->[0] eq 'S' && $next->[1] eq 'br') {
                $out .= '</p>';
                pop @block_stack;
                next;
            } else {
                $parser->unget_token($next);
            }
        }

        $out .= $safe->sanitize_token($parser, $token);
    }

    if ($block_stack[-1] eq 'p') {
        $out .= '</p>';
    }

    $out;
}
