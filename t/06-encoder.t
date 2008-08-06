# $Id$

use strict;
use HTML::Sanitizer;
use Test::More tests => 9;

my $safe = HTML::Sanitizer->new;

## Default encoder encodes '<>"&.
is $safe->sanitize(\"'"), '&#39;';
is $safe->sanitize(\'"'), '&quot;';
is $safe->sanitize(\'&'), '&amp;';
is $safe->sanitize(\'>'), '&gt;';

$safe->permit( 'script', _ => { '*' => 1 } );

my $out = $safe->sanitize( \<<IN );
3 > 2
<script type="text/javascript">
alert( 3 > 2 ? 'hi' : 'bye' );
</script>
IN
is $out, <<OUT, 'stuff inside script tags isn\'t encoded';
3 &gt; 2
<script type="text/javascript">
alert( 3 > 2 ? 'hi' : 'bye' );
</script>
OUT

## Try a null encoder, instead.
$safe->set_encoder(sub { $_[0] });
is $safe->sanitize(\"'"), "'";
is $safe->sanitize(\'"'), '"';
is $safe->sanitize(\'&'), '&';
is $safe->sanitize(\'>'), '>';
