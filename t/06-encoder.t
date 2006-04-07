# $Id$

use strict;
use HTML::Sanitizer;
use Test::More tests => 8;

my $safe = HTML::Sanitizer->new;

## Default encoder encodes '<>"&.
is $safe->sanitize(\"'"), '&#39;';
is $safe->sanitize(\'"'), '&quot;';
is $safe->sanitize(\'&'), '&amp;';
is $safe->sanitize(\'>'), '&gt;';

## Try a null encoder, instead.
$safe->set_encoder(sub { $_[0] });
is $safe->sanitize(\"'"), "'";
is $safe->sanitize(\'"'), '"';
is $safe->sanitize(\'&'), '&';
is $safe->sanitize(\'>'), '>';
