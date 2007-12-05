use strict;
use Test::More 'no_plan';
use HTML::Sanitizer;

my $s = HTML::Sanitizer->new('*' => 1);
my $out = $s->sanitize(\"<p>0</p>");
is $out, "<p>0</p>";

