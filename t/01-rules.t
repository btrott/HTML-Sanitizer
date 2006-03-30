# $Id$

use strict;
use HTML::Sanitizer;
use Test::More tests => 21;

my $safe = HTML::Sanitizer->new;
isa_ok $safe, 'HTML::Sanitizer';

isa_ok $safe->rules, 'HASH';
is scalar (keys %{ $safe->rules }), 0;

$safe = HTML::Sanitizer->new( p => 1 );
is $safe->rules->{p}, 1;

$safe = HTML::Sanitizer->new;
$safe->permit('p');
is $safe->rules->{p}, 1;

$safe = HTML::Sanitizer->new;
$safe->permit_only('p');
is $safe->rules->{p}, 1;
is $safe->rules->{'*'}, undef;

$safe = HTML::Sanitizer->new( div => 0 );
is $safe->rules->{div}, 0;

$safe = HTML::Sanitizer->new;
$safe->ignore('div');
is $safe->rules->{div}, 0;

$safe = HTML::Sanitizer->new;
$safe->ignore_only('p');
is $safe->rules->{p}, 0;
is $safe->rules->{'*'}{'*'}, 1;

$safe = HTML::Sanitizer->new( span => undef );
is $safe->rules->{span}, undef;

$safe = HTML::Sanitizer->new;
$safe->deny('span');
is $safe->rules->{span}, undef;

$safe = HTML::Sanitizer->new;
$safe->deny_only('p');
is $safe->rules->{p}, undef;
is $safe->rules->{'*'}{'*'}, 1;

$safe = HTML::Sanitizer->new;
$safe->permit_only(
        qw( strong em br ),
        img => [ qw( src alt ) ],
    );
is $safe->rules->{strong}, 1;
is $safe->rules->{em}, 1;
is $safe->rules->{br}, 1;
is $safe->rules->{img}{src}, 1;
is $safe->rules->{img}{alt}, 1;
is $safe->rules->{'*'}, undef;
