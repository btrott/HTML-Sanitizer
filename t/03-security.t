# $Id$

use strict;
use HTML::Sanitizer;
use Test::More tests => 13;

my $safe = HTML::Sanitizer->new(
	p     => 1,
	'*'   => undef,
);

is $safe->filter_xml_fragment('<p>unsafe</p><script'), '<p>unsafe</p>', 'Incomplete script tag is stripped';

is $safe->filter_xml_fragment('<p attr_ok="test>unsafe</p>'), '', 'Incomplete p tag is stripped';

$safe = HTML::Sanitizer->new;
is $safe->sanitize(\'<?php readfile("/etc/passwd") ?>'), '';

is $safe->sanitize(\'<? readfile("/etc/passwd") ?>'), '';

is $safe->sanitize(\'passwords! <? readfile("/etc/passwd") ?>'), 'passwords! ';

is $safe->sanitize(\'<? start some evil PHP'), '';

is $safe->sanitize(\'<% some ASP code %>'), '&lt;% some ASP code %&gt;';

is $safe->sanitize(\'<!--#exec cgi="/some/bad.cgi"-->'), '';

is $safe->sanitize(\'<script src="evil.js">'), '';

$safe->ignore_only('a');
is $safe->sanitize(\'<a href="foo.html" onclick="runEvilJS()">kittens</a>'), 'kittens';

$safe->permit_only('a');
is $safe->sanitize(\'<a href="foo.html" onclick="runEvilJS()">kittens</a>'), '<a>kittens</a>';

$safe->permit_only(a => [ 'href' ]);
is $safe->sanitize(\'<a href="foo.html" onclick="runEvilJS()">kittens</a>'), '<a href="foo.html">kittens</a>';

$safe->permit_only(img => [ 'src' ]);
is $safe->sanitize(\'<img onmouseover="killComputer()" src="foo.jpg">'), '<img src="foo.jpg" />';
