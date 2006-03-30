# $Id$

use inc::Module::Install;

name('HTML-Sanitizer');
abstract('Clean and sanitize HTML');
author('Six Apart <cpan@sixapart.com>');
version_from('lib/HTML/Sanitizer.pm');
license('perl');
no_index(directory => 't');
sign(1);

include('ExtUtils::AutoInstall');

requires('HTML::TokeParser');
requires('HTML::Entities');
requires('HTML::Tagset');

build_requires('Test::More');
build_requires('HTML::Element');

auto_include();
auto_install();

&WriteAll;
