# $Id$

package HTML::Sanitizer;
use strict;

our $VERSION = '0.10';

use fields qw( rules encoder );

use Carp qw( croak );
use HTML::TokeParser;
use HTML::Entities;
use HTML::Tagset;

sub new {
    my $class = shift;
    my $sanitizer = fields::new($class);
    $sanitizer->{rules} = ref($_[0]) ? shift : { @_ };
    $sanitizer->{encoder} = sub { 
        encode_entities($_[0], q('<>"&));
    };
    $sanitizer;
}

sub rules { $_[0]->{rules} }

sub set_encoder {
    my $sanitizer = shift;
    $sanitizer->{encoder} = $_[0];
}

sub permit {
    my $sanitizer = shift;
    my $rules = $sanitizer->{rules};

    while (@_) {
        my $element = shift;
        my $attrs = shift;

        if (UNIVERSAL::isa($attrs, 'HTML::Element')) {
            $rules->{$element} = $attrs;
        } elsif (ref($attrs) eq 'CODE') {
            $rules->{$element} = $attrs;
        } elsif (ref($attrs) eq 'ARRAY') {
            for my $key (@$attrs) {
                $rules->{$element}{$key} = 1;
            }
        } elsif (ref($attrs) eq 'HASH') {
            for my $key (keys %$attrs) {
                $rules->{$element}{$key} = $attrs->{$key};
            }
        } elsif (defined $attrs) {
            $rules->{$element} = 1;
            unshift(@_, $attrs);
        } else {
            $rules->{$element} = 1;
        }
    }
}

sub _deny {
    my $sanitizer = shift;
    my $with = shift;
    my $rules = $sanitizer->{rules};

    while (@_) {
        my $element = shift;
        my $attrs = shift;

        if (ref $attrs) {
            croak "Attribute list for deny/ignore must be an arrayref"
                unless ref($attrs) eq 'ARRAY';

            for my $key (@$attrs) {
                $rules->{$element}->{$_} = $with;
            }
            next;
        } 
        elsif (defined $attrs) {
            unshift @_, $attrs;
        }

        $rules->{$element} = $with;
    }
}

sub deny   { shift->_deny(undef, @_); }
sub ignore { shift->_deny(0, @_); }
    
sub permit_only {
    my $sanitizer = shift;

    $sanitizer->{rules} = {'*' => undef};
    $sanitizer->permit(@_);
}

sub deny_only {
    my $sanitizer = shift;

    $sanitizer->{rules} = {'*' => {'*' => 1 }};
    $sanitizer->deny(@_);
}

sub ignore_only {
    my $sanitizer = shift;

    $sanitizer->{rules} = {'*' => {'*' => 1 }};
    $sanitizer->ignore(@_);
}

sub filter_xml {
    my $sanitizer = shift;
    my $xhtml = $sanitizer->sanitize(\$_[0]);
    '<html><body>' . $xhtml . '</body></html>';
}
sub filter_xml_fragment { shift->sanitize(\$_[0]) }
*filter_html = \&filter_xml;
*filter_html_fragment = \&filter_xml_fragment;

sub sanitize {
    my $sanitizer = shift;
    my($stream) = @_;
    my $out = '';
    my $parser = HTML::TokeParser->new($stream)
        or croak "Parsing stream $stream failed";
    while (my $token = $parser->get_token) {
        my $res = $sanitizer->sanitize_token($parser, $token) or next;
        $out .= $res;
    }
    $out;
}

sub sanitize_token {
    my $sanitizer = shift;
    my($parser, $token) = @_;
    my $rules = $sanitizer->{rules};
    my $encoder = $sanitizer->{encoder};
    if ($token->[0] eq 'S') {
        my $tag = $token->[1];
        my $rule = $sanitizer->choose_rule_for($tag);

        ## If the $rule is defined and true, we need to apply it.
        if ($rule) {
            $sanitizer->sanitize_attributes($token);

            if (ref($rule) eq 'CODE') {
                my $res = $rule->($token);
                return unless $res;
                if (ref($res) eq 'SCALAR') {
                    $sanitizer->skip_node($parser, $tag);
                    return $$res;
                }
            }

            elsif (ref($rule) eq 'HTML::Element') {
                $sanitizer->merge_element_with_token($token, $rule);

                if (my @list = $rule->content_list) {
                    $sanitizer->skip_node($parser, $tag);
                    $parser->unget_token(
                            [ 'T', join('', @list) ],
                            [ 'E', $tag ]
                        );
                }
            }

            return $sanitizer->serialize_token($token);
        } elsif (defined $rule) {
            ## $rule == 0 means to skip this element, but keep its
            ## children.
            return;
        } else {
            ## $rule == undef means to skip this entire node in the tree.
            $sanitizer->skip_node($parser, $tag);
            return;
        }
    } elsif ($token->[0] eq 'E') {
        my $tag = $token->[1];
        my $rule = $sanitizer->choose_rule_for($tag);
        if (ref($rule) eq 'HTML::Element') {
            return '</' . $rules->{$tag}->tag . '>';
        } elsif ($rule) {
            return '</' . $tag . '>';
        }
    } elsif ($token->[0] eq 'T') {
        return $encoder->($token->[1]);
    }
}

sub sanitize_attributes {
    my $sanitizer = shift;
    my($token) = @_;

    my $tag = $token->[1];
    my $attributes = $token->[2];

    my $rules = $sanitizer->{rules};

    for my $attr (keys %$attributes) {
        $attr = lc $attr;

        my $r;
        ATTR_SEARCH: for my $o ($tag, "_", "*") {
            if (ref $rules->{$o}) {
                for my $i ($attr, '*') {
                    if (ref($rules->{$o}) eq 'HASH' &&
                        exists($rules->{$o}{$i})) {
                        $r = $rules->{$o}{$i};
                        last ATTR_SEARCH;
                    }
                }
            }
        }

        if (ref($r) eq 'Regexp') {
            delete $token->[2]{$attr}
                unless $attributes->{$attr} =~ /$r/;
        } 

        elsif (ref($r) eq 'CODE') {
            local $_ = $attributes->{$attr};
            if ($r->($token, $attr, $attributes->{$attr})) {
                unless ($_ eq $attributes->{$attr}) {
                    $attributes->{$attr} = $_;
                }
            } else {
                delete $token->[2]{$attr};
            }
        } 

        elsif (!$r) {
            delete $token->[2]{$attr};
        }
    }
}

sub choose_rule_for {
    my $sanitizer = shift;
    my($tag) = @_;
    my $rules = $sanitizer->{rules};
    if (defined $rules->{$tag}) {
        return $rules->{$tag};
    } elsif (!exists $rules->{$tag} && defined $rules->{'*'}) {
        return $rules->{'*'};
    }
    return undef;
}

sub merge_element_with_token {
    my $sanitizer = shift;
    my($token, $elem) = @_;
    $token->[1] = $elem->tag;
    my %attributes = $elem->all_external_attr;
    for my $attr (keys %attributes) {
        unless (exists $token->[2]{$attr}) {
            push @{ $token->[3] }, $attr;
        }
        $token->[2]{$attr} = $attributes{$attr};
    }
}

sub skip_node {
    my $sanitizer = shift;
    my($parser, $tag) = @_;
    return if $HTML::Tagset::emptyElement{$tag};
    my $t;
    my $level = 1;
    while (1) {
        $t = $parser->get_token or return;
        next unless $t->[0] eq 'S' || $t->[0] eq 'E';
        next unless $t->[1] eq $tag;
        if ($t->[0] eq 'S') {
            $level++;
            next;
        } elsif ($t->[0] eq 'E') {
            $level--;
        }
        return if $level <= 0;
    }
}

sub serialize_token {
    my $sanitizer = shift;
    my($token) = @_;
    my $out = '<' . $token->[1];
    my $attr = $token->[2];
    my $encoder = $sanitizer->{encoder};
    for my $key (sort keys %$attr) {
        my $val = $encoder->($attr->{$key});
        $out .= qq( $key="$val");
    }
    $out .= $HTML::Tagset::emptyElement{$token->[1]} ? ' />' : '>';
    $out;
}

1;
__END__

=head1 NAME

HTML::Sanitizer - Clean and sanitize HTML

=head1 SYNOPSIS

    my $safe = HTML::Sanitizer->new;

    $safe->permit_only(
        qw/ strong em /,
        a => {
            href => qr/^(?:http|ftp):/,
            title => 1,
        },
        img => {
            src => qr/^(?:http|ftp):/,
            alt => 1,
        },
        b => HTML::Element->new('strong'),
    );

    $sanitized = $safe->sanitize(\$evil_html);

=head1 ABSTRACT

This module acts as a filter for HTML. It is not a validator, though it
might be possible to write a validator-like tool with it. It's intended
to strip out unwanted/unsafe HTML elements and attributes and leave you with
non-dangerous HTML code that you should be able to trust.

=head1 DESCRIPTION

First, though this module attempts to strip out unwanted HTML, there is no
guarantee that it will be unbeatable. As always, tread lightly when using
untrusted data.

=head2 RULE SETUP

See the L<RULE SETS> section below for details on what a rule set actually
is.  This section documents the methods you'd use to set one up.

=over 4

=item new(...)

Creates a new C<HTML::Sanitizer> object, using the given ruleset.
Alternatively, a ruleset can be built piecemeal using the permit/deny
methods described below.

See the section on L<RULE SETS> below to see how to construct a
filter rule set.  An example might be:

  $safe = new HTML::Sanitizer(
     strong => 1,			# allow <strong>, <em> and <p>
     em => 1,
     p => 1,
     a => { href => qr/^http:/ },	# allow HTTP links
     b => HTML::Element->new('strong'), # convert <b> to <strong>
     '*' => 0,				# disallow everything else
  );

=item permit(...)

Accepts a list of rules and assumes each rule will have a true
value.  This allows you to be a little less verbose, since your
rule sets can look like this instead of a large data structure:

  $safe->permit( qw/ strong em i b br / );

Though you're still free to include attributes and more complex
validation requirements, if you still need them:

  $safe->permit( img => [ qw/ src alt / ], ... );

  $safe->permit( a => { href => qr/^http:/ }, 
                 blockquote => [ qw/ cite id / ], 
                 b => HTML::Element->new('strong'),
                 qw/ strong em /);

The value to each element should be an array, hash or code reference,
or an HTML::Element object, since the '=> 1' is always implied otherwise.

=item permit_only(...)

Like permit, but also assumes a default 'deny' policy.  This is
equivalent to including this in your ruleset as passed to new():

  '*' => undef

This will destroy any existing rule set in favor of the one you pass it.

If you would rather use a default 'ignore' policy, you could do
something like this:

  $safe->permit_only(...);
  $safe->ignore('*');

=item deny(...)

Like permit, but assumes each case will have a 'false' value by assuming a
'=> undef' for each element that isn't followed by an array reference.
This will cause any elements matching these rules to be stripped from
the document tree (along with any child elements).  You cannot pass
a hash reference of attributes, a code reference or an HTML::Element
object as a value to an element, as in permit.  If you need more complex
validation requirements, follow up with a permit() call or define them
in your call to new().

  $safe->deny( a => ['href'], qw/ img object embed script style /);

=item deny_only(...)

Like deny, but assumes a default 'permit' policy.  This is equivalent
to including this in your ruleset:

  '*' => { '*' => 1 }	# allow all elements and all attributes

This will destroy any existing rule set in favor of the one you pass it.

=item ignore(...)

Very similar to deny, this will cause a rule with an implied '=> 0' to
be created for the elements passed.  Matching elements will be replaced
with their child elements, with the element itself being removed from
the document tree.

=item ignore_only(...)

Like ignore, but assumes a default 'permit' policy.  See 'deny_only'.

=back

=head2 FILTER METHODS

=over 4

=item sanitize_tree($tree)

This runs the filter on a parse tree, as generated by HTML::TreeParser.
This WILL modify $tree.  This function is used by the filter functions
below, so you don't have to deal with HTML::TreeParser unless you
want to.

=item filter_html($html)

Filters an HTML document using the configured rule set.

=item filter_html_fragment($html)

Filters an HTML fragment.  Use this if you're filtering a chunk of
HTML that you're going to end up using within an existing document.
(In other words, it operates on $html as if it were a complete document,
but only ends up working on children of the <body> tag.)

=item filter_xml($xml)

=item filter_xml_fragment($xml)

Like above, but operates on the data as though it were well-formed XML.
Use this if you intend on providing XHTML, for example.

=back

When the above functions encounter an attribute they're meant to filter,
the attribute will be deleted from the element, but the element will
survive.  If you need to delete the entire element if an attribute
doesn't pass validation, set up a coderef for the element in your rule
set and use L<HTML::Element> methods to manipulate the element (e.g. by
calling C<$element->delete> or C<$element->replace_with_content> if
C<$element->attr('href')> doesn't pass muster.)

=head1 RULE SETS

A rule set is simply a list of elements and/or attributes and values
indicating whether those elements/attributes will be allowed, ignored,
or stripped from the parse tree.  Generally rule sets should be passed
to new() at object creation time, though they can also be built piecemeal
through calls to permit, deny and/or ignore as described above.

Each element in the list should be followed by one of the following:

=over 4

=item a 'true' value

This indicates the element should be permitted as-is with no filtering
or modification (aside from any other filtering done to child elements).

=item 0

If a zero (or some other defined, false value) is given, the element
itself is deleted but child elements are brought up to replace it.
Use this when you wish to filter a bad formatting tag while preserving
the text it was formatting, for example.

=item undef

If an undef is given, the element and all of its children will be deleted.
This would remove a scripting tag and all of its contents from the
document tree, for example.

=item an HTML::Element object

A copy of this object will replace the element matching the rule.
The attributes in the replacement object will overlay the attributes of
the original object (after attribute filtering has been done through
the _ rule).  If this element contains any child elements, they will
replace the children of the element fitting the rule.  If you wish
to delete the content without necessarily providing any replacement,
create a child that's simply an empty text node.

=item a code reference

This would permit the element if, and only if, the coderef returned a
true value.  The HTML::Element object in question is passed as the first
and only argument.

=item a hash reference

This implies the element itself is OK, but that some additional checking
of its attribute list is needed.  This hash reference should contain
keys of attributes and values that in turn should be one of:

=over 4

=item a 'true' value

This would preserve the attribute.

=item a 'false' value

This would delete the attribute.

=item a regular expression

This would preserve the attribute if the regular expression matched.

=item a code reference

This would permit the attribute if and only if the coderef returned
a true value.  The HTML::Element object, the attribute name and
attribute value are passed as arguments.  $_ is also set to the
attribute value (which can be modified).

=back 4

=back 4

=head2 EXAMPLES

Here is a sample rule set, which might do a fair job at stripping out
potentially dangerous tags, though I put this together without too much
thought, so I wouldn't rely on it:

  'script'          => undef,
  'style'           => undef,
  '*'               => {
  	onclick     => 0,
  	ondblclick  => 0,
  	onselect    => 0,
  	onmousedown => 0,
  	onmouseup   => 0,
  	onmouseover => 0,
  	onmousemove => 0,
  	onmouseout  => 0,
  	onfocus     => 0,
  	onblur      => 0,
  	onkeypress  => 0,
  	onkeydown   => 0,
  	onkeyup     => 0,
  	onselect    => 0,
  	onload      => 0,
  	onunload    => 0,
  	onerror     => 0,
  	onsubmit    => 0,
  	onreset     => 0,
  	onchange    => 0,
  	style       => 0,
  	href        => qr/^(?!(?:java)?script)/,
  	src         => qr/^(?!(?:java)?script)/,
  	cite        => sub { !/^(?:java)?script/ },  # same thing, mostly
  	'*'         => 1,
  },
  'link'            => {
  	rel         => sub { not_member("stylesheet", @_) },
  },
  'object'          => 0,	# strip but let children show through
  'embed'           => undef,
  'iframe'          => undef,
  'frameset'        => undef,
  'frame'           => undef,
  'applet'          => undef,
  'noframes'        => 0,
  'noscript'        => 0,

  # use a function like this to do some additional validation:

  sub not_member { !/\b\Q$_[0]\E\b/i; }	# maybe substitute it out instead

A web site incorporating user posts might want something a little more
strict:

  em           => 1,
  strong       => 1,
  p            => 1,
  ol           => 1,
  ul           => 1,
  li           => 1,
  tt           => 1,
  a            => 1,
  img          => 1,
  span         => 1,
  blockquote   => { cite => 1 },
  _            => {	 # for all tags above, these attribute rules apply:
      href     => qr/^(?:http|ftp|mailto|sip):/i,
      src      => qr/^(?:http|ftp|data):/i,
      title    => 1,
                  # Maybe add an x- prefix to all ID's to avoid collisions
      id       => sub { $_ = "x-$_" },
      xml:lang => 1,
      lang     => 1,
      *        => 0,
  },
  '*'          => 0,	 # everything else is 'ignored'
  script       => undef, # except these, which are stripped along with children
  style        => undef,

Note the use of the _ element here, which is magic in that it allows you
to set up some global attributes while still leaving the * element free
to express a default 'deny' policy.  The attributes specified here will
be applied to all of the explicitly defined elements (em, strong, etc.),
but they will not be applied to elements not present in the ruleset.

Attribute rule precedence goes from the tag-specific, the special "_" tag
and then the special "*" tag.

The following might be a simple way to force a 'b' tag to become a
'strong' tag, with the text within it surviving:

  b => HTML::Element->new('strong');

Here's how you might strip out a 'script' tag while letting the user
know something is up:

  script => HTML::Element
	->new('p', class => 'script_warning')
	->push_content("Warning: A <script> tag was removed!");

=head1 OTHER CONSIDERATIONS

This module just deals with HTML tags.	There are other ways of injecting
potentially harmful code into documents, including CSS, faking out
an img or object tag, etc.  Without extending this module to include
a CSS parser, for example, addressing these cases will be difficult.
It's recommended that tags and attributes like this simply be stripped.

If you're using this to sanitize code provided by a 3rd party, also check
to ensure that you're either matching character sets, or converting as
necessary.

=head1 SEE ALSO

L<HTML::Element>, L<HTML::TokeParser>

=head1 LICENSE

I<HTML::Sanitizer> is free software; you may redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR & COPYRIGHT

Except where otherwise noted, I<HTML::Sanitizer> is Copyright 2005-2006
Six Apart, cpan@sixapart.com. All rights reserved.

=cut
