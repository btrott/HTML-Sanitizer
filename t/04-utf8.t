use strict;
use Test::More tests => 3;
use Encode;
use HTML::Sanitizer;

my $raw = "foo &nbsp; bar テスト";
my $str = "foo \x{00a0} bar \x{30c6}\x{30b9}\x{30c8}";

my $s = HTML::Sanitizer->new('*' => 1);

{
    is $s->sanitize(\decode_utf8($raw)), $str, "Give Unicode and get Unicode correctly";
}

{
    isnt $s->sanitize(\$raw), encode_utf8($str), "Give UTF-8 bytes and get UTF-8 wrong";
}

{
    $s->utf8_mode(1);
    is $s->sanitize(\$raw), encode_utf8($str), "Give UTF-8 bytes and get UTF-8 correctly with utf8_mode ON";
}
