use strict;
use warnings;
use utf8;                     # source string literals are UTF-8
use open ':std', ':encoding(UTF-8)';
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

# Encoding coverage. Real-world traps see non-ASCII bytes from three places:
#   (a) tag — a planter role may pick a non-ASCII tag for site-specific
#       conventions, or an attacker with a granted planter role may
#       deliberately embed weird bytes.
#   (b) query — `debug_query_string` carries the raw client-sent SQL; PG
#       allows identifiers / string literals containing multi-byte UTF-8,
#       diacritics, RTL marks, etc.
#   (c) session_user / database / application_name — non-ASCII role/db
#       names exist; application_name is set by the client.
#
# Properties verified:
#   1. Multi-byte UTF-8 in tag, query, and application_name round-trips
#      verbatim through escape_json.
#   2. The resulting JSON line is itself valid UTF-8 (no mojibake from
#      double-encoding or lossy conversion).
#   3. All standard log fields are present on every line (field-stability
#      regression guard).

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('utf8_and_encoding');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

# Multi-byte UTF-8 in the tag value (Japanese + emoji + Cyrillic + diacritic).
my $tag_multibyte = '蜂蜜🍯 пчела café';

SHB::install_extension($node);
$node->safe_psql('postgres', qq{
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, '$tag_multibyte');
});

# Trigger 1: trap from a SELECT with multi-byte content in the query text
# (in a comment so the SQL parser is happy). PG strips non-ASCII from
# application_name (replacing with `?`), so we use ASCII there and reserve
# the multi-byte assertions for `tag` and `query`.
my $query_multibyte =
    "SELECT * FROM t WHERE id = 1 /* recherche français — αβγ — اَلْعَرَبِيَّةُ */";
$node->safe_psql('postgres',
    qq{SET application_name = 'shb_multibyte_probe'; $query_multibyte});

# Trigger 2: NUL bytes. SQL string literals can't contain raw NUL, but
# `chr(0)` via the typeoutput path would — except PG strips NUL from text
# values. So this trigger is just a regular trap; the point is that any
# NUL that DID sneak in must not crash escape_json. Since PG won't let us
# easily inject NUL, this is mostly a smoke test that NUL handling is
# robust.
$node->safe_psql('postgres', 'SELECT * FROM t');

open(my $fh, '<:raw', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, 2, 'two log lines for two trap events');

my $json = JSON::PP->new->utf8(1);
my @parsed;
for my $i (0 .. $#lines) {
    my $line = $lines[$i];
    chomp $line;
    my $obj = eval { $json->decode($line) };
    ok($obj, sprintf('line %d parses as UTF-8 JSON', $i + 1))
        or diag "decode error: $@\nline (hex): " . unpack('H*', substr($line, 0, 200));
    push @parsed, $obj if $obj;
}

# Tag round-trips with all multi-byte sequences intact.
is($parsed[0]{tag}, $tag_multibyte,
   'tag with Japanese + emoji + Cyrillic + diacritic round-trips verbatim');
is($parsed[1]{tag}, $tag_multibyte,
   'tag from second trap also round-trips');

# Query field carries the multi-byte comment verbatim.
like($parsed[0]{query}, qr/recherche français/,
   'multi-byte query content reaches the query field');
like($parsed[0]{query}, qr/αβγ/,
   'multi-byte Greek in query field');
like($parsed[0]{query}, qr/اَلْعَرَبِيَّةُ/,
   'multi-byte Arabic in query field');

# application_name round-trip (ASCII; PG normalizes non-ASCII to `?`).
is($parsed[0]{application_name}, 'shb_multibyte_probe',
   'application_name round-trips when ASCII');

# Field-stability regression guard: every line must have all expected fields.
my @expected_fields = qw(ts event tag session_user current_user
                         application_name database pid client_addr query);
for my $i (0 .. $#parsed) {
    for my $f (@expected_fields) {
        ok(exists $parsed[$i]{$f},
           sprintf('line %d has field `%s`', $i + 1, $f));
    }
}

$node->stop;
done_testing();
