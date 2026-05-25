use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

# Real-world SQL routinely carries JSON-shaped text inside it: string
# literals that hold JSON payloads, JSONB cast literals, dollar-quoted JSON
# (the usual way complex JSON is written in SQL without backslash-escaping
# every inner quote), and JSON-with-escapes for paths / line breaks.
# Every byte of the SQL ends up in debug_query_string and from there in
# the alert log's `query` field.
#
# The logger uses PG's escape_json, which inside a JSON string value must
# escape exactly two byte classes: `"` (which would otherwise close the
# string early) and `\` (which would start an escape sequence). `{`, `}`,
# `:`, `,`, `[`, `]` are all legal as-is inside a JSON string value, so
# they don't need escaping — and trying to "extra-escape" them would break
# the round-trip.
#
# This test verifies that:
#   (a) every JSON-bearing query produces one parseable log line;
#   (b) the embedded JSON in the `query` field cannot hijack any field of
#       the outer alert object (event/tag stay legitimate);
#   (c) the query field round-trips byte-for-byte after JSON decode.
#
# Companion to t/017_query_injection.pl (which covers JSON-corrupting bytes
# inside SQL *comments*); this one covers legitimate SQL syntax that
# happens to contain JSON content.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('json_in_queries');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

my @payloads = (
    # JSON in a single-quoted SQL string literal.
    q{SELECT '{"event":"forged","tag":"injected"}' AS j, * FROM t},

    # JSONB cast literal (PG-typed JSON).
    q{SELECT '{"k":"v","arr":[1,2,3]}'::jsonb, * FROM t},

    # Dollar-quoted JSON — the usual way complex JSON ends up in SQL
    # because it avoids inner-quote escaping entirely.
    q{SELECT $$ {"a":1,"nested":{"b":"c","d":[1,2]}} $$ AS j, * FROM t},

    # JSON-shaped text containing backslash escape sequences. In a
    # standard_conforming_strings SQL literal `\n` is two literal bytes,
    # not a newline; escape_json must emit `\\n` in the log line's JSON
    # so the JSON round-trip recovers `\n`.
    q{SELECT '{"path":"C:\\users","msg":"line\nbreak"}' AS j, * FROM t},

    # Adversarial JSON-shaped payload specifically aimed at the outer
    # alert object's fields. If the encoder ever leaked an unescaped `"`,
    # the rest of the line would parse as forged keys ("event":"forged",
    # etc.). The whole construct must end up inside the query field's
    # string value with all the `"` characters JSON-escaped.
    q{SELECT '","event":"forged","tag":"x","junk":"' AS poison, * FROM t},
);

for my $sql (@payloads) {
    $node->safe_psql('postgres', $sql);
}

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, scalar @payloads,
   'one log line per JSON-bearing query (no forged or split events)');

my $json = JSON::PP->new;
my @parsed;
for my $i (0 .. $#lines) {
    my $line = $lines[$i];
    chomp $line;
    my $obj = eval { $json->decode($line) };
    ok($obj, sprintf('line %d parses as standalone JSON', $i + 1))
        or diag "decode error: $@\nline: $line";
    next unless $obj;
    push @parsed, $obj;

    # The embedded JSON in `query` must not have hijacked the outer
    # alert object's identity-bearing fields.
    is($obj->{event}, 'read_text',
       sprintf('line %d event is read_text (not forged from payload)', $i + 1));
    is($obj->{tag}, 'public.t.honey',
       sprintf('line %d tag is the planted value (not forged from payload)', $i + 1));
}

# Byte-for-byte round-trip of the query field.
for my $i (0 .. $#payloads) {
    is($parsed[$i]{query}, $payloads[$i],
       sprintf('payload %d query field round-trips verbatim', $i + 1));
}

$node->stop;
done_testing();
