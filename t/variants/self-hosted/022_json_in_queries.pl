# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from t/variants/rds/022_json_in_queries.pl.
# The byte-exact query-field round-trip below is self-hosted-specific —
# direct log-file access lets us assert strict identity, not just a regex.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

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

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int, honey honey_bun);
});

my $run_psql = sub { $node->psql('postgres', $_[0]) };

my $get_event = sub {
    my ($needle) = @_;
    return undef unless -e $log_path && -s $log_path;
    open my $fh, '<', $log_path or die "cannot open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    for my $line (@lines) {
        next unless index($line, $needle) >= 0;
        my $event = eval { decode_json($line) };
        return $@ ? undef : $event;
    }
    return undef;
};

my @payloads = (
    # JSON in a single-quoted SQL string literal.
    {   label => 'JSON in a single-quoted SQL string literal',
        tag   => 'json_strlit.public.t.honey',
        sql_template => q{SELECT '{"event":"forged","tag":"injected"}' AS j, * FROM t WHERE id = },
    },
    # JSONB cast literal (PG-typed JSON).
    {   label => 'JSONB cast literal',
        tag   => 'json_jsonb.public.t.honey',
        sql_template => q{SELECT '{"k":"v","arr":[1,2,3]}'::jsonb, * FROM t WHERE id = },
    },
    # Dollar-quoted JSON — the usual way complex JSON ends up in SQL
    # because it avoids inner-quote escaping entirely.
    {   label => 'dollar-quoted JSON',
        tag   => 'json_dollar.public.t.honey',
        sql_template => q{SELECT $$ {"a":1,"nested":{"b":"c","d":[1,2]}} $$ AS j, * FROM t WHERE id = },
    },
    # JSON-shaped text containing backslash escape sequences. In a
    # standard_conforming_strings SQL literal `\n` is two literal bytes,
    # not a newline; escape_json must emit `\\n` in the log line's JSON
    # so the JSON round-trip recovers `\n`.
    {   label => 'backslash-escaped JSON',
        tag   => 'json_bsesc.public.t.honey',
        sql_template => q{SELECT '{"path":"C:\\users","msg":"line\nbreak"}' AS j, * FROM t WHERE id = },
    },
    # Adversarial JSON-shaped payload specifically aimed at the outer
    # alert object's fields. If the encoder ever leaked an unescaped `"`,
    # the rest of the line would parse as forged keys ("event":"forged",
    # etc.). The whole construct must end up inside the query field's
    # string value with all the `"` characters JSON-escaped.
    {   label => 'adversarial forge-shaped JSON payload',
        tag   => 'json_poison.public.t.honey',
        sql_template => q{SELECT '","event":"forged","tag":"x","junk":"' AS poison, * FROM t WHERE id = },
    },
);

my $row_id = 1;
my @full_queries;
for my $p (@payloads) {
    $run_psql->("INSERT INTO t VALUES ($row_id, '$p->{tag}')");
    my $sql = $p->{sql_template} . $row_id;
    push @full_queries, $sql;
    SHB_Assertions::assert_alert_fields(
        $run_psql, $get_event,
        tag     => $p->{tag},
        trigger => $sql,
        label   => "json-in-query: $p->{label}");
    $row_id++;
}

# Self-hosted-specific: byte-for-byte round-trip of the query field. The
# shared assertion only checks event=read_text and tag matches; it cannot
# enforce exact identity of the query field's bytes.
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
    push @parsed, $obj if $obj;
}

for my $i (0 .. $#full_queries) {
    is($parsed[$i]{query}, $full_queries[$i],
       sprintf('payload %d query field round-trips verbatim', $i + 1));
}

$node->stop;
done_testing();
