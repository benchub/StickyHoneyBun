# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from t/variants/rds/021_multiline_queries.pl.
# The byte-exact round-trip and the multi-statement batch checks below
# are self-hosted-specific — only direct log-file access lets us verify
# them.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

# The alert log's "one JSON object per line" invariant has to hold even when
# the SQL text contains literal newlines, which it routinely does in the
# real world: ORMs pretty-print queries across many lines, CTEs span many
# lines, and string literals are allowed to contain embedded newlines.
# debug_query_string captures those bytes verbatim and they reach the
# `query` field of the JSON line.
#
# The logger must JSON-escape every literal newline in the value as `\n`
# (two chars), so the on-disk line is exactly one row of JSON, terminated
# by exactly one real newline. If the encoder ever emitted a raw newline
# byte inside the value, a downstream line-based parser would see N+1
# events for an N-newline query.
#
# Multi-statement batches sent as ONE PQexec (e.g. from libpq, a connection
# pooler, an ORM that builds a single batched query, or pg_dump's prepared
# bodies) are the realistic adversarial case here. psql on stdin would
# normally split such input at `;` and send each statement separately, so
# we use psql's `\;` meta-syntax to suppress the split: `\;` keeps building
# the buffer, and the next real `;` flushes the whole batch in one message.
# PG's exec_simple_query sets debug_query_string to the full batch ONCE for
# the duration of every statement in the batch, so each per-statement trap
# event logs the same multi-line batch string in its `query` field.
#
# This test pins down:
#   (a) one log line per trap event (NOT per newline);
#   (b) each line parses as standalone JSON;
#   (c) the `query` field round-trips with its newlines intact after decode.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('multiline_queries');
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

# Pretty-printed multi-line query, no comments / string literals — just
# natural whitespace formatting that an ORM or human would write.
my $pretty_tag = 'mline_pretty.public.t.honey';
my $pretty     = "SELECT *\nFROM t\nWHERE id = 1";

# CTE-style query with newlines and tabs. Tabs go through escape_json as
# \t and must round-trip the same way.
my $cte_tag = 'mline_cte.public.t.honey';
my $cte     = "WITH q AS (\n\tSELECT * FROM t WHERE id = 2\n)\nSELECT * FROM q";

# Newlines inside a SQL string literal — accepted by PG, and the bytes are
# part of debug_query_string.
my $str_tag = 'mline_strlit.public.t.honey';
my $str_literal = "SELECT *, '
embedded
newlines
' AS lit FROM t WHERE id = 3";

$run_psql->("INSERT INTO t VALUES (1, '$pretty_tag')");
$run_psql->("INSERT INTO t VALUES (2, '$cte_tag')");
$run_psql->("INSERT INTO t VALUES (3, '$str_tag')");

SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    tag     => $pretty_tag,
    trigger => $pretty,
    like    => { query => qr/\n/ },
    label   => 'multiline: pretty-printed multi-line SELECT');

SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    tag     => $cte_tag,
    trigger => $cte,
    like    => { query => qr/\n/ },
    label   => 'multiline: CTE with tabs and newlines');

SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    tag     => $str_tag,
    trigger => $str_literal,
    like    => { query => qr/\n/ },
    label   => 'multiline: string literal containing newlines');

# Self-hosted-specific: byte-exact round-trip + multi-statement batch case.
# We need direct log-file access for both — the round-trip strictness goes
# beyond the shared `like => { query => /\n/ }` regex, and CloudWatch
# can't observe the single-PQexec-with-embedded-semicolon framing.

# Multi-statement batch as a single PQexec. The `\\;` (literal backslash-
# semicolon) tells psql to buffer rather than split; the closing `;` then
# flushes both statements together. Wire bytes: "SELECT * FROM t WHERE id
# = 1;\nSELECT * FROM t WHERE id = 2;" sent in one query message. Both
# traps see the same debug_query_string.
my $batched_wire =
    "SELECT * FROM t WHERE id = 1;\nSELECT * FROM t WHERE id = 2;";
my $batched_input =
    "SELECT * FROM t WHERE id = 1\\;\nSELECT * FROM t WHERE id = 2;";
$node->safe_psql('postgres', $batched_input);

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

# 3 single-statement triggers above + 2 events from the batched run = 5.
is(scalar @lines, 5,
   'one log line per trap event regardless of newlines in query text');

my $json = JSON::PP->new;
my @parsed;
for my $i (0 .. $#lines) {
    my $line = $lines[$i];
    chomp $line;
    my $obj = eval { $json->decode($line) };
    ok($obj, sprintf('line %d parses as standalone JSON', $i + 1))
        or diag "decode error: $@\nline: $line";
    push @parsed, $obj if $obj;
}

# Every event's query field must contain literal newlines after JSON decode —
# proving the encoder used `\n` (two chars), not a raw newline byte that
# would have split the log line.
my $with_newlines =
    grep { defined($_->{query}) && $_->{query} =~ /\n/ } @parsed;
is($with_newlines, 5,
   'every query field round-trips with literal newlines preserved');

# Exact round-trip per case — strict identity, not just "contains a newline".
is($parsed[0]{query}, $pretty,
   'pretty-printed multi-line query round-trips verbatim');
is($parsed[1]{query}, $cte,
   'CTE-style query with newlines and tabs round-trips verbatim');
is($parsed[2]{query}, $str_literal,
   'query with newlines in a string literal round-trips verbatim');
is($parsed[3]{query}, $batched_wire,
   'batched multi-statement: first trap logs the whole batch verbatim');
is($parsed[4]{query}, $batched_wire,
   'batched multi-statement: second trap also logs the whole batch verbatim');

$node->stop;
done_testing();
