use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

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
    INSERT INTO t VALUES (1, 'public.t.honey');
});

# Pretty-printed multi-line query, no comments / string literals — just
# natural whitespace formatting that an ORM or human would write.
my $pretty = "SELECT *\nFROM t\nWHERE honey IS NOT NULL";

# CTE-style query with newlines and tabs. Tabs go through escape_json as
# \t and must round-trip the same way.
my $cte = "WITH q AS (\n\tSELECT *\n\tFROM t\n)\nSELECT * FROM q";

# Newlines inside a SQL string literal — accepted by PG, and the bytes are
# part of debug_query_string.
my $str_literal = "SELECT *, '
embedded
newlines
' AS lit FROM t";

# Multi-statement batch as a single PQexec. The `\\;` (literal backslash-
# semicolon) tells psql to buffer rather than split; the closing `;` then
# flushes both statements together. Wire bytes: "SELECT * FROM t;\nSELECT
# * FROM t;" sent in one query message. Both traps see the same
# debug_query_string.
my $batched_wire = "SELECT * FROM t;\nSELECT * FROM t;";
my $batched_input = "SELECT * FROM t\\;\nSELECT * FROM t;";

$node->safe_psql('postgres', $pretty);
$node->safe_psql('postgres', $cte);
$node->safe_psql('postgres', $str_literal);
$node->safe_psql('postgres', $batched_input);

# 1 row in t, one trap event per SELECT. $pretty/$cte/$str_literal fire
# 1 event each; $batched_input runs two SELECTs in one PQexec so fires 2.
# Total: 5 events, 5 log lines.
open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

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
