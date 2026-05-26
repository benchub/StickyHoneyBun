#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: queries carrying JSON-shaped content (string literals
#          containing JSON, JSONB casts, dollar-quoted JSON, backslash
#          escapes, adversarial forge-shaped payloads) cannot escape
#          the alert's query-field container. Outer event/tag fields
#          stay legitimate; the query field round-trips the JSON
#          payload verbatim.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t022');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');

my @payloads = (
    {   label  => 'string literal containing JSON',
        suffix => 'json_strlit',
        sql    => q{SELECT *, '{"event":"forged"}'::text FROM t WHERE id = 1}, },
    {   label  => 'JSONB cast literal',
        suffix => 'json_jsonb',
        sql    => q{SELECT *, '{"tag":"forged"}'::jsonb FROM t WHERE id = 2}, },
    {   label  => 'dollar-quoted JSON',
        suffix => 'json_dollar',
        sql    => q{SELECT *, $j${"event":"forged","tag":"forged"}$j$ FROM t WHERE id = 3}, },
    {   label  => 'backslash-escaped JSON',
        suffix => 'json_bsesc',
        sql    => q{SELECT *, '{\"event\":\"forged\"}'::text FROM t WHERE id = 4}, },
);

my $row_id = 1;
for my $p (@payloads) {
    my $tag = SHB_RDS::unique_tag($st, $p->{suffix});
    $run->("INSERT INTO t VALUES ($row_id, '$tag')");
    # The shared assertion confirms event=read_text and tag matches the
    # legitimate planted value — i.e. the forged JSON in the query did
    # not hijack the outer alert object.
    SHB_Assertions::assert_alert_fields(
        $run, $get_event,
        tag     => $tag,
        trigger => $p->{sql},
        label   => "json-in-query: $p->{label}");
    $row_id++;
}

done_testing();
