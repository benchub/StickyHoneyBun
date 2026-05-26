#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: queries containing literal newlines (pretty-printed SQL,
#          CTEs, newlines inside string literals) produce one well-
#          formed JSON alert per trap event; the query field carries
#          the original newlines round-tripped through JSON's `\n`
#          escape.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t021');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');

# Each multiline payload gets its own tag so we can validate its
# specific alert. CloudWatch returns matches in time order, and a
# shared tag would conflate triggers (see 017 for the same reasoning).
my @payloads = (
    {   label  => 'pretty-printed multi-line SELECT',
        suffix => 'mline_pretty',
        sql    => qq{SELECT *\nFROM t\nWHERE id = 1}, },
    {   label  => 'CTE with tabs and newlines',
        suffix => 'mline_cte',
        sql    => qq{WITH x AS (\n\tSELECT * FROM t\n)\nSELECT * FROM x WHERE id = 2}, },
    {   label  => 'string literal containing newlines',
        suffix => 'mline_strlit',
        sql    => qq{SELECT * FROM t WHERE id = 3 AND 'multi\nline\nstring' IS NOT NULL}, },
);

my $row_id = 1;
for my $p (@payloads) {
    my $tag = SHB_RDS::unique_tag($st, $p->{suffix});
    $run->("INSERT INTO t VALUES ($row_id, '$tag')");
    SHB_Assertions::assert_alert_fields(
        $run, $get_event,
        tag     => $tag,
        trigger => $p->{sql},
        like    => { query => qr/\n/ },
        label   => "multiline: $p->{label}");
    $row_id++;
}

done_testing();
