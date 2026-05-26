#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: SQL comments carrying JSON-corrupting bytes (close-brace +
#          open-brace, embedded newlines, control chars, backslash
#          sequences) cannot hijack the alert's outer JSON envelope.
#          Every alert remains valid JSON with event=read_text and the
#          legitimate planted tag.
#
# Each payload uses its own unique tag so poll_alert can address its
# specific alert (CloudWatch returns matches in ascending time order;
# a shared tag would conflate the four triggers).

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t017');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');

my @payloads = (
    {   label   => 'line-comment with stray JSON quote',
        suffix  => 'inj_line',
        comment => qq{-- "}, },
    {   label   => 'block-comment with backslash + quote',
        suffix  => 'inj_blkesc',
        comment => qq{/* \\" */}, },
    {   label   => 'embedded close-brace + open-brace sequence',
        suffix  => 'inj_brace',
        comment => q[/* "}{ */], },
    {   label   => 'control bytes in comment',
        suffix  => 'inj_ctrl',
        comment => qq[/* \x01\x02\x03 */], },
);

my $row_id = 1;
for my $p (@payloads) {
    my $tag = SHB_RDS::unique_tag($st, $p->{suffix});
    $run->("INSERT INTO t VALUES ($row_id, '$tag')");
    SHB_Assertions::assert_alert_fields(
        $run, $get_event,
        tag     => $tag,
        trigger => "SELECT * FROM t WHERE id = $row_id $p->{comment}",
        label   => "injection: $p->{label}");
    $row_id++;
}

done_testing();
