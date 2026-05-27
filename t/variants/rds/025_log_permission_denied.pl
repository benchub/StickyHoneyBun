#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: a broken alert sink does NOT propagate to the caller. The
#          SELECT that fires the trap still succeeds and returns rows
#          normally — the trap is invisible whether or not the alert
#          ever reaches its destination.
#
# Self-hosted analog: t/variants/self-hosted/025_log_permission_denied.pl
# exercises an unwriteable log file path. Here we exercise an
# unreachable Lambda (lambda_arn pointing to a function that doesn't
# exist) by temporarily replacing the config table's lambda_arn with
# a bogus ARN. The honey_bun_out_rds function wraps its Lambda invoke
# in `EXCEPTION WHEN OTHERS THEN NULL`, so the broken sink must NOT
# unmask the trap to the attacker.
#
# Test isolation: operates on db_b (separate from 802 which operates
# on db_a) so concurrent kill-switch testing doesn't interfere. The
# END block restores the legitimate ARN even on failure.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t025', db => 'db_b');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# Capture the legitimate lambda_arn for restoration.
my (undef, $saved_arn) = SHB_RDS::psql_run(
    SHB_RDS::connstr($st, db => 'db_b'),
    "SELECT value FROM sticky_honey_bun.config WHERE key = 'lambda_arn'");
chomp $saved_arn;

END {
    if (defined $saved_arn && length $saved_arn) {
        SHB_RDS::psql_run(SHB_RDS::connstr($st, db => 'db_b'),
            "INSERT INTO sticky_honey_bun.config(key, value) "
          . "VALUES ('lambda_arn', '$saved_arn') "
          . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
    }
}

# Substitute a bogus ARN — points at a function that doesn't exist.
# aws_lambda.invoke will raise; honey_bun_out_rds's EXCEPTION block
# must swallow it.
my $bogus_arn = 'arn:aws:lambda:us-east-1:000000000000:function:shb-nonexistent';
SHB_RDS::psql_run(SHB_RDS::connstr($st, db => 'db_b'),
    "UPDATE sticky_honey_bun.config "
  . "SET value = '$bogus_arn' WHERE key = 'lambda_arn'");

$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'fails_silent');
$run->("INSERT INTO t VALUES (1, '$tag')");

# SELECT must succeed despite the trap's Lambda invoke failing. No
# error must reach the client — the trap stays masked.
my ($rc, $out, $err) = $run->('SELECT * FROM t WHERE id = 1');
is($rc, 0,
    'SELECT succeeds even though the trap cannot reach its Lambda');
is($err, '',
    'no error reaches the client (trap stays masked)');
like($out, qr/\Q$tag\E/,
    'rows are returned normally — caller cannot tell the trap fired');

done_testing();
