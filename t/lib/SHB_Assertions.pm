package SHB_Assertions;
#
# SHB_Assertions — assertion bodies that apply to both the self-hosted
# (C) and RDS (pg_tle) variants.
#
# Each assertion takes a `$run_psql` coderef that the caller wires up.
# The contract for the coderef:
#
#     $run_psql->($sql)  ->  ($rc, $stdout, $stderr)
#
# Self-hosted callers wrap `$node->psql`; RDS callers wrap
# `SHB_RDS::psql_run($cs, $sql)`. Setup logic (cluster boot vs RDS
# provisioning) is variant-specific and stays in its respective
# harness; only assertion bodies live here.
#
# Some assertions need MORE than just a psql runner — e.g.
# `assert_text_trip` needs a way to fetch the alert evidence
# (log-file tail on self-hosted, CloudWatch poll on RDS). Those take
# additional coderefs documented at the assertion.

use strict;
use warnings;
use Test::More;

# assert_honey_bun_type_exists($run_psql, $label)
# Both variants register a `honey_bun` base type in the public schema.
# Asserting at the pg_type layer (not pg_extension) gives one check
# that works for both the C extension and the pg_tle TLE wrapper —
# neither variant can ship without this row appearing.
sub assert_honey_bun_type_exists {
    my ($run_psql, $label) = @_;
    $label //= 'honey_bun type exists in pg_type';
    my ($rc, $out) = $run_psql->(
        "SELECT 1 FROM pg_type WHERE typname = 'honey_bun'");
    is($rc,  0,   "$label (query succeeded)");
    is($out, '1', "$label (one row matched)");
}

# assert_text_trip($run_psql, $get_alert, $tag, %opts)
# The textbook trap-trigger: plant a honey row, SELECT it back, then
# verify the generated alert has the expected JSON shape. Both variants
# produce identical alert JSON; the only thing that differs is the
# transport (local log file vs Lambda+CloudWatch), which the caller
# encapsulates in $get_alert.
#
# Coderefs:
#   $run_psql->($sql) -> ($rc, $stdout, $stderr)
#       Runs SQL as a role with USAGE on honey_bun (so it can plant).
#   $get_alert->($tag) -> $alert_text (or '' / undef on miss)
#       Returns the alert log line / payload containing the tag. The
#       caller is responsible for any timeout / polling logic — the
#       assertion treats this as a synchronous lookup.
#
# Options:
#   table => 't'              # default; caller can override if the
#                             # test's schema already has a `t` table
sub assert_text_trip {
    my ($run_psql, $get_alert, $tag, %opts) = @_;
    my $table = $opts{table} // 't';
    my $label = $opts{label} // 'text-protocol read fires the trap';

    my ($rc) = $run_psql->("CREATE TABLE $table (id int, honey honey_bun)");
    is($rc, 0, "$label: CREATE TABLE");

    ($rc) = $run_psql->("INSERT INTO $table VALUES (1, '$tag')");
    is($rc, 0, "$label: INSERT planted honey row");

    ($rc) = $run_psql->("SELECT * FROM $table");
    is($rc, 0, "$label: SELECT succeeds (trap fires async)");

    my $alert = $get_alert->($tag);
    ok(defined $alert && length $alert,
        "$label: alert was generated and reachable");
    return unless defined $alert && length $alert;

    like($alert, qr/"event":"read_text"/,
        "$label: event field is read_text");
    like($alert, qr/"tag":"\Q$tag\E"/,
        "$label: tag matches planted value");
    like($alert, qr/"pid":\d+/,
        "$label: pid field present");
    like($alert, qr/"ts":"\d{4}-\d{2}-\d{2}T/,
        "$label: ts is iso-8601-shaped");
    like($alert, qr/"session_user":"[^"]+"/,
        "$label: session_user populated");
}

# assert_io_function_call_denied($run_psql, $sql, $label)
# A non-privileged role calling a honey_bun I/O function by name
# (rather than going through typeoutput dispatch on a stored value)
# must fail with permission denied. The defense is REVOKE EXECUTE
# FROM PUBLIC; the assertion verifies both that the call is rejected
# and that the error message identifies the cause.
#
# Caller passes the exact SQL because the function names differ
# across variants:
#   self-hosted: SELECT honey_bun_out('forged'::honey_bun)
#   rds:         SELECT honey_bun_out_rds(convert_to('forged','UTF8'))
sub assert_io_function_call_denied {
    my ($run_psql, $sql, $label) = @_;
    $label //= 'direct I/O function call denied';
    my ($rc, undef, $stderr) = $run_psql->($sql);
    isnt($rc, 0, "$label: call rejected (non-zero rc)");
    like($stderr, qr/permission denied/i,
        "$label: rejected with permission denied");
}

# assert_cast_to_type_denied($run_psql, $type_name, $label)
# A role without USAGE on a honey-shaped type cannot cast to it. The
# error message identifies either the type or its underlying input
# function depending on PG version / dispatch path; the regex accepts
# both shapes.
#
# Caller passes the type name because aliases generated via
# create_honey_bun_alias() are tested with the same body and a
# different name. Self-hosted callers `SET ROLE attacker` inside their
# psql wrapper; RDS callers use a separately-provisioned non-USAGE
# role's connstr.
sub assert_cast_to_type_denied {
    my ($run_psql, $type_name, $label) = @_;
    $label //= "cast to $type_name denied without USAGE";
    my ($rc, undef, $stderr) = $run_psql->("SELECT 'forged'::$type_name");
    isnt($rc, 0, "$label: cast rejected (non-zero rc)");
    like($stderr, qr/permission denied for (type|function)/i,
        "$label: rejected with permission denied for type/function");
}

1;
