# Variants: self-hosted, rds
# (The "direct I/O function call denied" body is the cross-variant
# assertion in t/lib/SHB_Assertions.pm; the alias _send / _out coverage
# and the log-size-unchanged checks are self-hosted-specific.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

# honey_bun_out and honey_bun_send are PostgreSQL type-system primitives
# (typeoutput, typsend), but they're also callable directly via SQL. With
# PUBLIC EXECUTE — the CREATE FUNCTION default — any session can run
# SELECT honey_bun_out('attacker.chosen.tag'::honey_bun) and produce a
# fully-formed alert line with arbitrary `tag` and arbitrary query text.
# That gives an attacker a primitive to (a) drown out a real trap event in
# noise, (b) plant decoys aimed at innocent-looking targets, or (c) trigger
# the alert processor's auto-revoke against themselves on purpose.
#
# The fix is REVOKE EXECUTE FROM PUBLIC. The type system's typeoutput
# dispatch does NOT consult function ACLs (it's invoked from the protocol
# layer, not via fmgr's permission-checked entry points), so revoking
# direct-call EXECUTE leaves the actual trap intact.
#
# create_honey_bun_alias() generates per-alias _out / _send functions
# bound to the same C symbols. Those generated functions must also be
# revoked, or the attacker just routes around honey_bun_out via the
# alias's _out function.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('io_function_acl');
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
    CREATE ROLE attacker LOGIN;
    GRANT SELECT ON t TO attacker;
});

sub log_size {
    return 0 unless -e $log_path;
    return -s $log_path;
}

# Wraps $node->psql so the shared assertion can run the call as the
# non-superuser `attacker` role. SET ROLE survives only within one
# psql session, so the wrapper prepends it to every call.
my $as_attacker = sub {
    $node->psql('postgres', "SET ROLE attacker; $_[0]");
};

# Direct call to honey_bun_out as a non-superuser. Today: succeeds and
# writes a forged log line. After fix: ERROR with permission denied, log
# file unchanged.
my $size_before = log_size();
SHB_Assertions::assert_io_function_call_denied(
    $as_attacker,
    "SELECT honey_bun_out('forged.tag'::honey_bun)",
    'non-superuser direct call to honey_bun_out');
is(log_size(), $size_before,
    'failed honey_bun_out call does not write a log entry');

# Same for honey_bun_send.
$size_before = log_size();
SHB_Assertions::assert_io_function_call_denied(
    $as_attacker,
    "SELECT honey_bun_send('forged.tag'::honey_bun)",
    'non-superuser direct call to honey_bun_send');
is(log_size(), $size_before,
    'failed honey_bun_send call does not write a log entry');

# Critical regression check: typeoutput dispatch is NOT a direct-call path.
# A normal SELECT against a honey-bearing table must still fire the trap
# after the REVOKE — the trap mechanism does not depend on PUBLIC EXECUTE.
$size_before = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM t;});
cmp_ok(log_size(), '>', $size_before,
    'typeoutput dispatch still fires the trap after EXECUTE is revoked');

# Aliases generate per-type _out and _send functions. Those must be
# revoked too, otherwise the attacker just calls account_token_out
# instead of honey_bun_out.
$node->safe_psql('postgres',
    q{SELECT create_honey_bun_alias('account_token');});

$size_before = log_size();
SHB_Assertions::assert_io_function_call_denied(
    $as_attacker,
    "SELECT account_token_out('forged'::account_token)",
    'non-superuser direct call to alias-generated _out');
is(log_size(), $size_before,
    'failed alias _out call does not write a log entry');

$node->stop;
done_testing();
