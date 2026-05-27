# Variants: self-hosted, rds
# (The four "deny on direct attack" assertions live in
# t/lib/SHB_Assertions.pm and are shared with the RDS twin
# t/variants/rds/027_red_team.pl. ALTER SYSTEM-based attacks and the
# "no log entry on failed attack" invariants are self-hosted-specific
# and stay inline here.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

# Adversarial regression test: a single playbook walking an attacker
# through every documented forge / suppress / bypass vector and
# asserting each is blocked. Catches future regressions where any one
# defense is reverted in isolation (REVOKE removed, GUC context
# downgraded, USAGE check elided).
#
# Cross-variant vectors (asserted via the shared lib):
#   1. Direct call to honey_bun_in / honey_bun_out.
#   2. Cast a literal to honey_bun (or an alias type) via `::`.
#   3. CREATE TABLE with a honey_bun (or alias) column.
#   4. SELECT from the honey_bun_columns inventory view.
#
# Self-hosted-specific vectors (asserted inline below):
#   5. Turn off `sticky_honey_bun.enabled` at runtime via ALTER SYSTEM.
#   6. Redirect alerts at runtime via ALTER SYSTEM SET log_directory.
#
# Cross-variant "the trap still works" regression:
#   - Read a planted honey-bearing table as a role with SELECT —
#     trap fires. Verifying it here ensures no defense over-revokes.
#   - The self-hosted variant additionally asserts the failed-attack
#     log-size invariant ("no log line written by a denied attack")
#     inline; the RDS twin verifies the same via count_alerts.

my $log_dir  = SHB::tempdir();
my $log_path = "$log_dir/shb.log";
my $alt_dir  = SHB::tempdir();

my $node = SHB::new_node('red_team');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE secrets (id int, honey honey_bun);
    INSERT INTO secrets VALUES (1, 'public.secrets.honey');
    SELECT create_honey_bun_alias('account_token');
    CREATE TABLE auth (id int, tok account_token);
    INSERT INTO auth VALUES (1, 'public.auth.tok');
    CREATE ROLE attacker LOGIN;
    CREATE SCHEMA attacker_schema AUTHORIZATION attacker;
    GRANT SELECT ON secrets TO attacker;
    GRANT SELECT ON auth TO attacker;
});

sub log_size { return 0 unless -e $log_path; return -s $log_path; }

# Helper: wrap $node->psql as the `attacker` role for the shared lib's
# $run_psql contract.
my $as_attacker = sub {
    $node->psql('postgres', "SET ROLE attacker; $_[0]");
};

# Run a shared-lib assertion and additionally pin the self-hosted
# invariant that a failed attack writes no log line.
sub assert_silent {
    my ($label, $body) = @_;
    my $size_before = log_size();
    $body->();
    is(log_size(), $size_before,
        "$label: no log entry produced by the failed attack");
}

# Vector 1: direct call to the I/O functions.
assert_silent('direct honey_bun_in call', sub {
    SHB_Assertions::assert_io_function_call_denied(
        $as_attacker,
        q{SELECT honey_bun_in('forged.tag')},
        'red-team: direct honey_bun_in call');
});
assert_silent('direct honey_bun_out call', sub {
    SHB_Assertions::assert_io_function_call_denied(
        $as_attacker,
        q{SELECT honey_bun_out('x'::honey_bun)},
        'red-team: direct honey_bun_out call');
});

# Vector 2: literal cast bypassing the EXECUTE REVOKE via typinput dispatch.
# The C-level pg_type_aclcheck inside honey_bun_in is what closes this.
assert_silent('literal cast to honey_bun', sub {
    SHB_Assertions::assert_cast_to_type_denied(
        $as_attacker, 'honey_bun',
        'red-team: literal cast to honey_bun');
});
assert_silent('literal cast to alias type', sub {
    SHB_Assertions::assert_cast_to_type_denied(
        $as_attacker, 'account_token',
        'red-team: literal cast to alias type');
});

# Vector 3: CREATE TABLE forge (h honey_bun); INSERT; SELECT —
# fall-through to typeoutput dispatch on an attacker-owned table.
# REVOKE USAGE on TYPE blocks the CREATE TABLE step.
assert_silent('CREATE TABLE with honey_bun column', sub {
    SHB_Assertions::assert_create_column_of_type_denied(
        $as_attacker, 'attacker_schema', 'honey_bun',
        'red-team: CREATE TABLE forge (h honey_bun)');
});
assert_silent('CREATE TABLE with alias-type column', sub {
    SHB_Assertions::assert_create_column_of_type_denied(
        $as_attacker, 'attacker_schema', 'account_token',
        'red-team: CREATE TABLE forge_alias (h account_token)');
});

# Vector 4: enumerate planted traps via the inventory view.
assert_silent('inventory view enumeration', sub {
    SHB_Assertions::assert_inventory_locked_from_role(
        $as_attacker,
        'red-team: SELECT * FROM honey_bun_columns');
});

# Vector 5: disable the trap at runtime. PGC_POSTMASTER on `enabled`
# makes the auto.conf write futile until restart. Self-hosted-only —
# the RDS variant's equivalent (config-table `enabled` row) is
# covered by 806_enabled_kill_switch.pl from the RDS side.
$node->safe_psql('postgres',
    'ALTER SYSTEM SET sticky_honey_bun.enabled = off');
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');
my $runtime_enabled = $node->safe_psql('postgres',
    'SHOW sticky_honey_bun.enabled');
is($runtime_enabled, 'on',
    'red-team: ALTER SYSTEM + reload cannot turn off `enabled` at runtime');

# Vector 6: redirect alerts via the log_directory PGC_SIGHUP fallback.
# Self-hosted-only — the RDS variant has no log_directory; the analog
# tamper-resistance check on the locked-down config table is
# 804_config_tamper_resistance.pl from the RDS side.
$node->safe_psql('postgres',
    "ALTER SYSTEM SET log_directory = '$alt_dir'");
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');
my $size_before_redirect = log_size();
$node->safe_psql('postgres', 'SELECT * FROM secrets');
cmp_ok(log_size(), '>', $size_before_redirect,
    'red-team: after ALTER SYSTEM log_directory, alerts still land in the frozen path');
ok(! -e "$alt_dir/sticky_honey_bun.log" || -z "$alt_dir/sticky_honey_bun.log",
    'red-team: no alert landed in the runtime-changed log_directory');

# REGRESSION: the one thing the attacker SHOULD be able to do — read
# a planted table — must still fire the trap. If any of the above
# defenses over-revoked, this would fail.
my $size_before_legit = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM secrets});
cmp_ok(log_size(), '>', $size_before_legit,
    'red-team: attacker SELECT on canonical honey table fires alert');

$size_before_legit = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM auth});
cmp_ok(log_size(), '>', $size_before_legit,
    'red-team: attacker SELECT on alias-typed honey table fires alert');

$node->stop;
done_testing();
