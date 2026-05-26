use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Adversarial regression test: a single playbook walking an attacker through
# every documented forge / suppress / bypass vector and asserting each is
# blocked. Catches future regressions where any one defense is reverted in
# isolation (REVOKE removed, GUC context downgraded, USAGE check elided).
#
# What an attacker MUST NOT be able to do (each asserted below):
#   1. Directly call honey_bun_in / honey_bun_out via SQL.
#   2. Cast a literal to honey_bun (or any alias type) via `::`.
#   3. CREATE TABLE with a honey_bun (or alias) column.
#   4. SELECT from the honey_bun_columns inventory view.
#   5. Turn off `sticky_honey_bun.enabled` at runtime via ALTER SYSTEM.
#   6. Redirect alerts at runtime via ALTER SYSTEM SET log_directory.
#
# What an attacker MUST still be able to do (the LEGITIMATE trap path):
#   - Read a planted honey-bearing table they have SELECT on → trap fires.
#     This is the one capability the attacker has, and it is the whole point
#     of the trap. Verifying it here ensures no defense over-revokes.

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

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
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

# Helper: run a SQL fragment as `attacker` and assert it fails with
# "permission denied" and produces no log entry.
sub assert_denied {
    my ($sql, $label) = @_;
    my $size_before = log_size();
    my ($rc, undef, $stderr) = $node->psql('postgres',
        "SET ROLE attacker; $sql");
    isnt($rc, 0,
        "$label: query fails (rc != 0)");
    like($stderr, qr/permission denied/i,
        "$label: error is 'permission denied'");
    is(log_size(), $size_before,
        "$label: no log entry produced by the failed attack");
}

# Vector 1: direct call to the I/O functions.
assert_denied(q{SELECT honey_bun_in('forged.tag')},
              'direct honey_bun_in call');
assert_denied(q{SELECT honey_bun_out('x'::honey_bun)},
              'direct honey_bun_out call');

# Vector 2: literal cast bypassing the EXECUTE REVOKE via typinput dispatch.
# The C-level pg_type_aclcheck inside honey_bun_in is what closes this.
assert_denied(q{SELECT 'forged'::honey_bun},
              'literal cast to honey_bun');
assert_denied(q{SELECT 'forged'::account_token},
              'literal cast to alias type');

# Vector 3: CREATE TABLE forge (h honey_bun); INSERT; SELECT — fall-through
# to typeoutput dispatch on an attacker-owned table. REVOKE USAGE on TYPE
# blocks the CREATE TABLE step.
assert_denied(q{CREATE TABLE attacker_schema.forge (h honey_bun)},
              'CREATE TABLE with honey_bun column');
assert_denied(q{CREATE TABLE attacker_schema.forge_alias (h account_token)},
              'CREATE TABLE with alias-type column');

# Vector 4: enumerate planted traps via the inventory view.
assert_denied(q{SELECT * FROM honey_bun_columns},
              'inventory view enumeration');

# Vector 5: disable the trap at runtime. PGC_POSTMASTER on `enabled` makes
# the auto.conf write futile until restart.
$node->safe_psql('postgres',
    'ALTER SYSTEM SET sticky_honey_bun.enabled = off');
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');
my $runtime_enabled = $node->safe_psql('postgres',
    'SHOW sticky_honey_bun.enabled');
is($runtime_enabled, 'on',
    'ALTER SYSTEM + reload cannot turn off `enabled` at runtime');

# Vector 6: redirect alerts via the log_directory PGC_SIGHUP fallback. The
# log_path freeze at postmaster start neutralizes this.
$node->safe_psql('postgres',
    "ALTER SYSTEM SET log_directory = '$alt_dir'");
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');
my $size_before_redirect = log_size();
$node->safe_psql('postgres', 'SELECT * FROM secrets');
cmp_ok(log_size(), '>', $size_before_redirect,
    'after ALTER SYSTEM log_directory, alerts still land in the frozen path');
ok(! -e "$alt_dir/sticky_honey_bun.log" || -z "$alt_dir/sticky_honey_bun.log",
    'no alert landed in the runtime-changed log_directory');

# REGRESSION: the one thing the attacker SHOULD be able to do — read a
# planted table — must still fire the trap. If any of the above defenses
# over-revoked, this would fail.
my $size_before_legit = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM secrets});
cmp_ok(log_size(), '>', $size_before_legit,
    'legitimate trap path: attacker SELECT on canonical honey table fires alert');

$size_before_legit = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM auth});
cmp_ok(log_size(), '>', $size_before_legit,
    'legitimate trap path: attacker SELECT on alias-typed honey table fires alert');

$node->stop;
done_testing();
