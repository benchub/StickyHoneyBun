# Variants: self-hosted, rds
# (The "cast to a honey-shaped type denied without USAGE" body is the
# cross-variant assertion in t/lib/SHB_Assertions.pm; the CREATE-TABLE
# variant, alias coverage, post-GRANT regression, and log-size
# invariants are self-hosted-specific.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

# Closing PUBLIC EXECUTE on honey_bun_out / honey_bun_send (t/018) doesn't
# fully close the forge-an-alert primitive: USAGE on the type was still
# PUBLIC, so a non-superuser could either
#   (a) cast a chosen string to honey_bun and let result-row typeoutput
#       dispatch invoke honey_bun_out (which doesn't consult function
#       ACLs); or
#   (b) create their own table with a honey_bun column and SELECT from it
#       to fire the trap with an attacker-chosen tag.
# Both paths require USAGE on the type. Revoking USAGE FROM PUBLIC closes
# them both, including for alias types created via create_honey_bun_alias.
#
# The trap on legitimate planted columns is unaffected: PG checks USAGE at
# CREATE/CAST time, not when reading existing rows.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('type_usage_acl');
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
    CREATE SCHEMA attacker_schema AUTHORIZATION attacker;
    GRANT SELECT ON t TO attacker;
});

sub log_size {
    return 0 unless -e $log_path;
    return -s $log_path;
}

# Wraps $node->psql so the shared assertion runs the cast as the
# non-USAGE `attacker` role. SET ROLE is per-session, so the wrapper
# prepends it to every call.
my $as_attacker = sub {
    $node->psql('postgres', "SET ROLE attacker; $_[0]");
};

# Cast attempt: 'forged'::honey_bun requires USAGE on the type.
my $size_before = log_size();
SHB_Assertions::assert_cast_to_type_denied(
    $as_attacker, 'honey_bun',
    'attacker cast to honey_bun');
is(log_size(), $size_before,
    'failed cast does not produce a log entry');

# CREATE TABLE attempt: a column of type honey_bun also requires USAGE.
$size_before = log_size();
my ($rc_create, undef, $stderr_create) = $node->psql('postgres',
    q{SET ROLE attacker; CREATE TABLE attacker_schema.forge (h honey_bun);});
isnt($rc_create, 0,
    'non-superuser cannot create a column of type honey_bun');
like($stderr_create, qr/permission denied for (type|function)/i,
    'CREATE TABLE with honey_bun column errors with permission denied');
is(log_size(), $size_before,
    'failed CREATE TABLE does not produce a log entry');

# Critical regression: typeoutput dispatch on an existing honey-bearing
# table still fires the trap for any role with SELECT. USAGE is checked
# at CREATE / CAST time, not at result-row formatting time.
$size_before = log_size();
$node->safe_psql('postgres', q{SET ROLE attacker; SELECT * FROM t;});
cmp_ok(log_size(), '>', $size_before,
    'reading an existing honey-bearing table still fires the trap');

# Same closure on alias-generated types: otherwise the attacker just casts
# to the alias type instead of honey_bun.
$node->safe_psql('postgres',
    q{SELECT create_honey_bun_alias('account_token');});

$size_before = log_size();
SHB_Assertions::assert_cast_to_type_denied(
    $as_attacker, 'account_token',
    'attacker cast to alias type account_token');
is(log_size(), $size_before,
    'failed alias cast does not produce a log entry');

# Regression: an admin can authorize a specific planter role via GRANT
# USAGE, restoring planting capability for that role only.
$node->safe_psql('postgres',
    q{GRANT USAGE ON TYPE honey_bun TO attacker;});
my ($rc_grant) = $node->psql('postgres',
    q{SET ROLE attacker; CREATE TABLE attacker_schema.allowed (h honey_bun);});
is($rc_grant, 0,
    'after explicit GRANT USAGE, planter role can create honey columns');

$node->stop;
done_testing();
