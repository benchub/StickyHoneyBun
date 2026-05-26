#!/usr/bin/perl
# Variants: self-hosted, rds
# Adversarial regression test: a single playbook walking an attacker
# through every documented forge / suppress / bypass vector and
# asserting each is blocked. The four "deny on direct attack"
# assertions are shared with the self-hosted twin via
# t/lib/SHB_Assertions.pm; the RDS-specific attack vectors (config
# table tamper, kill-switch tamper) are asserted inline below.
#
# Cross-variant vectors (shared via the lib):
#   1. Direct call to honey_bun_in_rds / honey_bun_out_rds.
#   2. Cast a literal to honey_bun (or an alias type) via `::`.
#   3. CREATE TABLE with a honey_bun (or alias) column.
#   4. SELECT from the honey_bun_columns inventory view.
#
# RDS-specific vectors (inline below):
#   5. SELECT from sticky_honey_bun_rds_config — discovery of the
#      Lambda ARN (the alert sink) and the per-cluster cluster_id.
#   6. UPDATE / DELETE / INSERT on sticky_honey_bun_rds_config —
#      tamper attempts (redirect alerts, silence the trap, configure
#      a forged cluster_id).
#   7. INSERT enabled='off' specifically — the kill-switch tamper,
#      the analog of self-hosted's ALTER SYSTEM SET enabled = off.
#
# Cross-variant "the trap still works" regression: a legitimate read
# by an app role with SELECT GRANT must still fire the trap after all
# the above attacks are repelled.
#
# Other RDS-specific defenses tested in dedicated files (804 config
# tamper, 806 kill switch) are repeated here in playbook form so a
# reviewer can see every attack vector closed in one place — that's
# the spirit of the red-team test.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t027');

my $cs_app = SHB_RDS::connstr($st,
    user        => 'shbtest_app',
    password    => $st->{app_password},
    search_path => 'shb_t027');
my $as_app = sub { SHB_RDS::psql_run($cs_app, $_[0]) };

# Plant an alias type so the alias-cast / alias-CREATE-TABLE vectors
# have a real target. Unique per-invocation name + END-block cleanup
# (aliases must live in `public` because pg_tle requires the I/O
# functions to be in the same namespace as the type).
my $alias_name = 'shb_alias_red_team_' . $$ . '_' . time();
SHB_RDS::psql_run($cs_master,
    "SELECT create_honey_bun_alias('$alias_name', 'public')");
END {
    SHB_RDS::psql_run(SHB_RDS::connstr($st),
        "DROP TYPE IF EXISTS public.$alias_name CASCADE") if $alias_name;
}

# Give the app role CREATE on shb_t027 so the CREATE-TABLE-with-honey
# vectors fail on the type-USAGE check specifically (not on a
# generic schema-level CREATE denial).
SHB_RDS::psql_run($cs_master,
    'GRANT CREATE ON SCHEMA shb_t027 TO shbtest_app');

# ---- Vector 1: direct I/O function calls.
SHB_Assertions::assert_io_function_call_denied(
    $as_app,
    "SELECT honey_bun_in_rds('forged')",
    'red-team: direct honey_bun_in_rds call');
SHB_Assertions::assert_io_function_call_denied(
    $as_app,
    "SELECT honey_bun_out_rds(convert_to('forged','UTF8'))",
    'red-team: direct honey_bun_out_rds call');

# ---- Vector 2: cast to honey_bun / alias by non-USAGE role.
SHB_Assertions::assert_cast_to_type_denied(
    $as_app, 'honey_bun',
    'red-team: app cast to honey_bun');
SHB_Assertions::assert_cast_to_type_denied(
    $as_app, "public.$alias_name",
    'red-team: app cast to alias type');

# ---- Vector 3: CREATE TABLE with honey_bun / alias column.
SHB_Assertions::assert_create_column_of_type_denied(
    $as_app, 'shb_t027', 'honey_bun',
    'red-team: app CREATE TABLE forge (h honey_bun)');
SHB_Assertions::assert_create_column_of_type_denied(
    $as_app, 'shb_t027', "public.$alias_name",
    'red-team: app CREATE TABLE forge (h alias)');

# ---- Vector 4: enumerate planted columns via the inventory view.
SHB_Assertions::assert_inventory_locked_from_role(
    $as_app,
    'red-team: app SELECT * FROM honey_bun_columns');

# ---- Vector 5: discover the alert sink via the config table.
# SELECT is REVOKEd from PUBLIC, so the app role cannot learn the
# Lambda ARN or any other config row. This closes the recon path that
# would otherwise let an attacker design a downstream attack against
# the receiver.
{
    my ($rc, undef, $stderr) = $as_app->(
        "SELECT value FROM sticky_honey_bun_rds_config WHERE key = 'lambda_arn'");
    isnt($rc, 0,
        'red-team: app cannot SELECT from sticky_honey_bun_rds_config');
    like($stderr, qr/permission denied/i,
        'red-team: config table SELECT is permission-denied');
}

# ---- Vector 6: tamper with the config (redirect / silence the trap).
for my $tamper (
    [ 'UPDATE',
      "UPDATE sticky_honey_bun_rds_config "
    . "SET value = 'arn:aws:lambda:us-east-1:0:function:hijack' "
    . "WHERE key = 'lambda_arn'" ],
    [ 'DELETE',
      "DELETE FROM sticky_honey_bun_rds_config WHERE key = 'lambda_arn'" ],
    [ 'INSERT',
      "INSERT INTO sticky_honey_bun_rds_config(key, value) "
    . "VALUES ('lambda_arn', 'arn:aws:lambda:us-east-1:0:function:hijack')" ],
) {
    my ($verb, $sql) = @$tamper;
    my ($rc, undef, $stderr) = $as_app->($sql);
    isnt($rc, 0,
        "red-team: app cannot $verb sticky_honey_bun_rds_config");
    like($stderr, qr/permission denied/i,
        "red-team: $verb on config table is permission-denied");
}

# ---- Vector 7: flip the kill switch.
{
    my ($rc, undef, $stderr) = $as_app->(
        "INSERT INTO sticky_honey_bun_rds_config(key, value) "
      . "VALUES ('enabled', 'off')");
    isnt($rc, 0,
        'red-team: app cannot flip the `enabled` kill switch '
      . '(INSERT into config table denied)');
    like($stderr, qr/permission denied/i,
        'red-team: kill-switch tamper attempt is permission-denied');
}

# ---- REGRESSION: with every defense in place, a legitimate read
# by an app role that the operator has granted SELECT on a
# honey-bearing table MUST still fire the trap. This is the
# load-bearing positive case — if it ever stops firing, the trap is
# broken.
{
    SHB_RDS::psql_run($cs_master,
        'CREATE TABLE t (id int, honey honey_bun)');
    my $tag = SHB_RDS::unique_tag($st, 'red_team_legitimate');
    SHB_RDS::psql_run($cs_master, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs_master, 'GRANT SELECT ON t TO shbtest_app');
    SHB_RDS::psql_run($cs_master,
        'GRANT USAGE ON SCHEMA shb_t027 TO shbtest_app');

    my ($rc) = $as_app->('SELECT * FROM t');
    is($rc, 0, 'app role with SELECT can read the planted row');

    my $get_event = SHB_RDS::get_event_fn($st);
    my $event = $get_event->($tag);
    ok($event,
        'red-team: legitimate read still fires the trap after every '
      . 'attack vector closed');
    is($event->{tag}, $tag, 'red-team: legitimate alert carries the planted tag')
        if $event;

    # And one more pass against the alias type, which has its own
    # per-alias _in/_out functions: a legitimate read of an
    # alias-typed column must also fire.
    SHB_RDS::psql_run($cs_master,
        "CREATE TABLE t_alias (id int, tok public.$alias_name)");
    my $tag_alias = SHB_RDS::unique_tag($st, 'red_team_legit_alias');
    SHB_RDS::psql_run($cs_master, "INSERT INTO t_alias VALUES (1, '$tag_alias')");
    SHB_RDS::psql_run($cs_master, 'GRANT SELECT ON t_alias TO shbtest_app');

    ($rc) = $as_app->('SELECT * FROM t_alias');
    is($rc, 0, 'app role with SELECT can read the alias-typed row');
    my $alias_event = $get_event->($tag_alias);
    ok($alias_event,
        'red-team: legitimate read of alias-typed column also fires');
}

done_testing();
