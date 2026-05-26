# Variants: self-hosted, rds
# (The "non-privileged role denied honey_bun_columns" body lives in
# t/lib/SHB_Assertions.pm and also runs against the RDS variant from
# t/variants/rds/013_inventory_lockdown.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

# The honey_bun_columns view enumerates every planted honey column under
# every aliased type name — exactly the catalog an attacker who lands in
# the database wants. The install script REVOKEs all access from PUBLIC.
# This test confirms a non-superuser role cannot read it by default.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('inventory_lockdown');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE customers (id int, honey honey_bun);
    SELECT create_honey_bun_alias('account_token');
    CREATE TABLE accounts (id int, honey account_token);

    CREATE ROLE app_user LOGIN;
});

# Superuser (the install role) can still read the view.
my $admin_count = $node->safe_psql('postgres',
    'SELECT count(*) FROM honey_bun_columns');
is($admin_count, '2',
   'superuser still sees the full inventory (canonical + alias)');

# Wrap $node->psql to run queries as the non-privileged app_user role.
my $as_app_user = sub {
    $node->psql('postgres', $_[0], extra_params => ['-U', 'app_user']);
};

SHB_Assertions::assert_inventory_locked_from_role(
    $as_app_user,
    'app_user denied honey_bun_columns access');

# Once explicitly granted, the audit role can use it.
$node->safe_psql('postgres',
    'CREATE ROLE shb_audit; GRANT SELECT ON honey_bun_columns TO shb_audit; GRANT shb_audit TO app_user;');
my $granted = $node->safe_psql('postgres',
    'SELECT count(*) FROM honey_bun_columns',
    extra_params => ['-U', 'app_user']);
is($granted, '2', 'audit role with explicit GRANT can read the view');

$node->stop;
done_testing();
