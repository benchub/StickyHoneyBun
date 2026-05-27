# Variants: self-hosted, rds
# (The honey_bun-type-exists assertion is the cross-variant body in
# t/lib/SHB_Assertions.pm; the log_path GUC assertion is self-hosted-only.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('install');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
});
$node->start;

SHB::install_extension($node);

# Cross-variant assertion: honey_bun base type is registered in
# pg_type. The same body runs against the RDS variant from
# rds/online/t/001_install.pl. PostgreSQL::Test::Cluster's `psql`
# method already returns ($rc, $stdout, $stderr), so the coderef is
# a thin wrapper.
SHB_Assertions::assert_honey_bun_type_exists(
    sub { $node->psql('postgres', $_[0]) },
    'honey_bun base type registered (self-hosted variant)');

# Self-hosted-only: confirms the log_path GUC was honored at server
# start. No analog in the RDS variant (config lives in the locked-down
# sticky_honey_bun.config table, not a GUC).
my $log_path_setting = $node->safe_psql('postgres',
    'SHOW sticky_honey_bun.log_path');
is($log_path_setting, $log_path, 'sticky_honey_bun.log_path GUC honored');

$node->stop;
done_testing();
