#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: master can connect; sticky_honey_bun_rds extension is
#          installed in every database the harness provisions
#          (postgres + db_a + db_b); honey_bun type is in pg_type
#          (shared cross-variant assertion in t/lib/SHB_Assertions.pm,
#          also called from t/001_install.pl).

use strict;
use warnings;
use lib 'rds/online/lib';
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();

# Connectivity baseline: if master can't reach the cluster, every
# downstream test would fail with the same noise. Fail loudly here.
{
    my $cs = SHB_RDS::connstr($st);
    my ($rc, $out) = SHB_RDS::psql_run($cs, 'SELECT 1');
    is($rc,  0,   'master can connect and run SELECT 1');
    is($out, '1', 'SELECT 1 returns 1');
}

# Extension is installed in every db the harness set up. Per-db check
# matters because pg_tle install is database-scoped (unlike a global C
# extension), so a setup that missed a db would silently leak.
for my $db (qw(postgres db_a db_b)) {
    my $cs = SHB_RDS::connstr($st, db => $db);
    my ($rc, $out) = SHB_RDS::psql_run(
        $cs,
        "SELECT count(*) FROM pg_extension "
      . "WHERE extname = 'sticky_honey_bun_rds'");
    is($out, '1', "sticky_honey_bun_rds extension is installed in $db");
}

# Cross-variant assertion: the public.honey_bun base type exists. This
# is the one check that produces the same expected result against the
# self-hosted C variant and the RDS pg_tle variant, so the body lives
# in t/lib/SHB_Assertions.pm and both sides call it.
{
    my $cs = SHB_RDS::connstr($st);
    SHB_Assertions::assert_honey_bun_type_exists(
        sub { SHB_RDS::psql_run($cs, $_[0]) },
        'honey_bun base type registered (RDS variant)');
}

done_testing();
