use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Site-specific deployments may want to plant honey columns under a less
# discoverable type name (e.g. "account_token", "session_blob") so the
# attacker who reads the docs can't grep for "honey_bun". This test
# exercises the create_honey_bun_alias() helper that registers a new
# type sharing honey_bun's C I/O functions.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('alias_type');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    SELECT create_honey_bun_alias('account_token');
    CREATE TABLE accounts (id int, honey account_token);
    INSERT INTO accounts VALUES
        (1, NULL),
        (2, 'public.accounts.honey');
});

my $type_exists = $node->safe_psql('postgres',
    "SELECT 1 FROM pg_type WHERE typname = 'account_token'");
is($type_exists, '1', 'aliased type is registered');

# Confirm the alias is backed by the same C output implementation
# (different SQL-level OIDs, same compiled symbol).
my $shares_c_impl = $node->safe_psql('postgres', q{
    SELECT
        (SELECT p.prosrc FROM pg_type t JOIN pg_proc p ON t.typoutput = p.oid
          WHERE t.typname = 'account_token') =
        (SELECT p.prosrc FROM pg_type t JOIN pg_proc p ON t.typoutput = p.oid
          WHERE t.typname = 'honey_bun')
});
is($shares_c_impl, 't',
   'alias output function is backed by the same C symbol as honey_bun');

# NULL value through the alias should still not trip.
$node->safe_psql('postgres', 'SELECT * FROM accounts WHERE id = 1');
ok(! -e $log_path || -z $log_path,
   'NULL value through alias type does not trip');

# Non-NULL value through alias should trip.
$node->safe_psql('postgres', 'SELECT * FROM accounts WHERE id = 2');
ok(-e $log_path && -s $log_path, 'non-NULL through alias trips');

open(my $fh, '<', $log_path) or die "$!";
my $line = <$fh>;
close $fh;

like($line, qr/"event":"read_text"/,
     'alias produces read_text event');
like($line, qr/"tag":"public\.accounts\.honey"/,
     'tag survives through the aliased type');

# The inventory view should find columns of any type sharing our typoutput,
# not just the canonical honey_bun name.
my $inv_count = $node->safe_psql('postgres', q{
    SELECT count(*) FROM honey_bun_columns WHERE table_name = 'accounts'
});
is($inv_count, '1', 'inventory view finds alias-typed columns');

$node->stop;
done_testing();
