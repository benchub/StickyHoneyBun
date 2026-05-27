use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Documents (as a test) which recon paths an attacker has against the trap,
# so future changes to the catalog lockdown are detected by test churn
# rather than silently expanding the attacker's surface.
#
# Closed paths:
#   - SELECT from honey_bun_columns (locked by REVOKE — t/013 already
#     covers this, repeated here for one-stop recon visibility).
#
# Open paths (PG defaults — acknowledged limitations per the README's
# "Compromised admins" section):
#   - pg_type is readable by PUBLIC; an attacker can discover that the
#     type `honey_bun` exists.
#   - pg_proc is readable by PUBLIC; the alias's _out function still
#     reports prosrc='honey_bun_out', so an attacker who already knows
#     the C symbol can find every alias by joining on prosrc.
#   - pg_attribute is readable by PUBLIC; combined with the above, an
#     attacker can reconstruct the inventory the protected view exposes.
#
# This test pins those facts in place. If a future hardening change closes
# one of the open paths (e.g. ALTER ROLE rls or RLS on pg_proc), the
# corresponding assertion needs updating — which is the point.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('recon_paths');
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
    SELECT create_honey_bun_alias('auth_token');
    CREATE TABLE auth (id int, tok auth_token);
    INSERT INTO auth VALUES (1, 'public.auth.tok');
    CREATE ROLE attacker LOGIN;
    GRANT SELECT ON secrets TO attacker;
});

# Closed: the protected inventory view.
my ($rc, undef, $stderr) = $node->psql('postgres',
    'SET ROLE attacker; SELECT * FROM honey_bun_columns');
isnt($rc, 0,
    'honey_bun_columns SELECT is denied for non-superuser');
like($stderr, qr/permission denied/i,
    'inventory view denial is the standard permission-denied error');

# Open (acknowledged): an attacker can discover that the canonical type
# `honey_bun` exists by reading pg_type. This is a PG default and the
# threat model accepts it. Aliases mitigate by making the planted
# column type look like a domain-named type.
my $type_count = $node->safe_psql('postgres',
    q{SET ROLE attacker; SELECT count(*) FROM pg_type WHERE typname = 'honey_bun'});
is($type_count, '1',
    'recon path open: pg_type readable by PUBLIC reveals honey_bun');

# Open: prosrc leaks the C symbol. An attacker joining pg_type → pg_proc
# on typoutput can find every alias whose _out function shares the
# honey_bun_out symbol.
my $alias_count = $node->safe_psql('postgres', q{
    SET ROLE attacker;
    SELECT count(*)
      FROM pg_type t
      JOIN pg_proc p ON t.typoutput = p.oid
     WHERE p.prosrc = 'honey_bun_out'
});
cmp_ok($alias_count, '>=', 2,
    'recon path open: pg_proc.prosrc leaks honey_bun_out symbol; alias detection still possible by determined attackers');

# Open: an attacker can reconstruct honey_bun_columns from raw catalogs.
# (This is exactly what the protected view does — the protection raises
# the bar but doesn't eliminate it.)
my $reconstructed_count = $node->safe_psql('postgres', q{
    SET ROLE attacker;
    SELECT count(*)
      FROM pg_attribute a
      JOIN pg_class      c   ON a.attrelid = c.oid
      JOIN pg_namespace  n   ON c.relnamespace = n.oid
      JOIN pg_type       t   ON a.atttypid = t.oid
      JOIN pg_proc       fn  ON t.typoutput = fn.oid
     WHERE fn.prosrc  = 'honey_bun_out'
       AND NOT a.attisdropped
       AND a.attnum > 0
       AND c.relkind IN ('r', 'p')
});
cmp_ok($reconstructed_count, '>=', 2,
    'attacker can reconstruct the inventory from raw catalogs (known limitation)');

# Closed (regression check): the legitimate trap mechanism still fires
# when the attacker reads a planted table. This is the one thing they
# should be able to do.
my $size_before = -e $log_path ? -s $log_path : 0;
$node->safe_psql('postgres',
    'SET ROLE attacker; SELECT * FROM secrets');
cmp_ok(-e $log_path ? -s $log_path : 0, '>', $size_before,
    'legitimate trap fires when attacker reads granted honey table');

$node->stop;
done_testing();
