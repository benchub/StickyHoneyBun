#!/usr/bin/env perl
#
# run.pl — orchestrate the online RDS test.
#
# This is the entry point invoked by `make rds-test-online`. It does
# NOT emit TAP itself; the per-file tests under t/variants/rds/ do that.
# Flow:
#   1. Check that the AWS environment is present. If not, exit 0 with a
#      SKIP message — `make` sees success, the operator sees why.
#   2. Generate a fresh run_id (or reuse one via SHB_REUSE_RUN_ID) and
#      print it BEFORE registering anything destructive.
#   3. Register an END {} block that always invokes teardown, unless
#      SHB_KEEP is set (inner-loop iteration mode).
#   4. preflight.py — env sanity, IP detection, stale-resource halt.
#      Skipped under SHB_REUSE_RUN_ID.
#   5. setup.py — provision everything; write state-<run_id>.json.
#      Under reuse, runs in --install-only mode (extension reinstall
#      only; ~30 sec instead of ~12 min).
#   6. Export SHB_RUN_ID and exec `prove -v t/variants/rds/*.pl`. Each
#      test file is a standalone TAP script that reads state from the
#      file setup.py just wrote.
#
# Manual recovery: if this script is interrupted or its END block
# fails:
#     python3 rds/online/list_orphans.py
#     python3 rds/online/teardown.py <run_id>

use strict;
use warnings;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use File::Temp qw(tempfile);

# run_cmd(\@argv, $stream_stdout) -> ($rc, $stdout, $stderr)
# Captures both streams; optionally tees stdout to our own as it runs
# (used for the long-running setup step so the operator can see RDS
# provisioning progress).
sub run_cmd {
    my ($argv, $stream_stdout) = @_;
    my $err_fh = gensym;
    my $pid = open3(undef, my $out_fh, $err_fh, @$argv);
    my ($out, $err) = ('', '');
    if ($stream_stdout) {
        while (my $line = <$out_fh>) {
            print $line;
            $out .= $line;
        }
    } else {
        local $/;
        $out = <$out_fh> // '';
    }
    {
        local $/;
        $err = <$err_fh> // '';
    }
    waitpid($pid, 0);
    return ($? >> 8, $out, $err);
}

# -------- preconditions --------

my $have_env_auth =
    $ENV{AWS_ACCESS_KEY_ID}
 && $ENV{AWS_SECRET_ACCESS_KEY}
 && $ENV{AWS_SESSION_TOKEN};
my $have_profile = $ENV{AWS_PROFILE};

unless (($have_env_auth || $have_profile)
        && ($ENV{AWS_REGION} || $ENV{AWS_DEFAULT_REGION})
        && $ENV{SHB_TEST_VPC_ID}
        && $ENV{SHB_TEST_SUBNET_IDS}) {
    print STDERR
        "SKIP: RDS online test requires AWS auth (AWS_PROFILE or "
      . "AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY,SESSION_TOKEN}), "
      . "a region, plus SHB_TEST_VPC_ID and SHB_TEST_SUBNET_IDS\n";
    exit 0;
}

# -------- run_id + always-fire teardown --------

sub gen_run_id {
    my @hex = ('0'..'9', 'a'..'f');
    my $s = '';
    $s .= $hex[int(rand(16))] for 1..16;
    return $s;
}

my $reuse = $ENV{SHB_REUSE_RUN_ID};
my $keep  = $ENV{SHB_KEEP};

my $run_id;
if ($reuse) {
    $run_id = $reuse;
    print STDERR
        "\nREUSING RUN_ID=$run_id "
      . "(SHB_REUSE_RUN_ID set; skipping AWS provisioning)\n\n";
} else {
    $run_id = gen_run_id();
    print STDERR
        "\nRUN_ID=$run_id  "
      . "(use this with teardown.py if anything fails)\n\n";
}

END {
    return unless $run_id;
    if ($keep) {
        print STDERR "\n";
        print STDERR
            "END: SHB_KEEP=1 - leaving AWS resources in place "
          . "for run_id=$run_id\n";
        print STDERR "To run more assertions:\n";
        print STDERR
            "  SHB_KEEP=1 SHB_REUSE_RUN_ID=$run_id make rds-test-online\n";
        print STDERR "To tear down when done:\n";
        print STDERR
            "  rds/online/.venv/bin/python3 rds/online/teardown.py $run_id\n";
        return;
    }
    print STDERR "\nEND: invoking teardown for run_id=$run_id\n";
    my $rc = system(
        'rds/online/.venv/bin/python3',
        'rds/online/teardown.py', $run_id, '--force');
    if ($rc != 0) {
        print STDERR "TEARDOWN FAILED for run_id=$run_id\n";
        print STDERR "Manual recovery:\n";
        print STDERR "  python3 rds/online/list_orphans.py\n";
        print STDERR "  python3 rds/online/teardown.py $run_id\n";
    }
}

# -------- preflight + setup --------

my ($setup_rc, $setup_err);

if ($reuse) {
    print STDERR
        "reusing existing RDS instance; reinstalling extension only\n";
    ($setup_rc, undef, $setup_err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/setup.py',
         $run_id, '--install-only'],
        1);
} else {
    print STDERR "running preflight...\n";
    my ($pf_rc, $pf_out, $pf_err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/preflight.py']);
    if ($pf_rc != 0) {
        print STDERR "preflight stderr:\n$pf_err\n";
        die "preflight failed\n";
    }
    my ($pf_fh, $pf_path) = tempfile(SUFFIX => '.json', UNLINK => 1);
    print $pf_fh $pf_out;
    close $pf_fh;

    print STDERR
        "running setup (this takes 8-12 minutes for RDS provisioning)...\n";
    ($setup_rc, undef, $setup_err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/setup.py',
         $run_id, $pf_path],
        1);
}

if ($setup_rc != 0) {
    print STDERR "setup stderr:\n$setup_err\n";
    die "setup failed\n";
}

# -------- hand off to prove --------

$ENV{SHB_RUN_ID} = $run_id;

my @test_files = sort glob('t/variants/rds/*.pl');
unless (@test_files) {
    die "no test files found under t/variants/rds/\n";
}

my $rc = system('prove', '-v', @test_files);
# system() returns -1 on exec failure, or the raw wait status otherwise.
exit($rc == -1 ? 127 : ($rc >> 8));
