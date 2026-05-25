#include "postgres.h"

#include <limits.h>

#include "access/xact.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "utils/guc.h"
#include "utils/wait_event.h"

#include "sticky_honey_bun.h"

#define SHB_BGWORKER_DEFAULT_INTERVAL 60

static int shb_heartbeat_interval_seconds = SHB_BGWORKER_DEFAULT_INTERVAL;

PGDLLEXPORT void shb_heartbeat_main(Datum main_arg);

void
shb_heartbeat_main(Datum main_arg)
{
    pqsignal(SIGHUP, SignalHandlerForConfigReload);
    pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
    BackgroundWorkerUnblockSignals();

    BackgroundWorkerInitializeConnection("postgres", NULL, 0);

    while (!ShutdownRequestPending)
    {
        int  interval = shb_heartbeat_interval_seconds;
        int  events;

        if (interval > 0)
        {
            StartTransactionCommand();
            shb_log_event("heartbeat", "heartbeat");
            CommitTransactionCommand();

            events = WaitLatch(MyLatch,
                               WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
                               interval * 1000L,
                               PG_WAIT_EXTENSION);
        }
        else
        {
            events = WaitLatch(MyLatch,
                               WL_LATCH_SET | WL_POSTMASTER_DEATH,
                               0,
                               PG_WAIT_EXTENSION);
        }

        if (events & WL_POSTMASTER_DEATH)
            proc_exit(1);

        ResetLatch(MyLatch);

        if (ConfigReloadPending)
        {
            ConfigReloadPending = false;
            ProcessConfigFile(PGC_SIGHUP);
        }
    }

    proc_exit(0);
}

void
shb_register_bgworker(void)
{
    BackgroundWorker worker;

    DefineCustomIntVariable(
        "sticky_honey_bun.heartbeat_interval_seconds",
        "Seconds between heartbeat log lines emitted by the background worker.",
        "Set to 0 to disable heartbeats. PGC_POSTMASTER: can only be set "
        "in postgresql.conf at server start; a compromised superuser "
        "session cannot silence the heartbeat (and trigger the alerter's "
        "deadman) via ALTER SYSTEM.",
        &shb_heartbeat_interval_seconds,
        SHB_BGWORKER_DEFAULT_INTERVAL,
        0, INT_MAX,
        PGC_POSTMASTER,
        GUC_UNIT_S,
        NULL, NULL, NULL);

    memset(&worker, 0, sizeof(worker));
    worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time = BgWorkerStart_ConsistentState;
    worker.bgw_restart_time = 10;
    snprintf(worker.bgw_library_name,  BGW_MAXLEN, "sticky_honey_bun");
    snprintf(worker.bgw_function_name, BGW_MAXLEN, "shb_heartbeat_main");
    snprintf(worker.bgw_name,          BGW_MAXLEN, "sticky_honey_bun heartbeat");
    snprintf(worker.bgw_type,          BGW_MAXLEN, "sticky_honey_bun heartbeat");
    worker.bgw_main_arg  = (Datum) 0;
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);
}
