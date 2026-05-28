#include "postgres.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "access/xact.h"
#include "commands/dbcommands.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/json.h"
#include "utils/memutils.h"
#include "utils/resowner.h"

#include "sticky_honey_bun.h"

#define SHB_DEFAULT_FILENAME "sticky_honey_bun.log"
#define SHB_FALLBACK_DIR     "/var/log/postgresql"

static char *shb_log_path          = NULL;
static bool  shb_enabled           = true;
static bool  shb_terminate_on_read = false;

/*
 * Copy each event into PG's own logging stream at this elevel. Defaults
 * to a sentinel (-1) meaning "off, do not ereport". When set, an operator
 * can consume events from the PG log stream they already ship (rsyslog,
 * CloudWatch agent, vector, etc.) instead of standing up a tail of the
 * sticky_honey_bun.log file. Combined with log_path = '' this is the
 * "log stream is the sole sink" deployment.
 *
 * elevels we accept are DEBUG5..WARNING — read-only severities that
 * never abort the typeoutput dispatch. We deliberately exclude ERROR/
 * FATAL/PANIC: the subtxn wrapper around do_log_event would swallow
 * the longjmp without unmasking the trap, but the JSON line would
 * still emit, and a future contributor would be one config-typo away
 * from a really confusing failure mode. Better to make the enum say
 * "off, debug5..warning" and refuse the dangerous cases at GUC parse
 * time.
 */
#define SHB_LOG_LEVEL_OFF (-1)
static int shb_alert_log_level     = SHB_LOG_LEVEL_OFF;
static int shb_heartbeat_log_level = SHB_LOG_LEVEL_OFF;

static const struct config_enum_entry shb_log_level_options[] = {
    {"off",     SHB_LOG_LEVEL_OFF, false},
    {"debug5",  DEBUG5,            false},
    {"debug4",  DEBUG4,            false},
    {"debug3",  DEBUG3,            false},
    {"debug2",  DEBUG2,            false},
    {"debug1",  DEBUG1,            false},
    {"log",     LOG,               false},
    {"info",    INFO,              false},
    {"notice",  NOTICE,            false},
    {"warning", WARNING,           false},
    {NULL, 0, false}
};

/*
 * Path resolved once at _PG_init in TopMemoryContext, then frozen for the
 * lifetime of the postmaster (inherited by every backend via fork). This
 * is what closes the log_directory bypass: GetConfigOption("log_directory")
 * is PGC_SIGHUP, so an attacker who can ALTER SYSTEM could otherwise
 * redirect alerts at runtime via the resolve fallback. By capturing once,
 * subsequent reload-induced changes to log_directory have no effect.
 */
static char *shb_resolved_log_path = NULL;

void
shb_register_gucs(void)
{
    DefineCustomStringVariable(
        "sticky_honey_bun.log_path",
        "Path to the Sticky Honey Bun alert log file. Empty string disables.",
        "Defaults to <log_directory>/" SHB_DEFAULT_FILENAME " if log_directory "
        "is set, else " SHB_FALLBACK_DIR "/" SHB_DEFAULT_FILENAME ". Set to the "
        "empty string ('') to disable the file sink entirely — typically "
        "paired with sticky_honey_bun.alert_log_level so events flow only "
        "into PG's own logging stream. "
        "PGC_POSTMASTER: locked at server start so a compromised superuser "
        "cannot redirect alert writes (e.g. to /dev/null) via ALTER SYSTEM.",
        &shb_log_path,
        NULL,
        PGC_POSTMASTER,
        0,
        NULL, NULL, NULL);

    DefineCustomEnumVariable(
        "sticky_honey_bun.alert_log_level",
        "Severity at which to copy trap events into PG's own log stream.",
        "When set to anything other than 'off', each trap event (the same "
        "JSON line that's appended to log_path) is also emitted via ereport() "
        "at the named PG log level. This lets operators run the extension "
        "with log_path='' and consume alerts entirely from the PG log stream "
        "they already ship. Accepts off, debug5..debug1, log, info, notice, "
        "warning; error and higher are excluded by design. PGC_POSTMASTER: "
        "locked at server start.",
        &shb_alert_log_level,
        SHB_LOG_LEVEL_OFF,
        shb_log_level_options,
        PGC_POSTMASTER,
        0,
        NULL, NULL, NULL);

    DefineCustomEnumVariable(
        "sticky_honey_bun.heartbeat_log_level",
        "Severity at which to copy bgworker heartbeats into PG's own log stream.",
        "Independent of alert_log_level so an operator can keep heartbeats at "
        "LOG and alerts at WARNING (or filter them apart in CloudWatch / "
        "rsyslog). Same value set as alert_log_level. PGC_POSTMASTER: locked "
        "at server start.",
        &shb_heartbeat_log_level,
        SHB_LOG_LEVEL_OFF,
        shb_log_level_options,
        PGC_POSTMASTER,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "sticky_honey_bun.enabled",
        "Master switch for honeytoken logging.",
        "When false, honey_bun reads do not produce log entries. "
        "PGC_POSTMASTER: can only be set in postgresql.conf at server "
        "start; a compromised superuser session cannot disable the trap "
        "via ALTER SYSTEM.",
        &shb_enabled,
        true,
        PGC_POSTMASTER,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "sticky_honey_bun.terminate_on_read",
        "Terminate the backend after a honeytoken read.",
        "When true, a session that reads a honey value is terminated "
        "immediately after the alert is logged. This unmasks the trap to "
        "the attacker; in exchange the in-flight query is halted at the "
        "next CHECK_FOR_INTERRUPTS, limiting bulk exfiltration. Only "
        "ordinary client backends are terminated; the heartbeat bgworker, "
        "parallel workers, and walsenders are spared so heartbeats and "
        "logical replication continue to function. PGC_POSTMASTER: locked "
        "at server start so a compromised superuser session cannot bypass "
        "the kill via ALTER SYSTEM.",
        &shb_terminate_on_read,
        false,
        PGC_POSTMASTER,
        0,
        NULL, NULL, NULL);
}

static char *
resolve_log_path(void)
{
    const char *dir;

    /*
     * Explicit empty string ('') is the operator's "no file sink" signal.
     * Return NULL so shb_resolved_log_path stays NULL and write_line_locked
     * early-returns on every event. Distinct from the unset case (NULL
     * pointer), which falls through to the log_directory resolution chain
     * for backward compatibility with installs that pre-date this knob.
     */
    if (shb_log_path)
    {
        if (shb_log_path[0])
            return pstrdup(shb_log_path);
        return NULL;
    }

    dir = GetConfigOption("log_directory", true, false);
    if (dir && dir[0])
    {
        if (dir[0] == '/')
            return psprintf("%s/%s", dir, SHB_DEFAULT_FILENAME);
        return psprintf("%s/%s/%s", DataDir, dir, SHB_DEFAULT_FILENAME);
    }

    return psprintf("%s/%s", SHB_FALLBACK_DIR, SHB_DEFAULT_FILENAME);
}

static void
get_client_addr(char *out, size_t outlen)
{
    if (!MyProcPort)
    {
        snprintf(out, outlen, "internal");
        return;
    }
    if (MyProcPort->raddr.addr.ss_family == AF_UNIX)
    {
        snprintf(out, outlen, "local");
        return;
    }
    if (getnameinfo((struct sockaddr *) &MyProcPort->raddr.addr,
                    MyProcPort->raddr.salen,
                    out, outlen, NULL, 0, NI_NUMERICHOST) != 0)
        snprintf(out, outlen, "unknown");
}

/*
 * The address THIS server is bound to (the local side of the client
 * connection). Different per physical node, so primary vs replica
 * vs standby are distinguishable from the alert payload even when
 * they share a cluster_id. Mirrors the RDS variant's `server_addr`
 * field so a single alert processor sees the same field name regardless of
 * which variant emitted the event.
 *
 * For Unix-socket connections we include the listening socket path
 * (typically `/tmp/.s.PGSQL.<port>` or `<DataDir>/.s.PGSQL.<port>`)
 * because the path is the only thing that differs between two PG
 * instances running on the same host — without it, every node on the
 * same machine would report `local` and node identification would be
 * impossible for multi-cluster setups (test harness, replicas, etc.).
 */
static void
get_server_addr(char *out, size_t outlen)
{
    if (!MyProcPort)
    {
        snprintf(out, outlen, "internal");
        return;
    }
    if (MyProcPort->laddr.addr.ss_family == AF_UNIX)
    {
        struct sockaddr_un *un = (struct sockaddr_un *) &MyProcPort->laddr.addr;
        if (un->sun_path[0])
            snprintf(out, outlen, "local:%s", un->sun_path);
        else
            snprintf(out, outlen, "local");
        return;
    }
    if (getnameinfo((struct sockaddr *) &MyProcPort->laddr.addr,
                    MyProcPort->laddr.salen,
                    out, outlen, NULL, 0, NI_NUMERICHOST) != 0)
        snprintf(out, outlen, "unknown");
}

static void
append_kv_str(StringInfo buf, const char *key, const char *value, bool first)
{
    if (!first)
        appendStringInfoChar(buf, ',');
    appendStringInfoChar(buf, '"');
    appendStringInfoString(buf, key);
    appendStringInfoString(buf, "\":");
    if (value)
        escape_json(buf, value);
    else
        appendStringInfoString(buf, "null");
}

static void
append_kv_int(StringInfo buf, const char *key, long long value, bool first)
{
    if (!first)
        appendStringInfoChar(buf, ',');
    appendStringInfo(buf, "\"%s\":%lld", key, value);
}

void
shb_resolve_log_path_once(void)
{
    MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);

    shb_resolved_log_path = resolve_log_path();
    MemoryContextSwitchTo(old);
}

/*
 * Atomic write of a single fully-built line to the alert file.
 *
 * Open + flock + write + close as one syscall sequence. NO PostgreSQL
 * functions are called here, so this cannot ereport — which means we can
 * call it from any context including a bgworker without a database
 * connection, and we never have to worry about fd leaks across a longjmp.
 *
 * O_NOFOLLOW: if the target is a symlink (an attacker may have swapped
 * the file to redirect alerts), the open fails with ELOOP. flock blocks
 * concurrent backends because O_APPEND atomicity is only guaranteed up to
 * PIPE_BUF (4 KB) and our lines can exceed that. write() is looped to
 * tolerate short returns from NFS / FUSE / signal-after-partial-progress.
 * Every failure path drops the event silently, matching the project's
 * "broken log path must not surface as a SELECT error" rule.
 */
static void
write_line_locked(StringInfo line)
{
    int     fd;
    ssize_t total = 0;

    if (!shb_resolved_log_path)
        return;

    fd = open(shb_resolved_log_path,
              O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0640);
    if (fd < 0)
        return;

    if (flock(fd, LOCK_EX) < 0)
    {
        close(fd);
        return;
    }

    while (total < line->len)
    {
        ssize_t n = write(fd, line->data + total, line->len - total);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        total += n;
    }

    close(fd);
}

static void
do_log_event(const char *event, const char *tag)
{
    struct timeval  tv;
    struct tm       tm_utc;
    char            ts[32];
    char            client[NI_MAXHOST];
    char            server[NI_MAXHOST];
    StringInfoData  line;

    /*
     * Everything in this function up to write_line_locked can ereport
     * (palloc, syscache lookups, escape_json). That's fine: the caller
     * (shb_log_event) wraps us in a subtransaction whose rollback frees
     * the StringInfo's backing palloc on the error path. No file
     * descriptor is held at any of those points — write_line_locked
     * acquires + releases the fd as an atomic syscall sequence.
     */
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm_utc);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    get_client_addr(client, sizeof(client));
    get_server_addr(server, sizeof(server));

    initStringInfo(&line);
    appendStringInfoChar(&line, '{');
    appendStringInfo(&line, "\"ts\":\"%s.%06ldZ\"", ts, (long) tv.tv_usec);
    append_kv_str(&line, "event", event, false);
    append_kv_str(&line, "tag", tag, false);
    append_kv_str(&line, "session_user",
                  GetUserNameFromId(GetSessionUserId(), true), false);
    append_kv_str(&line, "current_user",
                  GetUserNameFromId(GetUserId(), true), false);
    append_kv_str(&line, "application_name",
                  GetConfigOption("application_name", true, false), false);
    append_kv_str(&line, "database", get_database_name(MyDatabaseId), false);
    append_kv_int(&line, "pid", MyProcPid, false);
    append_kv_str(&line, "client_addr", client, false);
    append_kv_str(&line, "server_addr", server, false);
    append_kv_str(&line, "query", debug_query_string, false);
    appendStringInfoChar(&line, '}');

    /*
     * ereport BEFORE the trailing newline so PG's logger gets a clean
     * single-line message (it adds its own line break). The write to the
     * file sink needs the newline so consumers tailing the file see one
     * event per line, so we append it after.
     */
    if (shb_alert_log_level != SHB_LOG_LEVEL_OFF)
        ereport(shb_alert_log_level, (errmsg_internal("%s", line.data)));

    appendStringInfoChar(&line, '\n');

    write_line_locked(&line);
    pfree(line.data);
}

void
shb_log_event(const char *event, const char *tag)
{
    MemoryContext oldcontext;
    ResourceOwner oldowner;

    if (!shb_enabled)
        return;

    /*
     * Wrap do_log_event in an internal subtransaction so a swallowed error
     * doesn't poison the caller's outer transaction. Without the subtxn,
     * FlushErrorState clears the error info but the outer transaction
     * stays in TBLOCK_INPROGRESS_ABORT; the next statement in the same
     * transaction errors with "current transaction is aborted." That's
     * fatal for the trap path (typeoutput is called mid-SELECT) and a
     * persistent foot-gun for the heartbeat path.
     */
    oldcontext = CurrentMemoryContext;
    oldowner   = CurrentResourceOwner;

    /*
     * BeginInternalSubTransaction switches CurrentMemoryContext into the
     * new subtxn's CurTransactionContext. We DELIBERATELY stay there for
     * the body of do_log_event so that any palloc/initStringInfo inside
     * gets cleaned up by RollbackAndReleaseCurrentSubTransaction on the
     * error path. (An earlier version switched back to oldcontext here,
     * which leaked line.data on every failed event.)
     */
    BeginInternalSubTransaction(NULL);

    PG_TRY();
    {
        do_log_event(event, tag);
        ReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;
    }
    PG_CATCH();
    {
        MemoryContextSwitchTo(oldcontext);
        FlushErrorState();
        RollbackAndReleaseCurrentSubTransaction();
        CurrentResourceOwner = oldowner;
    }
    PG_END_TRY();
}

/*
 * Heartbeat-specific log entry.
 *
 * Deliberately separate from shb_log_event() because the bgworker calling
 * us has NO database connection — it's registered with BGWORKER_SHMEM_ACCESS
 * only, no BGWORKER_BACKEND_DATABASE_CONNECTION. That means we cannot do
 * any of the syscache lookups (GetUserNameFromId, get_database_name) that
 * do_log_event() does, and we cannot start a transaction to wrap the work
 * in a subtransaction either. Trying to do either would crash the worker.
 *
 * The heartbeat line is therefore a minimal shape: ts, event, tag, pid.
 * That's all the bgworker has anyway — there's no session_user/database/
 * application_name/client_addr/query to populate. The alert processor must
 * tolerate a heartbeat line missing those fields.
 *
 * A short-lived MemoryContext absorbs the StringInfo so a palloc failure
 * during line construction doesn't leak across heartbeats.
 */
void
shb_log_heartbeat(void)
{
    static MemoryContext heartbeat_ctx = NULL;
    MemoryContext        oldcontext;
    struct timeval       tv;
    struct tm            tm_utc;
    char                 ts[32];
    StringInfoData       line;

    if (!shb_enabled)
        return;

    if (heartbeat_ctx == NULL)
        heartbeat_ctx = AllocSetContextCreate(TopMemoryContext,
                                              "shb heartbeat",
                                              ALLOCSET_SMALL_SIZES);

    oldcontext = MemoryContextSwitchTo(heartbeat_ctx);

    PG_TRY();
    {
        gettimeofday(&tv, NULL);
        gmtime_r(&tv.tv_sec, &tm_utc);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_utc);

        initStringInfo(&line);
        appendStringInfoChar(&line, '{');
        appendStringInfo(&line, "\"ts\":\"%s.%06ldZ\"",
                         ts, (long) tv.tv_usec);
        appendStringInfoString(&line, ",\"event\":\"heartbeat\"");
        appendStringInfoString(&line, ",\"tag\":\"heartbeat\"");
        appendStringInfo(&line, ",\"pid\":%d", MyProcPid);
        appendStringInfoChar(&line, '}');

        if (shb_heartbeat_log_level != SHB_LOG_LEVEL_OFF)
            ereport(shb_heartbeat_log_level,
                    (errmsg_internal("%s", line.data)));

        appendStringInfoChar(&line, '\n');

        write_line_locked(&line);
    }
    PG_CATCH();
    {
        FlushErrorState();
    }
    PG_END_TRY();

    MemoryContextSwitchTo(oldcontext);
    MemoryContextReset(heartbeat_ctx);
}

/*
 * Called from the typoutput / typsend paths after a trap is logged.
 * Deliberately NOT called from shb_log_event(): the heartbeat bgworker
 * shares that path, and self-terminating from a bgworker would suicide-
 * restart-suicide every bgw_restart_time seconds. The MyBackendType guard
 * is belt-and-suspenders against the same mistake in future call sites,
 * and also skips parallel workers and walsenders so logical replication
 * keeps flowing on the publisher.
 */
void
shb_terminate_self_if_configured(void)
{
    if (!shb_enabled || !shb_terminate_on_read)
        return;
    if (MyBackendType != B_BACKEND)
        return;
    kill(MyProcPid, SIGTERM);
}
