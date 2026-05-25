#include "postgres.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
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
        "Path to the Sticky Honey Bun alert log file.",
        "Defaults to <log_directory>/" SHB_DEFAULT_FILENAME " if log_directory "
        "is set, else " SHB_FALLBACK_DIR "/" SHB_DEFAULT_FILENAME ". "
        "PGC_POSTMASTER: locked at server start so a compromised superuser "
        "cannot redirect alert writes (e.g. to /dev/null) via ALTER SYSTEM.",
        &shb_log_path,
        NULL,
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

    if (shb_log_path && shb_log_path[0])
        return pstrdup(shb_log_path);

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

static void
do_log_event(const char *event, const char *tag)
{
    int             fd;
    struct timeval  tv;
    struct tm       tm_utc;
    char            ts[32];
    char            client[NI_MAXHOST];
    StringInfoData  line;
    ssize_t         total;

    if (!shb_resolved_log_path)
        return;

    /*
     * O_NOFOLLOW: if the target is a symlink, fail with ELOOP rather than
     * follow it. Without this an attacker with parent-directory write can
     * swap the log file for a symlink to /dev/null (silently suppress
     * alerts) or to any other file the postgres user can write.
     */
    fd = open(shb_resolved_log_path,
              O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0640);
    if (fd < 0)
        return;

    /*
     * O_APPEND atomicity is only guaranteed up to PIPE_BUF (4 KB on Linux);
     * a long debug_query_string can push the JSON line over that. flock the
     * fd before writing so concurrent backends serialize cleanly. The lock
     * releases automatically on close().
     *
     * If flock fails (e.g., NFS without lockd, or signal interruption),
     * drop the event rather than writing unlocked — interleaved writes
     * would produce corrupt JSON that the alert processor would have to
     * throw away anyway, and silently dropping matches every other I/O
     * failure on this path. Done outside PG_TRY because flock cannot
     * ereport and we need a safe early return.
     */
    if (flock(fd, LOCK_EX) < 0)
    {
        close(fd);
        return;
    }

    /*
     * Everything below this point can ereport(ERROR) — palloc, syscache
     * lookups in GetUserNameFromId / get_database_name, escape_json. The
     * fd is a raw kernel handle (not VFD-managed), so a longjmp out of
     * here would leak it. Inner PG_TRY closes the fd on the error path
     * and re-throws to the outer (subtransaction-rolled-back) handler.
     */
    PG_TRY();
    {
        gettimeofday(&tv, NULL);
        gmtime_r(&tv.tv_sec, &tm_utc);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_utc);
        get_client_addr(client, sizeof(client));

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
        append_kv_str(&line, "query", debug_query_string, false);
        appendStringInfoChar(&line, '}');
        appendStringInfoChar(&line, '\n');

        /*
         * Loop the write. write() to a regular file on a local FS normally
         * returns count or -1, but NFS / FUSE / signal-after-partial-progress
         * can produce a short positive return. Without the loop a short
         * write produces a truncated JSON line that downstream parsers
         * have to drop.
         */
        total = 0;
        while (total < line.len)
        {
            ssize_t n = write(fd, line.data + total, line.len - total);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            total += n;
        }
        pfree(line.data);
    }
    PG_CATCH();
    {
        close(fd);
        PG_RE_THROW();
    }
    PG_END_TRY();

    close(fd);
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
