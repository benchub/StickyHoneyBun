#include "postgres.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif
#include "catalog/pg_type.h"
#include "fmgr.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"

#include "sticky_honey_bun.h"

PG_MODULE_MAGIC;

void _PG_init(void);

PG_FUNCTION_INFO_V1(honey_bun_in);
PG_FUNCTION_INFO_V1(honey_bun_out);
PG_FUNCTION_INFO_V1(honey_bun_recv);
PG_FUNCTION_INFO_V1(honey_bun_send);

void
_PG_init(void)
{
    shb_register_gucs();
    shb_resolve_log_path_once();
    shb_register_bgworker();
}

/*
 * PostgreSQL checks USAGE on a TYPE when a column of that type is created
 * or a function signature references it, but NOT when a literal is cast
 * via `'x'::sometype` or when a row is inserted with a value of that type
 * — both go through typinput / typreceive dispatch, which bypasses fmgr's
 * ACL machinery the same way typeoutput dispatch does. Without this guard,
 * the SQL-level REVOKEs cannot close the forge-an-alert path:
 *
 *   SELECT 'forged.tag'::honey_bun;
 *
 * succeeds for any role with PUBLIC USAGE (the default before REVOKE) and
 * the result row's typeoutput dispatch fires the trap with the attacker's
 * chosen tag. We enforce the check in C: invocations of honey_bun_in /
 * honey_bun_recv (the construction paths) require the caller to hold
 * USAGE on the destination type. The function OID is the per-alias
 * pg_proc entry's OID; the return type of that function is the actual
 * honey-shaped type we want to gate.
 */
static void
check_type_usage(FunctionCallInfo fcinfo)
{
    Oid       type_oid = get_func_rettype(fcinfo->flinfo->fn_oid);
    AclResult aclresult;

    /*
     * PG 16 unified the per-catalog *_aclcheck functions into object_aclcheck
     * taking the catalog OID. PG 15 and earlier still use pg_type_aclcheck.
     */
#if PG_VERSION_NUM >= 160000
    aclresult = object_aclcheck(TypeRelationId, type_oid, GetUserId(), ACL_USAGE);
#else
    aclresult = pg_type_aclcheck(type_oid, GetUserId(), ACL_USAGE);
#endif

    if (aclresult != ACLCHECK_OK)
        aclcheck_error_type(aclresult, type_oid);
}

Datum
honey_bun_in(PG_FUNCTION_ARGS)
{
    char *input;

    check_type_usage(fcinfo);
    input = PG_GETARG_CSTRING(0);

    PG_RETURN_TEXT_P(cstring_to_text(input));
}

Datum
honey_bun_out(PG_FUNCTION_ARGS)
{
    text *value = PG_GETARG_TEXT_PP(0);
    char *tag = text_to_cstring(value);

    shb_log_event("read_text", tag);
    shb_terminate_self_if_configured();
    PG_FREE_IF_COPY(value, 0);

    PG_RETURN_CSTRING(tag);
}

Datum
honey_bun_recv(PG_FUNCTION_ARGS)
{
    StringInfo  buf;
    char       *str;
    int         nbytes;
    text       *result;

    check_type_usage(fcinfo);
    buf = (StringInfo) PG_GETARG_POINTER(0);

    str = pq_getmsgtext(buf, buf->len - buf->cursor, &nbytes);
    result = cstring_to_text_with_len(str, nbytes);
    pfree(str);

    PG_RETURN_TEXT_P(result);
}

Datum
honey_bun_send(PG_FUNCTION_ARGS)
{
    text           *value = PG_GETARG_TEXT_PP(0);
    char           *tag = text_to_cstring(value);
    StringInfoData  buf;

    shb_log_event("read_binary", tag);
    shb_terminate_self_if_configured();

    pq_begintypsend(&buf);
    pq_sendtext(&buf, VARDATA_ANY(value), VARSIZE_ANY_EXHDR(value));
    pfree(tag);
    PG_FREE_IF_COPY(value, 0);

    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}
