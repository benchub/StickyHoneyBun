#include "postgres.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif
#include "fmgr.h"
#include "libpq/pqformat.h"
#include "utils/builtins.h"

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
    shb_register_bgworker();
}

Datum
honey_bun_in(PG_FUNCTION_ARGS)
{
    char *input = PG_GETARG_CSTRING(0);

    PG_RETURN_TEXT_P(cstring_to_text(input));
}

Datum
honey_bun_out(PG_FUNCTION_ARGS)
{
    text *value = PG_GETARG_TEXT_PP(0);
    char *tag = text_to_cstring(value);

    shb_log_event("read_text", tag);
    shb_terminate_self_if_configured();

    PG_RETURN_CSTRING(tag);
}

Datum
honey_bun_recv(PG_FUNCTION_ARGS)
{
    StringInfo  buf = (StringInfo) PG_GETARG_POINTER(0);
    char       *str;
    int         nbytes;
    text       *result;

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

    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}
