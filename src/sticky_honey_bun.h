#ifndef STICKY_HONEY_BUN_H
#define STICKY_HONEY_BUN_H

void shb_register_gucs(void);
void shb_register_bgworker(void);
void shb_log_event(const char *event, const char *tag);
void shb_terminate_self_if_configured(void);
void shb_resolve_log_path_once(void);

#endif
