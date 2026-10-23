#ifndef AGENT_VAULT_CSQLITE_SHIM_H
#define AGENT_VAULT_CSQLITE_SHIM_H

#include <sqlite3.h>

// Swift cannot call variadic C functions or use SQLITE_TRANSIENT directly.
static inline int av_sqlite_db_config_int(sqlite3 *db, int op, int value, int *current) {
    return sqlite3_db_config(db, op, value, current);
}

static inline sqlite3_destructor_type av_sqlite_transient(void) {
    return SQLITE_TRANSIENT;
}

static inline const char *av_sqlite_header_version(void) { return SQLITE_VERSION; }
static inline const char *av_sqlite_header_source_id(void) { return SQLITE_SOURCE_ID; }

#endif
