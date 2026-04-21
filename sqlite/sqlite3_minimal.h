/*
 * sqlite3_minimal.h
 * Hand-written declarations for the sqlite3 APIs we use,
 * so we can compile without installing libsqlite3-dev.
 * Link with: /usr/lib/x86_64-linux-gnu/libsqlite3.so.0
 */
#ifndef SQLITE3_MINIMAL_H
#define SQLITE3_MINIMAL_H

#include <stdarg.h>

/* Opaque types */
typedef struct sqlite3       sqlite3;
typedef struct sqlite3_stmt  sqlite3_stmt;

/* Result codes */
#define SQLITE_OK        0
#define SQLITE_ERROR     1
#define SQLITE_ROW      100
#define SQLITE_DONE     101

/* Open flags */
#define SQLITE_OPEN_READWRITE  0x00000002
#define SQLITE_OPEN_CREATE     0x00000004

/* --- Core API --- */
int   sqlite3_open(const char *filename, sqlite3 **ppDb);
int   sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
int   sqlite3_close(sqlite3 *db);
int   sqlite3_exec(sqlite3 *db, const char *sql,
                   int (*callback)(void*,int,char**,char**),
                   void *arg, char **errmsg);
void  sqlite3_free(void *ptr);
const char *sqlite3_errmsg(sqlite3 *db);

/* --- Prepared statements --- */
int   sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte,
                         sqlite3_stmt **ppStmt, const char **pzTail);
int   sqlite3_step(sqlite3_stmt *pStmt);
int   sqlite3_finalize(sqlite3_stmt *pStmt);
int   sqlite3_reset(sqlite3_stmt *pStmt);

/* --- Bind --- */
int   sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void(*)(void*));
int   sqlite3_bind_int(sqlite3_stmt*, int, int);
int   sqlite3_bind_int64(sqlite3_stmt*, int, long long);

/* --- Column --- */
const unsigned char *sqlite3_column_text(sqlite3_stmt*, int iCol);
int                  sqlite3_column_int(sqlite3_stmt*, int iCol);
long long            sqlite3_column_int64(sqlite3_stmt*, int iCol);

/* Destructor sentinel */
#define SQLITE_TRANSIENT  ((void(*)(void*))(-1))
#define SQLITE_STATIC     ((void(*)(void*))(0))

/* Last insert rowid */
long long sqlite3_last_insert_rowid(sqlite3*);

#endif /* SQLITE3_MINIMAL_H */
