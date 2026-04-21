/*
 * database.h
 * SQLite3-backed persistence layer for:
 *   - users        (credentials, salt)
 *   - files        (metadata, server path, owner)
 *   - permissions  (read/write per user per file)
 *   - sessions     (token, expiry, user binding)
 *
 * All public functions are thread-safe (single global mutex + WAL mode).
 * Link with: /usr/lib/x86_64-linux-gnu/libsqlite3.so.0
 */
#ifndef DATABASE_H
#define DATABASE_H

#include "../common/common.h"
#include "../common/sha256.h"
#include "../sqlite/sqlite3_minimal.h"

/* ══════════════════════════════════════════════════════
   INTERNAL GLOBALS
   ══════════════════════════════════════════════════════ */
static sqlite3        *g_db   = NULL;
static pthread_mutex_t g_db_lock = PTHREAD_MUTEX_INITIALIZER;

/* ══════════════════════════════════════════════════════
   SCHEMA
   ══════════════════════════════════════════════════════ */
static const char *SCHEMA_SQL =
    /* Users table */
    "CREATE TABLE IF NOT EXISTS users ("
    "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  username      TEXT    NOT NULL UNIQUE,"
    "  password_hash TEXT    NOT NULL,"
    "  salt          TEXT    NOT NULL,"
    "  created_at    TEXT    DEFAULT (datetime('now'))"
    ");"

    /* Files table */
    "CREATE TABLE IF NOT EXISTS files ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  filename    TEXT    NOT NULL,"
    "  filepath    TEXT    NOT NULL,"
    "  owner_id    INTEGER NOT NULL,"
    "  file_size   INTEGER NOT NULL DEFAULT 0,"
    "  uploaded_at TEXT    DEFAULT (datetime('now')),"
    "  FOREIGN KEY(owner_id) REFERENCES users(id)"
    ");"

    /* Permissions table */
    "CREATE TABLE IF NOT EXISTS permissions ("
    "  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  file_id   INTEGER NOT NULL,"
    "  user_id   INTEGER NOT NULL,"
    "  can_read  INTEGER NOT NULL DEFAULT 1,"
    "  can_write INTEGER NOT NULL DEFAULT 0,"
    "  UNIQUE(file_id, user_id),"
    "  FOREIGN KEY(file_id) REFERENCES files(id),"
    "  FOREIGN KEY(user_id) REFERENCES users(id)"
    ");"

    /* Sessions table */
    "CREATE TABLE IF NOT EXISTS sessions ("
    "  token      TEXT    PRIMARY KEY,"
    "  user_id    INTEGER NOT NULL,"
    "  username   TEXT    NOT NULL,"
    "  expires_at INTEGER NOT NULL,"
    "  FOREIGN KEY(user_id) REFERENCES users(id)"
    ");"

    /* Indexes for performance */
    "CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);"
    "CREATE INDEX IF NOT EXISTS idx_files_owner     ON files(owner_id);"
    "CREATE INDEX IF NOT EXISTS idx_perms_file_user ON permissions(file_id, user_id);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_token  ON sessions(token);";

/* ══════════════════════════════════════════════════════
   INIT / OPEN
   ══════════════════════════════════════════════════════ */
int db_init(const char *db_path)
{
    if (sqlite3_open(db_path, &g_db) != SQLITE_OK) {
        LOG_ERROR("Cannot open database '%s': %s", db_path, sqlite3_errmsg(g_db));
        return -1;
    }
    char *err = NULL;
    /* Enable WAL mode for concurrent reads */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err);
    if (err) { sqlite3_free(err); err = NULL; }
    /* Enforce foreign keys */
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, &err);
    if (err) { sqlite3_free(err); err = NULL; }

    if (sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &err) != SQLITE_OK) {
        LOG_ERROR("Schema creation failed: %s", err);
        sqlite3_free(err);
        return -1;
    }
    LOG_INFO("Database initialised: %s", db_path);
    return 0;
}

void db_close(void)
{
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
}

/* ══════════════════════════════════════════════════════
   USER OPERATIONS
   ══════════════════════════════════════════════════════ */

/*
 * db_register_user
 * Returns: 0 = success
 *         -1 = username already exists
 *         -2 = database error
 */
int db_register_user(const char *username, const char *password)
{
    char salt[9], hash[65];
    generate_salt(salt);
    hash_password(password, salt, hash);

    pthread_mutex_lock(&g_db_lock);
    const char *sql =
        "INSERT INTO users (username, password_hash, salt) VALUES (?,?,?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_lock);
        return -2;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash,     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, salt,     -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_lock);

    if (rc == SQLITE_DONE) return 0;
    /* SQLITE_CONSTRAINT means UNIQUE violation */
    return (rc == 1 /* SQLITE_ERROR */ || rc == 19 /* SQLITE_CONSTRAINT */) ? -1 : -2;
}

/*
 * db_login_user
 * Verifies credentials. On success fills token_out (MAX_TOKEN bytes).
 * Returns: 0 = success, -1 = wrong creds, -2 = db error
 */
int db_login_user(const char *username, const char *password, char *token_out)
{
    pthread_mutex_lock(&g_db_lock);
    const char *sql =
        "SELECT id, password_hash, salt FROM users WHERE username=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_lock);
        return -2;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    int user_id = -1;
    char stored_hash[65] = {0}, stored_salt[9] = {0};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
        snprintf(stored_hash, sizeof(stored_hash), "%s",
                 (const char *)sqlite3_column_text(stmt, 1));
        snprintf(stored_salt, sizeof(stored_salt), "%s",
                 (const char *)sqlite3_column_text(stmt, 2));
    }
    sqlite3_finalize(stmt);

    if (user_id < 0) { pthread_mutex_unlock(&g_db_lock); return -1; }

    /* Verify password */
    char computed[65];
    hash_password(password, stored_salt, computed);
    if (strcmp(computed, stored_hash) != 0) {
        pthread_mutex_unlock(&g_db_lock);
        return -1;
    }

    /* Generate unique token */
    uint64_t v = (uint64_t)time(NULL) ^ ((uint64_t)rand()<<32) ^ (uint64_t)getpid();
    snprintf(token_out, MAX_TOKEN, "%016llx%08x", (unsigned long long)v, rand());

    /* Store session */
    long long expires = (long long)time(NULL) + SESSION_TIMEOUT;
    const char *isql =
        "INSERT OR REPLACE INTO sessions(token,user_id,username,expires_at)"
        " VALUES(?,?,?,?);";
    if (sqlite3_prepare_v2(g_db, isql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token_out, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, user_id);
        sqlite3_bind_text(stmt, 3, username,  -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt,4, expires);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
    return 0;
}

/* ══════════════════════════════════════════════════════
   SESSION OPERATIONS
   ══════════════════════════════════════════════════════ */

typedef struct {
    int  user_id;
    char username[MAX_USERNAME];
    int  valid;
} SessionInfo;

/*
 * db_validate_session
 * Fills info. Returns 1 if valid, 0 if expired/invalid.
 * Also prunes expired sessions.
 */
int db_validate_session(const char *token, SessionInfo *info)
{
    pthread_mutex_lock(&g_db_lock);

    /* Purge expired sessions */
    char *err = NULL;
    char purge[128];
    snprintf(purge, sizeof(purge),
             "DELETE FROM sessions WHERE expires_at < %lld;",
             (long long)time(NULL));
    sqlite3_exec(g_db, purge, NULL, NULL, &err);
    if (err) { sqlite3_free(err); err = NULL; }

    const char *sql =
        "SELECT user_id, username, expires_at FROM sessions WHERE token=?;";
    sqlite3_stmt *stmt;
    int found = 0;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            long long exp = sqlite3_column_int64(stmt, 2);
            if (exp > (long long)time(NULL)) {
                info->user_id = sqlite3_column_int(stmt, 0);
                snprintf(info->username, MAX_USERNAME, "%s",
                         (const char *)sqlite3_column_text(stmt, 1));
                info->valid = 1;
                found = 1;
                /* Refresh expiry */
                long long new_exp = (long long)time(NULL) + SESSION_TIMEOUT;
                char upd[256];
                snprintf(upd, sizeof(upd),
                         "UPDATE sessions SET expires_at=%lld WHERE token='%s';",
                         new_exp, token);
                sqlite3_exec(g_db, upd, NULL, NULL, NULL);
            }
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
    return found;
}

void db_destroy_session(const char *token)
{
    pthread_mutex_lock(&g_db_lock);
    const char *sql = "DELETE FROM sessions WHERE token=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
}

/* ══════════════════════════════════════════════════════
   FILE METADATA OPERATIONS
   ══════════════════════════════════════════════════════ */

/*
 * db_save_file_meta
 * Inserts file record and grants owner full permissions.
 * Returns file id on success, -1 on error.
 */
int db_save_file_meta(const char *filename, const char *filepath,
                      int owner_id, uint64_t size)
{
    pthread_mutex_lock(&g_db_lock);

    /* Begin transaction for atomicity */
    sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);

    const char *fsql =
        "INSERT INTO files(filename,filepath,owner_id,file_size)"
        " VALUES(?,?,?,?);";
    sqlite3_stmt *stmt;
    int file_id = -1;
    if (sqlite3_prepare_v2(g_db, fsql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text (stmt, 1, filename, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 2, filepath, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (stmt, 3, owner_id);
        sqlite3_bind_int64(stmt, 4, (long long)size);
        if (sqlite3_step(stmt) == SQLITE_DONE)
            file_id = (int)sqlite3_last_insert_rowid(g_db);
        sqlite3_finalize(stmt);
    }

    if (file_id > 0) {
        /* Grant owner read+write */
        const char *psql =
            "INSERT INTO permissions(file_id,user_id,can_read,can_write)"
            " VALUES(?,?,1,1);";
        if (sqlite3_prepare_v2(g_db, psql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, file_id);
            sqlite3_bind_int(stmt, 2, owner_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
    } else {
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
    }

    pthread_mutex_unlock(&g_db_lock);
    return file_id;
}

typedef struct {
    int      file_id;
    char     filepath[MAX_FILEPATH];
    uint64_t file_size;
    int      owner_id;
    int      found;
} FileRecord;

/*
 * db_get_file
 * Fills rec if user has read permission.
 * Returns 1 on success, 0 on not found / no permission.
 */
int db_get_file(const char *filename, int user_id, FileRecord *rec)
{
    pthread_mutex_lock(&g_db_lock);
    const char *sql =
        "SELECT f.id, f.filepath, f.file_size, f.owner_id"
        "  FROM files f"
        "  JOIN permissions p ON p.file_id = f.id"
        " WHERE f.filename=? AND p.user_id=? AND p.can_read=1"
        " LIMIT 1;";
    sqlite3_stmt *stmt;
    int found = 0;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, user_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            rec->file_id  = sqlite3_column_int(stmt, 0);
            snprintf(rec->filepath, MAX_FILEPATH, "%s",
                     (const char *)sqlite3_column_text(stmt, 1));
            rec->file_size = (uint64_t)sqlite3_column_int64(stmt, 2);
            rec->owner_id  = sqlite3_column_int(stmt, 3);
            rec->found     = 1;
            found = 1;
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
    return found;
}

/*
 * db_list_files
 * Fills out[] with files accessible to user_id.
 * Returns count.
 */
int db_list_files(int user_id, FileInfo *out, int max_out)
{
    pthread_mutex_lock(&g_db_lock);
    const char *sql =
        "SELECT f.filename, f.file_size, f.uploaded_at,"
        "       p.can_read, p.can_write"
        "  FROM files f"
        "  JOIN permissions p ON p.file_id = f.id"
        " WHERE p.user_id=? AND p.can_read=1"
        " ORDER BY f.uploaded_at DESC;";
    sqlite3_stmt *stmt;
    int count = 0;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, user_id);
        while (sqlite3_step(stmt) == SQLITE_ROW && count < max_out) {
            snprintf(out[count].filename, MAX_FILENAME, "%s",
                     (const char *)sqlite3_column_text(stmt, 0));
            out[count].file_size = (uint64_t)sqlite3_column_int64(stmt, 1);
            snprintf(out[count].uploaded_at, 32, "%s",
                     (const char *)sqlite3_column_text(stmt, 2));
            out[count].can_read  = (uint8_t)sqlite3_column_int(stmt, 3);
            out[count].can_write = (uint8_t)sqlite3_column_int(stmt, 4);
            count++;
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
    return count;
}

/*
 * db_grant_permission
 * Returns: 0 = success
 *         -1 = file not found / not owner
 *         -2 = target user not found
 *         -3 = db error
 */
int db_grant_permission(const char *filename, int owner_id,
                        const char *target_username,
                        int can_read, int can_write)
{
    pthread_mutex_lock(&g_db_lock);

    /* Resolve target user */
    const char *usql = "SELECT id FROM users WHERE username=?;";
    sqlite3_stmt *stmt;
    int target_id = -1;
    if (sqlite3_prepare_v2(g_db, usql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, target_username, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            target_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (target_id < 0) { pthread_mutex_unlock(&g_db_lock); return -2; }

    /* Resolve file (must be owned by owner_id) */
    const char *fsql =
        "SELECT id FROM files WHERE filename=? AND owner_id=?;";
    int file_id = -1;
    if (sqlite3_prepare_v2(g_db, fsql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, owner_id);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            file_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (file_id < 0) { pthread_mutex_unlock(&g_db_lock); return -1; }

    /* Insert or replace permission */
    const char *psql =
        "INSERT OR REPLACE INTO permissions(file_id,user_id,can_read,can_write)"
        " VALUES(?,?,?,?);";
    int rc = -3;
    if (sqlite3_prepare_v2(g_db, psql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, file_id);
        sqlite3_bind_int(stmt, 2, target_id);
        sqlite3_bind_int(stmt, 3, can_read);
        sqlite3_bind_int(stmt, 4, can_write);
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -3;
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_db_lock);
    return rc;
}

/*
 * db_delete_file
 * Owner-only deletion. Returns 0 on success, -1 otherwise.
 */
int db_delete_file(const char *filename, int owner_id, char *filepath_out)
{
    pthread_mutex_lock(&g_db_lock);

    /* Get filepath first */
    const char *gsql =
        "SELECT id, filepath FROM files WHERE filename=? AND owner_id=?;";
    sqlite3_stmt *stmt;
    int file_id = -1;
    if (sqlite3_prepare_v2(g_db, gsql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, owner_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            file_id = sqlite3_column_int(stmt, 0);
            if (filepath_out)
                snprintf(filepath_out, MAX_FILEPATH, "%s",
                         (const char *)sqlite3_column_text(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }
    if (file_id < 0) { pthread_mutex_unlock(&g_db_lock); return -1; }

    sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);

    /* Delete permissions first (FK) */
    char dsql[128];
    snprintf(dsql, sizeof(dsql),
             "DELETE FROM permissions WHERE file_id=%d;", file_id);
    sqlite3_exec(g_db, dsql, NULL, NULL, NULL);

    /* Delete file record */
    snprintf(dsql, sizeof(dsql),
             "DELETE FROM files WHERE id=%d;", file_id);
    sqlite3_exec(g_db, dsql, NULL, NULL, NULL);

    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
    pthread_mutex_unlock(&g_db_lock);
    return 0;
}

#endif /* DATABASE_H */
