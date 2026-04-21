# Secure File Sharing System — C + SQLite3
## Subject: Computer Networks / Socket Programming
## Language: C (C99, POSIX Threads)
## Database: SQLite3 (via system shared library)
## Platform: Linux / Ubuntu

---

## Project Structure

```
SecureFileShare/
├── server.c                  ← Multi-threaded TCP server (all logic)
├── client.c                  ← Interactive menu-driven client
├── Makefile                  ← Build system
├── common/
│   ├── common.h              ← Shared structs, protocol codes, send_all/recv_all
│   ├── sha256.h              ← Pure-C SHA-256 (salted password hashing)
│   └── database.h            ← SQLite3 CRUD: users, files, permissions, sessions
├── sqlite/
│   └── sqlite3_minimal.h     ← Hand-written SQLite3 API declarations (no dev pkg needed)
└── README.md
```

---

## Build Instructions

```bash
# Build both server and client
make

# Or manually:
gcc -Wall -Wextra -O2 -Icommon -Isqlite \
    server.c /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -lpthread -o server_bin

gcc -Wall -Wextra -O2 -Icommon client.c -o client_bin
```

---

## Run Instructions

### Start Server (Terminal 1)
```bash
./server_bin 9999
```

### Start Client (Terminal 2)
```bash
./client_bin 127.0.0.1 9999
```

### Test with multiple clients (Terminal 3, 4 ...)
```bash
./client_bin 127.0.0.1 9999
```

---

## Features

| Feature              | Implementation Detail                                    |
|----------------------|----------------------------------------------------------|
| TCP Server           | AF_INET SOCK_STREAM, bind/listen/accept loop             |
| Concurrency          | pthread_create (detached), one thread per client         |
| Socket Options       | SO_REUSEADDR, SO_RCVBUF=65536, SO_SNDBUF=65536, SO_RCVTIMEO |
| Authentication       | SHA-256 + random salt, session tokens with 30-min expiry |
| File Upload          | Chunked 4096-byte recv loop, partial-read safe           |
| File Download        | Chunked 4096-byte fread/send loop, ACK handshake         |
| Encryption           | XOR stream cipher keyed on session token (app-level)     |
| Database             | SQLite3 WAL mode, transactions, foreign keys enforced    |
| File Sharing         | Per-user read/write permissions table                    |
| File Delete          | Owner-only, cascades permission removal                  |
| Path Safety          | Rejects filenames containing ".." or "/"                 |

---

## SQLite3 Schema

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT NOT NULL,
    filepath    TEXT NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    file_size   INTEGER NOT NULL DEFAULT 0,
    uploaded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE permissions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id   INTEGER NOT NULL REFERENCES files(id),
    user_id   INTEGER NOT NULL REFERENCES users(id),
    can_read  INTEGER NOT NULL DEFAULT 1,
    can_write INTEGER NOT NULL DEFAULT 0,
    UNIQUE(file_id, user_id)
);

CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    username   TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
```

---

## Test Cases

### Positive Tests
1. Register new user with valid username/password → "Registration successful"
2. Login with correct credentials → session token returned
3. Upload a small file (< 1 MB) → "File uploaded successfully"
4. Upload a large file (> 100 MB) → complete and correct via chunking
5. Download own file → file saved locally, bytes match
6. List files after upload → shows file with size and date
7. Share file with another user → permission row inserted
8. Download a file shared to you → success
9. Delete own file → removed from disk and database
10. Multiple clients simultaneously → all handled, no data mixing

### Negative Tests
11. Register with duplicate username → "Username already exists"
12. Register with username < 3 chars → validation error
13. Login with wrong password → "Invalid username or password"
14. Upload without login → "Not authenticated or session expired"
15. Download file with no permission → "File not found or access denied"
16. Share file you don't own → "File not found or you are not the owner"
17. Share with non-existent user → "Target user does not exist"
18. Delete file you don't own → "File not found or you are not the owner"
19. Upload with empty filename → "Filename cannot be empty"
20. Upload 0-byte file → "File size must be greater than 0"
21. Filename with "../" (path traversal) → "Invalid filename"
22. Expired session token → "Not authenticated or session expired"
23. Server at MAX_CLIENTS capacity → reject new connection with message
24. Client disconnect mid-upload → server detects, removes partial file

---

## Clean / Reset
```bash
make clean    # removes binaries, database, uploads/
```
