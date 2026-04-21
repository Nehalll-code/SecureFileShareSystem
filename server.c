/*
 * server.c  —  Secure File Sharing Server
 *
 * Features:
 *   - TCP socket with SO_REUSEADDR, SO_RCVBUF/SO_SNDBUF, SO_RCVTIMEO
 *   - Thread-per-client concurrency (pthread, detached threads)
 *   - SQLite3 database for users, files, permissions, sessions
 *   - SHA-256 salted password hashing
 *   - Fixed-size binary packet protocol (no parsing overhead)
 *   - Reliable chunked file transfer (handles partial reads/writes)
 *   - XOR stream cipher for application-level encryption
 *
 * Compile:
 *   gcc -Wall -Wextra -O2 -Icommon -Isqlite \
 *       server.c \
 *       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 \
 *       -lpthread -o server_bin
 *
 * Usage:
 *   ./server_bin [port]          (default port: 9999)
 */

#include "common/common.h"
#include "common/database.h"

/* ══════════════════════════════════════════════════════════════
   XOR STREAM CIPHER  (application-level encryption)
   Key is derived from the session token; keeps it simple but
   demonstrates the concept for the assignment.
   ══════════════════════════════════════════════════════════════ */
static void xor_crypt(const char *key, char *data, size_t len)
{
    size_t klen = strlen(key);
    if (klen == 0) return;
    for (size_t i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}

/* ══════════════════════════════════════════════════════════════
   HELPERS: send / receive packet
   ══════════════════════════════════════════════════════════════ */
static void srv_send(int fd, uint32_t status, const char *msg,
                     const char *token, uint64_t file_size, uint32_t file_count)
{
    ResponsePacket rp;
    memset(&rp, 0, sizeof(rp));
    rp.status     = htonl(status);
    rp.file_count = htonl(file_count);
    rp.file_size  = file_size;     /* raw bytes, client reads as-is */
    if (msg)   strncpy(rp.message, msg,   MAX_MSG   - 1);
    if (token) strncpy(rp.token,   token, MAX_TOKEN - 1);
    send_all(fd, &rp, sizeof(rp));
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: REGISTER
   ══════════════════════════════════════════════════════════════ */
static void handle_register(int fd, const RequestPacket *req)
{
    if (strlen(req->username) < 3) {
        srv_send(fd, RESP_ERROR, "Username must be at least 3 characters", NULL,0,0);
        return;
    }
    if (strlen(req->password) < 4) {
        srv_send(fd, RESP_ERROR, "Password must be at least 4 characters", NULL,0,0);
        return;
    }
    int rc = db_register_user(req->username, req->password);
    switch (rc) {
        case  0: srv_send(fd, RESP_OK,    "Registration successful", NULL,0,0); break;
        case -1: srv_send(fd, RESP_ERROR, "Username already exists", NULL,0,0); break;
        default: srv_send(fd, RESP_ERROR, "Database error during registration", NULL,0,0);
    }
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: LOGIN
   ══════════════════════════════════════════════════════════════ */
static void handle_login(int fd, const RequestPacket *req)
{
    char token[MAX_TOKEN] = {0};
    int rc = db_login_user(req->username, req->password, token);
    if (rc == 0) {
        LOG_INFO("Login: %s", req->username);
        srv_send(fd, RESP_OK, "Login successful", token, 0, 0);
    } else if (rc == -1) {
        srv_send(fd, RESP_AUTH_ERROR, "Invalid username or password", NULL,0,0);
    } else {
        srv_send(fd, RESP_ERROR, "Database error during login", NULL,0,0);
    }
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: LOGOUT
   ══════════════════════════════════════════════════════════════ */
static void handle_logout(int fd, const RequestPacket *req)
{
    db_destroy_session(req->token);
    srv_send(fd, RESP_OK, "Logged out successfully", NULL,0,0);
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: UPLOAD
   Protocol flow:
     1. Client  → RequestPacket (CMD_UPLOAD, filename, file_size)
     2. Server  → ResponsePacket (RESP_READY)
     3. Client  → raw encrypted bytes (file_size bytes)
     4. Server  → ResponsePacket (RESP_OK or RESP_ERROR)
   ══════════════════════════════════════════════════════════════ */
static void handle_upload(int fd, const RequestPacket *req, const SessionInfo *sess)
{
    if (strlen(req->filename) == 0) {
        srv_send(fd, RESP_ERROR, "Filename cannot be empty", NULL,0,0); return;
    }
    if (req->file_size == 0) {
        srv_send(fd, RESP_ERROR, "File size must be greater than 0", NULL,0,0); return;
    }
    /* Reject path traversal attempts */
    if (strstr(req->filename, "..") || strstr(req->filename, "/")) {
        srv_send(fd, RESP_ERROR, "Invalid filename", NULL,0,0); return;
    }

    char filepath[MAX_FILEPATH];
    snprintf(filepath, sizeof(filepath), "%s%d_%s",
             UPLOAD_DIR, sess->user_id, req->filename);

    /* Signal client to start sending */
    srv_send(fd, RESP_READY, "Ready to receive", NULL,0,0);

    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        LOG_ERROR("Cannot create %s: %s", filepath, strerror(errno));
        srv_send(fd, RESP_ERROR, "Server cannot create file", NULL,0,0); return;
    }

    char     buf[BUFFER_SIZE];
    uint64_t remaining     = req->file_size;
    uint64_t total_written = 0;

    while (remaining > 0) {
        size_t  to_read = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)remaining;
        ssize_t n       = recv(fd, buf, to_read, 0);
        if (n <= 0) {
            LOG_WARN("[%s] Upload interrupted at byte %llu",
                     sess->username, (unsigned long long)total_written);
            fclose(fp); remove(filepath);
            srv_send(fd, RESP_ERROR, "Upload interrupted", NULL,0,0);
            return;
        }
        /* Decrypt chunk using token as XOR key */
        xor_crypt(req->token, buf, (size_t)n);
        fwrite(buf, 1, (size_t)n, fp);
        remaining      -= (uint64_t)n;
        total_written  += (uint64_t)n;
    }
    fclose(fp);

    int fid = db_save_file_meta(req->filename, filepath,
                                 sess->user_id, req->file_size);
    if (fid < 0) {
        remove(filepath);
        srv_send(fd, RESP_ERROR, "Metadata save failed", NULL,0,0); return;
    }

    LOG_INFO("[%s] Uploaded '%s' (%llu bytes) → id=%d",
             sess->username, req->filename,
             (unsigned long long)req->file_size, fid);
    srv_send(fd, RESP_OK, "File uploaded successfully", NULL,0,0);
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: DOWNLOAD
   Protocol flow:
     1. Client  → RequestPacket (CMD_DOWNLOAD, filename)
     2. Server  → ResponsePacket (RESP_READY, file_size)
     3. Client  → ResponsePacket (RESP_READY, as ACK)
     4. Server  → raw encrypted bytes (file_size bytes)
   ══════════════════════════════════════════════════════════════ */
static void handle_download(int fd, const RequestPacket *req, const SessionInfo *sess)
{
    FileRecord rec; memset(&rec, 0, sizeof(rec));
    if (!db_get_file(req->filename, sess->user_id, &rec)) {
        srv_send(fd, RESP_NOT_FOUND, "File not found or access denied", NULL,0,0);
        return;
    }

    FILE *fp = fopen(rec.filepath, "rb");
    if (!fp) {
        srv_send(fd, RESP_ERROR, "Cannot open file on server", NULL,0,0); return;
    }

    /* Actual on-disk size (may differ if file was modified externally) */
    fseek(fp, 0, SEEK_END);
    uint64_t actual = (uint64_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Notify client; file_size is plain uint64_t in host byte order */
    srv_send(fd, RESP_READY, "File found, ready to send", NULL, actual, 0);

    /* Wait for client ACK */
    ResponsePacket ack; memset(&ack,0,sizeof(ack));
    if (recv_all(fd, &ack, sizeof(ack)) <= 0 || ntohl(ack.status) != RESP_READY) {
        fclose(fp); return;
    }

    char     buf[BUFFER_SIZE];
    uint64_t sent = 0;
    size_t   n;

    while ((n = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
        /* Encrypt chunk */
        xor_crypt(req->token, buf, n);
        if (send_all(fd, buf, n) != (ssize_t)n) {
            LOG_WARN("[%s] Download of '%s' interrupted at byte %llu",
                     sess->username, req->filename, (unsigned long long)sent);
            break;
        }
        sent += (uint64_t)n;
    }
    fclose(fp);
    LOG_INFO("[%s] Downloaded '%s' (%llu bytes)",
             sess->username, req->filename, (unsigned long long)sent);
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: LIST
   ══════════════════════════════════════════════════════════════ */
static void handle_list(int fd, const SessionInfo *sess)
{
    FileInfo files[512];
    int count = db_list_files(sess->user_id, files, 512);
    srv_send(fd, RESP_OK, "File list follows", NULL, 0, (uint32_t)count);
    for (int i = 0; i < count; i++)
        send_all(fd, &files[i], sizeof(FileInfo));
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: SHARE
   ══════════════════════════════════════════════════════════════ */
static void handle_share(int fd, const RequestPacket *req, const SessionInfo *sess)
{
    int rc = db_grant_permission(req->filename, sess->user_id,
                                  req->target_user,
                                  req->can_read, req->can_write);
    char msg[MAX_MSG];
    switch (rc) {
        case  0:
            snprintf(msg, sizeof(msg), "Permissions granted to '%s'", req->target_user);
            srv_send(fd, RESP_OK, msg, NULL,0,0);
            LOG_INFO("[%s] Shared '%s' with '%s'",
                     sess->username, req->filename, req->target_user);
            break;
        case -1: srv_send(fd, RESP_FORBIDDEN, "File not found or you are not the owner", NULL,0,0); break;
        case -2: srv_send(fd, RESP_NOT_FOUND, "Target user does not exist", NULL,0,0); break;
        default: srv_send(fd, RESP_ERROR,     "Database error during share", NULL,0,0);
    }
}

/* ══════════════════════════════════════════════════════════════
   HANDLER: DELETE
   ══════════════════════════════════════════════════════════════ */
static void handle_delete(int fd, const RequestPacket *req, const SessionInfo *sess)
{
    char filepath[MAX_FILEPATH] = {0};
    if (db_delete_file(req->filename, sess->user_id, filepath) == 0) {
        if (strlen(filepath) > 0) remove(filepath);
        srv_send(fd, RESP_OK, "File deleted", NULL,0,0);
        LOG_INFO("[%s] Deleted '%s'", sess->username, req->filename);
    } else {
        srv_send(fd, RESP_FORBIDDEN, "File not found or you are not the owner", NULL,0,0);
    }
}

/* ══════════════════════════════════════════════════════════════
   CLIENT THREAD
   ══════════════════════════════════════════════════════════════ */
static pthread_mutex_t g_count_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int    g_active     = 0;

typedef struct { int fd; char ip[INET_ADDRSTRLEN]; int port; } ClientArg;

static void *client_thread(void *arg)
{
    ClientArg *ca = (ClientArg *)arg;
    /* reread because struct field name is .fd not .client_fd
       Let's be careful: */
    int  cfd  = ca->fd;
    char cip[INET_ADDRSTRLEN];
    memcpy(cip, ca->ip, INET_ADDRSTRLEN);
    free(ca);

    pthread_mutex_lock(&g_count_lock); g_active++; pthread_mutex_unlock(&g_count_lock);

    /* Per-socket receive timeout */
    struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    LOG_INFO("Client connected: %s  (active=%d)", cip, g_active);

    RequestPacket req;
    while (1) {
        memset(&req, 0, sizeof(req));
        ssize_t n = recv_all(cfd, &req, sizeof(req));
        if (n <= 0) break;   /* disconnect or timeout */

        uint32_t cmd = ntohl(req.command);

        /* ── Commands that need no session ── */
        if (cmd == CMD_REGISTER) { handle_register(cfd, &req); continue; }
        if (cmd == CMD_LOGIN)    { handle_login(cfd, &req);    continue; }
        if (cmd == CMD_QUIT) {
            srv_send(cfd, RESP_OK, "Goodbye", NULL,0,0);
            break;
        }

        /* ── All other commands: validate session ── */
        SessionInfo sess; memset(&sess,0,sizeof(sess));
        if (!db_validate_session(req.token, &sess)) {
            srv_send(cfd, RESP_AUTH_ERROR,
                     "Not authenticated or session expired", NULL,0,0);
            continue;
        }

        switch (cmd) {
            case CMD_LOGOUT:   handle_logout(cfd, &req);           break;
            case CMD_UPLOAD:   handle_upload(cfd, &req, &sess);    break;
            case CMD_DOWNLOAD: handle_download(cfd, &req, &sess);  break;
            case CMD_LIST:     handle_list(cfd, &sess);            break;
            case CMD_SHARE:    handle_share(cfd, &req, &sess);     break;
            case CMD_DELETE:   handle_delete(cfd, &req, &sess);    break;
            default:
                srv_send(cfd, RESP_ERROR, "Unknown command", NULL,0,0);
        }
    }

    close(cfd);
    pthread_mutex_lock(&g_count_lock); g_active--; pthread_mutex_unlock(&g_count_lock);
    LOG_INFO("Client disconnected: %s  (active=%d)", cip, g_active);
    return NULL;

    
}

/* ══════════════════════════════════════════════════════════════
   MAIN
   ══════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Usage: %s [port]  (1–65535)\n", argv[0]);
            return 1;
        }
    }

    /* Ignore SIGPIPE so we get EPIPE on send() instead of crashing */
    signal(SIGPIPE, SIG_IGN);

    /* Initialise SQLite database */
    if (db_init("fileshare.db") != 0) return 1;

    /* Create uploads directory */
    mkdir(UPLOAD_DIR, 0755);
    srand((unsigned int)(time(NULL) ^ getpid()));

    /* Create TCP socket */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    /* Socket options */
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int rcvbuf = 65536, sndbuf = 65536;
    setsockopt(srv_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(srv_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);
    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }

    /* Listen */
    if (listen(srv_fd, BACKLOG) < 0) {
        perror("listen"); close(srv_fd); return 1;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   Secure File Sharing Server  v1.0           ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Port       : %-30d ║\n", port);
    printf("║  Upload dir : %-30s ║\n", UPLOAD_DIR);
    printf("║  Database   : fileshare.db                   ║\n");
    printf("║  Max clients: %-30d ║\n", MAX_CLIENTS);
    printf("║  Buffer size: %-30d ║\n", BUFFER_SIZE);
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* Accept loop */
    while (1) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(srv_fd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) { perror("accept"); continue; }

        /* Reject if server full */
        pthread_mutex_lock(&g_count_lock);
        int cur = g_active;
        pthread_mutex_unlock(&g_count_lock);
        if (cur >= MAX_CLIENTS) {
            srv_send(cfd, RESP_ERROR, "Server at capacity, try later", NULL,0,0);
            close(cfd); continue;
        }

        ClientArg *ca = malloc(sizeof(ClientArg));
        if (!ca) { close(cfd); continue; }
        ca->fd   = cfd;
        ca->port = ntohs(caddr.sin_port);
        inet_ntop(AF_INET, &caddr.sin_addr, ca->ip, INET_ADDRSTRLEN);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_thread, ca) != 0) {
            perror("pthread_create"); free(ca); close(cfd);
        }
        pthread_attr_destroy(&attr);
    }

    db_close();
    close(srv_fd);
    return 0;
}
