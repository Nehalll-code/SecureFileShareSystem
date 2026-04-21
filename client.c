/*
 * client.c  —  Secure File Sharing Client
 *
 * Features:
 *   - Interactive menu-driven terminal UI
 *   - Fixed-size binary packet protocol
 *   - XOR stream cipher matching server-side encryption
 *   - Real-time progress bar for upload/download
 *   - All dynamic input (no hardcoded values)
 *
 * Compile:
 *   gcc -Wall -Wextra -O2 -Icommon client.c -o client_bin
 *
 * Usage:
 *   ./client_bin <server_ip> <port>
 */

#include "common/common.h"

/* ══════════════════════════════════════════════════════════════
   CLIENT STATE
   ══════════════════════════════════════════════════════════════ */
static int  g_sockfd              = -1;
static char g_token[MAX_TOKEN]    = {0};
static char g_username[MAX_USERNAME] = {0};
static int  g_logged_in           = 0;

/* ══════════════════════════════════════════════════════════════
   XOR STREAM CIPHER  (must match server side)
   ══════════════════════════════════════════════════════════════ */
static void xor_crypt(const char *key, char *data, size_t len)
{
    size_t klen = strlen(key);
    if (klen == 0) return;
    for (size_t i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}

/* ══════════════════════════════════════════════════════════════
   PACKET HELPERS
   ══════════════════════════════════════════════════════════════ */
static int send_req(const RequestPacket *req)
{
    return send_all(g_sockfd, req, sizeof(RequestPacket))
           == (ssize_t)sizeof(RequestPacket);
}

static int recv_resp(ResponsePacket *rp)
{
    memset(rp, 0, sizeof(*rp));
    ssize_t n = recv_all(g_sockfd, rp, sizeof(ResponsePacket));
    if (n <= 0) { printf("[!] Server disconnected or timed out.\n"); return 0; }
    rp->status     = ntohl(rp->status);
    rp->file_count = ntohl(rp->file_count);
    return 1;
}

static void print_status(uint32_t code)
{
    switch ((ResponseCode)code) {
        case RESP_OK:         printf("\033[32m[OK]\033[0m        "); break;
        case RESP_READY:      printf("\033[34m[READY]\033[0m     "); break;
        case RESP_AUTH_ERROR: printf("\033[31m[AUTH ERR]\033[0m  "); break;
        case RESP_FORBIDDEN:  printf("\033[31m[FORBIDDEN]\033[0m "); break;
        case RESP_NOT_FOUND:  printf("\033[33m[NOT FOUND]\033[0m "); break;
        default:              printf("\033[31m[ERROR]\033[0m     "); break;
    }
}

/* ══════════════════════════════════════════════════════════════
   PROGRESS BAR
   ══════════════════════════════════════════════════════════════ */
static void show_progress(uint64_t done, uint64_t total, const char *label)
{
    if (total == 0) return;
    int pct  = (int)(done * 100 / total);
    int fill = pct / 2;
    printf("\r  %s [", label);
    for (int i=0; i<50; i++) putchar(i < fill ? '#' : '-');
    printf("] %3d%% (%llu/%llu bytes)",
           pct, (unsigned long long)done, (unsigned long long)total);
    fflush(stdout);
    if (done == total) putchar('\n');
}

/* ══════════════════════════════════════════════════════════════
   INPUT HELPERS
   ══════════════════════════════════════════════════════════════ */
static void read_line(const char *prompt, char *buf, size_t sz)
{
    printf("  %s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)sz, stdin)) { buf[0]='\0'; return; }
    buf[strcspn(buf, "\r\n")] = '\0';
}

/* ══════════════════════════════════════════════════════════════
   CONNECT
   ══════════════════════════════════════════════════════════════ */
static int do_connect(const char *host, int port)
{
    g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sockfd < 0) { perror("socket"); return 0; }

    int buf = 65536;
    setsockopt(g_sockfd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(g_sockfd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    /* Set a connection timeout via SO_RCVTIMEO */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(g_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        fprintf(stderr, "[!] Invalid IP address: %s\n", host); return 0;
    }
    if (connect(g_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[!] connect"); return 0;
    }
    printf("\033[32m[+] Connected to %s:%d\033[0m\n\n", host, port);

    /* Extend timeout for normal operation */
    tv.tv_sec = 60;
    setsockopt(g_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 1;
}

/* ══════════════════════════════════════════════════════════════
   1. REGISTER
   ══════════════════════════════════════════════════════════════ */
static void do_register(void)
{
    char uname[MAX_USERNAME], pass[MAX_PASSWORD], pass2[MAX_PASSWORD];
    read_line("Username (min 3 chars) : ", uname, sizeof(uname));
    read_line("Password (min 4 chars) : ", pass,  sizeof(pass));
    read_line("Confirm password       : ", pass2, sizeof(pass2));
    if (strcmp(pass, pass2) != 0) { printf("[!] Passwords do not match.\n"); return; }

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_REGISTER);
    strncpy(req.username, uname, MAX_USERNAME-1);
    strncpy(req.password, pass,  MAX_PASSWORD-1);
    if (!send_req(&req)) return;

    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);
}

/* ══════════════════════════════════════════════════════════════
   2. LOGIN
   ══════════════════════════════════════════════════════════════ */
static void do_login(void)
{
    if (g_logged_in) { printf("[!] Already logged in as '%s'.\n", g_username); return; }

    char uname[MAX_USERNAME], pass[MAX_PASSWORD];
    read_line("Username : ", uname, sizeof(uname));
    read_line("Password : ", pass,  sizeof(pass));

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_LOGIN);
    strncpy(req.username, uname, MAX_USERNAME-1);
    strncpy(req.password, pass,  MAX_PASSWORD-1);
    if (!send_req(&req)) return;

    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);

    if (rp.status == RESP_OK) {
        strncpy(g_token,    rp.token, MAX_TOKEN-1);
        strncpy(g_username, uname,    MAX_USERNAME-1);
        g_logged_in = 1;
        printf("  [*] Session token (first 16 chars): %.16s...\n", g_token);
    }
}

/* ══════════════════════════════════════════════════════════════
   3. LOGOUT
   ══════════════════════════════════════════════════════════════ */
static void do_logout(void)
{
    if (!g_logged_in) { printf("[!] Not logged in.\n"); return; }
    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_LOGOUT);
    strncpy(req.token, g_token, MAX_TOKEN-1);
    if (!send_req(&req)) return;
    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);
    g_logged_in = 0;
    memset(g_token,    0, sizeof(g_token));
    memset(g_username, 0, sizeof(g_username));
}

/* ══════════════════════════════════════════════════════════════
   4. UPLOAD
   ══════════════════════════════════════════════════════════════ */
static void do_upload(void)
{
    if (!g_logged_in) { printf("[!] Please login first.\n"); return; }

    char path[MAX_FILEPATH];
    read_line("Local file path : ", path, sizeof(path));

    struct stat st;
    if (stat(path, &st) < 0) { perror("[!] stat"); return; }
    uint64_t fsize = (uint64_t)st.st_size;

    /* Extract filename */
    const char *fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;

    printf("  Uploading '%s' (%llu bytes)...\n", fname,
           (unsigned long long)fsize);

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command   = htonl(CMD_UPLOAD);
    req.file_size = fsize;
    strncpy(req.token,    g_token, MAX_TOKEN-1);
    strncpy(req.filename, fname,   MAX_FILENAME-1);
    if (!send_req(&req)) return;

    /* Wait for READY */
    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    if (rp.status != RESP_READY) {
        print_status(rp.status); printf("%s\n", rp.message); return;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("[!] fopen"); return; }

    char     buf[BUFFER_SIZE];
    uint64_t sent = 0;
    size_t   n;

    while ((n = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
        /* Encrypt before sending */
        xor_crypt(g_token, buf, n);
        if (send_all(g_sockfd, buf, n) != (ssize_t)n) {
            printf("\n[!] Send failed at byte %llu\n", (unsigned long long)sent);
            fclose(fp); return;
        }
        sent += (uint64_t)n;
        show_progress(sent, fsize, "Uploading");
    }
    fclose(fp);

    /* Final server response */
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);
}

/* ══════════════════════════════════════════════════════════════
   5. DOWNLOAD
   ══════════════════════════════════════════════════════════════ */
static void do_download(void)
{
    if (!g_logged_in) { printf("[!] Please login first.\n"); return; }

    char fname[MAX_FILENAME], savedir[MAX_FILEPATH];
    read_line("Remote filename        : ", fname,   sizeof(fname));
    read_line("Save to directory      : ", savedir, sizeof(savedir));
    if (strlen(savedir) == 0) strcpy(savedir, ".");

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_DOWNLOAD);
    strncpy(req.token,    g_token, MAX_TOKEN-1);
    strncpy(req.filename, fname,   MAX_FILENAME-1);
    if (!send_req(&req)) return;

    /* READY response contains file size */
    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    if (rp.status != RESP_READY) {
        print_status(rp.status); printf("%s\n", rp.message); return;
    }
    uint64_t fsize = rp.file_size;
    printf("  File size: %llu bytes\n", (unsigned long long)fsize);

    /* Send ACK (RESP_READY) */
    ResponsePacket ack; memset(&ack,0,sizeof(ack));
    ack.status = htonl(RESP_READY);
    send_all(g_sockfd, &ack, sizeof(ack));

    /* Build local save path */
    char savepath[MAX_FILEPATH];
    snprintf(savepath, sizeof(savepath), "%s/%s", savedir, fname);
    FILE *fp = fopen(savepath, "wb");
    if (!fp) { perror("[!] fopen"); return; }

    char     buf[BUFFER_SIZE];
    uint64_t received = 0;

    while (received < fsize) {
        size_t  to_recv = (fsize - received > BUFFER_SIZE)
                          ? BUFFER_SIZE : (size_t)(fsize - received);
        ssize_t n = recv(g_sockfd, buf, to_recv, 0);
        if (n <= 0) {
            printf("\n[!] Connection lost at byte %llu\n",
                   (unsigned long long)received);
            fclose(fp); return;
        }
        /* Decrypt */
        xor_crypt(g_token, buf, (size_t)n);
        fwrite(buf, 1, (size_t)n, fp);
        received += (uint64_t)n;
        show_progress(received, fsize, "Downloading");
    }
    fclose(fp);
    printf("  \033[32m[OK]\033[0m Saved to: %s\n", savepath);
}

/* ══════════════════════════════════════════════════════════════
   6. LIST
   ══════════════════════════════════════════════════════════════ */
static void do_list(void)
{
    if (!g_logged_in) { printf("[!] Please login first.\n"); return; }

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_LIST);
    strncpy(req.token, g_token, MAX_TOKEN-1);
    if (!send_req(&req)) return;

    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    if (rp.status != RESP_OK) {
        print_status(rp.status); printf("%s\n", rp.message); return;
    }

    uint32_t count = rp.file_count;
    printf("\n  %-35s  %12s  %-19s  READ  WRITE\n",
           "Filename", "Size (bytes)", "Uploaded At");
    printf("  %s\n",
     "─────────────────────────────────────────────────────────────────────────────");
    for (uint32_t i = 0; i < count; i++) {
        FileInfo fi; memset(&fi,0,sizeof(fi));
        if (recv_all(g_sockfd, &fi, sizeof(fi)) <= 0) break;
        printf("  %-35s  %12llu  %-19s   %c     %c\n",
               fi.filename,
               (unsigned long long)fi.file_size,
               fi.uploaded_at,
               fi.can_read  ? 'Y' : 'N',
               fi.can_write ? 'Y' : 'N');
    }
    printf("  ─────────────────────────────────────────────────────────────────────────────\n");
    printf("  Total: %u file(s)\n\n", count);
}

/* ══════════════════════════════════════════════════════════════
   7. SHARE
   ══════════════════════════════════════════════════════════════ */
static void do_share(void)
{
    if (!g_logged_in) { printf("[!] Please login first.\n"); return; }

    char fname[MAX_FILENAME], target[MAX_USERNAME], perm[4];
    read_line("Filename to share      : ", fname,  sizeof(fname));
    read_line("Target username        : ", target, sizeof(target));
    read_line("Allow read?  (y/n)     : ", perm,   sizeof(perm));
    int can_read  = (perm[0]=='y'||perm[0]=='Y') ? 1 : 0;
    read_line("Allow write? (y/n)     : ", perm,   sizeof(perm));
    int can_write = (perm[0]=='y'||perm[0]=='Y') ? 1 : 0;

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command   = htonl(CMD_SHARE);
    req.can_read  = (uint8_t)can_read;
    req.can_write = (uint8_t)can_write;
    strncpy(req.token,       g_token, MAX_TOKEN-1);
    strncpy(req.filename,    fname,   MAX_FILENAME-1);
    strncpy(req.target_user, target,  MAX_USERNAME-1);
    if (!send_req(&req)) return;

    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);
}

/* ══════════════════════════════════════════════════════════════
   8. DELETE
   ══════════════════════════════════════════════════════════════ */
static void do_delete(void)
{
    if (!g_logged_in) { printf("[!] Please login first.\n"); return; }

    char fname[MAX_FILENAME], confirm[8];
    read_line("Filename to delete     : ", fname,   sizeof(fname));
    printf("  Are you sure you want to delete '%s'? (yes/no): ", fname);
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin)) return;
    if (strncmp(confirm, "yes", 3) != 0) { printf("  Cancelled.\n"); return; }

    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_DELETE);
    strncpy(req.token,    g_token, MAX_TOKEN-1);
    strncpy(req.filename, fname,   MAX_FILENAME-1);
    if (!send_req(&req)) return;

    ResponsePacket rp;
    if (!recv_resp(&rp)) return;
    print_status(rp.status); printf("%s\n", rp.message);
}

/* ══════════════════════════════════════════════════════════════
   9. QUIT
   ══════════════════════════════════════════════════════════════ */
static void do_quit(void)
{
    RequestPacket req; memset(&req,0,sizeof(req));
    req.command = htonl(CMD_QUIT);
    strncpy(req.token, g_token, MAX_TOKEN-1);
    send_req(&req);
    ResponsePacket rp; recv_resp(&rp);
}

/* ══════════════════════════════════════════════════════════════
   MENU
   ══════════════════════════════════════════════════════════════ */
static void print_menu(void)
{
    printf("\033[2J\033[H");   /* clear screen */
    printf("╔══════════════════════════════════════════╗\n");
    printf("║     Secure File Sharing System v1.0      ║\n");
    if (g_logged_in)
        printf("║  User: \033[32m%-34s\033[0m║\n", g_username);
    else
        printf("║  \033[33mNot logged in\033[0m                            ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  1  Register new account                 ║\n");
    printf("║  2  Login                                ║\n");
    printf("║  3  Upload a file                        ║\n");
    printf("║  4  Download a file                      ║\n");
    printf("║  5  List my files                        ║\n");
    printf("║  6  Share a file with another user       ║\n");
    printf("║  7  Delete a file                        ║\n");
    printf("║  8  Logout                               ║\n");
    printf("║  9  Quit                                 ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("  Choice: ");
    fflush(stdout);
}

/* ══════════════════════════════════════════════════════════════
   MAIN
   ══════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "[!] Invalid port: %s\n", argv[2]);
        return 1;
    }
    if (!do_connect(host, port)) return 1;

    char choice[8];
    int  running = 1;

    while (running) {
        print_menu();
        if (!fgets(choice, sizeof(choice), stdin)) break;
        int c = atoi(choice);
        printf("\n");
        switch (c) {
            case 1: do_register(); break;
            case 2: do_login();    break;
            case 3: do_upload();   break;
            case 4: do_download(); break;
            case 5: do_list();     break;
            case 6: do_share();    break;
            case 7: do_delete();   break;
            case 8: do_logout();   break;
            case 9: do_quit(); running=0; break;
            default: printf("[!] Invalid choice, enter 1-9.\n");
        }
        if (running && c >= 1 && c <= 9) {
            printf("\n  Press ENTER to continue...");
            fflush(stdout);
            fgets(choice, sizeof(choice), stdin);
        }
    }

    if (g_sockfd >= 0) close(g_sockfd);
    printf("\n[*] Connection closed. Goodbye.\n");
    return 0;
}
