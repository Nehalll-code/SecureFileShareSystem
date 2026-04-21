/*
 * common.h
 * Shared definitions for the Secure File Sharing System.
 * Included by both server.c and client.c
 */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>

/* ══════════════════════════════════════════════════════════════
   NETWORK / SERVER CONSTANTS
   ══════════════════════════════════════════════════════════════ */
#define DEFAULT_PORT       9999
#define BUFFER_SIZE        4096       /* chunk size for file transfer  */
#define MAX_CLIENTS        50         /* max concurrent threads        */
#define BACKLOG            10         /* listen() backlog              */
#define RECV_TIMEOUT_SEC   120        /* per-client receive timeout    */
#define UPLOAD_DIR         "uploads/" /* server-side storage directory */

/* ══════════════════════════════════════════════════════════════
   FIELD SIZE LIMITS
   ══════════════════════════════════════════════════════════════ */
#define MAX_USERNAME    64
#define MAX_PASSWORD   128
#define MAX_FILENAME   256
#define MAX_FILEPATH   512
#define MAX_TOKEN       64
#define MAX_MSG        512
#define MAX_HASH        65   /* SHA-256 hex = 64 chars + NUL */
#define SESSION_TIMEOUT 1800 /* 30 minutes                   */

/* ══════════════════════════════════════════════════════════════
   PROTOCOL COMMAND CODES  (client → server)
   ══════════════════════════════════════════════════════════════ */
typedef enum {
    CMD_REGISTER  = 1,
    CMD_LOGIN     = 2,
    CMD_LOGOUT    = 3,
    CMD_UPLOAD    = 4,
    CMD_DOWNLOAD  = 5,
    CMD_LIST      = 6,
    CMD_SHARE     = 7,
    CMD_DELETE    = 8,
    CMD_QUIT      = 9
} CommandCode;

/* ══════════════════════════════════════════════════════════════
   PROTOCOL RESPONSE CODES  (server → client)
   ══════════════════════════════════════════════════════════════ */
typedef enum {
    RESP_OK         = 200,
    RESP_READY      = 201,
    RESP_AUTH_ERROR = 401,
    RESP_FORBIDDEN  = 403,
    RESP_NOT_FOUND  = 404,
    RESP_ERROR      = 500
} ResponseCode;

/* ══════════════════════════════════════════════════════════════
   FIXED-SIZE BINARY PACKET STRUCTURES
   All integers stored in network byte order (big-endian).
   ══════════════════════════════════════════════════════════════ */

/* Request: client  →  server */
typedef struct __attribute__((packed)) {
    uint32_t command;                  /* CommandCode, network byte order */
    char     token[MAX_TOKEN];
    char     username[MAX_USERNAME];
    char     password[MAX_PASSWORD];
    char     filename[MAX_FILENAME];
    char     target_user[MAX_USERNAME];
    uint64_t file_size;                /* host byte order; converted by sender */
    uint8_t  can_read;
    uint8_t  can_write;
} RequestPacket;

/* Response: server  →  client */
typedef struct __attribute__((packed)) {
    uint32_t status;                   /* ResponseCode, network byte order */
    char     message[MAX_MSG];
    char     token[MAX_TOKEN];
    uint64_t file_size;
    uint32_t file_count;               /* network byte order */
} ResponsePacket;

/* One record in a LIST response */
typedef struct __attribute__((packed)) {
    char     filename[MAX_FILENAME];
    uint64_t file_size;
    char     uploaded_at[32];
    uint8_t  can_read;
    uint8_t  can_write;
} FileInfo;

/*LOGGING MACROS*/
#define LOG_INFO(fmt,...)  fprintf(stdout, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt,...)  fprintf(stdout, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt,...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/*RELIABLE SEND / RECV  (handle partial transfers)*/
static inline ssize_t send_all(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    const char *p = (const char *)buf;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return n;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

static inline ssize_t recv_all(int fd, void *buf, size_t len)
{
    size_t got = 0;
    char *p = (char *)buf;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return n;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

#endif /* COMMON_H */
