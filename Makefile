CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -Icommon -Isqlite
LFLAGS  = -lpthread
SQLITE  = /usr/lib/x86_64-linux-gnu/libsqlite3.so.0

.PHONY: all clean run_server run_client

all: server_bin client_bin

server_bin: server.c common/common.h common/database.h common/sha256.h sqlite/sqlite3_minimal.h
	$(CC) $(CFLAGS) server.c $(SQLITE) $(LFLAGS) -o server_bin
	@echo "[OK] server_bin built"

client_bin: client.c common/common.h
	$(CC) $(CFLAGS) client.c -o client_bin
	@echo "[OK] client_bin built"

run_server: server_bin
	./server_bin 9999

run_client: client_bin
	./client_bin 127.0.0.1 9999

clean:
	rm -f server_bin client_bin
	rm -f fileshare.db
	rm -rf uploads/
	@echo "[OK] cleaned"

