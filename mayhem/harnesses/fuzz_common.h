/* Shared helpers for the guacamole-server harnesses (mayhem/harnesses). */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Writes the input to a fresh file under $TMPDIR (default /tmp); returns its fd (positioned at 0)
 * and the path in `path`, or -1. The caller unlinks the path and closes the fd. */
static int fuzz_write_tmp(const uint8_t* data, size_t size, char* path, size_t path_len) {
    const char* dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0')
        dir = "/tmp";
    snprintf(path, path_len, "%s/guacfuzz-XXXXXX", dir);
    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) { close(fd); unlink(path); return -1; }
        off += (size_t) n;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

#endif

#include <guacamole/socket.h>

/* An in-memory guac_socket (libguac's public custom-socket interface): reads return the input in
 * chunks of `chunk` bytes, so instructions are split across reads the way network reads split them;
 * end of input is EOF. Writes are discarded. */
typedef struct fuzz_mem_socket {
    const uint8_t* data;
    size_t size;
    size_t pos;
    size_t chunk;
} fuzz_mem_socket;

static ssize_t fuzz_mem_read(guac_socket* socket, void* buf, size_t count) {
    fuzz_mem_socket* m = (fuzz_mem_socket*) socket->data;
    size_t n = m->size - m->pos;
    if (n > count) n = count;
    if (n > m->chunk) n = m->chunk;
    memcpy(buf, m->data + m->pos, n);
    m->pos += n;
    return (ssize_t) n;
}

static ssize_t fuzz_mem_write(guac_socket* socket, const void* buf, size_t count) {
    (void) socket; (void) buf;
    return (ssize_t) count;
}

static guac_socket* fuzz_mem_socket_open(fuzz_mem_socket* m) {
    guac_socket* socket = guac_socket_alloc();
    if (socket == NULL)
        return NULL;
    socket->data = m;
    socket->read_handler = fuzz_mem_read;
    socket->write_handler = fuzz_mem_write;
    return socket;
}
