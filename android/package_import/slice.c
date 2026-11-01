#define _GNU_SOURCE
#include "slice.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef struct { int fd; int64_t start, size, pos; } Slice;
static ssize_t read_slice(void *p, char *buf, size_t n) {
    Slice *s = p;
    if (n > (uint64_t)(s->size - s->pos)) n = s->size - s->pos;
    ssize_t r = pread(s->fd, buf, n, s->start + s->pos);
    if (r > 0) s->pos += r;
    return r;
}
static int seek_slice(void *p, int64_t *offset, int whence) {
    Slice *s = p;
    int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? s->pos : s->size;
    if ((whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) ||
        *offset < -base || *offset > s->size - base) { errno = EINVAL; return -1; }
    s->pos = base + *offset;
    *offset = s->pos;
    return 0;
}
static int close_slice(void *p) { Slice *s = p; int r = close(s->fd); free(s); return r; }
#ifdef __ANDROID__
static int android_read(void *p, char *b, int n) { return read_slice(p, b, n); }
static fpos_t android_seek(void *p, fpos_t off, int whence) {
    int64_t value = off;
    return seek_slice(p, &value, whence) ? (fpos_t)-1 : (fpos_t)value;
}
#else
static int linux_seek(void *p, off64_t *off, int whence) {
    int64_t value = *off;
    int r = seek_slice(p, &value, whence); *off = value; return r;
}
#endif
// slice:<offset>:<length>:<path>; bounds apply even to a malformed NCA's seeks.
FILE *package_open(const char *path, const char *mode) {
    if (strncmp(path, "slice:", 6)) return fopen(path, mode);
    if (strcmp(mode, "rb")) { errno = EINVAL; return NULL; }
    char *end;
    errno = 0;
    int64_t start = strtoll(path + 6, &end, 10);
    if (errno || end == path + 6 || *end != ':' || start < 0) return NULL;
    const char *next = end + 1;
    int64_t size = strtoll(next, &end, 10);
    if (errno || end == next || *end != ':' || size <= 0 || start > INT64_MAX - size) return NULL;
    int fd = open(end + 1, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) || start + size > st.st_size) { close(fd); errno = EINVAL; return NULL; }
    Slice *s = calloc(1, sizeof *s);
    if (!s) { close(fd); return NULL; }
    s->fd = fd; s->start = start; s->size = size;
#ifdef __ANDROID__
    FILE *f = funopen(s, android_read, NULL, android_seek, close_slice);
#else
    cookie_io_functions_t io = { .read = read_slice, .seek = linux_seek, .close = close_slice };
    FILE *f = fopencookie(s, "rb", io);
#endif
    if (!f) close_slice(s);
    return f;
}
