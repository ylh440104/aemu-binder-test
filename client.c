#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 4, int)

struct binder_write_read {
    uint32_t write_size;
    uint32_t write_consumed;
    uint32_t write_buffer;
    uint32_t read_size;
    uint32_t read_consumed;
    uint32_t read_buffer;
};

struct binder_transaction_data {
    union { uint32_t handle; uint32_t ptr; } target;
    uint32_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct { uint32_t buffer; uint32_t offsets; } ptr;
        uint8_t buf[8];
    } data;
};

#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_NOOP _IO('r', 0)

static int binder_open(void) {
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open /dev/binder"); return -1; }
    return fd;
}

static int binder_write_read(int fd, void *wdata, size_t wsize, void *rdata, size_t rsize) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = wsize;
    bwr.write_buffer = (uint32_t)(uintptr_t)wdata;
    bwr.read_size = rsize;
    bwr.read_buffer = (uint32_t)(uintptr_t)rdata;
    int r = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (r < 0) { perror("BINDER_WRITE_READ"); return -1; }
    return bwr.read_consumed;
}

static void put_string16(uint8_t **p, const char *s) {
    size_t n = strlen(s);
    uint32_t len = (uint32_t)n;
    memcpy(*p, &len, 4); *p += 4;
    for (size_t i = 0; i < n; i++) {
        uint16_t c = (uint8_t)s[i];
        memcpy(*p, &c, 2); *p += 2;
    }
    if ((n & 1) == 0) { uint16_t pad = 0; memcpy(*p, &pad, 2); *p += 2; }
}

static int get_service(int fd, const char *name) {
    uint8_t wbuf[512], rbuf[512];
    uint8_t *p = wbuf;
    uint32_t cmd = BC_TRANSACTION;
    memcpy(p, &cmd, 4); p += 4;
    struct binder_transaction_data *tr = (void *)p;
    memset(tr, 0, sizeof *tr);
    tr->target.handle = 0;
    tr->code = 2; // GET_SERVICE
    tr->flags = 0;
    tr->data_size = 0;
    uint8_t *d = (uint8_t *)tr->data.ptr.buffer;
    (void)d;
    // 数据部分
    p += sizeof *tr;
    uint8_t *data = p;
    put_string16(&p, "android.os.IServiceManager");
    put_string16(&p, name);
    tr->data_size = (uint32_t)(p - data);
    tr->data.ptr.buffer = (uint32_t)(uintptr_t)data;
    tr->offsets_size = 0;
    int n = binder_write_read(fd, wbuf, p - wbuf, rbuf, sizeof rbuf);
    if (n <= 0) { printf("get_service(%s): no reply\n", name); return -1; }
    // 解析 reply
    uint8_t *r = rbuf;
    uint32_t rcmd;
    memcpy(&rcmd, r, 4); r += 4;
    if (rcmd == BR_NOOP) { memcpy(&rcmd, r, 4); r += 4; }
    if (rcmd != BR_REPLY) { printf("get_service(%s): unexpected cmd 0x%x\n", name, rcmd); return -1; }
    struct binder_transaction_data *rtr = (void *)r;
    printf("get_service(%s): reply data_size=%u\n", name, rtr->data_size);
    return 0;
}

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "SurfaceFlinger";
    int fd = binder_open();
    if (fd < 0) return 1;
    printf("binder fd=%d, querying %s...\n", fd, name);
    int r = get_service(fd, name);
    close(fd);
    return r;
}