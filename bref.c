#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define BINDER_WRITE_READ 0xc0186201

/* _IOW('c', n, type) on 32-bit: 0x40000000 | (sizeof type << 16) | ('c' << 8) | n.
 * binder_transaction_data is 0x28, binder_uintptr_t and uint32_t are 4. */
#define BC_TRANSACTION 0x40286300
#define BC_REPLY 0x40286301
#define BC_ACQUIRE 0x40046305
#define BC_RELEASE 0x40046306
#define BC_INCREFS 0x40046307
#define BC_DECREFS 0x40046308
#define BC_FREE_BUFFER 0x40046303
#define BC_ENTER_LOOPER 0x630c
#define BC_EXIT_LOOPER 0x630d

#define BR_TRANSACTION 0x80407200
#define BR_REPLY 0x80407201
#define BR_ACQUIRE 0x40047208
#define BR_RELEASE 0x40047209
#define BR_INCREFS 0x40047207
#define BR_DECREFS 0x4004720a
#define BR_NOOP 0x720c
#define BR_SPAWN_LOOPER 0x720d
#define BR_FAILED_REPLY 0x7217
#define BR_DEAD_REPLY 0x7215
#define BR_ERROR 0x80007216

#define TF_ONE_WAY 0x01

#define T_BINDER 0x73622a85u
#define T_HANDLE 0x73682a85u

struct fbo {
    uint32_t type;
    uint32_t flags;
    uint32_t binder;
    uint32_t cookie;
};

struct btd {
    uint32_t handle;
    uint32_t cookie;
    uint32_t code;
    uint32_t flags;
    uint32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    uint32_t buffer;
    uint32_t offsets;
};

struct bwr {
    uint32_t write_size;
    uint32_t write_consumed;
    uint32_t write_buffer;
    uint32_t read_size;
    uint32_t read_consumed;
    uint32_t read_buffer;
};

/* Ten 32-bit words: target, cookie, code, flags, sender_pid, sender_euid, data_size, offsets_size,
 * then the parcel's buffer and its offset table. Sizing any of them wider makes the kernel side read
 * a different layout, which is what the ioctl descriptor has to agree with as well. */
_Static_assert(sizeof(struct btd) == 40, "binder_transaction_data must be 40 bytes on 32-bit");
_Static_assert(sizeof(struct bwr) == 24, "binder_write_read must be 24 bytes on 32-bit");
_Static_assert(sizeof(struct fbo) == 16, "flat_binder_object must be 16 bytes on 32-bit");

static int bfd = -1;
/* where the reply sat inside the last read, so the caller can look at it */
static uint32_t g_reply_off, g_reply_len;

static int binder_open(void) {
    bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) { perror("open /dev/binder"); return -1; }
    return 0;
}

static int talk(uint32_t *wb, uint32_t wlen, uint8_t *rb, uint32_t rlen, uint32_t *rout) {
    struct bwr b;
    memset(&b, 0, sizeof b);
    b.write_size = wlen;
    b.write_buffer = (uint32_t)(uintptr_t)wb;
    b.read_size = rlen;
    b.read_buffer = (uint32_t)(uintptr_t)rb;
    if (ioctl(bfd, BINDER_WRITE_READ, &b) < 0) { perror("ioctl"); return -1; }
    if (rout) *rout = b.read_consumed;
    return 0;
}

/* No read buffer means the ioctl returns as soon as the write side is taken in instead of
 * blocking until something arrives on the read side, which is what a nonzero read_size asks for. */
static int talk_write_only(uint32_t *wb, uint32_t wlen) {
    return talk(wb, wlen, 0, 0, 0);
}

static void put_s16(uint8_t *d, size_t *o, const char *s) {
    size_t n = strlen(s);
    memcpy(d + *o, &n, 4); *o += 4;
    for (size_t i = 0; i < n; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(d + *o, &c, 2); *o += 2;
    }
    memcpy(d + *o, &(uint32_t){0}, 4); *o += 4;
    while (*o & 3) d[(*o)++] = 0;
}

static int transact(uint32_t handle, uint32_t code, const void *data, uint32_t dsize,
                    struct fbo *obj, uint8_t *rb, uint32_t rlen, uint32_t *rout) {
    static uint32_t wb[1024];
    uint32_t k = 0;
    wb[k++] = BC_TRANSACTION;
    struct btd *t = (struct btd *)&wb[k];
    memset(t, 0, sizeof *t);
    t->handle = handle;
    t->code = code;
    t->data_size = dsize;
    t->offsets_size = obj ? 8 : 0;
    t->buffer = (uint32_t)(uintptr_t)data;
    t->offsets = obj ? (uint32_t)(uintptr_t)obj : 0;
    k += sizeof *t / 4;
    if (talk_write_only(wb, k * 4)) return -1;
    /*
     * The write is taken in first (the daemon answers with an ACK), and the reply arrives on the read
     * side afterwards. Asking for both in one ioctl blocks inside the first call until something is
     * readable, which hides the transaction from the daemon — so read separately.
     */
    g_reply_off = g_reply_len = 0;
    for (int spin = 0; spin < 300; spin++) {
        if (talk(0, 0, rb, rlen, rout)) return -1;
        uint32_t got = rout ? *rout : 0, cmd;
        for (uint32_t i = 0; i + 4 <= got; ) {
            memcpy(&cmd, rb + i, 4);
            if (cmd == BR_REPLY) {
                struct btd *t = (struct btd *)(rb + i + 4);
                g_reply_off = i + 4;
                g_reply_len = (uint32_t)sizeof *t;
                (void)t;
                return 0;
            }
            if (cmd == BR_TRANSACTION) {
                struct btd *t = (struct btd *)(rb + i + 4);
                uint32_t fb[2] = { BC_FREE_BUFFER, t->buffer };
                talk_write_only(fb, 8);
                i += 4 + sizeof *t;
                continue;
            }
            if (cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_INCREFS || cmd == BR_DECREFS) {
                uint32_t p[2];
                memcpy(p, rb + i + 4, 8);
                printf("  ref cmd %#x ptr %#x\n", cmd, p[0]);
                i += 12;
                continue;
            }
            if (cmd != 0x720c /* BR_NOOP */) printf("  cmd %#x\n", cmd);
            i += 4;
        }
        usleep(10000);
    }
    return 0;
}

static void dump(const char *what, const uint8_t *d, uint32_t n) {
    printf("%s: %u bytes:", what, n);
    for (uint32_t i = 0; i < n && i < 40; i++) printf(" %02x", d[i]);
    printf("\n");
}

/* Prints what came back in the parcel the reply points at. */
static void show_reply(const uint8_t *rb) {
    if (!g_reply_off) { printf("  (no reply)\n"); return; }
    const struct btd *t = (const struct btd *)(rb + g_reply_off);
    printf("  reply code %u data %u offsets %u\n", t->code, t->data_size, t->offsets_size);
    if (t->data_size >= sizeof(struct fbo)) {
        struct fbo f;
        memcpy(&f, (const void *)(uintptr_t)t->buffer, sizeof f);
        printf("  object: type %#x binder %#x cookie %#x -> %s\n", f.type, f.binder, f.cookie,
               f.type == T_BINDER ? "T_BINDER (its own again)" :
               f.type == T_HANDLE ? "T_HANDLE" : "?");
    } else if (t->data_size == 4) {
        int32_t v;
        memcpy(&v, (const void *)(uintptr_t)t->buffer, 4);
        printf("  result %d\n", v);
    }
    uint32_t fb[2] = { BC_FREE_BUFFER, t->buffer };
    talk_write_only(fb, 8);
}

int main(void) {
    char payload[256];
    struct fbo obj;
    uint8_t rb[4096];
    uint32_t rout;

    if (binder_open()) return 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("binder fd %d\n", bfd);

    uint32_t wb[2] = { BC_ENTER_LOOPER };
    talk_write_only(wb, 4);

    size_t o = 0;
    put_s16((uint8_t *)payload, &o, "android.os.IServiceManager");
    put_s16((uint8_t *)payload, &o, "test.svc");

    memset(&obj, 0, sizeof obj);
    obj.type = T_BINDER;
    obj.flags = 0x7f | 0x100;
    obj.binder = (uint32_t)(uintptr_t)&obj;
    obj.cookie = (uint32_t)(uintptr_t)&payload[0];
    printf("registering own object at %p\n", (void *)&obj);

    if (transact(0, 3, payload, (uint32_t)o, &obj, rb, sizeof rb, &rout)) return 1;
    dump("addService reply", rb, rout);
    show_reply(rb);

    usleep(200000);

    o = 0;
    put_s16((uint8_t *)payload, &o, "android.os.IServiceManager");
    put_s16((uint8_t *)payload, &o, "test.svc");
    if (transact(0, 1, payload, (uint32_t)o, NULL, rb, sizeof rb, &rout)) return 1;
    dump("getService reply", rb, rout);
    show_reply(rb);

    printf("survived\n");
    return 0;
}
