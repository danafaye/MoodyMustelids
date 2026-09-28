/*
 * grumpyferret - a benign "crackme" built to look and behave like a small
 * malware sample, for demoing Ghidra (static RE), Recorded Future Sandbox
 * (dynamic behavior), and Recorded Future MCP (indicator triage) together.
 *
 * This binary does nothing harmful. It:
 *   - prints a banner and a lock string (like a malware campaign tag)
 *   - decodes an embedded XOR'd "config" containing 4 network-looking
 *     indicators (two are intentionally fake/reserved, one is a real but
 *     totally benign domain, for the RF-lookup teaching moment)
 *   - probes DNS for each of those 4 indicators
 *   - attempts one real, safe outbound request (api.ipify.org) to generate
 *     believable sandbox network telemetry
 *   - has a lightweight anti-debug gate (checks /proc/self/status TracerPid)
 *     guarding only the final serial-check step, as an optional bonus
 *     challenge
 *   - validates a 12-character serial (argv[1]) against a byte-transform
 *     check; the correct serial reveals an XOR'd flag string
 *
 * Build: see Makefile. No special libraries required beyond libc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ---- decoys: present in `strings` output on purpose ---- */
static const char *decoy_flag_1   = "GF{TRY_AGAIN_LOSER}";
static const char *decoy_flag_2   = "GF{404_FLAG_NOT_HERE}";
static const char *decoy_note     = "backup_flag=GF{NICE_TRY}";
static const char *lock_string    = "grumpyferret_singleinstance_lock";
static const char *banner_str     =
    "grumpyferret v1.0 -- \"ferret?\"\n";

/* ---- serial validation constants ----
 * transform: enc[i] = ((input[i] ^ MAGIC[i]) + i) & 0xFF
 * success when enc[] == TARGET[] for all 12 bytes.
 * MAGIC, read as ASCII, spells something -- worth noticing in Ghidra.
 */
#define SERIAL_LEN 12
static const unsigned char MAGIC[SERIAL_LEN] = {
    0x4d, 0x43, 0x50, 0x2d, 0x52, 0x46, 0x2d, 0x47, 0x48, 0x49, 0x44, 0x52
};
static const unsigned char TARGET[SERIAL_LEN] = {
    0x0a, 0x0c, 0x1b, 0x6c, 0x04, 0x0c, 0x71, 0x09, 0x22, 0x24, 0x0b, 0x11
};

/* ---- embedded config blob, XOR'd with a 4-byte repeating key ---- */
#define CONFIG_LEN 125
static const unsigned char CONFIG_KEY[4] = { 0x13, 0x37, 0xc0, 0xde };
static const unsigned char CONFIG_BLOB[CONFIG_LEN] = {
    0x76,0x59,0xb3,0xe3,0x77,0x52,0xa6,0xb7,0x7d,0x5e,0xb4,0xbb,0x7f,0x4e,0xed,
    0xb0,0x7c,0x43,0xed,0xbd,0x21,0x19,0xa5,0xaa,0x7b,0x0c,0xa9,0xae,0x2e,0x05,
    0xf0,0xed,0x3d,0x07,0xee,0xef,0x22,0x04,0xee,0xe9,0x28,0x53,0xaf,0xb3,0x72,
    0x5e,0xae,0xe3,0x70,0x05,0xee,0xb9,0x61,0x42,0xad,0xae,0x6a,0x51,0xa5,0xac,
    0x61,0x52,0xb4,0xf3,0x77,0x52,0xad,0xb1,0x3d,0x5e,0xae,0xa8,0x72,0x5b,0xa9,
    0xba,0x28,0x44,0xa1,0xb8,0x76,0x0a,0xa5,0xa6,0x72,0x5a,0xb0,0xb2,0x76,0x19,
    0xa3,0xb1,0x7e,0x0c,0xa3,0xbf,0x7e,0x47,0xa1,0xb7,0x74,0x59,0xfd,0xb1,0x63,
    0x52,0xb2,0xbf,0x67,0x5e,0xaf,0xb0,0x3e,0x50,0xa8,0xb7,0x77,0x45,0xa1,0xf3,
    0x60,0x59,0xa1,0xbd,0x78
};

/* ---- embedded flag blob, XOR'd with a 5-byte repeating key ---- */
#define FLAG_LEN 21
static const unsigned char FLAG_KEY[5] = { 0x9c, 0x5a, 0xe1, 0x03, 0x7f };
static const unsigned char FLAG_BLOB[FLAG_LEN] = {
    0xdb,0x1c,0x9a,0x47,0x2d,0xc9,0x14,0xaa,0x5c,0x3e,0xcf,0x05,0xa0,0x5c,0x39,
    0xd9,0x08,0xb3,0x46,0x2b,0xe1
};

static void gf_banner(void) {
    fputs(banner_str, stdout);
    fprintf(stdout, "[*] lock: %s\n", lock_string);
}

/* Reads /proc/self/status looking for a nonzero TracerPid.
 * Classic, low-effort anti-debug check based on ptrace-family tracing. */
static int gf_check_debugger(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0; /* fail open: assume not traced if we can't check */
    char line[256];
    int traced = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) traced = 1;
            break;
        }
    }
    fclose(f);
    return traced;
}

typedef struct {
    char ens[64];
    char ip[32];
    char domain[64];
    char safe[32];
    char campaign[48];
} gf_config_t;

static void gf_decode_config(gf_config_t *out) {
    char plain[CONFIG_LEN + 1];
    for (int i = 0; i < CONFIG_LEN; i++)
        plain[i] = (char)(CONFIG_BLOB[i] ^ CONFIG_KEY[i % 4]);
    plain[CONFIG_LEN] = '\0';

    memset(out, 0, sizeof(*out));
    /* plain looks like: ens=...;ip=...;domain=...;safe=...;campaign=... */
    char buf[CONFIG_LEN + 1];
    strncpy(buf, plain, sizeof(buf));
    char *field = strtok(buf, ";");
    while (field) {
        char *eq = strchr(field, '=');
        if (eq) {
            *eq = '\0';
            const char *key = field, *val = eq + 1;
            if (strcmp(key, "ens") == 0) strncpy(out->ens, val, sizeof(out->ens)-1);
            else if (strcmp(key, "ip") == 0) strncpy(out->ip, val, sizeof(out->ip)-1);
            else if (strcmp(key, "domain") == 0) strncpy(out->domain, val, sizeof(out->domain)-1);
            else if (strcmp(key, "safe") == 0) strncpy(out->safe, val, sizeof(out->safe)-1);
            else if (strcmp(key, "campaign") == 0) strncpy(out->campaign, val, sizeof(out->campaign)-1);
        }
        field = strtok(NULL, ";");
    }

    fprintf(stdout, "[*] decoded config:\n");
    fprintf(stdout, "    ens      = %s\n", out->ens);
    fprintf(stdout, "    ip       = %s\n", out->ip);
    fprintf(stdout, "    domain   = %s\n", out->domain);
    fprintf(stdout, "    safe     = %s\n", out->safe);
    fprintf(stdout, "    campaign = %s\n", out->campaign);
}

/* Best-effort DNS probe. Prints the outcome; never fatal. */
static void gf_dns_probe(const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    fprintf(stdout, "[*] resolving %s ... ", host);
    fflush(stdout);
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stdout, "failed (%s)\n", gai_strerror(rc));
        return;
    }
    char ipstr[INET6_ADDRSTRLEN] = {0};
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &a->sin_addr, ipstr, sizeof(ipstr));
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &a->sin6_addr, ipstr, sizeof(ipstr));
    }
    fprintf(stdout, "resolved -> %s\n", ipstr[0] ? ipstr : "(unknown)");
    freeaddrinfo(res);
}

/* Safe, real "phone home": a public-IP check service, same trick used by
 * plenty of real commodity malware for environment recon. Times out fast
 * so this never hangs a demo. */
static void gf_phone_home(void) {
    const char *host = "api.ipify.org";
    fprintf(stdout, "[*] phoning home to %s ... ", host);
    fflush(stdout);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "80", &hints, &res) != 0) {
        fprintf(stdout, "dns failed\n");
        return;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { fprintf(stdout, "socket failed\n"); freeaddrinfo(res); return; }

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        fprintf(stdout, "connect failed (%s)\n", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);

    const char req[] = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n";
    if (write(fd, req, sizeof(req) - 1) < 0) {
        fprintf(stdout, "write failed\n");
        close(fd);
        return;
    }

    char resp[256] = {0};
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n > 0) {
        /* just show the tail of the response (usually the IP body) */
        fprintf(stdout, "ok, got %zd bytes\n", n);
    } else {
        fprintf(stdout, "no response\n");
    }
}

static int gf_validate_serial(const char *input) {
    if (strlen(input) != SERIAL_LEN) return 0;
    for (int i = 0; i < SERIAL_LEN; i++) {
        unsigned char c = (unsigned char)input[i];
        unsigned char enc = (unsigned char)(((c ^ MAGIC[i]) + i) & 0xFF);
        if (enc != TARGET[i]) return 0;
    }
    return 1;
}

static void gf_reveal_flag(void) {
    char plain[FLAG_LEN + 1];
    for (int i = 0; i < FLAG_LEN; i++)
        plain[i] = (char)(FLAG_BLOB[i] ^ FLAG_KEY[i % 5]);
    plain[FLAG_LEN] = '\0';
    fprintf(stdout, "\n[+] serial accepted.\n%s\n", plain);
}

int main(int argc, char **argv) {
    gf_banner();

    gf_config_t cfg;
    gf_decode_config(&cfg);

    gf_dns_probe(cfg.domain);
    gf_dns_probe(cfg.ens);
    gf_dns_probe(cfg.safe);
    gf_phone_home();

    if (argc < 2) {
        fprintf(stdout,
            "\nusage: %s <serial>\n"
            "  (a valid serial is %d characters)\n",
            argv[0], SERIAL_LEN);
        return 0;
    }

    if (gf_check_debugger()) {
        fprintf(stdout,
            "\n[!] tracer detected. %s\n"
            "%s\n",
            decoy_note, decoy_flag_1);
        return 1;
    }

    if (gf_validate_serial(argv[1])) {
        gf_reveal_flag();
        return 0;
    }

    fprintf(stdout, "\n[-] incorrect serial. %s\n", decoy_flag_2);
    return 1;
}
