/*
 * soggybadger - a benign Windows "crackme," a companion to grumpyferret
 * for the same three-tool demo (Ghidra via MCP, Recorded Future Sandbox,
 * Recorded Future MCP indicator triage), but built around Windows-native
 * techniques instead of the Linux ones grumpyferret used. Does nothing
 * harmful: no persistence that survives the process, no destructive
 * behavior, only one real (safe) outbound HTTP call.
 *
 * What's different from grumpyferret, on purpose, for the class:
 *
 *   - Windows PE (not ELF): imports show up as DLL names, not ptrace/procfs.
 *   - A named mutex (CreateMutexA) as a genuine host-based indicator,
 *     the Windows-native version of grumpyferret's "single instance lock"
 *     string, but this one is a real API object Sandbox will report.
 *   - A benign, self-cleaning registry "check-in" under
 *     HKCU\Software\SoggyBadgerDemo -- shows up in Sandbox's registry
 *     activity, a telemetry class that doesn't exist for the Linux build.
 *   - Two independent anti-debug checks: IsDebuggerPresent() (the
 *     obvious one) and a manual PEB->BeingDebugged read (the one that
 *     survives naive IsDebuggerPresent hooking) -- still only guards the
 *     final serial-check step, same non-blocking-recon-first design as
 *     grumpyferret.
 *   - The four "config" values (mutex name, fake domain, fake IP, real
 *     safe domain) are NOT stored as a string anywhere. They're built
 *     byte-by-byte on the stack at runtime ("stack strings"), a classic
 *     technique to defeat a plain `strings` pass. Contrast this with
 *     grumpyferret's single static XOR blob.
 *   - The unlock check is a ROR13 rolling hash, not a per-byte transform.
 *     This is the same style of hash a lot of real Windows malware uses
 *     for hash-based dynamic API resolution (walk a name, ROR13 + add
 *     each character). The intended solving method mirrors the real
 *     professional technique for breaking that: don't try to invert the
 *     hash, compute the hash of candidate strings and compare. The
 *     intended candidate list is short and sits in the binary's own
 *     import table (see README.md).
 *   - Real network calls use WinINet (InternetOpenA/InternetOpenUrlA)
 *     for the HTTP phone-home, and Winsock2 (getaddrinfo) for the DNS
 *     probes -- both real, commonly-abused Windows API surfaces, and a
 *     different "how do I know this thing can touch the network" static
 *     signal than grumpyferret's libc sockets calls.
 *
 * Build with MinGW-w64 (see Makefile / README.md). This file has not
 * been compiled in the environment that wrote it (no Windows/MinGW
 * toolchain was available there) -- do a test build before using it in
 * class.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

/* ---- decoys: present in a plain `strings` pass on purpose ---- */
static const char *decoy_flag_1 = "SB{TRY_HARDER}";
static const char *decoy_flag_2 = "SB{NOT_TODAY}";
static const char *decoy_note   = "backup_hash=0xDEADBEEF"; /* not the real target, on purpose */
static const char *banner_str   = "soggybadger v2.0 -- \"who's a good boy\"\n";
static const char *build_tag    = "soggybadger_v2_build";

/* ---- ROR13 hash gate ----
 * Same shape as classic hash-based Windows API name resolution:
 *   h = 0
 *   for each char c: h = ROR32(h, 13) + c
 * The intended unlock value is the uppercase base name of one of this
 * binary's own imported DLLs -- check the import table in Ghidra.
 */
#define TARGET_HASH 0xa2ac2abdU

static uint32_t gf2_ror13_hash(const char *s) {
    uint32_t h = 0;
    while (*s) {
        h = (h >> 13) | (h << (32 - 13));
        h += (unsigned char)(*s);
        s++;
    }
    return h;
}

/* ---- embedded flag, XOR'd with a 6-byte repeating key ---- */
#define FLAG_LEN 21
static const unsigned char FLAG_KEY[6] = { 0x2f, 0xc4, 0x88, 0x51, 0xda, 0x06 };
static const unsigned char FLAG_BLOB[FLAG_LEN] = {
    0x7c,0x86,0xf3,0x02,0x8e,0x47,0x6c,0x8f,0xd7,0x02,0x8e,0x54,0x66,0x8a,0xcf,
    0x02,0x85,0x51,0x66,0x8a,0xf5
};

static void gf2_reveal_flag(void) {
    char plain[FLAG_LEN + 1];
    for (int i = 0; i < FLAG_LEN; i++)
        plain[i] = (char)(FLAG_BLOB[i] ^ FLAG_KEY[i % 6]);
    plain[FLAG_LEN] = '\0';
    printf("\n[+] hash matched.\n%s\n", plain);
}

/* ---- stack strings: every real "indicator" is built one byte at a
 * time on the stack, never stored as a contiguous literal anywhere.
 * This is the intentional contrast with grumpyferret's static XOR blob. */

static void gf2_build_mutex_name(char *out) {
    int i = 0;
    out[i++]='S'; out[i++]='o'; out[i++]='g'; out[i++]='g'; out[i++]='y';
    out[i++]='B'; out[i++]='a'; out[i++]='d'; out[i++]='g'; out[i++]='e';
    out[i++]='r'; out[i++]='S'; out[i++]='i'; out[i++]='n'; out[i++]='g';
    out[i++]='l'; out[i++]='e'; out[i++]='t'; out[i++]='o'; out[i++]='n';
    out[i++]='_'; out[i++]='M'; out[i++]='u'; out[i++]='t'; out[i++]='e';
    out[i++]='x'; out[i]='\0';
}

static void gf2_build_fake_domain(char *out) {
    int i = 0;
    out[i++]='c'; out[i++]='2'; out[i++]='.'; out[i++]='s'; out[i++]='o';
    out[i++]='g'; out[i++]='g'; out[i++]='y'; out[i++]='b'; out[i++]='a';
    out[i++]='d'; out[i++]='g'; out[i++]='e'; out[i++]='r'; out[i++]='-';
    out[i++]='d'; out[i++]='e'; out[i++]='m'; out[i++]='o'; out[i++]='.';
    out[i++]='i'; out[i++]='n'; out[i++]='v'; out[i++]='a'; out[i++]='l';
    out[i++]='i'; out[i++]='d'; out[i]='\0';
}

static void gf2_build_fake_ip(char *out) {
    int i = 0;
    out[i++]='2'; out[i++]='0'; out[i++]='3'; out[i++]='.'; out[i++]='0';
    out[i++]='.'; out[i++]='1'; out[i++]='1'; out[i++]='3'; out[i++]='.';
    out[i++]='9'; out[i]='\0';
}

static void gf2_build_safe_domain(char *out) {
    int i = 0;
    out[i++]='e'; out[i++]='x'; out[i++]='a'; out[i++]='m'; out[i++]='p';
    out[i++]='l'; out[i++]='e'; out[i++]='.'; out[i++]='c'; out[i++]='o';
    out[i++]='m'; out[i]='\0';
}

static void gf2_build_campaign(char *out) {
    int i = 0;
    out[i++]='o'; out[i++]='p'; out[i++]='e'; out[i++]='r'; out[i++]='a';
    out[i++]='t'; out[i++]='i'; out[i++]='o'; out[i++]='n'; out[i++]='-';
    out[i++]='w'; out[i++]='e'; out[i++]='t'; out[i++]='-'; out[i++]='b';
    out[i++]='l'; out[i++]='a'; out[i++]='n'; out[i++]='k'; out[i++]='e';
    out[i++]='t'; out[i]='\0';
}

/* ---- anti-debug: IsDebuggerPresent() plus a manual PEB read.
 * Only guards the final serial-check step; everything above it
 * (mutex, registry check-in, DNS probes, phone-home) runs the same
 * whether or not something is attached. */

#if defined(_M_X64) || defined(__x86_64__)
static int gf2_peb_being_debugged(void) {
#if defined(_MSC_VER)
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    return peb[2];
#else
    unsigned long long peb;
    __asm__ __volatile__ ("movq %%gs:0x60, %0" : "=r"(peb));
    return *((unsigned char *)(peb + 2));
#endif
}
#else
static int gf2_peb_being_debugged(void) { return 0; } /* 32-bit target: not implemented */
#endif

static int gf2_is_debugged(void) {
    if (IsDebuggerPresent()) return 1;
    if (gf2_peb_being_debugged()) return 1;
    return 0;
}

/* ---- benign, self-cleaning registry check-in ---- */
static void gf2_registry_checkin(HKEY *out_key, int *out_created) {
    HKEY hKey;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\SoggyBadgerDemo", 0,
                               NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                               NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        printf("[*] registry check-in: failed (%ld)\n", rc);
        *out_key = NULL;
        *out_created = 0;
        return;
    }
    const char *marker = "soggybadger-demo-marker";
    RegSetValueExA(hKey, "Marker", 0, REG_SZ, (const BYTE *)marker,
                    (DWORD)strlen(marker) + 1);
    printf("[*] registry check-in: HKCU\\Software\\SoggyBadgerDemo\\Marker = %s\n", marker);
    *out_key = hKey;
    *out_created = 1;
}

static void gf2_registry_cleanup(HKEY hKey, int created) {
    if (!hKey) return;
    if (created) {
        RegDeleteValueA(hKey, "Marker");
        RegCloseKey(hKey);
        RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\SoggyBadgerDemo");
    } else {
        RegCloseKey(hKey);
    }
}

/* ---- DNS probe via Winsock2 getaddrinfo ---- */
static void gf2_dns_probe(const char *host) {
    struct addrinfo hints, *res = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    printf("[*] resolving %s ... ", host);
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        printf("failed (%d)\n", rc);
        return;
    }
    char ipstr[64] = {0};
    void *addr = NULL;
    if (res->ai_family == AF_INET)
        addr = &(((struct sockaddr_in *)res->ai_addr)->sin_addr);
    else if (res->ai_family == AF_INET6)
        addr = &(((struct sockaddr_in6 *)res->ai_addr)->sin6_addr);
    if (addr) InetNtopA(res->ai_family, addr, ipstr, sizeof(ipstr));
    printf("resolved -> %s\n", ipstr[0] ? ipstr : "(unknown)");
    freeaddrinfo(res);
}

/* ---- real, safe phone-home over WinINet ---- */
static void gf2_phone_home(const char *safe_domain) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s/", safe_domain);
    printf("[*] phoning home to %s ... ", url);

    HINTERNET hInternet = InternetOpenA("soggybadger-demo/1.0",
                                          INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpen failed (%lu)\n", GetLastError());
        return;
    }
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        printf("connect failed (%lu)\n", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }
    char buf[128] = {0};
    DWORD bytesRead = 0;
    if (InternetReadFile(hUrl, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        printf("ok, got %lu bytes\n", bytesRead);
    } else {
        printf("no response\n");
    }
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
}

int main(int argc, char **argv) {
    int rc = 0;
    HANDLE hMutex = NULL;
    HKEY hKey = NULL;
    int created_key = 0;
    WSADATA wsa;

    printf("%s", banner_str);
    printf("[*] build: %s\n", build_tag);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[*] WSAStartup failed, network probes will be skipped\n");
    }

    char mutex_name[40];
    gf2_build_mutex_name(mutex_name);
    hMutex = CreateMutexA(NULL, FALSE, mutex_name);
    printf("[*] mutex: %s (%s)\n", mutex_name,
           (GetLastError() == ERROR_ALREADY_EXISTS) ? "already existed" : "created");

    char fake_domain[48];
    char fake_ip[32];
    char safe_domain[32];
    char campaign[48];
    gf2_build_fake_domain(fake_domain);
    gf2_build_fake_ip(fake_ip);
    gf2_build_safe_domain(safe_domain);
    gf2_build_campaign(campaign);
    printf("[*] config: domain=%s ip=%s safe=%s campaign=%s\n",
           fake_domain, fake_ip, safe_domain, campaign);

    gf2_registry_checkin(&hKey, &created_key);

    gf2_dns_probe(fake_domain);
    gf2_dns_probe(safe_domain);
    gf2_phone_home(safe_domain);

    if (argc < 2) {
        printf("\nusage: %s <code>\n"
               "  (hint: the code is the uppercase base name of one of\n"
               "   this binary's own imported DLLs)\n", argv[0]);
        rc = 0;
        goto cleanup;
    }

    if (gf2_is_debugged()) {
        printf("\n[!] tracer detected. %s\n%s\n", decoy_note, decoy_flag_1);
        rc = 1;
        goto cleanup;
    }

    {
        uint32_t h = gf2_ror13_hash(argv[1]);
        if (h == TARGET_HASH) {
            gf2_reveal_flag();
            rc = 0;
        } else {
            printf("\n[-] wrong. %s\n", decoy_flag_2);
            rc = 1;
        }
    }

cleanup:
    gf2_registry_cleanup(hKey, created_key);
    if (hMutex) CloseHandle(hMutex);
    WSACleanup();
    return rc;
}
