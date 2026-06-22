/*
 * gen_golden.c — C golden file generator for cross-language protocol verification.
 *
 * Compile (MSVC):
 *   cl /O2 gen_golden.c /Fe:gen_golden.exe
 *
 * Compile (GCC):
 *   gcc -O2 gen_golden.c -o gen_golden.exe
 *
 * Run:
 *   gen_golden.exe
 *
 * Produces:
 *   golden_tcp_chrome.bin     — TCP header with "chrome.exe" (48 bytes)
 *   golden_tcp_no_name.bin    — TCP header without proc_name (36 bytes)
 *   golden_tcp_ipv6.bin       — TCP header with IPv6 dest (36 bytes)
 *   golden_udp_req.bin        — UDP request header + payload (64 bytes)
 *   golden_udp_resp.bin       — UDP response header (32 bytes)
 *   golden_error.bin          — Error packet (8 bytes)
 *
 * These files can be read by Go tests in internal/protocol/golden_test.go
 * to verify cross-language binary compatibility.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  protocol;
    uint8_t  proc_name_len;
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t  dst_addr[16];
    uint32_t pid;
    uint32_t token;
} NbTcpHeaderBase;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  protocol;
    uint8_t  reserved;
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t  dst_addr[16];
    uint8_t  src_addr[16];
    uint32_t pid;
    uint32_t token;
    uint16_t payload_len;
    uint16_t reserved2;
} NbUdpReqHeader;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  reserved[2];
    uint16_t src_port;
    uint16_t reserved2;
    uint8_t  src_addr[16];
    uint16_t payload_len;
    uint16_t reserved3;
} NbUdpRespHeader;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  error_code;
    uint16_t reserved;
} NbError;

#pragma pack(pop)

#define NB_MAGIC   0x4E425632u
#define NB_VERSION 1

static void write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("Written: %s (%zu bytes)\n", path, len);
    }
}

int main(void) {
    /* 1. TCP header with "chrome.exe" */
    {
        const char *name = "chrome.exe";
        uint8_t name_len = (uint8_t)strlen(name);
        uint32_t raw_len = sizeof(NbTcpHeaderBase) + name_len;
        uint32_t total = (raw_len + 3) & ~3u;
        uint8_t buf[64] = {0};

        NbTcpHeaderBase *h = (NbTcpHeaderBase *)buf;
        h->magic = NB_MAGIC;
        h->version = NB_VERSION;
        h->addr_type = 0x04; /* IPv4 */
        h->protocol = 6;     /* TCP */
        h->proc_name_len = name_len;
        h->dst_port = 443;
        h->src_port = 54321;
        h->dst_addr[0] = 1; h->dst_addr[1] = 1;
        h->dst_addr[2] = 1; h->dst_addr[3] = 1;
        h->pid = 0x1234;
        h->token = 0xDEADBEEF;
        memcpy(buf + sizeof(NbTcpHeaderBase), name, name_len);

        write_file("golden_tcp_chrome.bin", buf, total);
    }

    /* 2. TCP header without proc_name */
    {
        NbTcpHeaderBase h = {0};
        h.magic = NB_MAGIC;
        h.version = NB_VERSION;
        h.addr_type = 0x04;
        h.protocol = 6;
        h.proc_name_len = 0;
        h.dst_port = 53;
        h.src_port = 12345;
        h.dst_addr[0] = 8; h.dst_addr[1] = 8;
        h.dst_addr[2] = 8; h.dst_addr[3] = 8;
        h.pid = 999;
        h.token = 0x12345678;

        write_file("golden_tcp_no_name.bin", &h, sizeof(h));
    }

    /* 3. TCP header with IPv6 */
    {
        NbTcpHeaderBase h = {0};
        h.magic = NB_MAGIC;
        h.version = NB_VERSION;
        h.addr_type = 0x06; /* IPv6 */
        h.protocol = 6;
        h.proc_name_len = 0;
        h.dst_port = 443;
        h.src_port = 11111;
        /* 2001:db8::1 */
        h.dst_addr[0] = 0x20; h.dst_addr[1] = 0x01;
        h.dst_addr[2] = 0x0D; h.dst_addr[3] = 0xB8;
        h.dst_addr[15] = 0x01;
        h.pid = 5555;
        h.token = 0xCAFEBABE;

        write_file("golden_tcp_ipv6.bin", &h, sizeof(h));
    }

    /* 4. UDP request header + payload */
    {
        NbUdpReqHeader h = {0};
        h.magic = NB_MAGIC;
        h.version = NB_VERSION;
        h.addr_type = 0x04;
        h.protocol = 17; /* UDP */
        h.dst_port = 53;
        h.src_port = 12345;
        h.dst_addr[0] = 8; h.dst_addr[1] = 8;
        h.dst_addr[2] = 8; h.dst_addr[3] = 8;
        h.src_addr[0] = 192; h.src_addr[1] = 168;
        h.src_addr[2] = 1; h.src_addr[3] = 1;
        h.pid = 9999;
        h.token = 0xCAFEBABE;
        h.payload_len = 8;

        uint8_t buf[64];
        memcpy(buf, &h, sizeof(h));
        memcpy(buf + sizeof(h), "dnsquery", 8);

        write_file("golden_udp_req.bin", buf, sizeof(h) + 8);
    }

    /* 5. UDP response header */
    {
        NbUdpRespHeader h = {0};
        h.magic = NB_MAGIC;
        h.version = NB_VERSION;
        h.addr_type = 0x04;
        h.src_port = 53;
        h.src_addr[0] = 8; h.src_addr[1] = 8;
        h.src_addr[2] = 8; h.src_addr[3] = 8;
        h.payload_len = 16;

        write_file("golden_udp_resp.bin", &h, sizeof(h));
    }

    /* 6. Error packet */
    {
        NbError e = {0};
        e.magic = NB_MAGIC;
        e.version = NB_VERSION;
        e.error_code = 0x02; /* NB_ERR_TOKEN */

        write_file("golden_error.bin", &e, sizeof(e));
    }

    printf("\nAll golden files generated.\n");
    return 0;
}
