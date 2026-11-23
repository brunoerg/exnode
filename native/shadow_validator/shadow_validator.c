/*
 * exnode shadow validator: a separate OS process that runs Bitcoin Core v32.1's
 * own validation engine (libbitcoinkernel btck_chainstate_manager_*) on its own
 * data directory, fed the blocks exnode connects or rejects.
 *
 * Usage: shadow_validator <chain> <datadir>
 *   chain: mainnet | testnet | testnet4 | signet | regtest
 *
 * Wire protocol on stdin/stdout (Erlang {packet, 4}): each frame is
 * <<len:32/big, payload:len/bytes>>.
 *
 * Requests:
 *   <<1, raw_block/bytes>>  process_block
 *   <<2>>                   get_tip
 * Responses:
 *   <<0, rc:8, new_block:8, n_events:32/big, events..., tip>>  for process_block
 *       event = <<hash:32/bytes, mode:8, result:32/big>>  (one per block_checked
 *               callback fired during the call, in order)
 *   <<0, tip>>                       for get_tip
 *       tip = <<height:32/big-signed, hash:32/bytes>>  (height -1 if no chain)
 *   <<1, reason/bytes>>               error (e.g. undecodable block)
 *
 * Fatal kernel errors write to stderr and exit(2). exnode treats that as a
 * shadow failure and halts.
 *
 * Shutdown: on EOF, on a bad or cut-short request frame (exit 3) or event
 * overflow (exit 4), or when exnode has closed the pipe while a response is
 * being written (EPIPE; SIGPIPE is ignored so it cannot kill the process),
 * the chainstate manager is destroyed, which flushes Core's coins cache and
 * block index (btck_chainstate_manager_destroy -> ForceFlushStateToDisk).
 * Dying without that flush loses everything since Core's last periodic flush.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bitcoinkernel.h"

#define MAX_EVENTS 4096
#define MAX_FRAME (64u * 1024u * 1024u)

typedef struct {
    uint8_t hash[32];
    uint8_t mode;
    uint32_t result;
} event_t;

static event_t g_events[MAX_EVENTS];
static size_t g_nevents = 0;
static int g_event_overflow = 0;

static void put32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static int read_full(void *buf, size_t n) {
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = read(STDIN_FILENO, p, n);
        if (r == 0) return 0;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 1;
}

static int g_out_broken = 0;

static void write_full(const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0 && !g_out_broken) {
        ssize_t w = write(STDOUT_FILENO, p, n);
        if (w < 0) { if (errno == EINTR) continue; g_out_broken = 1; return; }
        p += w; n -= (size_t)w;
    }
}

static void send_frame(const uint8_t *buf, size_t n) {
    uint8_t hdr[4];
    put32(hdr, (uint32_t)n);
    write_full(hdr, 4);
    write_full(buf, n);
}

static void send_error(const char *reason) {
    size_t n = strlen(reason);
    uint8_t hdr[5];
    put32(hdr, (uint32_t)(n + 1));
    hdr[4] = 1;
    write_full(hdr, sizeof hdr);
    write_full(reason, n);
}

/* block_checked runs synchronously inside process_block (validation.cpp:
 * ProcessNewBlock / ConnectTip -> ValidationSignals::BlockChecked).
 *
 * Ownership: the kernel passes btck_Block::copy(...) (bitcoinkernel.cpp
 * BlockChecked), a new owned object the callback must destroy. The state is a
 * borrowed reference. The typedef in the header does not say so explicitly;
 * the non-const pointer follows the kernel's convention for owned objects. */
static void on_block_checked(void *ud, btck_Block *block, const btck_BlockValidationState *state) {
    (void)ud;
    if (g_nevents >= MAX_EVENTS) { g_event_overflow = 1; btck_block_destroy(block); return; }
    event_t *e = &g_events[g_nevents++];
    btck_BlockHash *h = btck_block_get_hash(block);
    btck_block_hash_to_bytes(h, e->hash);
    btck_block_hash_destroy(h);
    e->mode = (uint8_t)btck_block_validation_state_get_validation_mode(state);
    e->result = (uint32_t)btck_block_validation_state_get_block_validation_result(state);
    btck_block_destroy(block);
}

static void on_fatal(void *ud, const char *msg, size_t len) {
    (void)ud;
    fprintf(stderr, "shadow_validator: fatal kernel error: %.*s\n", (int)len, msg);
    exit(2);
}

static void on_flush_error(void *ud, const char *msg, size_t len) {
    (void)ud;
    fprintf(stderr, "shadow_validator: flush error: %.*s\n", (int)len, msg);
    exit(2);
}

static size_t encode_tip(btck_ChainstateManager *cm, uint8_t *out) {
    const btck_Chain *chain = btck_chainstate_manager_get_active_chain(cm);
    int32_t height = btck_chain_get_height(chain);
    memset(out, 0, 36);
    put32(out, (uint32_t)height);
    if (height >= 0) {
        const btck_BlockTreeEntry *tip = btck_chain_get_by_height(chain, height);
        if (tip) btck_block_hash_to_bytes(btck_block_tree_entry_get_block_hash(tip), out + 4);
    }
    return 36;
}

static int parse_chain(const char *s, btck_ChainType *out) {
    if (!strcmp(s, "mainnet")) *out = btck_ChainType_MAINNET;
    else if (!strcmp(s, "testnet")) *out = btck_ChainType_TESTNET;
    else if (!strcmp(s, "testnet4")) *out = btck_ChainType_TESTNET_4;
    else if (!strcmp(s, "signet")) *out = btck_ChainType_SIGNET;
    else if (!strcmp(s, "regtest")) *out = btck_ChainType_REGTEST;
    else return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <chain> <datadir>\n", argv[0]); return 64; }
    btck_ChainType chain_type;
    if (!parse_chain(argv[1], &chain_type)) { fprintf(stderr, "unknown chain %s\n", argv[1]); return 64; }
    const char *datadir = argv[2];
    char blocksdir[4096];
    int bn = snprintf(blocksdir, sizeof blocksdir, "%s/blocks", datadir);
    if (bn < 0 || (size_t)bn >= sizeof blocksdir) { fprintf(stderr, "datadir path too long\n"); return 64; }

    signal(SIGPIPE, SIG_IGN);
    btck_logging_disable();

    btck_ChainParameters *params = btck_chain_parameters_create(chain_type);
    btck_ContextOptions *copts = btck_context_options_create();
    btck_context_options_set_chainparams(copts, params);

    btck_NotificationInterfaceCallbacks notif;
    memset(&notif, 0, sizeof notif);
    notif.fatal_error = on_fatal;
    notif.flush_error = on_flush_error;
    btck_context_options_set_notifications(copts, notif);

    btck_ValidationInterfaceCallbacks vcbs;
    memset(&vcbs, 0, sizeof vcbs);
    vcbs.block_checked = on_block_checked;
    btck_context_options_set_validation_interface(copts, vcbs);

    btck_Context *ctx = btck_context_create(copts);
    btck_context_options_destroy(copts);
    btck_chain_parameters_destroy(params);
    if (!ctx) { fprintf(stderr, "context create failed\n"); return 1; }

    btck_ChainstateManagerOptions *mopts = btck_chainstate_manager_options_create(
        ctx, datadir, strlen(datadir), blocksdir, strlen(blocksdir));
    if (!mopts) { fprintf(stderr, "chainstate manager options create failed\n"); return 1; }
    btck_ChainstateManager *cm = btck_chainstate_manager_create(mopts);
    btck_chainstate_manager_options_destroy(mopts);
    if (!cm) { fprintf(stderr, "chainstate manager create failed\n"); return 1; }

    /* Every exit from the loop goes through the flush below, errors included. */
    int status = 0;
    for (;;) {
        uint8_t hdr[4];
        int r = read_full(hdr, 4);
        if (r == 0) break; /* EOF: exnode closed the port */
        if (r < 0) { status = 3; break; }
        uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
        if (len == 0 || len > MAX_FRAME) { fprintf(stderr, "bad frame length %u\n", len); status = 3; break; }
        uint8_t *buf = malloc(len);
        if (!buf || read_full(buf, len) != 1) { free(buf); status = 3; break; }

        if (buf[0] == 1) {
            btck_Block *block = btck_block_create(buf + 1, len - 1);
            if (!block) { send_error("bad_block_encoding"); free(buf); continue; }
            g_nevents = 0;
            g_event_overflow = 0;
            int new_block = 0;
            int rc = btck_chainstate_manager_process_block(cm, block, &new_block);
            btck_block_destroy(block);
            if (g_event_overflow) { fprintf(stderr, "event overflow\n"); free(buf); status = 4; break; }

            size_t out_len = 1 + 1 + 1 + 4 + g_nevents * 37 + 36;
            uint8_t *out = malloc(out_len), *p = out;
            if (!out) { fprintf(stderr, "out of memory\n"); free(buf); status = 3; break; }
            *p++ = 0;
            *p++ = (uint8_t)(rc != 0);
            *p++ = (uint8_t)new_block;
            put32(p, (uint32_t)g_nevents); p += 4;
            for (size_t i = 0; i < g_nevents; i++) {
                memcpy(p, g_events[i].hash, 32); p += 32;
                *p++ = g_events[i].mode;
                put32(p, g_events[i].result); p += 4;
            }
            p += encode_tip(cm, p);
            send_frame(out, (size_t)(p - out));
            free(out);
        } else if (buf[0] == 2) {
            uint8_t out[37];
            out[0] = 0;
            encode_tip(cm, out + 1);
            send_frame(out, sizeof out);
        } else {
            send_error("unknown_op");
        }
        free(buf);
        if (g_out_broken) break; /* exnode is gone: flush and exit */
    }

    btck_chainstate_manager_destroy(cm);
    btck_context_destroy(ctx);
    return status;
}
