/*
 * The archive overlay's tables in native memory (Exnode.Archive.Overlay):
 * `coins`, outpoint => {gen, coin}, and `spent`, the outpoints spent by
 * uncommitted blocks. The role of Bitcoin Core's CCoinsViewCache map
 * (coins.h CCoinsMap): plain malloc'd entries in an open-addressing table,
 * never scanned or copied by a garbage collector, with keys hashed by a
 * salted SipHash-1-3 (Core SaltedCoinsCacheHasher), so a peer cannot grind
 * outpoints that collide.
 *
 * As ETS tables (each entry ~320 bytes, copied in and out on every access)
 * they held ~100M coins once a 32 GiB cache filled during a mainnet IBD,
 * and lookups slowed with the table's size. Here an entry is its fields,
 * key and script in one allocation (~100-130 bytes), and a slot is 16 bytes.
 *
 * One resource holds both tables. The archive's process is the only
 * writer and the only one to look coins up; other processes (prefetch)
 * only test membership, without waiting (see nif_member). A rwlock guards
 * every call. Calls that insert or delete in bulk run on dirty CPU
 * schedulers (a table resize rehashes every entry).
 *
 * Packed formats (big-endian integers, as Elixir's bit syntax writes them):
 *   outpoints: <<len::8, txid::binary-size(len), vout::32>>...
 *   coins:     <<len::8, txid, vout::32, output_id::64, value::64,
 *                height::32, coinbase::8, spk_len::32, spk::binary>>...
 * Every record is bounds-checked before anything is changed: a malformed
 * binary is badarg and leaves the tables as they were.
 */
#include <erl_nif.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

typedef struct {
    uint64_t output_id;
    uint64_t value;
    uint32_t gen;
    uint32_t vout;
    uint32_t height;
    uint32_t spk_len;
    uint8_t coinbase;
    uint8_t key_len;
    unsigned char data[]; /* key, then script */
} entry_t;

typedef struct {
    uint64_t h;
    entry_t *e; /* NULL: empty; TOMB: deleted */
} slot_t;

#define TOMB ((entry_t *)1)
#define MIN_CAP 1024

typedef struct {
    slot_t *slots;
    size_t cap;   /* power of two */
    size_t size;  /* live entries */
    size_t tombs;
    size_t entry_bytes; /* malloc_usable_size of live entries */
} table_t;

typedef struct {
    ErlNifRWLock *lock;
    table_t coins;
    table_t spent;
    uint64_t k0, k1; /* SipHash key */
} overlay_t;

static ErlNifResourceType *overlay_type;
static ERL_NIF_TERM atom_ok, atom_spent, atom_unknown, atom_true, atom_false;
static ERL_NIF_TERM k_output_id, k_value, k_script_pubkey, k_height, k_coinbase;

/* --- SipHash-1-3 (Core crypto/siphash.h SipHasher13 role) ---------------- */

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                                  \
    do {                                                                          \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);                 \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                                    \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                                    \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);                 \
    } while (0)

static uint64_t load64le(const unsigned char *p) {
    uint64_t v;
    memcpy(&v, p, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

/* SipHash-1-3 of key || vout (little-endian 32 bits). */
static uint64_t hash_op(const overlay_t *ov, const unsigned char *key, size_t len, uint32_t vout) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ ov->k0, v1 = 0x646f72616e646f6dULL ^ ov->k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ ov->k0, v3 = 0x7465646279746573ULL ^ ov->k1;
    unsigned char buf[256 + 4];
    memcpy(buf, key, len);
    buf[len] = vout & 0xff;
    buf[len + 1] = (vout >> 8) & 0xff;
    buf[len + 2] = (vout >> 16) & 0xff;
    buf[len + 3] = (vout >> 24) & 0xff;
    size_t n = len + 4, i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t m = load64le(buf + i);
        v3 ^= m;
        SIPROUND;
        v0 ^= m;
    }
    uint64_t b = ((uint64_t)n) << 56;
    for (size_t j = 0; i + j < n; j++) b |= ((uint64_t)buf[i + j]) << (8 * j);
    v3 ^= b;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* --- table ------------------------------------------------------------------ */

/* An empty table holds no slots (cap 0) until its first insert, so
 * creating or clearing one never allocates and cannot fail. */
static void table_init(table_t *t) {
    t->slots = NULL;
    t->cap = 0;
    t->size = t->tombs = t->entry_bytes = 0;
}

static void table_free_entries(table_t *t) {
    for (size_t i = 0; i < t->cap; i++)
        if (t->slots[i].e > TOMB) free(t->slots[i].e);
}

static int key_eq(const entry_t *e, const unsigned char *key, size_t len, uint32_t vout) {
    return e->vout == vout && e->key_len == len && memcmp(e->data, key, len) == 0;
}

/* Slot index holding the key, or -1. */
static long table_find(const table_t *t, uint64_t h, const unsigned char *key, size_t len, uint32_t vout) {
    if (t->cap == 0) return -1;
    size_t mask = t->cap - 1, i = h & mask;
    for (;;) {
        entry_t *e = t->slots[i].e;
        if (e == NULL) return -1;
        if (e != TOMB && t->slots[i].h == h && key_eq(e, key, len, vout)) return (long)i;
        i = (i + 1) & mask;
    }
}

static int table_resize(table_t *t, size_t cap) {
    slot_t *s = calloc(cap, sizeof(slot_t));
    if (!s) return 0;
    size_t mask = cap - 1;
    for (size_t i = 0; i < t->cap; i++) {
        entry_t *e = t->slots[i].e;
        if (e > TOMB) {
            size_t j = t->slots[i].h & mask;
            while (s[j].e) j = (j + 1) & mask;
            s[j] = t->slots[i];
        }
    }
    free(t->slots);
    t->slots = s;
    t->cap = cap;
    t->tombs = 0;
    return 1;
}

/* Room for one more entry: grow past 70% use, or rehash in place when
 * tombstones are most of it. */
static int table_reserve(table_t *t) {
    if (t->cap == 0) return table_resize(t, MIN_CAP);
    if ((t->size + t->tombs + 1) * 10 <= t->cap * 7) return 1;
    size_t cap = (t->size + 1) * 10 > t->cap * 5 ? t->cap * 2 : t->cap;
    return table_resize(t, cap);
}

static void table_remove_at(table_t *t, size_t i) {
    entry_t *e = t->slots[i].e;
    t->entry_bytes -= malloc_usable_size(e);
    free(e);
    t->size--;
    /* The next slot empty: no probe sequence passes here, so empty it. */
    if (t->slots[(i + 1) & (t->cap - 1)].e == NULL) {
        t->slots[i].e = NULL;
    } else {
        t->slots[i].e = TOMB;
        t->tombs++;
    }
}

static int table_delete(table_t *t, uint64_t h, const unsigned char *key, size_t len, uint32_t vout) {
    long i = table_find(t, h, key, len, vout);
    if (i < 0) return 0;
    table_remove_at(t, (size_t)i);
    return 1;
}

/* Inserts or replaces (the key's old entry is freed). Returns 0 on ENOMEM. */
static int table_put(table_t *t, uint64_t h, entry_t *e) {
    long i = table_find(t, h, e->data, e->key_len, e->vout);
    if (i >= 0) {
        t->entry_bytes -= malloc_usable_size(t->slots[i].e);
        free(t->slots[i].e);
        t->slots[i].e = e;
        t->entry_bytes += malloc_usable_size(e);
        return 1;
    }
    if (!table_reserve(t)) return 0;
    size_t mask = t->cap - 1, j = h & mask;
    while (t->slots[j].e > TOMB) j = (j + 1) & mask;
    if (t->slots[j].e == TOMB) t->tombs--;
    t->slots[j].h = h;
    t->slots[j].e = e;
    t->size++;
    t->entry_bytes += malloc_usable_size(e);
    return 1;
}

static void table_clear(table_t *t) {
    table_free_entries(t);
    free(t->slots);
    table_init(t);
}

static size_t table_bytes(const table_t *t) { return t->cap * sizeof(slot_t) + t->entry_bytes; }

/* --- packed records ------------------------------------------------------------ */

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const unsigned char *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }

typedef struct {
    const unsigned char *key;
    size_t len;
    uint32_t vout;
} op_t;

/* Next outpoint record at *off; 0 when cut short. */
static int next_op(const ErlNifBinary *b, size_t *off, op_t *op) {
    if (b->size - *off < 1) return 0;
    size_t len = b->data[*off];
    if (b->size - *off < 1 + len + 4) return 0;
    op->key = b->data + *off + 1;
    op->len = len;
    op->vout = be32(b->data + *off + 1 + len);
    *off += 1 + len + 4;
    return 1;
}

static int valid_ops(const ErlNifBinary *b) {
    size_t off = 0;
    op_t op;
    while (off < b->size)
        if (!next_op(b, &off, &op)) return 0;
    return 1;
}

typedef struct {
    op_t op;
    uint64_t output_id, value;
    uint32_t height, spk_len;
    uint8_t coinbase;
    const unsigned char *spk;
} coin_rec_t;

static int next_coin(const ErlNifBinary *b, size_t *off, coin_rec_t *c) {
    if (!next_op(b, off, &c->op)) return 0;
    if (b->size - *off < 8 + 8 + 4 + 1 + 4) return 0;
    const unsigned char *p = b->data + *off;
    c->output_id = be64(p);
    c->value = be64(p + 8);
    c->height = be32(p + 16);
    c->coinbase = p[20];
    c->spk_len = be32(p + 21);
    *off += 25;
    if (b->size - *off < c->spk_len) return 0;
    c->spk = b->data + *off;
    *off += c->spk_len;
    return 1;
}

static int valid_coins(const ErlNifBinary *b) {
    size_t off = 0;
    coin_rec_t c;
    while (off < b->size)
        if (!next_coin(b, &off, &c)) return 0;
    return 1;
}

static entry_t *new_entry(const op_t *op, uint32_t gen, const coin_rec_t *c) {
    size_t spk = c ? c->spk_len : 0;
    entry_t *e = malloc(sizeof(entry_t) + op->len + spk);
    if (!e) return NULL;
    e->vout = op->vout;
    e->key_len = (uint8_t)op->len;
    e->gen = gen;
    memcpy(e->data, op->key, op->len);
    if (c) {
        e->output_id = c->output_id;
        e->value = c->value;
        e->height = c->height;
        e->coinbase = c->coinbase;
        e->spk_len = c->spk_len;
        memcpy(e->data + op->len, c->spk, c->spk_len);
    } else {
        e->output_id = e->value = 0;
        e->height = e->spk_len = 0;
        e->coinbase = 0;
    }
    return e;
}

/* --- NIFs --------------------------------------------------------------------- */

static void overlay_dtor(ErlNifEnv *env, void *obj) {
    (void)env;
    overlay_t *ov = obj;
    table_clear(&ov->coins);
    table_clear(&ov->spent);
    if (ov->lock) enif_rwlock_destroy(ov->lock);
}

static ERL_NIF_TERM enomem(ErlNifEnv *env) {
    return enif_raise_exception(env, enif_make_atom(env, "enomem"));
}

static int get_ov(ErlNifEnv *env, ERL_NIF_TERM t, overlay_t **ov) {
    return enif_get_resource(env, t, overlay_type, (void **)ov);
}

static ERL_NIF_TERM nif_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    overlay_t *ov = enif_alloc_resource(overlay_type, sizeof(overlay_t));
    memset(ov, 0, sizeof(*ov));
    uint64_t k[2];
    ov->lock = enif_rwlock_create("exnode_overlay");
    table_init(&ov->coins);
    table_init(&ov->spent);
    if (!ov->lock || getrandom(k, sizeof(k), 0) != sizeof(k)) {
        enif_release_resource(ov);
        return enomem(env);
    }
    ov->k0 = k[0];
    ov->k1 = k[1];
    ERL_NIF_TERM t = enif_make_resource(env, ov);
    enif_release_resource(ov);
    return t;
}

/* apply(ov, gen, spent_ops, coins): Archive's connected block. Spent
 * outpoints leave `coins` and join `spent`; then each created coin leaves
 * `spent` and goes into `coins` under `gen` (replacing an older entry: a
 * BIP30-allowed duplicate). Both binaries are checked first, so a malformed
 * one changes nothing. Out of memory it raises enomem with the block partly
 * applied; the owner must then discard the tables. Returns {ok, spent_us, created_us}: the two phases'
 * times. */
static ERL_NIF_TERM nif_apply(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    unsigned int gen;
    ErlNifBinary mask, coins;
    if (!get_ov(env, argv[0], &ov) || !enif_get_uint(env, argv[1], &gen) ||
        !enif_inspect_binary(env, argv[2], &mask) || !enif_inspect_binary(env, argv[3], &coins) ||
        !valid_ops(&mask) || !valid_coins(&coins))
        return enif_make_badarg(env);

    int ok = 1;
    enif_rwlock_rwlock(ov->lock);
    ErlNifTime t0 = enif_monotonic_time(ERL_NIF_USEC);
    size_t off = 0;
    op_t op;
    while (ok && off < mask.size) {
        next_op(&mask, &off, &op);
        uint64_t h = hash_op(ov, op.key, op.len, op.vout);
        table_delete(&ov->coins, h, op.key, op.len, op.vout);
        if (table_find(&ov->spent, h, op.key, op.len, op.vout) < 0) {
            entry_t *e = new_entry(&op, 0, NULL);
            ok = e && table_put(&ov->spent, h, e);
            if (e && !ok) free(e);
        }
    }
    ErlNifTime t1 = enif_monotonic_time(ERL_NIF_USEC);
    off = 0;
    coin_rec_t c;
    while (ok && off < coins.size) {
        next_coin(&coins, &off, &c);
        uint64_t h = hash_op(ov, c.op.key, c.op.len, c.op.vout);
        table_delete(&ov->spent, h, c.op.key, c.op.len, c.op.vout);
        entry_t *e = new_entry(&c.op, gen, &c);
        ok = e && table_put(&ov->coins, h, e);
        if (e && !ok) free(e);
    }
    ErlNifTime t2 = enif_monotonic_time(ERL_NIF_USEC);
    enif_rwlock_rwunlock(ov->lock);
    if (!ok) return enomem(env);
    return enif_make_tuple3(env, atom_ok, enif_make_int64(env, t1 - t0), enif_make_int64(env, t2 - t1));
}

static int get_op_args(ErlNifEnv *env, const ERL_NIF_TERM argv[], overlay_t **ov, ErlNifBinary *key,
                       unsigned int *vout) {
    return get_ov(env, argv[0], ov) && enif_inspect_binary(env, argv[1], key) && key->size <= 255 &&
           enif_get_uint(env, argv[2], vout);
}

/* lookup(ov, txid, vout): {:ok, coin} | :spent | :unknown. */
static ERL_NIF_TERM nif_lookup(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    ErlNifBinary key;
    unsigned int vout;
    if (!get_op_args(env, argv, &ov, &key, &vout)) return enif_make_badarg(env);
    ERL_NIF_TERM res;
    enif_rwlock_rlock(ov->lock);
    uint64_t h = hash_op(ov, key.data, key.size, vout);
    long i = table_find(&ov->coins, h, key.data, key.size, vout);
    if (i >= 0) {
        entry_t *e = ov->coins.slots[i].e;
        ERL_NIF_TERM spk;
        unsigned char *p = enif_make_new_binary(env, e->spk_len, &spk);
        memcpy(p, e->data + e->key_len, e->spk_len);
        ERL_NIF_TERM keys[5] = {k_output_id, k_value, k_script_pubkey, k_height, k_coinbase};
        ERL_NIF_TERM vals[5] = {enif_make_uint64(env, e->output_id), enif_make_uint64(env, e->value), spk,
                                enif_make_uint(env, e->height), e->coinbase ? atom_true : atom_false};
        ERL_NIF_TERM map;
        enif_make_map_from_arrays(env, keys, vals, 5, &map);
        res = enif_make_tuple2(env, atom_ok, map);
    } else if (table_find(&ov->spent, h, key.data, key.size, vout) >= 0) {
        res = atom_spent;
    } else {
        res = atom_unknown;
    }
    enif_rwlock_runlock(ov->lock);
    return res;
}

/* member(ov, txid, vout): lookup answers it (a coin or a spend). Called
 * by other processes (prefetch) on normal schedulers, where waiting out a
 * dirty writer (a resize rehashes every entry) would stall the scheduler:
 * with the lock taken it answers false. The answer is advisory anyway (the
 * owner may change the tables right after), and false only means the
 * caller fetches that outpoint itself. */
static ERL_NIF_TERM nif_member(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    ErlNifBinary key;
    unsigned int vout;
    if (!get_op_args(env, argv, &ov, &key, &vout)) return enif_make_badarg(env);
    if (enif_rwlock_tryrlock(ov->lock) != 0) return atom_false;
    uint64_t h = hash_op(ov, key.data, key.size, vout);
    int found = table_find(&ov->coins, h, key.data, key.size, vout) >= 0 ||
                table_find(&ov->spent, h, key.data, key.size, vout) >= 0;
    enif_rwlock_runlock(ov->lock);
    return found ? atom_true : atom_false;
}

/* gen_of(ov, txid, vout): the coin's generation, or nil (tests). */
static ERL_NIF_TERM nif_gen_of(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    ErlNifBinary key;
    unsigned int vout;
    if (!get_op_args(env, argv, &ov, &key, &vout)) return enif_make_badarg(env);
    enif_rwlock_rlock(ov->lock);
    long i = table_find(&ov->coins, hash_op(ov, key.data, key.size, vout), key.data, key.size, vout);
    ERL_NIF_TERM r = i >= 0 ? enif_make_uint(env, ov->coins.slots[i].e->gen) : enif_make_atom(env, "nil");
    enif_rwlock_runlock(ov->lock);
    return r;
}

/* evict(ov, gen, ops): removes each outpoint's coin if it still belongs to
 * `gen` (it may have been spent, or replaced by a later block). Returns
 * how many were removed. */
static ERL_NIF_TERM nif_evict(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    unsigned int gen;
    ErlNifBinary ops;
    if (!get_ov(env, argv[0], &ov) || !enif_get_uint(env, argv[1], &gen) ||
        !enif_inspect_binary(env, argv[2], &ops) || !valid_ops(&ops))
        return enif_make_badarg(env);
    size_t off = 0, n = 0;
    op_t op;
    enif_rwlock_rwlock(ov->lock);
    while (off < ops.size) {
        next_op(&ops, &off, &op);
        uint64_t h = hash_op(ov, op.key, op.len, op.vout);
        long i = table_find(&ov->coins, h, op.key, op.len, op.vout);
        if (i >= 0 && ov->coins.slots[i].e->gen == gen) {
            table_remove_at(&ov->coins, (size_t)i);
            n++;
        }
    }
    enif_rwlock_rwunlock(ov->lock);
    return enif_make_uint64(env, n);
}

/* clear(ov, which): :spent, or :all. */
static ERL_NIF_TERM nif_clear(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    if (!get_ov(env, argv[0], &ov) || !enif_is_atom(env, argv[1])) return enif_make_badarg(env);
    int all = enif_is_identical(argv[1], enif_make_atom(env, "all"));
    enif_rwlock_rwlock(ov->lock);
    table_clear(&ov->spent);
    if (all) table_clear(&ov->coins);
    enif_rwlock_rwunlock(ov->lock);
    return atom_ok;
}

/* info(ov): {coins, spent, bytes}; bytes counts both tables' slots and
 * their entries' allocations. */
static ERL_NIF_TERM nif_info(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    overlay_t *ov;
    if (!get_ov(env, argv[0], &ov)) return enif_make_badarg(env);
    enif_rwlock_rlock(ov->lock);
    ERL_NIF_TERM r = enif_make_tuple3(env, enif_make_uint64(env, ov->coins.size),
                                      enif_make_uint64(env, ov->spent.size),
                                      enif_make_uint64(env, table_bytes(&ov->coins) + table_bytes(&ov->spent)));
    enif_rwlock_runlock(ov->lock);
    return r;
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv; (void)info;
    overlay_type = enif_open_resource_type(env, NULL, "exnode_overlay", overlay_dtor, ERL_NIF_RT_CREATE, NULL);
    if (!overlay_type) return 1;
    atom_ok = enif_make_atom(env, "ok");
    atom_spent = enif_make_atom(env, "spent");
    atom_unknown = enif_make_atom(env, "unknown");
    atom_true = enif_make_atom(env, "true");
    atom_false = enif_make_atom(env, "false");
    k_output_id = enif_make_atom(env, "output_id");
    k_value = enif_make_atom(env, "value");
    k_script_pubkey = enif_make_atom(env, "script_pubkey");
    k_height = enif_make_atom(env, "height");
    k_coinbase = enif_make_atom(env, "coinbase");
    return 0;
}

static ErlNifFunc funcs[] = {
    {"new_nif", 0, nif_new, 0},
    {"apply_nif", 4, nif_apply, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"lookup_nif", 3, nif_lookup, 0},
    {"member_nif", 3, nif_member, 0},
    {"gen_of_nif", 3, nif_gen_of, 0},
    {"evict_nif", 3, nif_evict, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"clear_nif", 2, nif_clear, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"info_nif", 1, nif_info, 0},
};

ERL_NIF_INIT(Elixir.Exnode.Archive.Overlay, funcs, load, NULL, NULL, NULL)
