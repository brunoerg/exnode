/*
 * Stable sort of packed key/value records by key (bytewise, RocksDB's
 * default comparator), for Exnode.Store.PackedSort.
 *
 * A packed binary is a run of records, each `key <> value` with a
 * `key_size`-byte key and either a `value_size`-byte value or, when
 * value_size is 0, a value preceded by its 32-bit big-endian length (the
 * `{:put_packed, cf, ks, vs, bin}` layout of Exnode.Store.KV). The result is
 * a new binary of the same records, ordered by key; records with equal keys
 * keep their input order, so a later put of the same key still wins when the
 * run is written in order.
 *
 * Every record is bounds-checked before anything is sorted: a binary whose
 * last record is cut short is badarg.
 */
#include <erl_nif.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const unsigned char *p; /* record start (its key) */
    size_t len;             /* whole record; ks + 4 + a 32-bit length can pass 4 GiB */
} rec_t;


static int key_le(const rec_t *a, const rec_t *b, size_t ks) {
    return memcmp(a->p, b->p, ks) <= 0;
}

/* Bottom-up merge sort (stable): `a` sorted into `a`, `tmp` as scratch. */
static void merge_sort(rec_t *a, rec_t *tmp, size_t n, size_t ks) {
    rec_t *src = a, *dst = tmp;
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * w) {
            size_t mid = lo + w < n ? lo + w : n;
            size_t hi = lo + 2 * w < n ? lo + 2 * w : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi) dst[k++] = key_le(&src[i], &src[j], ks) ? src[i++] : src[j++];
            while (i < mid) dst[k++] = src[i++];
            while (j < hi) dst[k++] = src[j++];
        }
        rec_t *t = src; src = dst; dst = t;
    }
    if (src != a) memcpy(a, src, n * sizeof(rec_t));
}

static ERL_NIF_TERM sort_packed(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    ErlNifBinary in;
    unsigned int ks, vs;
    if (!enif_inspect_binary(env, argv[0], &in) || !enif_get_uint(env, argv[1], &ks) ||
        !enif_get_uint(env, argv[2], &vs) || ks == 0 || ks > 1024)
        return enif_make_badarg(env);

    /* Count and bounds-check the records. */
    size_t n = 0, off = 0;
    while (off < in.size) {
        uint64_t len; /* 64-bit so ks + vs cannot wrap where size_t is 32 bits */
        if (vs > 0) {
            len = (uint64_t)ks + vs;
        } else {
            if (in.size - off < (size_t)ks + 4) return enif_make_badarg(env);
            const unsigned char *l = in.data + off + ks;
            uint32_t vl = ((uint32_t)l[0] << 24) | ((uint32_t)l[1] << 16) | ((uint32_t)l[2] << 8) | l[3];
            len = (uint64_t)ks + 4 + vl;
        }
        if ((uint64_t)(in.size - off) < len) return enif_make_badarg(env);
        off += (size_t)len;
        n++;
    }

    ERL_NIF_TERM out_term;
    unsigned char *out = enif_make_new_binary(env, in.size, &out_term);
    if (out == NULL) return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    if (n < 2) {
        if (in.size > 0) memcpy(out, in.data, in.size); /* an empty binary may have no data */
        return out_term;
    }

    rec_t *recs = malloc(n * sizeof(rec_t));
    rec_t *tmp = malloc(n * sizeof(rec_t));
    if (recs == NULL || tmp == NULL) {
        free(recs);
        free(tmp);
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    }

    off = 0;
    for (size_t i = 0; i < n; i++) {
        size_t len = vs > 0 ? (size_t)ks + vs : (size_t)ks + 4 +
            (((uint32_t)in.data[off + ks] << 24) | ((uint32_t)in.data[off + ks + 1] << 16) |
             ((uint32_t)in.data[off + ks + 2] << 8) | in.data[off + ks + 3]);
        recs[i].p = in.data + off;
        recs[i].len = len;
        off += len;
    }

    merge_sort(recs, tmp, n, ks);

    unsigned char *w = out;
    for (size_t i = 0; i < n; i++) {
        memcpy(w, recs[i].p, recs[i].len);
        w += recs[i].len;
    }
    free(recs);
    free(tmp);
    return out_term;
}

static ErlNifFunc funcs[] = {
    {"sort_nif", 3, sort_packed, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.Exnode.Store.PackedSort, funcs, NULL, NULL, NULL, NULL)
