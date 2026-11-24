/*
 * Stable sort and direct RocksDB WriteBatch framing of packed key/value
 * records (bytewise, RocksDB's default comparator), for Exnode.Store.PackedSort.
 *
 * A packed binary is a run of records, each `key <> value` with a
 * `key_size`-byte key and either a `value_size`-byte value or, when
 * value_size is 0, a value preceded by its 32-bit big-endian length (the
 * `{:put_packed, cf, ks, vs, bin}` layout of Exnode.Store.KV).
 *
 * `encode_wb_nif` frames one or more packed binaries directly into RocksDB's
 * WriteBatch record wire format (`kTypeColumnFamilyValue = 5` + varint32(cf_id)
 * + varint32(klen) + key + varint32(vlen) + val, or `kTypeValue = 1` when
 * cf_id == 0), optionally sorting all records stably by key in the same pass.
 * That bypasses millions of per-record `rocksdb:batch_put` NIF calls and
 * `enif_make_copy` allocations during IBD commits.
 *
 * Every record is bounds-checked before anything is sorted or written.
 */
#include <erl_nif.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const unsigned char *p; /* record start (its key) */
    size_t len;             /* whole record; ks + 4 + a 32-bit length can pass 4 GiB */
} rec_t;

typedef struct {
    const unsigned char *p; /* record start (its key) */
    uint32_t vlen;          /* value byte length */
} wb_rec_t;

static int key_le(const rec_t *a, const rec_t *b, size_t ks) {
    return memcmp(a->p, b->p, ks) <= 0;
}

static int wb_key_le(const wb_rec_t *a, const wb_rec_t *b, size_t ks) {
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

static void merge_sort_wb(wb_rec_t *a, wb_rec_t *tmp, size_t n, size_t ks) {
    wb_rec_t *src = a, *dst = tmp;
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * w) {
            size_t mid = lo + w < n ? lo + w : n;
            size_t hi = lo + 2 * w < n ? lo + 2 * w : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi) dst[k++] = wb_key_le(&src[i], &src[j], ks) ? src[i++] : src[j++];
            while (i < mid) dst[k++] = src[i++];
            while (j < hi) dst[k++] = src[j++];
        }
        wb_rec_t *t = src; src = dst; dst = t;
    }
    if (src != a) memcpy(a, src, n * sizeof(wb_rec_t));
}

static size_t varint32_len(uint32_t v) {
    size_t n = 1;
    while (v >= 128) {
        v >>= 7;
        n++;
    }
    return n;
}

static unsigned char *put_varint32(unsigned char *dst, uint32_t v) {
    while (v >= 128) {
        *dst++ = (unsigned char)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    *dst++ = (unsigned char)v;
    return dst;
}

static uint32_t read_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
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
            uint32_t vl = read_be32(in.data + off + ks);
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

    if (n > SIZE_MAX / sizeof(rec_t))
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));

    rec_t *recs = malloc(n * sizeof(rec_t));
    rec_t *tmp = malloc(n * sizeof(rec_t));
    if (recs == NULL || tmp == NULL) {
        free(recs);
        free(tmp);
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    }

    off = 0;
    for (size_t i = 0; i < n; i++) {
        size_t len = vs > 0 ? (size_t)ks + vs : (size_t)ks + 4 + read_be32(in.data + off + ks);
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

/*
 * encode_wb_nif(cf_id, ks, vs, bin_or_list_of_bins, flags) ->
 *   {:ok, wb_records_bin, count, kv_bytes} | :truncated
 *
 * flags bit 0: sort stably by key
 * flags bit 1: variable-length values (32-bit big-endian length prefix; vs must be 0)
 */
static ERL_NIF_TERM encode_wb_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    unsigned int cf_id, ks, vs, flags;
    if (!enif_get_uint(env, argv[0], &cf_id) || !enif_get_uint(env, argv[1], &ks) ||
        !enif_get_uint(env, argv[2], &vs) || !enif_get_uint(env, argv[4], &flags) ||
        ks == 0 || ks > 1024 || flags > 3 || ((flags & 2) && vs != 0))
        return enif_make_badarg(env);

    const int sort_flag = (flags & 1) != 0;
    const int is_var = (flags & 2) != 0;

    ErlNifBinary single_seg;
    ErlNifBinary *heap_segs = NULL;
    ErlNifBinary *segs = NULL;
    size_t seg_count = 0;

    if (enif_inspect_binary(env, argv[3], &single_seg)) {
        segs = &single_seg;
        seg_count = 1;
    } else if (enif_is_list(env, argv[3])) {
        unsigned int len = 0;
        if (!enif_get_list_length(env, argv[3], &len))
            return enif_make_badarg(env);
        seg_count = len;
        if (seg_count > 0) {
            if (seg_count > SIZE_MAX / sizeof(ErlNifBinary))
                return enif_raise_exception(env, enif_make_atom(env, "enomem"));
            heap_segs = malloc(seg_count * sizeof(ErlNifBinary));
            if (heap_segs == NULL)
                return enif_raise_exception(env, enif_make_atom(env, "enomem"));
            ERL_NIF_TERM head, tail = argv[3];
            for (size_t i = 0; i < seg_count; i++) {
                if (!enif_get_list_cell(env, tail, &head, &tail) ||
                    !enif_inspect_binary(env, head, &heap_segs[i])) {
                    free(heap_segs);
                    return enif_make_badarg(env);
                }
            }
            segs = heap_segs;
        }
    } else {
        return enif_make_badarg(env);
    }

    /* Constant per-record header: tag (0x01 or 0x05 + varint32(cf_id)) + varint32(ks). */
    unsigned char hdr_ks[16];
    unsigned char *hp = hdr_ks;
    if (cf_id == 0) {
        *hp++ = 0x01; /* kTypeValue */
    } else {
        *hp++ = 0x05; /* kTypeColumnFamilyValue */
        hp = put_varint32(hp, (uint32_t)cf_id);
    }
    hp = put_varint32(hp, (uint32_t)ks);
    size_t hdr_ks_len = (size_t)(hp - hdr_ks);

    unsigned char vs_vi[8];
    size_t vs_vi_len = !is_var ? (size_t)(put_varint32(vs_vi, (uint32_t)vs) - vs_vi) : 0;

    /* Pass 1: bounds-check all segments and compute exact output byte size. */
    size_t n = 0;
    uint64_t kv_bytes = 0;
    size_t wb_bytes = 0;

    for (size_t s = 0; s < seg_count; s++) {
        const ErlNifBinary *seg = &segs[s];
        size_t off = 0;
        while (off < seg->size) {
            uint32_t vlen;
            uint64_t in_len;
            size_t vlen_vi;
            if (!is_var) {
                vlen = (uint32_t)vs;
                in_len = (uint64_t)ks + vlen;
                vlen_vi = vs_vi_len;
            } else {
                if (seg->size - off < (size_t)ks + 4) {
                    free(heap_segs);
                    return enif_make_atom(env, "truncated");
                }
                vlen = read_be32(seg->data + off + ks);
                in_len = (uint64_t)ks + 4 + vlen;
                vlen_vi = varint32_len(vlen);
            }
            if ((uint64_t)(seg->size - off) < in_len) {
                free(heap_segs);
                return enif_make_atom(env, "truncated");
            }
            if (n == UINT32_MAX) {
                free(heap_segs);
                return enif_raise_exception(env, enif_make_atom(env, "enomem"));
            }
            uint64_t rec_wb = (uint64_t)hdr_ks_len + ks + vlen_vi + vlen;
            if (rec_wb > SIZE_MAX - wb_bytes) {
                free(heap_segs);
                return enif_raise_exception(env, enif_make_atom(env, "enomem"));
            }
            wb_bytes += (size_t)rec_wb;
            kv_bytes += (uint64_t)ks + vlen;
            off += (size_t)in_len;
            n++;
        }
    }

    ERL_NIF_TERM out_term;
    unsigned char *out = enif_make_new_binary(env, wb_bytes, &out_term);
    if (out == NULL) {
        free(heap_segs);
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    }

    if (n == 0) {
        free(heap_segs);
        return enif_make_tuple4(env, enif_make_atom(env, "ok"), out_term,
                                enif_make_uint64(env, 0), enif_make_uint64(env, 0));
    }

    const size_t val_off = !is_var ? (size_t)ks : (size_t)ks + 4;

    if (!sort_flag || n < 2) {
        unsigned char *w = out;
        for (size_t s = 0; s < seg_count; s++) {
            const ErlNifBinary *seg = &segs[s];
            size_t off = 0;
            while (off < seg->size) {
                const unsigned char *rec = seg->data + off;
                uint32_t vlen = !is_var ? (uint32_t)vs : read_be32(rec + ks);
                memcpy(w, hdr_ks, hdr_ks_len);
                w += hdr_ks_len;
                memcpy(w, rec, ks);
                w += ks;
                if (!is_var) {
                    memcpy(w, vs_vi, vs_vi_len);
                    w += vs_vi_len;
                } else {
                    w = put_varint32(w, vlen);
                }
                if (vlen > 0) {
                    memcpy(w, rec + val_off, vlen);
                    w += vlen;
                }
                off += val_off + vlen;
            }
        }
        free(heap_segs);
        return enif_make_tuple4(env, enif_make_atom(env, "ok"), out_term,
                                enif_make_uint64(env, n), enif_make_uint64(env, kv_bytes));
    }

    if (n > SIZE_MAX / sizeof(wb_rec_t)) {
        free(heap_segs);
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    }

    wb_rec_t *recs = malloc(n * sizeof(wb_rec_t));
    wb_rec_t *tmp = malloc(n * sizeof(wb_rec_t));
    if (recs == NULL || tmp == NULL) {
        free(recs);
        free(tmp);
        free(heap_segs);
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));
    }

    size_t idx = 0;
    for (size_t s = 0; s < seg_count; s++) {
        const ErlNifBinary *seg = &segs[s];
        size_t off = 0;
        while (off < seg->size) {
            const unsigned char *rec = seg->data + off;
            uint32_t vlen = !is_var ? (uint32_t)vs : read_be32(rec + ks);
            recs[idx].p = rec;
            recs[idx].vlen = vlen;
            idx++;
            off += val_off + vlen;
        }
    }

    merge_sort_wb(recs, tmp, n, ks);

    unsigned char *w = out;
    for (size_t i = 0; i < n; i++) {
        uint32_t vlen = recs[i].vlen;
        memcpy(w, hdr_ks, hdr_ks_len);
        w += hdr_ks_len;
        memcpy(w, recs[i].p, ks);
        w += ks;
        if (!is_var) {
            memcpy(w, vs_vi, vs_vi_len);
            w += vs_vi_len;
        } else {
            w = put_varint32(w, vlen);
        }
        if (vlen > 0) {
            memcpy(w, recs[i].p + val_off, vlen);
            w += vlen;
        }
    }

    free(recs);
    free(tmp);
    free(heap_segs);
    return enif_make_tuple4(env, enif_make_atom(env, "ok"), out_term,
                            enif_make_uint64(env, n), enif_make_uint64(env, kv_bytes));
}

static ErlNifFunc funcs[] = {
    {"sort_nif", 3, sort_packed, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encode_wb_nif", 5, encode_wb_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.Exnode.Store.PackedSort, funcs, NULL, NULL, NULL, NULL)
