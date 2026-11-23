/*
 * ElligatorSwift ECDH for BIP324, from the libsecp256k1 pinned with Bitcoin
 * Core v32.1 (vendor/bitcoin/src/secp256k1, module ellswift). Core uses it in
 * key.cpp: CKey::EllSwiftCreate (secp256k1_ellswift_create) and
 * CKey::ComputeBIP324ECDHSecret (secp256k1_ellswift_xdh with
 * secp256k1_ellswift_xdh_hash_function_bip324).
 *
 * Every argument is checked here before the library is called: binaries of
 * exactly the required sizes, party 0 or 1, and a valid secret key
 * (secp256k1_ec_seckey_verify). The library is never handed a NULL or short
 * buffer.
 */
#include <erl_nif.h>
#include <string.h>
#include <sys/random.h>

#include "secp256k1.h"
#include "secp256k1_ellswift.h"

static secp256k1_context *ctx = NULL;

static ERL_NIF_TERM atom_error;

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv; (void)info;
    atom_error = enif_make_atom(env, "error");
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) return 1;
    /* Side-channel blinding, as Core's ECC_Start (key.cpp). */
    unsigned char seed[32];
    int ok = getrandom(seed, sizeof(seed), 0) == (ssize_t)sizeof(seed) && secp256k1_context_randomize(ctx, seed);
    /* A plain memset of a dead local may be optimised away. */
    explicit_bzero(seed, sizeof(seed));
    if (ok) return 0;
    /* A failed load never reaches unload. */
    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return 1;
}

static void unload(ErlNifEnv *env, void *priv) {
    (void)env; (void)priv;
    if (ctx) secp256k1_context_destroy(ctx);
    ctx = NULL;
}

static int get_bin(ErlNifEnv *env, ERL_NIF_TERM t, size_t len, ErlNifBinary *out) {
    return enif_inspect_binary(env, t, out) && out->size == len;
}

/* ellswift_create(seckey32, auxrnd32) -> {ok, Ell64} | error */
static ERL_NIF_TERM ellswift_create(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary sk, aux;
    if (argc != 2 || !get_bin(env, argv[0], 32, &sk) || !get_bin(env, argv[1], 32, &aux)) return enif_make_badarg(env);
    if (!secp256k1_ec_seckey_verify(ctx, sk.data)) return atom_error;
    ERL_NIF_TERM out;
    unsigned char *ell = enif_make_new_binary(env, 64, &out);
    if (!secp256k1_ellswift_create(ctx, ell, sk.data, aux.data)) return atom_error;
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), out);
}

/* ellswift_xdh(ell_a64, ell_b64, seckey32, party) -> {ok, Secret32} | error (BIP324 hash) */
static ERL_NIF_TERM ellswift_xdh(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary a, b, sk;
    int party;
    if (argc != 4 || !get_bin(env, argv[0], 64, &a) || !get_bin(env, argv[1], 64, &b) ||
        !get_bin(env, argv[2], 32, &sk) || !enif_get_int(env, argv[3], &party) || (party != 0 && party != 1))
        return enif_make_badarg(env);
    if (!secp256k1_ec_seckey_verify(ctx, sk.data)) return atom_error;
    ERL_NIF_TERM out;
    unsigned char *secret = enif_make_new_binary(env, 32, &out);
    if (!secp256k1_ellswift_xdh(ctx, secret, a.data, b.data, sk.data, party,
                                secp256k1_ellswift_xdh_hash_function_bip324, NULL))
        return atom_error;
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), out);
}

/* ellswift_decode(ell64) -> Pubkey33 (compressed). Always succeeds for 64 bytes. */
static ERL_NIF_TERM ellswift_decode(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary e;
    if (argc != 1 || !get_bin(env, argv[0], 64, &e)) return enif_make_badarg(env);
    secp256k1_pubkey pk;
    if (!secp256k1_ellswift_decode(ctx, &pk, e.data)) return atom_error;
    ERL_NIF_TERM out;
    unsigned char *ser = enif_make_new_binary(env, 33, &out);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &pk, SECP256K1_EC_COMPRESSED);
    return out;
}

static ErlNifFunc funcs[] = {
    {"create_nif", 2, ellswift_create, 0},
    {"xdh_nif", 4, ellswift_xdh, 0},
    {"decode_nif", 1, ellswift_decode, 0},
};

ERL_NIF_INIT(Elixir.Exnode.Crypto.Secp, funcs, load, NULL, NULL, unload)
