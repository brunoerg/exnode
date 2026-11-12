/*
 * exnode kernel script-verification NIF.
 *
 * Links libbitcoinkernel from Bitcoin Core v32.1 (pinned). This is the only C
 * file that calls the kernel's script API; Exnode.Kernel is its Elixir wrapper.
 *
 * Safety: the v32.1 kernel assert()s on several bad caller inputs
 * (src/kernel/bitcoinkernel.cpp):
 *   - btck_script_pubkey_verify: flags outside btck_ScriptVerificationFlags_ALL
 *   - btck_script_pubkey_verify: input_index >= tx.vin.size()
 *   - btck_precomputed_transaction_data_create: spent_outputs_len != vin.size()
 * An abort inside a NIF kills the whole VM, so each of these is checked here
 * before the kernel is called, and a violation returns badarg.
 *
 * Thread safety: every kernel object is created and destroyed within one
 * call and never shared, so concurrent calls on dirty schedulers are safe.
 * btck_script_pubkey_verify needs no btck_Context (the kernel holds a static
 * one that does the ECC init).
 */
#include <erl_nif.h>
#include <stdint.h>
#include <string.h>

#include "bitcoinkernel.h"

static ERL_NIF_TERM atom_ok, atom_error, atom_invalid, atom_bad_tx,
    atom_invalid_flags_combination, atom_spent_outputs_required, atom_unknown_status;

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv; (void)info;
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_invalid = enif_make_atom(env, "invalid");
    atom_bad_tx = enif_make_atom(env, "bad_tx");
    atom_invalid_flags_combination = enif_make_atom(env, "invalid_flags_combination");
    atom_spent_outputs_required = enif_make_atom(env, "spent_outputs_required");
    atom_unknown_status = enif_make_atom(env, "unknown_status");
    /* Header: call once; not thread or re-entry safe. load() runs once. */
    btck_logging_disable();
    return 0;
}

static ERL_NIF_TERM status_term(btck_ScriptVerifyStatus s) {
    switch (s) {
    case btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION: return atom_invalid_flags_combination;
    case btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED: return atom_spent_outputs_required;
    default: return atom_unknown_status;
    }
}

/*
 * verify_tx(TxBin, SpentOutputs, Flags) -> {ok, [Result]} | {error, bad_tx} | badarg
 *   TxBin        :: binary(), serialized transaction (with witness)
 *   SpentOutputs :: [{ScriptPubKey :: binary(), Amount :: integer()}], one per input
 *   Flags        :: non_neg_integer(), subset of btck_ScriptVerificationFlags_ALL
 *   Result       :: ok | invalid | {error, StatusAtom}
 * Runs on a dirty CPU scheduler.
 */
static ERL_NIF_TERM verify_tx(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    ErlNifBinary txbin;
    unsigned int nspent;
    unsigned int flags;

    if (!enif_inspect_binary(env, argv[0], &txbin)) return enif_make_badarg(env);
    if (!enif_get_list_length(env, argv[1], &nspent)) return enif_make_badarg(env);
    if (!enif_get_uint(env, argv[2], &flags)) return enif_make_badarg(env);
    /* Guards: assert((flags & ~btck_ScriptVerificationFlags_ALL) == 0) */
    if ((flags & ~((unsigned int)btck_ScriptVerificationFlags_ALL)) != 0) return enif_make_badarg(env);

    btck_Transaction *tx = btck_transaction_create(txbin.data, txbin.size);
    if (tx == NULL) return enif_make_tuple2(env, atom_error, atom_bad_tx);

    size_t nin = btck_transaction_count_inputs(tx);
    /* Guards: assert(spent_outputs_len == tx.vin.size()) */
    if ((size_t)nspent != nin) {
        btck_transaction_destroy(tx);
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM result = 0;
    btck_ScriptPubkey **spks = NULL;
    btck_TransactionOutput **outs = NULL;
    int64_t *amounts = NULL;
    btck_PrecomputedTransactionData *txdata = NULL;
    size_t built = 0;

    if (nin > 0) {
        spks = enif_alloc(sizeof(*spks) * nin);
        outs = enif_alloc(sizeof(*outs) * nin);
        amounts = enif_alloc(sizeof(*amounts) * nin);
        if (!spks || !outs || !amounts) { result = enif_raise_exception(env, enif_make_atom(env, "enomem")); goto cleanup; }
    }

    ERL_NIF_TERM list = argv[1], head;
    for (size_t i = 0; i < nin; i++) {
        const ERL_NIF_TERM *tup;
        int arity;
        ErlNifBinary spk;
        ErlNifSInt64 amount;
        if (!enif_get_list_cell(env, list, &head, &list) ||
            !enif_get_tuple(env, head, &arity, &tup) || arity != 2 ||
            !enif_inspect_binary(env, tup[0], &spk) ||
            !enif_get_int64(env, tup[1], &amount)) {
            result = enif_make_badarg(env);
            goto cleanup;
        }
        spks[i] = btck_script_pubkey_create(spk.data, spk.size);
        if (spks[i] == NULL) { result = enif_raise_exception(env, enif_make_atom(env, "kernel_alloc")); goto cleanup; }
        outs[i] = btck_transaction_output_create(spks[i], (int64_t)amount);
        if (outs[i] == NULL) { btck_script_pubkey_destroy(spks[i]); result = enif_raise_exception(env, enif_make_atom(env, "kernel_alloc")); goto cleanup; }
        amounts[i] = (int64_t)amount;
        built++;
    }

    txdata = btck_precomputed_transaction_data_create(
        tx, nin > 0 ? (const btck_TransactionOutput **)outs : NULL, nin);
    if (txdata == NULL) { result = enif_raise_exception(env, enif_make_atom(env, "kernel_txdata")); goto cleanup; }

    ERL_NIF_TERM *res = nin > 0 ? enif_alloc(sizeof(ERL_NIF_TERM) * nin) : NULL;
    /* enif_alloc returns NULL on failure; cleanup frees everything built so far. */
    if (nin > 0 && res == NULL) { result = enif_raise_exception(env, enif_make_atom(env, "enomem")); goto cleanup; }
    for (size_t i = 0; i < nin; i++) {
        btck_ScriptVerifyStatus status = btck_ScriptVerifyStatus_OK;
        /* input_index < nin by construction (guards assert(input_index < tx.vin.size())) */
        int ok = btck_script_pubkey_verify(spks[i], amounts[i], tx, txdata, (unsigned int)i,
                                           (btck_ScriptVerificationFlags)flags, &status);
        if (status != btck_ScriptVerifyStatus_OK) res[i] = enif_make_tuple2(env, atom_error, status_term(status));
        else res[i] = ok == 1 ? atom_ok : atom_invalid;
    }
    result = enif_make_tuple2(env, atom_ok, enif_make_list_from_array(env, res, (unsigned)nin));
    if (res) enif_free(res);

cleanup:
    if (txdata) btck_precomputed_transaction_data_destroy(txdata);
    for (size_t i = 0; i < built; i++) {
        btck_transaction_output_destroy(outs[i]);
        btck_script_pubkey_destroy(spks[i]);
    }
    if (spks) enif_free(spks);
    if (outs) enif_free(outs);
    if (amounts) enif_free(amounts);
    btck_transaction_destroy(tx);
    return result;
}

static ERL_NIF_TERM flags_all(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_make_uint(env, (unsigned int)btck_ScriptVerificationFlags_ALL);
}

static ErlNifFunc nif_funcs[] = {
    {"verify_tx_nif", 3, verify_tx, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"flags_all_nif", 0, flags_all, 0},
};

ERL_NIF_INIT(Elixir.Exnode.Kernel, nif_funcs, load, NULL, NULL, NULL)
