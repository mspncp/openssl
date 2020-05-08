/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/e_os2.h>
#include <openssl/params.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"
#include "drbg_local.h"

static OSSL_OP_rand_newctx_fn test_rng_new_wrapper;
static OSSL_OP_rand_freectx_fn test_rng_free;
static OSSL_OP_rand_instantiate_fn test_rng_instantiate_wrapper;
static OSSL_OP_rand_uninstantiate_fn test_rng_uninstantiate;
static OSSL_OP_rand_generate_fn test_rng_generate;
static OSSL_OP_rand_reseed_fn test_rng_reseed;
static OSSL_OP_rand_settable_ctx_params_fn test_rng_settable_ctx_params;
static OSSL_OP_rand_set_ctx_params_fn test_rng_set_ctx_params;
static OSSL_OP_rand_gettable_ctx_params_fn test_rng_gettable_ctx_params;
static OSSL_OP_rand_get_ctx_params_fn test_rng_get_ctx_params;

typedef struct {
    unsigned char *entropy, *nonce;
    size_t entropy_len, entropy_pos, nonce_len, nonce_pos;
} PROV_TEST_RNG;

static int test_rng_new(PROV_DRBG *ctx, int secure)
{
    PROV_TEST_RNG *hash;

    hash = OPENSSL_zalloc(sizeof(*hash));
    if (hash == NULL)
        return 0;
    ctx->data = hash;
    ctx->seedlen = INT_MAX;
    ctx->max_entropylen = INT_MAX;
    ctx->max_noncelen = INT_MAX;
    ctx->max_perslen = INT_MAX;
    ctx->max_adinlen = INT_MAX;
    ctx->max_request = INT_MAX;
    return 1;
}

static void *test_rng_new_wrapper(void *provctx, int secure, void *parent,
                                   const OSSL_DISPATCH *parent_dispatch)
{
    return prov_rand_drbg_new(provctx, secure, parent, parent_dispatch,
                              &test_rng_new);
}

static void test_rng_free(void *vdrbg)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;

    OPENSSL_free(hash->entropy);
    OPENSSL_free(hash->nonce);
    OPENSSL_free(drbg->data);
    prov_rand_drbg_free(drbg);
}

static int test_rng_instantiate(PROV_DRBG *drbg,
                                const unsigned char *ent, size_t ent_len,
                                const unsigned char *nonce, size_t nonce_len,
                                const unsigned char *pstr, size_t pstr_len)
{
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;

    hash->entropy_pos = 0;
    return 1;
}

static int test_rng_instantiate_wrapper(void *vdrbg, int strength,
                                        int prediction_resistance,
                                        const unsigned char *pstr,
                                        size_t pstr_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return PROV_DRBG_instantiate(drbg, strength, prediction_resistance,
                                 pstr, pstr_len, &test_rng_instantiate);
}

static int test_rng_uninstantiate(void *vdrbg)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;

    hash->entropy_pos = hash->nonce_pos = 0;
    return 1;
}

static int test_rng_generate(void *vdrbg,
                              unsigned char *out, size_t outlen,
                              int strength, int prediction_resistance,
                              const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;
    size_t i;
    
    if (hash->entropy == NULL || strength > drbg->strength)
        return 0;
    for (i = 0; i < outlen; i++) {
        out[i] = hash->entropy[hash->entropy_pos++];
        if (hash->entropy_pos >= hash->entropy_len)
            hash->entropy_pos = 0;
    }
    return 1;
}

static int test_rng_reseed(void *vdrbg, int prediction_resistance,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    return 1;
}

static int test_rng_nonce(void *vdrbg, unsigned char *out, size_t outlen)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;
    size_t i;

    if (hash->nonce == NULL)
        return 0;
    for (i = 0; i < outlen; i++) {
        out[i] = hash->nonce[hash->nonce_pos++];
        if (hash->nonce_pos >= hash->nonce_len)
            hash->nonce_pos = 0;
    }
    return 1;
}

static int test_rng_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *test_rng_gettable_ctx_params(void)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DRBG_GETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int test_rng_set_ctx_params(void *vdrbg, const OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *hash = (PROV_TEST_RNG *)drbg->data;
    const OSSL_PARAM *p;
    void *ptr = NULL;
    size_t size = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_get_int(p, &drbg->strength))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_ENTROPY);
    if (p != NULL && !OSSL_PARAM_get_octet_string(p, &ptr, INT_MAX, &size)) {
        OPENSSL_free(hash->entropy);
        hash->entropy = ptr;
        hash->entropy_len = size;
        hash->entropy_pos = 0;
        ptr = NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_NONCE);
    if (p != NULL && !OSSL_PARAM_get_octet_string(p, &ptr, INT_MAX, &size)) {
        OPENSSL_free(hash->entropy);
        hash->nonce = ptr;
        hash->nonce_len = size;
        hash->nonce_pos = 0;
    }

    return drbg_set_ctx_params(drbg, params);
}

static const OSSL_PARAM *test_rng_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_NONCE, NULL, 0),
        OSSL_PARAM_DRBG_SETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH test_rng_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))test_rng_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))test_rng_free },
    { OSSL_FUNC_RAND_INSTANTIATE,
      (void(*)(void))test_rng_instantiate_wrapper },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))test_rng_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))test_rng_generate },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))test_rng_reseed },
    { OSSL_FUNC_RAND_NONCE, (void(*)(void))test_rng_nonce },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))drbg_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))drbg_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))drbg_unlock },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void(*)(void))test_rng_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))test_rng_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void(*)(void))test_rng_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))test_rng_get_ctx_params },
    { 0, NULL }
};
