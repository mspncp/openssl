/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "crypto/evp.h"
#include "crypto/dh.h"
#include "dh_local.h"

static DH *dh_new_intern(ENGINE *engine, OSSL_LIB_CTX *libctx);

#ifndef FIPS_MODULE
int DH_set_method(DH *dh, const DH_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DH_METHOD *mtmp;
    mtmp = dh->meth;
    if (mtmp->finish)
        mtmp->finish(dh);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(dh->engine);
    dh->engine = NULL;
#endif
    dh->meth = meth;
    if (meth->init)
        meth->init(dh);
    return 1;
}

const DH_METHOD *dh_get_method(const DH *dh)
{
    return dh->meth;
}

DH *DH_new(void)
{
    return dh_new_intern(NULL, NULL);
}

DH *DH_new_method(ENGINE *engine)
{
    return dh_new_intern(engine, NULL);
}
#endif /* !FIPS_MODULE */

DH *dh_new_with_libctx(OSSL_LIB_CTX *libctx)
{
    return dh_new_intern(NULL, libctx);
}

static DH *dh_new_intern(ENGINE *engine, OSSL_LIB_CTX *libctx)
{
    DH *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->libctx = libctx;
    ret->meth = DH_get_default_method();
#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)
    ret->flags = ret->meth->flags;  /* early default init */
    if (engine) {
        if (!ENGINE_init(engine)) {
            DHerr(0, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DH();
    if (ret->engine) {
        ret->meth = ENGINE_get_DH(ret->engine);
        if (ret->meth == NULL) {
            DHerr(0, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags;

#ifndef FIPS_MODULE
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data))
        goto err;
#endif /* FIPS_MODULE */

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DHerr(0, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    DH_free(ret);
    return NULL;
}

void DH_free(DH *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("DH", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#if !defined(FIPS_MODULE)
# if !defined(OPENSSL_NO_ENGINE)
    ENGINE_finish(r->engine);
# endif
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);
#endif

    CRYPTO_THREAD_lock_free(r->lock);

    ffc_params_cleanup(&r->params);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

int DH_up_ref(DH *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DH", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

#ifndef FIPS_MODULE
int DH_set_ex_data(DH *d, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *DH_get_ex_data(const DH *d, int idx)
{
    return CRYPTO_get_ex_data(&d->ex_data, idx);
}
#endif

int DH_bits(const DH *dh)
{
    return BN_num_bits(dh->params.p);
}

int DH_size(const DH *dh)
{
    return BN_num_bytes(dh->params.p);
}

int DH_security_bits(const DH *dh)
{
    int N;
    if (dh->params.q != NULL)
        N = BN_num_bits(dh->params.q);
    else if (dh->length)
        N = dh->length;
    else
        N = -1;
    return BN_security_bits(BN_num_bits(dh->params.p), N);
}

void DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    ffc_params_get0_pqg(&dh->params, p, q, g);
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /*
     * If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->params.p == NULL && p == NULL)
        || (dh->params.g == NULL && g == NULL))
        return 0;

    ffc_params_set0_pqg(&dh->params, p, q, g);
    dh_cache_named_group(dh);
    if (q != NULL)
        dh->length = BN_num_bits(q);
    /*
     * Check if this is a named group. If it finds a named group then the
     * 'q' and 'length' value are either already set or are set by the
     * call.
     */
    if (DH_get_nid(dh) == NID_undef) {
        /* If its not a named group then set the 'length' if q is not NULL */
        if (q != NULL)
            dh->length = BN_num_bits(q);
    }
    dh->dirty_cnt++;
    return 1;
}

long DH_get_length(const DH *dh)
{
    return dh->length;
}

int DH_set_length(DH *dh, long length)
{
    dh->length = length;
    return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (pub_key != NULL) {
        BN_clear_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_clear_free(dh->priv_key);
        dh->priv_key = priv_key;
        dh->length = BN_num_bits(priv_key);
    }

    dh->dirty_cnt++;
    return 1;
}

const BIGNUM *DH_get0_p(const DH *dh)
{
    return dh->params.p;
}

const BIGNUM *DH_get0_q(const DH *dh)
{
    return dh->params.q;
}

const BIGNUM *DH_get0_g(const DH *dh)
{
    return dh->params.g;
}

const BIGNUM *DH_get0_priv_key(const DH *dh)
{
    return dh->priv_key;
}

const BIGNUM *DH_get0_pub_key(const DH *dh)
{
    return dh->pub_key;
}

void DH_clear_flags(DH *dh, int flags)
{
    dh->flags &= ~flags;
}

int DH_test_flags(const DH *dh, int flags)
{
    return dh->flags & flags;
}

void DH_set_flags(DH *dh, int flags)
{
    dh->flags |= flags;
}

#ifndef FIPS_MODULE
ENGINE *DH_get0_engine(DH *dh)
{
    return dh->engine;
}
#endif /*FIPS_MODULE */

FFC_PARAMS *dh_get0_params(DH *dh)
{
    return &dh->params;
}
int dh_get0_nid(const DH *dh)
{
    return dh->params.nid;
}

int dh_ffc_params_fromdata(DH *dh, const OSSL_PARAM params[])
{
    int ret;
    FFC_PARAMS *ffc;

    if (dh == NULL)
        return 0;
    ffc = dh_get0_params(dh);
    if (ffc == NULL)
        return 0;

    ret = ffc_params_fromdata(ffc, params);
    if (ret) {
        dh_cache_named_group(dh);
        dh->dirty_cnt++;
    }
    return ret;
}
