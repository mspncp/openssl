/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "internal/rand_int.h"
#include <openssl/engine.h>
#include "internal/thread_once.h"
#include "rand_lcl.h"

#ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref;
static CRYPTO_RWLOCK *rand_engine_lock;
#endif
static CRYPTO_RWLOCK *rand_meth_lock;
static const RAND_METHOD *default_RAND_meth;
static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;

int rand_fork_count;

#ifdef OPENSSL_RAND_SEED_RDTSC
/*
 * IMPORTANT NOTE:  It is not currently possible to use this code
 * because we are not sure about the amount of randomness it provides.
 * Some SP900 tests have been run, but there is internal skepticism.
 * So for now this code is not used.
 */
# error "RDTSC enabled?  Should not be possible!"

/*
 * Since we get some randomness from the low-order bits of the
 * high-speec clock, it can help.  But don't return a status since
 * it's not sufficient to indicate whether or not the seeding was
 * done.
 */
void rand_read_tsc(RAND_POOL * pool)
{
    unsigned char c;
    int i;

    if ((OPENSSL_ia32cap_P[0] & (1 << 4)) != 0) {
        for (i = 0; i < TSC_READ_COUNT; i++) {
            c = (unsigned char)(OPENSSL_rdtsc() & 0xFF);
            RAND_POOL_add(pool, &c, 1, 0.5);
        }
    }
}
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(unsigned char *buf, size_t len);

extern unsigned int OPENSSL_ia32cap_P[];

int rand_read_cpu(RAND_POOL *pool)
{
    int bytes_needed;
    unsigned char *buffer;

    bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        buffer = RAND_POOL_add_begin(pool, bytes_needed);

        if (buffer != NULL) {

            /* If RDSEED is available, use that. */
            if ((OPENSSL_ia32cap_P[2] & (1 << 18)) != 0) {
                if (OPENSSL_ia32_rdseed_bytes(buffer, bytes_needed) == bytes_needed)
                    return RAND_POOL_add_end(pool, bytes_needed, bytes_needed);
            }

            /* Second choice is RDRAND. */
            if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
                if (OPENSSL_ia32_rdrand_bytes(buffer, bytes_needed) == bytes_needed)
                    return RAND_POOL_add_end(pool, bytes_needed, bytes_needed);
            }
        }
    }

    return RAND_POOL_entropy_available(pool);
}
#endif


/*
 * DRBG has two sets of callbacks; we only discuss the "entropy" one
 * here.  When the DRBG needs additional entropy, it calls the 
 * get_entropy callback which allocates a buffer, stores its address 
 * in *pount and returns the number of bytes. 
 * When the DRBG is finished with
 * the buffer, it calls the cleanup_entropy callback, with the value of
 * the buffer that the get_entropy callback filled in.
 */


/*
 * Implements the get_entropy() callback
 *
 * If the DRBG has a parent, then the required amount of entropy input
 * is fetched using the parent's RAND_DRBG_generate().
 *
 * Otherwise, the entropy is polled from the system entropy sources.
 * Previously, this used to be done by calling RAND_poll().
 * Nowadays, both RAND_poll() and drbg_get_entropy() are based on 
 * the RAND_POOL API, i.e., the entropy is aqcuired by RAND_POOL_fill().
 */
size_t drbg_get_entropy(RAND_DRBG *drbg,
                        unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    int bytes = 0;
    size_t ret = 0;
    int entropy_available = 0;

    RAND_POOL* pool = RAND_POOL_new(entropy, min_len, max_len);
    
    if (drbg->parent) {
        int bytes_needed = RAND_POOL_bytes_needed(pool, 8);
        unsigned char *buf = RAND_POOL_add_begin(pool, bytes_needed);

        if (buf != NULL) {
            /* Get entropy from parent, include our state as additional input. */
            bytes = RAND_DRBG_generate(drbg->parent,
                                    buf, bytes_needed,
                                    0,
                                    (unsigned char *)drbg, sizeof(*drbg));

            if (bytes)
                bytes = bytes_needed;
            
            entropy_available = RAND_POOL_add_end(pool, bytes, bytes);
        }

    } else {
        /* Get entropy by polling system entropy sources. */
        entropy_available = RAND_POOL_fill(pool);
    }

    if (entropy_available > 0) {
        *pout = RAND_POOL_detach(pool);
        ret   = RAND_POOL_length(pool);
    }
    
    RAND_POOL_free(pool);
    return ret;
}


/*
 * Implements the cleanup_entropy() callback
 *
 */
void drbg_cleanup_entropy(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}

void rand_fork()
{
    rand_fork_count++;
}

DEFINE_RUN_ONCE_STATIC(do_rand_init)
{
    int ret = 1;

#ifndef OPENSSL_NO_ENGINE
    rand_engine_lock = CRYPTO_THREAD_glock_new("rand_engine");
    ret &= rand_engine_lock != NULL;
#endif
    rand_meth_lock = CRYPTO_THREAD_glock_new("rand_meth");
    ret &= rand_meth_lock != NULL;

    return ret;
}

void rand_cleanup_int(void)
{
    const RAND_METHOD *meth = default_RAND_meth;

    if (meth != NULL && meth->cleanup != NULL)
        meth->cleanup();
    RAND_set_rand_method(NULL);
#ifndef OPENSSL_NO_ENGINE
    CRYPTO_THREAD_lock_free(rand_engine_lock);
#endif
    CRYPTO_THREAD_lock_free(rand_meth_lock);
}

/*
 * RAND_poll() reseeds the default RNG using random input
 *
 * The random input is obtained from polling various entropy
 * sources which depend on the operating system and are 
 * configurable via the --with-rand-seed configure option.
 */
int RAND_poll(void)
{
    int ret = 0;
    
    RAND_POOL *pool = NULL;

    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth == RAND_OpenSSL()) {
        /* fill random pool and seed the default DRBG */
        RAND_DRBG *drbg = RAND_DRBG_get0_global();
        
        pool = RAND_POOL_new(drbg->strength, 
                             drbg->min_entropylen,
                             drbg->max_entropylen);

        if (RAND_POOL_fill(pool) == 0)
            goto err;
            
        if (RAND_DRBG_reseed(drbg,
                RAND_POOL_buffer(pool),
                RAND_POOL_length(pool)) == 0)
            goto err;

    } else {
        /* fill random pool and seed the current legacy RNG */
        pool = RAND_POOL_new(RAND_DRBG_STRENGTH,
                             RAND_DRBG_STRENGTH/8,
                             RAND_DRBG_STRENGTH/8);
            
        if (RAND_POOL_fill(pool) == 0)
            goto err;

        if (meth->add == NULL ||
            meth->add(
                RAND_POOL_buffer(pool),
                RAND_POOL_length(pool),
                (RAND_POOL_entropy(pool)/8.0)) == 0)
            goto err;
    }

    ret = 1;

err:
    RAND_POOL_free(pool);
    return ret;

}

/*
 * The 'random pool' acts as a dumb container for collecting random
 * input from various entropy sources. The pool has no knowledge about
 * whether its randomness is fed into a legacy RAND_METHOD via RAND_add() 
 * or into a new style RAND_DRBG. It is the callers duty to 1) initialize the 
 * random pool, 2) pass it to the the polling callbacks, 3) seed the RNG,
 * and 4) cleanup the random pool again.
 * 
 * The random pool contains no locking mechanism because it's scope and 
 * lifetime is intended to be restricted to a single stack frame.
 */
typedef struct rand_pool_st {
    unsigned char *buffer;

    size_t len;
    size_t min_len;
    size_t max_len;

    int entropy;
    int requested_entropy;

    size_t reserved_len;
} RAND_POOL;

/*
 * Allocate memory and initialize a new random pool
 */

RAND_POOL *RAND_POOL_new(int entropy, size_t min_len, size_t max_len)
{
    RAND_POOL *pool = OPENSSL_zalloc(sizeof(*pool));

    if (pool == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    pool->len = 0;
    pool->min_len = min_len;
    pool->max_len = max_len;

    pool->buffer = OPENSSL_secure_zalloc(pool->max_len);
    
    if (pool->buffer == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pool->entropy = 0;
    pool->requested_entropy = entropy;

    pool->reserved_len = 0;
    
    return pool;

err:
    OPENSSL_free(pool);
    return NULL;
}

/*
 * Uninstantiate |pool| and free all memory. If |pout| != NULL,
 * return the pool data to the caller 
 */
void RAND_POOL_free(RAND_POOL *pool)
{
    if (pool == NULL)
        return;
    
    OPENSSL_secure_clear_free(pool->buffer, pool->max_len);
    OPENSSL_free(pool);
}

/*
 * Return the |pool|'s buffer to the caller (readonly).
 */
const unsigned char *RAND_POOL_buffer(RAND_POOL *pool)
{
    return pool->buffer;
}

/*
 * Return the |pool|'s entropy to the caller.
 */
int RAND_POOL_entropy(RAND_POOL *pool)
{
    return pool->entropy;
}

/*
 * Return the |pool|'s buffer length to the caller.
 */
size_t RAND_POOL_length(RAND_POOL *pool)
{
    return pool->len;
}

/*
 * Detach the |pool| buffer and return it to the caller.
 * It's the responsibility of the caller to free the buffer
 * using OPENSSL_secure_free().
 */
unsigned char *RAND_POOL_detach(RAND_POOL *pool)
{
    unsigned char * ret = pool->buffer;
    pool->buffer = NULL;
    return ret;
}


/*
 * If every byte of the input contains |entropy_per_bytes| bits of entropy,
 * how many bytes does one need to obtain at least |bits| bits of entropy?
 */
#define ENTROPY_TO_BYTES(bits, entropy_per_bytes) \
    (((bits) + (entropy_per_bytes - 1))/(entropy_per_bytes))


/*
 * Checks whether the |pool|'s entropy is available to the caller.
 * This is the case when entropy count and buffer length are high enough.
 * Returns
 *
 *  |entropy|  if the entropy count and buffer size is large enough
 *      0      otherwise
 *     -1      on error 
 */
int RAND_POOL_entropy_available(RAND_POOL *pool)
{
    if (pool == NULL)
        return -1;

    if (pool->entropy < pool->requested_entropy)
        return 0;

    if (pool->len < pool->min_len)
        return 0;

    return pool->entropy;
}

/*
 * Returns the (remaining) amount of entropy needed to fill
 * the random pool.
 *
 * If an error occurs, -1 is returned.
 */

int RAND_POOL_entropy_needed(RAND_POOL *pool)
{
    if (pool == NULL)
        return -1;

    if (pool->entropy < pool->requested_entropy)
        return pool->requested_entropy - pool->entropy;
    
    return 0;
}

/*
 * Returns the remaining number of bytes available
 *
 * If an error occurs, -1 is returned.
 */

int RAND_POOL_bytes_remaining(RAND_POOL *pool)
{
    if (pool == NULL)
        return -1;
    return pool->max_len - pool->len;
}

/*
 * Returns the number of bytes needed to fill the pool, assuming
 * the input has 'entropy_per_byte' entropy bits per byte.
 *
 * If an error occurs, -1 is returned.
 */

int RAND_POOL_bytes_needed(RAND_POOL *pool, int entropy_per_byte)
{
    int bytes_needed;
    
    int entropy_needed = RAND_POOL_entropy_needed(pool);
        
    if (entropy_needed < 0 || entropy_per_byte <= 0)
        return -1;

    bytes_needed = ENTROPY_TO_BYTES(entropy_needed, entropy_per_byte);

    if (bytes_needed > pool->max_len - pool->len)
        return -1; /* not enough space left */
    else if (bytes_needed < pool->min_len - pool->len)
        bytes_needed = pool->min_len - pool->len; /* to meet the min_len requirement */
    
    return bytes_needed;
}

/*
 * Add the contents of the |buffer| to the random pool.
 * Return available amount of entropy after this operation.
 * (see RAND_POOL_entropy_available(pool))
 */
int RAND_POOL_add(RAND_POOL *pool, const void *buffer, int num, double randomness)
{
    size_t len  = (size_t)num;
    int entropy = (int)(randomness * 8.0);

    if (pool->len + len > pool->max_len) {
        RANDerr(RAND_F_RAND_POOL_ADD, RAND_R_SIZE_OUT_OF_RANGE);
        return -1;
    }

    if (len > 0) {
        memcpy(pool->buffer + pool->len, buffer, len);
        pool->len += len;
        pool->entropy += entropy;
    }

    return RAND_POOL_entropy_available(pool);
}

/*
 * Add the contents of the |buffer| to the random pool in-place.
 * Return available amount of entropy after this operation.
 * (see RAND_POOL_entropy_available(pool))
 *
 * RAND_POOL_add_begin() reserves the next |num| bytes for adding 
 * randomness in-place and returns a pointer to the buffer. It
 * is allowed to copy up to |num| bytes into the buffer.
 *
 * RAND_POOL_add_end() is called after updating the buffer. The 
 * |num| argument specifies the number of bytes updated. It is 
 * to allowed to update less bytes than originally reserved
 *
 *     unsigned char *buffer = RAND_POOL_add_begin(pool, num);
 *     if (buf != NULL) {
 *        n = getrandom(buffer, bytes, 0);
 *        RAND_POOL_add_end(pool, n, n);
 *     }
 */
unsigned char * RAND_POOL_add_begin(RAND_POOL *pool, int num)
{
    size_t len  = (size_t)num;

    if (pool->reserved_len != 0) {
        RANDerr(RAND_F_RAND_POOL_ADD_BEGIN, RAND_R_NESTED_GROUP);
        return NULL;
    }

    if (pool->len + len > pool->max_len) {
        RANDerr(RAND_F_RAND_POOL_ADD_BEGIN, RAND_R_SIZE_OUT_OF_RANGE);
        return NULL;
    }

    pool->reserved_len = len;

    return pool->buffer + pool->len;
}

int RAND_POOL_add_end(RAND_POOL *pool, int num, double randomness)
{
    size_t len  = (size_t)num;
    int entropy = (int)(randomness * 8.0);

    if (pool->reserved_len == 0) {
        RANDerr(RAND_F_RAND_POOL_ADD_END, RAND_R_NO_GROUP);
        return -1;
    }

    if (len > pool->reserved_len) {
        RANDerr(RAND_F_RAND_POOL_ADD_END, RAND_R_SIZE_OUT_OF_RANGE);
        return -1;
    }

    if (len > 0) {
        pool->len += len;
        pool->entropy += entropy;
    }

    pool->reserved_len = 0;

    return RAND_POOL_entropy_available(pool);
}


    

int RAND_set_rand_method(const RAND_METHOD *meth)
{
    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(funct_ref);
    funct_ref = NULL;
#endif
    default_RAND_meth = meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return 1;
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return NULL;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
    if (default_RAND_meth == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e;

        /* If we have an engine that can do RAND, use it. */
        if ((e = ENGINE_get_default_RAND()) != NULL
                && (tmp_meth = ENGINE_get_RAND(e)) != NULL) {
            funct_ref = e;
            default_RAND_meth = tmp_meth;
        } else {
            ENGINE_finish(e);
            default_RAND_meth = &rand_meth;
        }
#else
        default_RAND_meth = &rand_meth;
#endif
    }
    tmp_meth = default_RAND_meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return tmp_meth;
}

#ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine)
{
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    if (engine != NULL) {
        if (!ENGINE_init(engine))
            return 0;
        tmp_meth = ENGINE_get_RAND(engine);
        if (tmp_meth == NULL) {
            ENGINE_finish(engine);
            return 0;
        }
    }
    CRYPTO_THREAD_write_lock(rand_engine_lock);
    /* This function releases any prior ENGINE so call it first */
    RAND_set_rand_method(tmp_meth);
    funct_ref = engine;
    CRYPTO_THREAD_unlock(rand_engine_lock);
    return 1;
}
#endif

void RAND_seed(const void *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->seed != NULL)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double randomness)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->add != NULL)
        meth->add(buf, num, randomness);
}

/*
 * This function is not part of RAND_METHOD, so if we're not using
 * the default method, then just call RAND_bytes().  Otherwise make
 * sure we're instantiated and use the private DRBG.
 */
int RAND_priv_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    RAND_DRBG *drbg;

    if (meth != RAND_OpenSSL())
        return RAND_bytes(buf, num);

    drbg = RAND_DRBG_get0_priv_global();
    if (drbg == NULL)
        return 0;

    return RAND_DRBG_generate(drbg, buf, num, 0, NULL, 0);
}

int RAND_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->bytes != NULL)
        return meth->bytes(buf, num);
    RANDerr(RAND_F_RAND_BYTES, RAND_R_FUNC_NOT_IMPLEMENTED);
    return -1;
}

#if OPENSSL_API_COMPAT < 0x10100000L
int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->pseudorand != NULL)
        return meth->pseudorand(buf, num);
    return -1;
}
#endif

int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->status != NULL)
        return meth->status();
    return 0;
}
