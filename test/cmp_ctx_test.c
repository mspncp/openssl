/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP tests by Tobias Pankert, Andreas Kretschmer, and David von Oheimb.
 */

#include "cmp_testlib.h"

#include <openssl/x509_vfy.h>

typedef struct test_fixture {
    const char *test_case_name;
    OSSL_CMP_CTX *ctx;
} OSSL_CMP_CTX_TEST_FIXTURE;

static void tear_down(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    if (fixture != NULL)
        OSSL_CMP_CTX_free(fixture->ctx);
    OPENSSL_free(fixture);
}

static OSSL_CMP_CTX_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    OSSL_CMP_CTX_TEST_FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture)))
            || !TEST_ptr(fixture->ctx = OSSL_CMP_CTX_new())) {
        tear_down(fixture);
        return NULL;
    }
    fixture->test_case_name = test_case_name;
    return fixture;
}

static STACK_OF(X509) *sk_X509_new_1(void) {
    STACK_OF(X509) *sk = sk_X509_new_null();
    X509 *x = X509_new();

    if (x == NULL || !sk_X509_push(sk, x)) {
        sk_X509_free(sk);
        X509_free(x);
        sk = NULL;
    }
    return sk;
}

static void sk_X509_pop_X509_free(STACK_OF(X509) *sk) {
    sk_X509_pop_free(sk, X509_free);
}

static int execute_CTX_reinit_test(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    OSSL_CMP_CTX *ctx = fixture->ctx;
    ASN1_OCTET_STRING *bytes = NULL;
    STACK_OF(X509) *certs = NULL;
    int res = 0;

    /* set non-default values in all relevant fields */
    ctx->status = 1;
    ctx->failInfoCode = 1;
    if (!ossl_cmp_ctx_set0_statusString(ctx, sk_ASN1_UTF8STRING_new_null())
            || !ossl_cmp_ctx_set0_newCert(ctx, X509_new())
            || !TEST_ptr(certs = sk_X509_new_1())
            || !ossl_cmp_ctx_set1_caPubs(ctx, certs)
            || !ossl_cmp_ctx_set1_extraCertsIn(ctx, certs)
            || !ossl_cmp_ctx_set0_validatedSrvCert(ctx, X509_new())
            || !TEST_ptr(bytes = ASN1_OCTET_STRING_new())
            || !OSSL_CMP_CTX_set1_transactionID(ctx, bytes)
            || !OSSL_CMP_CTX_set1_senderNonce(ctx, bytes)
            || !ossl_cmp_ctx_set1_recipNonce(ctx, bytes)
        )
        goto err;

    if (!TEST_true(OSSL_CMP_CTX_reinit(ctx)))
        goto err;

    /* check whether values have been reset to default in all relevant fields */
    if (!TEST_true(ctx->status == -1
                       && ctx->failInfoCode == -1
                       && ctx->statusString == NULL
                       && ctx->newCert == NULL
                       && ctx->caPubs == NULL
                       && ctx->extraCertsIn == NULL
                       && ctx->validatedSrvCert == NULL
                       && ctx->transactionID == NULL
                       && ctx->senderNonce == NULL
                   && ctx->recipNonce == NULL))
        goto err;

    /* this does not check that all remaining fields are untouched */
    res = 1;

 err:
    sk_X509_pop_X509_free(certs);
    ASN1_OCTET_STRING_free(bytes);
    return res;
}

static int test_CTX_reinit(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_CTX_reinit_test, tear_down);
    return result;
}

static int msg_total_size = 0;
static int msg_total_size_log_cb(const char *func, const char *file, int line,
                                 OSSL_CMP_severity level, const char *msg)
{
    msg_total_size += strlen(msg);
    return 1;
}

#define STR64 "This is a 64 bytes looooooooooooooooooooooooooooooooong string.\n"
/* max string length ISO C90 compilers are required to support is 509. */
#define STR509 STR64 STR64 STR64 STR64 STR64 STR64 STR64 \
    "This is a 61 bytes loooooooooooooooooooooooooooooong string.\n"
static const char *const max_str_literal = STR509;
#define STR_SEP "<SEP>"

static int execute_CTX_print_errors_test(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    OSSL_CMP_CTX *ctx = fixture->ctx;
    int trace_enabled = 1;
    int base_err_msg_size, expected_size;
    int res = 1;

#ifdef OPENSSL_NO_TRACE
    trace_enabled = 0;
#endif
    if (!TEST_int_eq(OSSL_CMP_CTX_set_log_cb(ctx, NULL), trace_enabled))
        res = 0;
    if (!TEST_true(ctx->log_cb == NULL))
        res = 0;

#ifndef OPENSSL_NO_STDIO
    CMPerr(0, CMP_R_MULTIPLE_SAN_SOURCES);
    OSSL_CMP_CTX_print_errors(ctx); /* should print above error to STDERR */
#endif

    /* this should work regardless of OPENSSL_NO_STDIO and OPENSSL_NO_TRACE: */
#ifndef OPENSSL_NO_TRACE
    if (!TEST_true(OSSL_CMP_CTX_set_log_cb(ctx, msg_total_size_log_cb)))
        res = 0;
#else
    ctx->log_cb = msg_total_size_log_cb;
#endif
    if (!TEST_true(ctx->log_cb != NULL))
        res = 0;
    else {
        CMPerr(0, CMP_R_INVALID_ARGS);
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        base_err_msg_size = strlen("INVALID_ARGS") + strlen("NULL_ARGUMENT");
        OSSL_CMP_add_error_data("data1"); /* should prepend separator " : " */
        OSSL_CMP_add_error_data("data2"); /* should prepend separator " : " */
        OSSL_CMP_add_error_line("new line"); /* should prepend separator "\n" */
        OSSL_CMP_CTX_print_errors(ctx);
        expected_size = base_err_msg_size + strlen(" : ") +
            strlen("data1") + strlen(" : ""data2") + strlen("\n""new line");
        if (!TEST_int_eq(msg_total_size, expected_size))
            res = 0;

        CMPerr(0, CMP_R_INVALID_ARGS);
        base_err_msg_size = strlen("INVALID_ARGS") + strlen(" : ");
        expected_size = base_err_msg_size;
        while (expected_size < 4096) { /* force split */
            OSSL_CMP_add_error_txt(STR_SEP, max_str_literal);
            expected_size += strlen(max_str_literal) + strlen(STR_SEP);
        }
        expected_size += base_err_msg_size - 2 * strlen(STR_SEP);
        msg_total_size = 0;
        OSSL_CMP_CTX_print_errors(ctx);
#ifdef FIX_9558_merged
        if (!TEST_int_eq(msg_total_size, expected_size))
#else
        if (!TEST_int_le(msg_total_size, expected_size))
#endif
            res = 0;
    }

    return res;
}

static int test_CTX_print_errors(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_CTX_print_errors_test, tear_down);
    return result;
}

static int execute_CTX_reqExtensions_have_SAN_dup_test(
                                             OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    OSSL_CMP_CTX *ctx = fixture->ctx;
    const int len = 16;
    unsigned char str[16 /* = len */ ];
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *ext = NULL;
    X509_EXTENSIONS *exts = NULL;
    int res = 0;

    if (!TEST_false(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)))
        return 0;

    if (!TEST_int_eq(1, RAND_bytes(str, len))
            || !TEST_ptr(data = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(data, str, len)))
        goto err;
    ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_alt_name, 0, data);
    if (!TEST_ptr(ext)
            || !TEST_ptr(exts = sk_X509_EXTENSION_new_null())
            || !TEST_true(sk_X509_EXTENSION_push(exts, ext))
            || !TEST_true(OSSL_CMP_CTX_set0_reqExtensions(ctx, exts))) {
        X509_EXTENSION_free(ext);
        sk_X509_EXTENSION_free(exts);
        goto err;
    }
    if (TEST_true(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx))) {
        X509_EXTENSIONS *exts_copy = ossl_cmp_x509_extensions_dup(exts);

        ext = sk_X509_EXTENSION_pop(exts);
        res = TEST_false(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx));
        X509_EXTENSION_free(ext);
        if (!TEST_true(OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy))
            || !TEST_true(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)))
            res = 0;
    }
 err:
    ASN1_OCTET_STRING_free(data);
    return res;
}

static int test_CTX_reqExtensions_have_SAN_dup(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_CTX_reqExtensions_have_SAN_dup_test, tear_down);
    return result;
}

#ifndef OPENSSL_NO_TRACE
static int test_log_line;
static int test_log_cb_res = 0;
static int test_log_cb(const char *func, const char *file, int line,
                       OSSL_CMP_severity level, const char *msg)
{
    test_log_cb_res =
# ifndef PEDANTIC
        strcmp(func, "execute_cmp_ctx_log_cb_test") == 0 &&
# endif
        (strcmp(file, OPENSSL_FILE) == 0 || strcmp(file, "(no file)") == 0)
        && (line == test_log_line || line == 0)
        && (level == OSSL_CMP_LOG_INFO || level == -1)
        && strcmp(msg, "CMP INFO: ok\n") == 0;
    return 1;
}
#endif

static int execute_cmp_ctx_log_cb_test(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    int res = 1;
#if !defined OPENSSL_NO_TRACE && !defined OPENSSL_NO_STDIO
    OSSL_CMP_CTX *ctx = fixture->ctx;

    OSSL_TRACE(ALL, "this general trace message is not shown by default\n");

    OSSL_CMP_log_open();
    OSSL_CMP_log_open(); /* multiple calls should be harmless */

    if (!TEST_true(OSSL_CMP_CTX_set_log_cb(ctx, NULL))) {
        res = 0;
    } else {
        OSSL_CMP_err("this should be printed as CMP error message");
        OSSL_CMP_warn("this should be printed as CMP warning message");
        OSSL_CMP_debug("this should not be printed");
        TEST_true(OSSL_CMP_CTX_set_log_verbosity(ctx, OSSL_CMP_LOG_DEBUG));
        OSSL_CMP_debug("this should be printed as CMP debug message");
        TEST_true(OSSL_CMP_CTX_set_log_verbosity(ctx, OSSL_CMP_LOG_INFO));
    }
    if (!TEST_true(OSSL_CMP_CTX_set_log_cb(ctx, test_log_cb))) {
        res = 0;
    } else {
        test_log_line = OPENSSL_LINE + 1;
        OSSL_CMP_log2(INFO, "%s%c", "o", 'k');
        if (!TEST_int_eq(test_log_cb_res, 1))
            res = 0;
        OSSL_CMP_CTX_set_log_verbosity(ctx, OSSL_CMP_LOG_ERR);
        test_log_cb_res = -1; /* callback should not be called at all */
        test_log_line = OPENSSL_LINE + 1;
        OSSL_CMP_log2(INFO, "%s%c", "o", 'k');
        if (!TEST_int_eq(test_log_cb_res, -1))
            res = 0;
    }
    OSSL_CMP_log_close();
    OSSL_CMP_log_close(); /* multiple calls should be harmless */
#endif
    return res;
}

static int test_cmp_ctx_log_cb(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_cmp_ctx_log_cb_test, tear_down);
    return result;
}

static BIO *test_http_cb(OSSL_CMP_CTX *ctx, BIO *hbio, unsigned long detail)
{
    return NULL;
}

static int test_transfer_cb(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                            OSSL_CMP_MSG **res)
{
    return 0;
}

static int test_certConf_cb(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info,
                            const char **txt)
{
    return 0;
}

#define set 0
#define set0 0
#define set1 1
#define get 0
#define get0 0
#define get1 1
#define DECLARE_SET_GET_BASE_TEST(SETN, GETN, DUP, FIELD, TYPE, \
                                  ERR, DEFAULT, NEW, FREE) \
static int execute_CTX_##SETN##_##GETN##_##FIELD( \
    OSSL_CMP_CTX_TEST_FIXTURE *fixture) \
{ \
    OSSL_CMP_CTX *ctx = fixture->ctx; \
    int (*set_fn)(OSSL_CMP_CTX *ctx, TYPE) = \
        (int (*)(OSSL_CMP_CTX *ctx, TYPE))OSSL_CMP_CTX_##SETN##_##FIELD; \
 /* need type cast in above assignment because TYPE arg sometimes is const */ \
    TYPE (*get_fn)(const OSSL_CMP_CTX *ctx) = OSSL_CMP_CTX_##GETN##_##FIELD; \
    TYPE val1_to_free = NEW; \
    TYPE val1 = val1_to_free; \
    TYPE val1_read = 0; /* 0 works for any type */ \
    TYPE val2_to_free = NEW; \
    TYPE val2 = val2_to_free; \
    TYPE val2_read = 0; \
    TYPE val3_read = 0; \
    int res = 1; \
    \
    if (!TEST_int_eq(ERR_peek_error(), 0)) \
        res = 0; \
    if ((*set_fn)(NULL, val1) || ERR_peek_error() == 0) { \
        TEST_error("setter did not return error on ctx == NULL"); \
        res = 0; \
    } \
    ERR_clear_error(); \
    \
    if ((*get_fn)(NULL) != ERR || ERR_peek_error() == 0) { \
        TEST_error("getter did not return error on ctx == NULL"); \
        res = 0; \
    } \
    ERR_clear_error(); \
    \
    val1_read = (*get_fn)(ctx); \
    if (!DEFAULT(val1_read)) { \
        TEST_error("did not get default value"); \
        res = 0; \
    } \
    if (!(*set_fn)(ctx, val1)) { \
        TEST_error("setting first value failed"); \
        res = 0; \
    } \
    if (SETN == 0) \
        val1_to_free = 0; /* 0 works for any type */ \
    \
    if (GETN == 1) \
        FREE(val1_read); \
    val1_read = (*get_fn)(ctx); \
    if (SETN == 0) { \
        if (val1_read != val1) { \
            TEST_error("set/get first value did not match"); \
            res = 0; \
        } \
    } else { \
        if (DUP && val1_read == val1) { \
            TEST_error("first set did not dup the value"); \
            res = 0; \
        } \
        if (DEFAULT(val1_read)) { \
            TEST_error("first set had no effect"); \
            res = 0; \
        } \
    } \
    \
    if (!(*set_fn)(ctx, val2)) { \
        TEST_error("setting second value failed"); \
        res = 0; \
    } \
    if (SETN == 0) \
        val2_to_free = 0; \
    \
    val2_read = (*get_fn)(ctx); \
    if (DEFAULT(val2_read)) { \
        TEST_error("second set reset the value"); \
        res = 0; \
    } \
    if (SETN == 0 && GETN == 0) { \
        if (val2_read != val2) { \
            TEST_error("set/get second value did not match"); \
            res = 0; \
        } \
    } else { \
        if (DUP && val2_read == val2) { \
            TEST_error("second set did not dup the value"); \
            res = 0; \
        } \
        if (val2 == val1) { \
            TEST_error("second value is same as first value"); \
            res = 0; \
        } \
        if (GETN == 1 && val2_read == val1_read) { \
            /* \
             * Note that if GETN == 0 then possibly val2_read == val1_read \
             * because set1 may allocate the new copy at the same location. \
             */ \
            TEST_error("second get returned same as first get"); \
            res = 0; \
        } \
    } \
    \
    val3_read = (*get_fn)(ctx); \
    if (DEFAULT(val3_read)) { \
        TEST_error("third set reset the value"); \
        res = 0; \
    } \
    if (GETN == 0) { \
        if (val3_read != val2_read) { \
            TEST_error("third get gave different value"); \
            res = 0; \
        } \
    } else  { \
        if (DUP && val3_read == val2_read) { \
            TEST_error("third get did not create a new dup"); \
            res = 0; \
        } \
    } \
    /* this does not check that all remaining fields are untouched */ \
    \
    if (!TEST_int_eq(ERR_peek_error(), 0)) \
        res = 0; \
    \
    FREE(val1_to_free); \
    FREE(val2_to_free); \
    if (GETN == 1) { \
        FREE(val1_read); \
        FREE(val2_read); \
        FREE(val3_read); \
    } \
    return TEST_true(res); \
} \
\
static int test_CTX_##SETN##_##GETN##_##FIELD(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_##SETN##_##GETN##_##FIELD, tear_down); \
    return result; \
} \

static char *char_new(void) {
    return OPENSSL_strdup("test");
}

static void char_free(char *val) {
    OPENSSL_free(val);
}

#define EMPTY_STR(x) ((x) == NULL || strlen(x) == 0)

#define EMPTY_SK_X509(x) ((x) == NULL || sk_X509_num(x) == 0)

static X509_STORE *X509_STORE_new_1(void) {
    X509_STORE *store = X509_STORE_new();

    if (store != NULL)
        X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store), 1);
    return store;
}

#define DEFAULT_STORE(x) ((x) == NULL \
    || X509_VERIFY_PARAM_get_flags(X509_STORE_get0_param(x)) == 0)

#define IS_NEG(x) ((x) < 0)
#define IS_0(x) ((x) == 0) /* for any type */
#define IS_DEFAULT_PORT(x) ((x) == OSSL_CMP_DEFAULT_PORT)
#define DROP(x) (void)(x) /* dummy free() for non-pointer and function types */

#define ERR(x) (CMPerr(0, CMP_R_NULL_ARGUMENT), x)

#define DECLARE_SET_GET_TEST(N, M, DUP, FIELD, TYPE) \
    DECLARE_SET_GET_BASE_TEST(set##N, get##M, DUP, FIELD, TYPE*, \
                              NULL, IS_0, TYPE##_new(), TYPE##_free)

#define DECLARE_SET_GET_SK_TEST_DEFAULT(N, M, FIELD, ELEM_TYPE, \
                                        DEFAULT, NEW, FREE) \
    DECLARE_SET_GET_BASE_TEST(set##N, get##M, 1, FIELD, \
                              STACK_OF(ELEM_TYPE)*, NULL, DEFAULT, NEW, FREE)
#define DECLARE_SET_GET_SK_TEST(N, M, FIELD, T) \
    DECLARE_SET_GET_SK_TEST_DEFAULT(N, M, FIELD, T, \
                                    IS_0, sk_##T##_new_null(), sk_##T##_free)
#define DECLARE_SET_GET_SK_X509_TEST(N, M, FNAME) \
    DECLARE_SET_GET_SK_TEST_DEFAULT(N, M, FNAME, X509, EMPTY_SK_X509, \
                                    sk_X509_new_1(), sk_X509_pop_X509_free)

#define DECLARE_SET_GET_TEST_DEFAULT(N, M, DUP, FIELD, TYPE, DEFAULT) \
    DECLARE_SET_GET_BASE_TEST(set##N, get##M, DUP, FIELD, TYPE*, \
                              NULL, DEFAULT, TYPE##_new(), TYPE##_free)
#define DECLARE_SET_TEST_DEFAULT(N, DUP, FIELD, TYPE, DEFAULT) \
    static TYPE *OSSL_CMP_CTX_get0_##FIELD(const OSSL_CMP_CTX *ctx) \
    { \
        return ctx == NULL ? ERR(NULL) : ctx->FIELD; \
    } \
    DECLARE_SET_GET_TEST_DEFAULT(N, 0, DUP, FIELD, TYPE, DEFAULT)
#define DECLARE_SET_TEST(N, DUP, FIELD, TYPE) \
    DECLARE_SET_TEST_DEFAULT(N, DUP, FIELD, TYPE, IS_0)

#define DECLARE_SET_SK_TEST(N, FIELD, TYPE) \
    static STACK_OF(TYPE) *OSSL_CMP_CTX_get0_##FIELD(const OSSL_CMP_CTX *ctx) \
    { \
        return ctx == NULL ? ERR(NULL) : ctx->FIELD; \
    } \
    DECLARE_SET_GET_BASE_TEST(set##N, get0, 1, FIELD, STACK_OF(TYPE)*, \
                              NULL, IS_0, sk_##TYPE##_new_null(), \
                              sk_##TYPE##_free)

#define DECLARE_SET_CB_TEST(FIELD) \
    static OSSL_cmp_##FIELD##_t \
        OSSL_CMP_CTX_get_##FIELD(const OSSL_CMP_CTX *ctx) \
    { \
        if (ctx == NULL) \
            CMPerr(0, CMP_R_NULL_ARGUMENT); \
        return ctx == NULL ? NULL /* cannot use ERR(NULL) here */ : ctx->FIELD;\
    } \
    DECLARE_SET_GET_BASE_TEST(set, get, 0, FIELD, OSSL_cmp_##FIELD##_t, \
                              NULL, IS_0, test_##FIELD, DROP)
#define DECLARE_SET_GET_P_VOID_TEST(FIELD) \
    DECLARE_SET_GET_BASE_TEST(set, get, 0, FIELD, void*, \
                              NULL, IS_0, ((void *)1), DROP)

#define DECLARE_SET_GET_INT_TEST_DEFAULT(FIELD, DEFAULT) \
    DECLARE_SET_GET_BASE_TEST(set, get, 0, FIELD, int, -1, DEFAULT, 1, DROP)
#define DECLARE_SET_GET_INT_TEST(FIELD) \
    DECLARE_SET_GET_INT_TEST_DEFAULT(FIELD, IS_NEG)
#define DECLARE_SET_PORT_TEST(FIELD) \
    static int OSSL_CMP_CTX_get_##FIELD(const OSSL_CMP_CTX *ctx) \
    { \
        return ctx == NULL ? ERR(-1) : ctx->FIELD; \
    } \
    DECLARE_SET_GET_INT_TEST_DEFAULT(FIELD, IS_DEFAULT_PORT)

#define DECLARE_SET_GET_ARG_FN(SETN, GETN, FIELD, ARG, T) \
    static int OSSL_CMP_CTX_##SETN##_##FIELD##_##ARG(OSSL_CMP_CTX *ctx, T val) \
    { \
        return OSSL_CMP_CTX_##SETN##_##FIELD(ctx, ARG, val); \
    } \
    \
    static T OSSL_CMP_CTX_##GETN##_##FIELD##_##ARG(const OSSL_CMP_CTX *ctx) \
    { \
        return OSSL_CMP_CTX_##GETN##_##FIELD(ctx, ARG); \
    }

#define DECLARE_SET_GET1_STR_FN(SETN, FIELD) \
    static int OSSL_CMP_CTX_##SETN##_##FIELD##_str(OSSL_CMP_CTX *ctx, char *val)\
    { \
        return OSSL_CMP_CTX_##SETN##_##FIELD(ctx, (unsigned char *)val, \
                                            strlen(val)); \
    } \
    \
    static char *OSSL_CMP_CTX_get1_##FIELD##_str(const OSSL_CMP_CTX *ctx) \
    { \
        const ASN1_OCTET_STRING *bytes = ctx == NULL ? ERR(NULL) : ctx->FIELD; \
        \
        return bytes == NULL ? NULL : \
            OPENSSL_strndup((char *)bytes->data, bytes->length); \
    }

#define push 0
#define push0 0
#define push1 1
#define DECLARE_PUSH_BASE_TEST(PUSHN, DUP, FIELD, ELEM, TYPE, T, \
                               DEFAULT, NEW, FREE) \
static TYPE sk_top_##FIELD(const OSSL_CMP_CTX *ctx) { \
    return sk_##T##_value(ctx->FIELD, sk_##T##_num(ctx->FIELD) - 1); \
} \
\
static int execute_CTX_##PUSHN##_##ELEM(OSSL_CMP_CTX_TEST_FIXTURE *fixture) \
{ \
    OSSL_CMP_CTX *ctx = fixture->ctx; \
    int (*push_fn)(OSSL_CMP_CTX *ctx, TYPE) = \
        (int (*)(OSSL_CMP_CTX *ctx, TYPE))OSSL_CMP_CTX_##PUSHN##_##ELEM; \
 /* need type cast in above assignment because TYPE arg sometimes is const */ \
    int n_elem = sk_##T##_num(ctx->FIELD); \
    STACK_OF(TYPE) field_read; \
    TYPE val1_to_free = NEW; \
    TYPE val1 = val1_to_free; \
    TYPE val1_read = 0; /* 0 works for any type */ \
    TYPE val2_to_free = NEW; \
    TYPE val2 = val2_to_free; \
    TYPE val2_read = 0; \
    int res = 1; \
    \
    if (!TEST_int_eq(ERR_peek_error(), 0)) \
        res = 0; \
    if ((*push_fn)(NULL, val1) || ERR_peek_error() == 0) { \
        TEST_error("pusher did not return error on ctx == NULL"); \
        res = 0; \
    } \
    ERR_clear_error(); \
    \
    if (n_elem < 0) /* can happen for NULL stack */ \
        n_elem = 0; \
    field_read = ctx->FIELD; \
    if (!DEFAULT(field_read)) { \
        TEST_error("did not get default value for stack field"); \
        res = 0; \
    } \
    if (!(*push_fn)(ctx, val1)) { \
        TEST_error("pushing first value failed"); \
        res = 0; \
    } \
    if (PUSHN == 0) \
        val1_to_free = 0; /* 0 works for any type */ \
    \
    if (sk_##T##_num(ctx->FIELD) != ++n_elem) { \
        TEST_error("pushing first value did not increment number"); \
        res = 0; \
    } \
    val1_read = sk_top_##FIELD(ctx); \
    if (PUSHN == 0) { \
        if (val1_read != val1) { \
            TEST_error("push/sk_top first value did not match"); \
            res = 0; \
        } \
    } else { \
        if (DUP && val1_read == val1) { \
            TEST_error("first push did not dup the value"); \
            res = 0; \
        } \
    } \
    \
    if (!(*push_fn)(ctx, val2)) { \
        TEST_error("pushting second value failed"); \
        res = 0; \
    } \
    if (PUSHN == 0) \
        val2_to_free = 0; \
    \
    if (sk_##T##_num(ctx->FIELD) != ++n_elem) { \
        TEST_error("pushing second value did not increment number"); \
        res = 0; \
    } \
    val2_read = sk_top_##FIELD(ctx); \
    if (PUSHN == 0) { \
        if (val2_read != val2) { \
            TEST_error("push/sk_top second value did not match"); \
            res = 0; \
        } \
    } else { \
        if (DUP && val2_read == val2) { \
            TEST_error("second push did not dup the value"); \
            res = 0; \
        } \
        if (val2 == val1) { \
            TEST_error("second value is same as first value"); \
            res = 0; \
        } \
    } \
    /* this does not check that all remaining fields and elems are untouched */\
    \
    if (!TEST_int_eq(ERR_peek_error(), 0)) \
        res = 0; \
    \
    FREE(val1_to_free); \
    FREE(val2_to_free); \
    return TEST_true(res); \
} \
\
static int test_CTX_##PUSHN##_##ELEM(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_##PUSHN##_##ELEM, tear_down); \
    return result; \
} \

#define DECLARE_PUSH_TEST(N, DUP, FIELD, ELEM, TYPE) \
    DECLARE_PUSH_BASE_TEST(push##N, DUP, FIELD, ELEM, TYPE*, TYPE, \
                           IS_0, TYPE##_new(), TYPE##_free)

void cleanup_tests(void)
{
    return;
}

DECLARE_SET_GET_ARG_FN(set, get, option, 16, int)
                                    /* option == OSSL_CMP_OPT_IGNORE_KEYUSAGE */
DECLARE_SET_GET_BASE_TEST(set, get, 0, option_16, int, -1, IS_0, 1 /* true */, DROP)

#ifndef OPENSSL_NO_TRACE
DECLARE_SET_CB_TEST(log_cb)
#endif

DECLARE_SET_TEST_DEFAULT(1, 1, serverPath, char, EMPTY_STR)
DECLARE_SET_TEST(1, 1, serverName, char)
DECLARE_SET_PORT_TEST(serverPort)
DECLARE_SET_TEST(1, 1, proxyName, char)
DECLARE_SET_PORT_TEST(proxyPort)
DECLARE_SET_CB_TEST(http_cb)
DECLARE_SET_GET_P_VOID_TEST(http_cb_arg)
DECLARE_SET_CB_TEST(transfer_cb)
DECLARE_SET_GET_P_VOID_TEST(transfer_cb_arg)

DECLARE_SET_TEST(1, 0, srvCert, X509)
#define OSSL_CMP_CTX_set0_validatedSrvCert ossl_cmp_ctx_set0_validatedSrvCert
DECLARE_SET_TEST(0, 0, validatedSrvCert, X509)
DECLARE_SET_TEST(1, 1, expected_sender, X509_NAME)
DECLARE_SET_GET_BASE_TEST(set0, get0, 0, trustedStore, X509_STORE*, NULL,
                          DEFAULT_STORE, X509_STORE_new_1(), X509_STORE_free)
DECLARE_SET_GET_SK_X509_TEST(1, 0, untrusted_certs)

DECLARE_SET_TEST(1, 0, clCert, X509)
DECLARE_SET_TEST(0, 0, pkey, EVP_PKEY)
DECLARE_SET_GET_TEST(1, 0, 0, pkey, EVP_PKEY)

DECLARE_SET_TEST(1, 1, recipient, X509_NAME)
DECLARE_PUSH_TEST(0, 0, geninfo_ITAVs, geninfo_ITAV, OSSL_CMP_ITAV)
DECLARE_SET_SK_TEST(1, extraCertsOut, X509)
DECLARE_PUSH_TEST(1, 0, extraCertsOut, extraCertsOut, X509)
DECLARE_SET_GET_ARG_FN(set0, get0, newPkey, 1, EVP_PKEY*) /* priv == 1 */
DECLARE_SET_GET_TEST(0, 0, 0, newPkey_1, EVP_PKEY)
DECLARE_SET_GET_ARG_FN(set1, get0, newPkey, 0, EVP_PKEY*) /* priv == 0 */
DECLARE_SET_GET_TEST(1, 0, 0, newPkey_0, EVP_PKEY)
DECLARE_SET_GET1_STR_FN(set1, referenceValue)
DECLARE_SET_GET_TEST_DEFAULT(1, 1, 1, referenceValue_str, char, IS_0)
DECLARE_SET_GET1_STR_FN(set1, secretValue)
DECLARE_SET_GET_TEST_DEFAULT(1, 1, 1, secretValue_str, char, IS_0)
DECLARE_SET_TEST(1, 1, issuer, X509_NAME)
DECLARE_SET_TEST(1, 1, subjectName, X509_NAME)
#ifdef ISSUE_9504_RESOLVED
DECLARE_PUSH_TEST(1, 1, subjectAltNames, subjectAltName, GENERAL_NAME)
#endif
DECLARE_SET_SK_TEST(0, reqExtensions, X509_EXTENSION)
DECLARE_SET_GET_SK_TEST(1, 0, reqExtensions, X509_EXTENSION)
DECLARE_PUSH_TEST(0, 0, policies, policy, POLICYINFO)
DECLARE_SET_TEST(1, 0, oldClCert, X509)
#ifdef ISSUE_9504_RESOLVED
DECLARE_SET_TEST(1, 1, p10CSR, X509_REQ)
#endif
DECLARE_PUSH_TEST(0, 0, genm_ITAVs, genm_ITAV, OSSL_CMP_ITAV)
DECLARE_SET_CB_TEST(certConf_cb)
DECLARE_SET_GET_P_VOID_TEST(certConf_cb_arg)

#define OSSL_CMP_CTX_set_status ossl_cmp_ctx_set_status
DECLARE_SET_GET_INT_TEST(status)
#define OSSL_CMP_CTX_set0_statusString ossl_cmp_ctx_set0_statusString
DECLARE_SET_GET_SK_TEST(0, 0, statusString, ASN1_UTF8STRING)
#define OSSL_CMP_CTX_set_failInfoCode ossl_cmp_ctx_set_failInfoCode
DECLARE_SET_GET_INT_TEST(failInfoCode)
#define OSSL_CMP_CTX_set0_newCert ossl_cmp_ctx_set0_newCert
DECLARE_SET_GET_TEST(0, 0, 0, newCert, X509)
#define OSSL_CMP_CTX_set1_caPubs ossl_cmp_ctx_set1_caPubs
DECLARE_SET_GET_SK_X509_TEST(1, 1, caPubs)
#define OSSL_CMP_CTX_set1_extraCertsIn ossl_cmp_ctx_set1_extraCertsIn
DECLARE_SET_GET_SK_X509_TEST(1, 1, extraCertsIn)

DECLARE_SET_GET_TEST(1, 0, 1, transactionID, ASN1_OCTET_STRING)
#define OSSL_CMP_CTX_get0_senderNonce ossl_cmp_ctx_get0_senderNonce
DECLARE_SET_GET_TEST(1, 0, 1, senderNonce, ASN1_OCTET_STRING)
#define OSSL_CMP_CTX_set1_recipNonce ossl_cmp_ctx_set1_recipNonce
#define OSSL_CMP_CTX_get0_recipNonce ossl_cmp_ctx_get0_recipNonce
DECLARE_SET_GET_TEST(1, 0, 1, recipNonce, ASN1_OCTET_STRING)

int setup_tests(void)
{
    /* OSSL_CMP_CTX_new() is tested by set_up() */
    /* OSSL_CMP_CTX_free() is tested by tear_down() */
    ADD_TEST(test_CTX_reinit);

/* various CMP options: */
    ADD_TEST(test_CTX_set_get_option_16);
/* CMP-specific callback for logging and outputting the error queue: */
#ifndef OPENSSL_NO_TRACE
    ADD_TEST(test_CTX_set_get_log_cb);
#endif
    /*
     * also tests OSSL_CMP_log_open(), OSSL_CMP_CTX_set_log_verbosity(),
     * OSSL_CMP_err(), OSSL_CMP_warn(), * OSSL_CMP_debug(),
     * OSSL_CMP_log2(), ossl_cmp_log_parse_metadata(), and OSSL_CMP_log_close()
     * with OSSL_CMP_severity OSSL_CMP_LOG_ERR/WARNING/DEBUG/INFO:
     */
    ADD_TEST(test_cmp_ctx_log_cb);
    /* also tests OSSL_CMP_CTX_set_log_cb(), OSSL_CMP_print_errors_cb(),
       OSSL_CMP_add_error_txt(), and the macros
       OSSL_CMP_add_error_data and OSSL_CMP_add_error_line:
    */
    ADD_TEST(test_CTX_print_errors);
/* message transfer: */
    ADD_TEST(test_CTX_set1_get0_serverPath);
    ADD_TEST(test_CTX_set1_get0_serverName);
    ADD_TEST(test_CTX_set_get_serverPort);
    ADD_TEST(test_CTX_set1_get0_proxyName);
    ADD_TEST(test_CTX_set_get_proxyPort);
    ADD_TEST(test_CTX_set_get_http_cb);
    ADD_TEST(test_CTX_set_get_http_cb_arg);
    ADD_TEST(test_CTX_set_get_transfer_cb);
    ADD_TEST(test_CTX_set_get_transfer_cb_arg);
/* server authentication: */
    ADD_TEST(test_CTX_set1_get0_srvCert);
    ADD_TEST(test_CTX_set0_get0_validatedSrvCert);
    ADD_TEST(test_CTX_set1_get0_expected_sender);
    ADD_TEST(test_CTX_set0_get0_trustedStore);
    ADD_TEST(test_CTX_set1_get0_untrusted_certs);
/* client authentication: */
    ADD_TEST(test_CTX_set1_get0_clCert);
    ADD_TEST(test_CTX_set0_get0_pkey);
    ADD_TEST(test_CTX_set1_get0_pkey);
    /* the following two also test ossl_cmp_asn1_octet_string_set1_bytes(): */
    ADD_TEST(test_CTX_set1_get1_referenceValue_str);
    ADD_TEST(test_CTX_set1_get1_secretValue_str);
/* CMP message header and extra certificates: */
    ADD_TEST(test_CTX_set1_get0_recipient);
    ADD_TEST(test_CTX_push0_geninfo_ITAV);
    ADD_TEST(test_CTX_set1_get0_extraCertsOut);
    ADD_TEST(test_CTX_push1_extraCertsOut);
/* certificate template: */
    ADD_TEST(test_CTX_set0_get0_newPkey_1);
    ADD_TEST(test_CTX_set1_get0_newPkey_0);
    ADD_TEST(test_CTX_set1_get0_issuer);
    ADD_TEST(test_CTX_set1_get0_subjectName);
#ifdef ISSUE_9504_RESOLVED
/* test currently fails, see https://github.com/openssl/openssl/issues/9504 */
    ADD_TEST(test_CTX_push1_subjectAltName);
#endif
    ADD_TEST(test_CTX_set0_get0_reqExtensions);
    ADD_TEST(test_CTX_set1_get0_reqExtensions);
    /* also tests ossl_cmp_x509_extensions_dup: */
    ADD_TEST(test_CTX_reqExtensions_have_SAN_dup);
    ADD_TEST(test_CTX_push0_policy);
    ADD_TEST(test_CTX_set1_get0_oldClCert);
#ifdef ISSUE_9504_RESOLVED
/* test currently fails, see https://github.com/openssl/openssl/issues/9504 */
    ADD_TEST(test_CTX_set1_get0_p10CSR);
#endif
/* misc body contents: */
    ADD_TEST(test_CTX_push0_genm_ITAV);
/* certificate confirmation: */
    ADD_TEST(test_CTX_set_get_certConf_cb);
    ADD_TEST(test_CTX_set_get_certConf_cb_arg);
/* result fetching: */
    ADD_TEST(test_CTX_set_get_status);
    ADD_TEST(test_CTX_set0_get0_statusString);
    ADD_TEST(test_CTX_set_get_failInfoCode);
    ADD_TEST(test_CTX_set0_get0_newCert);
    ADD_TEST(test_CTX_set1_get1_caPubs);
    ADD_TEST(test_CTX_set1_get1_extraCertsIn);
/* exported for testing and debugging purposes: */
    /* the following three also test ossl_cmp_asn1_octet_string_set1(): */
    ADD_TEST(test_CTX_set1_get0_transactionID);
    ADD_TEST(test_CTX_set1_get0_senderNonce);
    ADD_TEST(test_CTX_set1_get0_recipNonce);

    /* TODO ossl_cmp_build_cert_chain() will be tested with cmp_protect.c*/

    return 1;
}
