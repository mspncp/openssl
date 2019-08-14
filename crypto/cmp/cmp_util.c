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
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <string.h>
#include <openssl/cmp_util.h>
#include "cmp_local.h" /* just for decls of internal functions defined here */
#include <openssl/cmperr.h>
#include <openssl/err.h> /* should be implied by cmperr.h */
#include <openssl/x509v3.h>

/*
 * use trace API for CMP-specific logging, prefixed by "CMP " and severity
 */

int OSSL_CMP_log_open(void) /* is designed to be idempotent */
{
#ifndef OPENSSL_NO_STDIO
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (bio != NULL && OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, bio))
        return 1;
    BIO_free(bio);
#endif
    CMPerr(0, CMP_R_NO_STDIO);
    return 0;
}

void OSSL_CMP_log_close(void) /* is designed to be idempotent */
{
    (void)OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, NULL);
}

static OSSL_CMP_severity parse_level(const char *level)
{
    const char *end_level = strchr(level, ':');
    int len;

    if (end_level == NULL)
        return -1;

    if (strncmp(level, OSSL_CMP_LOG_PREFIX,
                strlen(OSSL_CMP_LOG_PREFIX)) == 0)
        level += strlen(OSSL_CMP_LOG_PREFIX);
    len = end_level - level;
    return
        strncmp(level, "EMERG", len) == 0 ? OSSL_CMP_LOG_EMERG :
        strncmp(level, "ALERT", len) == 0 ? OSSL_CMP_LOG_ALERT :
        strncmp(level, "CRIT", len) == 0 ? OSSL_CMP_LOG_CRIT :
        strncmp(level, "ERROR", len) == 0 ? OSSL_CMP_LOG_ERR :
        strncmp(level, "WARN", len) == 0 ? OSSL_CMP_LOG_WARNING :
        strncmp(level, "NOTE", len) == 0 ? OSSL_CMP_LOG_NOTICE :
        strncmp(level, "INFO", len) == 0 ? OSSL_CMP_LOG_INFO :
        strncmp(level, "DEBUG", len) == 0 ? OSSL_CMP_LOG_DEBUG :
        -1;
}

const char *ossl_cmp_log_parse_metadata(const char *buf,
                 OSSL_CMP_severity *level, char **func, char **file, int *line)
{
    const char *p_func = buf;
    const char *p_file = buf == NULL ? NULL : strchr(buf, ':');
    const char *p_level = buf;
    const char *prefix = buf;

    *level = -1;
    *func = NULL;
    *file = NULL;
    *line = 0;

    if (p_file != NULL) {
        const char *p_line = strchr(++p_file, ':');

        /* check if buf contains at least "CMP "followed by logging level */
        if ((*level = parse_level(buf)) < 0 && p_line++ != NULL) {
            /* else check if buf contains location info and logging level */
            char *p_level_tmp = (char *)p_level;
            const long line_number = strtol(p_line, &p_level_tmp, 10);

            p_level = p_level_tmp;
            if (p_level > p_line && *(p_level++) == ':') {
                if ((*level = parse_level(p_level)) >= 0) {
                    *func = OPENSSL_strndup(p_func, p_file - 1 - p_func);
                    *file = OPENSSL_strndup(p_file, p_line - 1 - p_file);
                    *line = (int)line_number;
                    prefix = p_level;
                }
            }
        }
    }
    return prefix;
}


/*
 * auxiliary function for incrementally reporting texts via the error queue
 */
static void put_error(int lib, const char *func, int reason,
                      const char *file, int line)
{
    ERR_new();
    ERR_set_debug(file, line, func);
    ERR_set_error(lib, reason, NULL);
}

#define ERR_print_errors_cb_LIMIT 4096 /* size of char buf2[] variable there */
#define TYPICAL_MAX_OUTPUT_BEFORE_DATA 100
#define MAX_DATA_LEN (ERR_print_errors_cb_LIMIT-TYPICAL_MAX_OUTPUT_BEFORE_DATA)
void OSSL_CMP_add_error_txt(const char *separator, const char *txt)
{
    const char *file;
    int line;
    const char *func = NULL;
    const char *data;
    int flags;
    unsigned long err = ERR_peek_last_error();

    if (separator == NULL)
        separator = "";
    if (err == 0)
        put_error(ERR_LIB_CMP, NULL, 0, "", 0);

    do {
        int available_len;
        const char *curr = txt, *next = txt;
        char *tmp;

        ERR_peek_last_error_line_data(&file, &line, &data, &flags);
        if ((flags & ERR_TXT_STRING) == 0) {
            data = "";
            separator = "";
        }
        /* TODO add when available: ERR_peek_last_error_func(&func); */

        /* workaround for limit of ERR_print_errors_cb() */
        available_len = MAX_DATA_LEN - (int)strlen(data) - strlen(separator);
        if (*separator == '\0') {
            const long len_next = strlen(next);

            if (len_next < available_len) {
                next += len_next;
                curr = NULL; /* no need to split */
            }
            else {
                next += available_len - 1;
                curr = next; /* will split at this point */
            }
        } else {
            while (*next != '\0' && next - txt < available_len) {
                curr = next;
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            }
            if (next - txt < available_len) /* implies here: *next == '\0' */
                curr = NULL;
        }
        if (curr != NULL) {
            /* split error msg at curr since error data would get too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                ERR_add_error_data(2, separator, tmp);
                OPENSSL_free(tmp);
            }
            put_error(ERR_LIB_CMP, func, err, file, line);
            txt = curr;
        } else {
            ERR_add_error_data(2, separator, txt);
            txt = next; /* finished */
        }
    } while (*txt != '\0');
}

/* this is similar to ERR_print_errors_cb, but uses the CMP-specific cb type */
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn)
{
    unsigned long err;
    char component[128];
    char msg[ERR_print_errors_cb_LIMIT];
    const char *file, *func = NULL, *data;
    int line, flags;

    if (log_fn == NULL) {
#ifndef OPENSSL_NO_STDIO
        BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

        ERR_print_errors(bio_err);
        BIO_free(bio_err);
#else
        CMPerr(0, CMP_R_NO_STDIO);
#endif
        return;
    }

    /* TODO add when available: ERR_peek_error_func(&func); */
    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        if (!(flags & ERR_TXT_STRING))
            data = NULL;
        BIO_snprintf(component, sizeof(component), "OpenSSL:%s:%s",
                     ERR_lib_error_string(err), func != NULL ? func : "");
        BIO_snprintf(msg, sizeof(msg), "%s%s%s", ERR_reason_error_string(err),
                     data == NULL ? "" : " : ", data == NULL ? "" : data);
        if (log_fn(component, file, line, OSSL_CMP_LOG_ERR, msg) <= 0)
            break;              /* abort outputting the error report */
        /* TODO add when available: ERR_peek_error_func(&func); */
    }
}

/*
 * functions manipulating lists of certificates etc.
 */

int OSSL_CMP_sk_X509_add1_cert(STACK_OF(X509) *sk, X509 *cert,
                               int not_duplicate, int prepend)
{
    if (not_duplicate) {
        /*
         * not using sk_X509_set_cmp_func() and sk_X509_find()
         * because this re-orders the certs on the stack
         */
        int i;

        for (i = 0; i < sk_X509_num(sk); i++) {
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
        }
    }
    if (!sk_X509_insert(sk, cert, prepend ? 0 : -1))
        return 0;
    return X509_up_ref(cert);
}

int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates)
/* compiler would allow 'const' for the list of certs, yet they are up-ref'ed */
{
    int i;

    if (sk == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);

        if (!no_self_signed || X509_check_issued(cert, cert) != X509_V_OK) {
            if (!OSSL_CMP_sk_X509_add1_cert(sk, cert, no_duplicates, 0))
                return 0;
        }
    }
    return 1;
}

int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed)
{
    int i;

    if (store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);

        if (!only_self_signed || X509_check_issued(cert, cert) == X509_V_OK)
            if (!X509_STORE_add_cert(store, cert)) /* ups cert ref counter */
                return 0;
    }
    return 1;
}

STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(X509_STORE *store)
{
    int i;
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;

    if (store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    objs = X509_STORE_get0_objects(store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));

        if (cert != NULL) {
            if (!sk_X509_push(sk, cert) || !X509_up_ref(cert)) {
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
        }
    }
    return sk;
}

/*-
 * Builds up the certificate chain of certs as high up as possible using
 * the given list of certs containing all possible intermediate certificates and
 * optionally the (possible) trust anchor(s). See also ssl_add_cert_chain().
 *
 * Intended use of this function is to find all the certificates above the trust
 * anchor needed to verify an EE's own certificate.  Those are supposed to be
 * included in the ExtraCerts field of every first sent message of a transaction
 * when MSG_SIG_ALG is utilized.
 *
 * NOTE: This allocates a stack and increments the reference count of each cert,
 * so when not needed any more the stack and all its elements should be freed.
 * NOTE: in case there is more than one possibility for the chain,
 * OpenSSL seems to take the first one, check X509_verify_cert() for details.
 *
 * returns a pointer to a stack of (up_ref'ed) X509 certificates containing:
 *      - the EE certificate given in the function arguments (cert)
 *      - all intermediate certificates up the chain toward the trust anchor
 *        whereas the (self-signed) trust anchor is not included
 * returns NULL on error
 */
STACK_OF(X509) *ossl_cmp_build_cert_chain(STACK_OF(X509) *certs, X509 *cert)
{
    STACK_OF(X509) *chain = NULL, *result = NULL;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *csc = NULL;

    if (certs == NULL || cert == NULL || store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        goto err;

    OSSL_CMP_X509_STORE_add1_certs(store, certs, 0);
    if (!X509_STORE_CTX_init(csc, store, cert, NULL))
        goto err;

    (void)ERR_set_mark();
    /*
     * ignore return value as it would fail without trust anchor given in store
     */
    (void)X509_verify_cert(csc);

    /* don't leave any new errors in the queue */
    (void)ERR_pop_to_mark();

    chain = X509_STORE_CTX_get0_chain(csc);

    /* result list to store the up_ref'ed not self-signed certificates */
    if ((result = sk_X509_new_null()) == NULL)
        goto err;
    OSSL_CMP_sk_X509_add1_certs(result, chain,
                                1 /* no self-signed */, 1 /* no duplicates */);

 err:
    X509_STORE_free(store);
    X509_STORE_CTX_free(csc);
    return result;
}

X509_EXTENSIONS *ossl_cmp_x509_extensions_dup(const X509_EXTENSIONS *exts)
{
    if (exts == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return sk_X509_EXTENSION_deep_copy(exts, X509_EXTENSION_dup,
                                       X509_EXTENSION_free);
}

int ossl_cmp_asn1_octet_string_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if ((*tgt = ASN1_OCTET_STRING_dup(src)) == NULL)
            return 0;
    } else {
        *tgt = NULL;
    }

    return 1;
}

int ossl_cmp_asn1_octet_string_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, int len)
{
    ASN1_OCTET_STRING *new = NULL;
    int res;

    if (tgt == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (bytes != NULL) {
        if ((new = ASN1_OCTET_STRING_new()) == NULL
                || !(ASN1_OCTET_STRING_set(new, bytes, len))) {
            ASN1_OCTET_STRING_free(new);
            return 0;
        }
    }

    res = ossl_cmp_asn1_octet_string_set1(tgt, new);
    ASN1_OCTET_STRING_free(new);
    return res;
}
