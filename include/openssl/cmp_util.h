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

#ifndef OSSL_HEADER_CMP_UTIL_H
# define OSSL_HEADER_CMP_UTIL_H

# include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_CMP

#  include <openssl/trace.h>
#  include <openssl/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

/* helper macros */

#  define OSSL_CMP_STRINGIZE(x) OSSL_CMP_STRINGIZE2(x)
#  define OSSL_CMP_STRINGIZE2(x) #x
#  define OSSL_CMP_STRINGIZED_LINE OSSL_CMP_STRINGIZE(OPENSSL_LINE)

/*
 * convenience functions for CMP-specific logging via the trace API
 */

int  OSSL_CMP_log_open(void);
void OSSL_CMP_log_close(void);
#  define OSSL_CMP_LOG_PREFIX "CMP "
#  define OSSL_CMP_LOG_STRINGIZE(x) OSSL_CMP_LOG_STRINGIZE2(x)
#  define OSSL_CMP_LOG_STRINGIZE2(x) #x
#  define OSSL_CMP_LOG_START OPENSSL_FUNC ":" OPENSSL_FILE ":" \
                             OSSL_CMP_STRINGIZED_LINE ":" OSSL_CMP_LOG_PREFIX
#  define OSSL_CMP_alert(msg) OSSL_CMP_log(ALERT, msg)
#  define OSSL_CMP_err(msg)   OSSL_CMP_log(ERROR, msg)
#  define OSSL_CMP_warn(msg)  OSSL_CMP_log(WARN, msg)
#  define OSSL_CMP_info(msg)  OSSL_CMP_log(INFO, msg)
#  define OSSL_CMP_debug(msg) OSSL_CMP_log(DEBUG, msg)
#  define OSSL_CMP_log(level, msg) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": %s\n", msg))
#  define OSSL_CMP_log1(level, fmt, arg1) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", arg1))
#  define OSSL_CMP_log2(level, fmt, arg1, arg2) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", arg1, arg2))
#  define OSSL_CMP_log3(level, fmt, arg1, arg2, arg3) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", arg1, arg2, arg3))
#  define OSSL_CMP_log4(level, fmt, arg1, arg2, arg3, arg4) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", arg1, arg2, arg3, arg4))

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int OSSL_CMP_severity;
#  define OSSL_CMP_LOG_EMERG   0
#  define OSSL_CMP_LOG_ALERT   1
#  define OSSL_CMP_LOG_CRIT    2
#  define OSSL_CMP_LOG_ERR     3
#  define OSSL_CMP_LOG_WARNING 4
#  define OSSL_CMP_LOG_NOTICE  5
#  define OSSL_CMP_LOG_INFO    6
#  define OSSL_CMP_LOG_DEBUG   7
typedef int (*OSSL_cmp_log_cb_t)(const char *func, const char *file, int line,
                                 OSSL_CMP_severity level, const char *msg);

/*
 * enhancements of the error queue and use of the logging callback for it
 */
void OSSL_CMP_add_error_txt(const char *separator, const char *txt);
# define OSSL_CMP_add_error_data(txt) OSSL_CMP_add_error_txt(" : ", txt)
# define OSSL_CMP_add_error_line(txt) OSSL_CMP_add_error_txt("\n", txt)
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn);

/*
 * functions manipulating lists of certificates etc.
 * these functions could be generally useful
 */
int OSSL_CMP_sk_X509_add1_cert (STACK_OF(X509) *sk, X509 *cert,
                                int not_duplicate, int prepend);
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates);
int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed);
STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(X509_STORE *store);

#   ifdef  __cplusplus
}
#   endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OSSL_HEADER_CMP_UTIL_H */
