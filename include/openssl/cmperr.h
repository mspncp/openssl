/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMPERR_H
# define OPENSSL_CMPERR_H
# pragma once

# define HEADER_CMPERR_H  /* deprecated in version 3.0 */

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_CMP_strings(void);

/*
 * CMP function codes.
 */
# if !OPENSSL_API_3
# endif

/*
 * CMP reason codes.
 */
#  define CMP_R_INVALID_ARGS                               100
#  define CMP_R_MULTIPLE_SAN_SOURCES                       102
#  define CMP_R_NO_STDIO                                   101
#  define CMP_R_NULL_ARGUMENT                              103

# endif
#endif
