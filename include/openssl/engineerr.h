/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ENGINEERR_H
# define OPENSSL_ENGINEERR_H
# pragma once

# define HEADER_ENGINEERR_H  /* deprecated in version 3.0 */

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_ENGINE

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_ENGINE_strings(void);

/*
 * ENGINE function codes.
 */
# if !OPENSSL_API_3
#   define ENGINE_F_DIGEST_UPDATE                           0
#   define ENGINE_F_DYNAMIC_CTRL                            0
#   define ENGINE_F_DYNAMIC_GET_DATA_CTX                    0
#   define ENGINE_F_DYNAMIC_LOAD                            0
#   define ENGINE_F_DYNAMIC_SET_DATA_CTX                    0
#   define ENGINE_F_ENGINE_ADD                              0
#   define ENGINE_F_ENGINE_BY_ID                            0
#   define ENGINE_F_ENGINE_CMD_IS_EXECUTABLE                0
#   define ENGINE_F_ENGINE_CTRL                             0
#   define ENGINE_F_ENGINE_CTRL_CMD                         0
#   define ENGINE_F_ENGINE_CTRL_CMD_STRING                  0
#   define ENGINE_F_ENGINE_FINISH                           0
#   define ENGINE_F_ENGINE_GET_CIPHER                       0
#   define ENGINE_F_ENGINE_GET_DIGEST                       0
#   define ENGINE_F_ENGINE_GET_FIRST                        0
#   define ENGINE_F_ENGINE_GET_LAST                         0
#   define ENGINE_F_ENGINE_GET_NEXT                         0
#   define ENGINE_F_ENGINE_GET_PKEY_ASN1_METH               0
#   define ENGINE_F_ENGINE_GET_PKEY_METH                    0
#   define ENGINE_F_ENGINE_GET_PREV                         0
#   define ENGINE_F_ENGINE_INIT                             0
#   define ENGINE_F_ENGINE_LIST_ADD                         0
#   define ENGINE_F_ENGINE_LIST_REMOVE                      0
#   define ENGINE_F_ENGINE_LOAD_PRIVATE_KEY                 0
#   define ENGINE_F_ENGINE_LOAD_PUBLIC_KEY                  0
#   define ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT             0
#   define ENGINE_F_ENGINE_NEW                              0
#   define ENGINE_F_ENGINE_PKEY_ASN1_FIND_STR               0
#   define ENGINE_F_ENGINE_REMOVE                           0
#   define ENGINE_F_ENGINE_SET_DEFAULT_STRING               0
#   define ENGINE_F_ENGINE_SET_ID                           0
#   define ENGINE_F_ENGINE_SET_NAME                         0
#   define ENGINE_F_ENGINE_TABLE_REGISTER                   0
#   define ENGINE_F_ENGINE_UNLOCKED_FINISH                  0
#   define ENGINE_F_ENGINE_UP_REF                           0
#   define ENGINE_F_INT_CLEANUP_ITEM                        0
#   define ENGINE_F_INT_CTRL_HELPER                         0
#   define ENGINE_F_INT_ENGINE_CONFIGURE                    0
#   define ENGINE_F_INT_ENGINE_MODULE_INIT                  0
#   define ENGINE_F_OSSL_HMAC_INIT                          0
# endif

/*
 * ENGINE reason codes.
 */
#  define ENGINE_R_ALREADY_LOADED                          100
#  define ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER                133
#  define ENGINE_R_CMD_NOT_EXECUTABLE                      134
#  define ENGINE_R_COMMAND_TAKES_INPUT                     135
#  define ENGINE_R_COMMAND_TAKES_NO_INPUT                  136
#  define ENGINE_R_CONFLICTING_ENGINE_ID                   103
#  define ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED            119
#  define ENGINE_R_DSO_FAILURE                             104
#  define ENGINE_R_DSO_NOT_FOUND                           132
#  define ENGINE_R_ENGINES_SECTION_ERROR                   148
#  define ENGINE_R_ENGINE_CONFIGURATION_ERROR              102
#  define ENGINE_R_ENGINE_IS_NOT_IN_LIST                   105
#  define ENGINE_R_ENGINE_SECTION_ERROR                    149
#  define ENGINE_R_FAILED_LOADING_PRIVATE_KEY              128
#  define ENGINE_R_FAILED_LOADING_PUBLIC_KEY               129
#  define ENGINE_R_FINISH_FAILED                           106
#  define ENGINE_R_ID_OR_NAME_MISSING                      108
#  define ENGINE_R_INIT_FAILED                             109
#  define ENGINE_R_INTERNAL_LIST_ERROR                     110
#  define ENGINE_R_INVALID_ARGUMENT                        143
#  define ENGINE_R_INVALID_CMD_NAME                        137
#  define ENGINE_R_INVALID_CMD_NUMBER                      138
#  define ENGINE_R_INVALID_INIT_VALUE                      151
#  define ENGINE_R_INVALID_STRING                          150
#  define ENGINE_R_NOT_INITIALISED                         117
#  define ENGINE_R_NOT_LOADED                              112
#  define ENGINE_R_NO_CONTROL_FUNCTION                     120
#  define ENGINE_R_NO_INDEX                                144
#  define ENGINE_R_NO_LOAD_FUNCTION                        125
#  define ENGINE_R_NO_REFERENCE                            130
#  define ENGINE_R_NO_SUCH_ENGINE                          116
#  define ENGINE_R_UNIMPLEMENTED_CIPHER                    146
#  define ENGINE_R_UNIMPLEMENTED_DIGEST                    147
#  define ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD         101
#  define ENGINE_R_VERSION_INCOMPATIBILITY                 145

# endif
#endif
