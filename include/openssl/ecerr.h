/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ECERR_H
# define OPENSSL_ECERR_H
# pragma once

# define HEADER_ECERR_H  /* deprecated in version 3.0 */

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_EC_strings(void);

/*
 * EC function codes.
 */
# if !OPENSSL_API_3
#   define EC_F_BN_TO_FELEM                                 0
#   define EC_F_D2I_ECPARAMETERS                            0
#   define EC_F_D2I_ECPKPARAMETERS                          0
#   define EC_F_D2I_ECPRIVATEKEY                            0
#   define EC_F_DO_EC_KEY_PRINT                             0
#   define EC_F_ECDH_CMS_DECRYPT                            0
#   define EC_F_ECDH_CMS_SET_SHARED_INFO                    0
#   define EC_F_ECDH_COMPUTE_KEY                            0
#   define EC_F_ECDH_SIMPLE_COMPUTE_KEY                     0
#   define EC_F_ECDSA_DO_SIGN_EX                            0
#   define EC_F_ECDSA_DO_VERIFY                             0
#   define EC_F_ECDSA_SIGN_EX                               0
#   define EC_F_ECDSA_SIGN_SETUP                            0
#   define EC_F_ECDSA_SIG_NEW                               0
#   define EC_F_ECDSA_VERIFY                                0
#   define EC_F_ECD_ITEM_VERIFY                             0
#   define EC_F_ECKEY_PARAM2TYPE                            0
#   define EC_F_ECKEY_PARAM_DECODE                          0
#   define EC_F_ECKEY_PRIV_DECODE                           0
#   define EC_F_ECKEY_PRIV_ENCODE                           0
#   define EC_F_ECKEY_PUB_DECODE                            0
#   define EC_F_ECKEY_PUB_ENCODE                            0
#   define EC_F_ECKEY_TYPE2PARAM                            0
#   define EC_F_ECPARAMETERS_PRINT                          0
#   define EC_F_ECPARAMETERS_PRINT_FP                       0
#   define EC_F_ECPKPARAMETERS_PRINT                        0
#   define EC_F_ECPKPARAMETERS_PRINT_FP                     0
#   define EC_F_ECP_NISTZ256_GET_AFFINE                     0
#   define EC_F_ECP_NISTZ256_INV_MOD_ORD                    0
#   define EC_F_ECP_NISTZ256_MULT_PRECOMPUTE                0
#   define EC_F_ECP_NISTZ256_POINTS_MUL                     0
#   define EC_F_ECP_NISTZ256_PRE_COMP_NEW                   0
#   define EC_F_ECP_NISTZ256_WINDOWED_MUL                   0
#   define EC_F_ECX_KEY_OP                                  0
#   define EC_F_ECX_PRIV_ENCODE                             0
#   define EC_F_ECX_PUB_ENCODE                              0
#   define EC_F_EC_ASN1_GROUP2CURVE                         0
#   define EC_F_EC_ASN1_GROUP2FIELDID                       0
#   define EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY           0
#   define EC_F_EC_GF2M_SIMPLE_FIELD_INV                    0
#   define EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT     0
#   define EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE              0
#   define EC_F_EC_GF2M_SIMPLE_LADDER_POST                  0
#   define EC_F_EC_GF2M_SIMPLE_LADDER_PRE                   0
#   define EC_F_EC_GF2M_SIMPLE_OCT2POINT                    0
#   define EC_F_EC_GF2M_SIMPLE_POINT2OCT                    0
#   define EC_F_EC_GF2M_SIMPLE_POINTS_MUL                   0
#   define EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 0
#   define EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 0
#   define EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES   0
#   define EC_F_EC_GFP_MONT_FIELD_DECODE                    0
#   define EC_F_EC_GFP_MONT_FIELD_ENCODE                    0
#   define EC_F_EC_GFP_MONT_FIELD_INV                       0
#   define EC_F_EC_GFP_MONT_FIELD_MUL                       0
#   define EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE                0
#   define EC_F_EC_GFP_MONT_FIELD_SQR                       0
#   define EC_F_EC_GFP_MONT_GROUP_SET_CURVE                 0
#   define EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE             0
#   define EC_F_EC_GFP_NISTP224_POINTS_MUL                  0
#   define EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES 0
#   define EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE             0
#   define EC_F_EC_GFP_NISTP256_POINTS_MUL                  0
#   define EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES 0
#   define EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE             0
#   define EC_F_EC_GFP_NISTP521_POINTS_MUL                  0
#   define EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES 0
#   define EC_F_EC_GFP_NIST_FIELD_MUL                       0
#   define EC_F_EC_GFP_NIST_FIELD_SQR                       0
#   define EC_F_EC_GFP_NIST_GROUP_SET_CURVE                 0
#   define EC_F_EC_GFP_SIMPLE_BLIND_COORDINATES             0
#   define EC_F_EC_GFP_SIMPLE_FIELD_INV                     0
#   define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT      0
#   define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE               0
#   define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE                   0
#   define EC_F_EC_GFP_SIMPLE_OCT2POINT                     0
#   define EC_F_EC_GFP_SIMPLE_POINT2OCT                     0
#   define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE            0
#   define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES  0
#   define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES  0
#   define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES    0
#   define EC_F_EC_GROUP_CHECK                              0
#   define EC_F_EC_GROUP_CHECK_DISCRIMINANT                 0
#   define EC_F_EC_GROUP_COPY                               0
#   define EC_F_EC_GROUP_GET_CURVE                          0
#   define EC_F_EC_GROUP_GET_CURVE_GF2M                     0
#   define EC_F_EC_GROUP_GET_CURVE_GFP                      0
#   define EC_F_EC_GROUP_GET_DEGREE                         0
#   define EC_F_EC_GROUP_GET_ECPARAMETERS                   0
#   define EC_F_EC_GROUP_GET_ECPKPARAMETERS                 0
#   define EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS              0
#   define EC_F_EC_GROUP_GET_TRINOMIAL_BASIS                0
#   define EC_F_EC_GROUP_NEW                                0
#   define EC_F_EC_GROUP_NEW_BY_CURVE_NAME                  0
#   define EC_F_EC_GROUP_NEW_FROM_DATA                      0
#   define EC_F_EC_GROUP_NEW_FROM_ECPARAMETERS              0
#   define EC_F_EC_GROUP_NEW_FROM_ECPKPARAMETERS            0
#   define EC_F_EC_GROUP_SET_CURVE                          0
#   define EC_F_EC_GROUP_SET_CURVE_GF2M                     0
#   define EC_F_EC_GROUP_SET_CURVE_GFP                      0
#   define EC_F_EC_GROUP_SET_GENERATOR                      0
#   define EC_F_EC_GROUP_SET_SEED                           0
#   define EC_F_EC_KEY_CHECK_KEY                            0
#   define EC_F_EC_KEY_COPY                                 0
#   define EC_F_EC_KEY_GENERATE_KEY                         0
#   define EC_F_EC_KEY_NEW                                  0
#   define EC_F_EC_KEY_NEW_METHOD                           0
#   define EC_F_EC_KEY_OCT2PRIV                             0
#   define EC_F_EC_KEY_PRINT                                0
#   define EC_F_EC_KEY_PRINT_FP                             0
#   define EC_F_EC_KEY_PRIV2BUF                             0
#   define EC_F_EC_KEY_PRIV2OCT                             0
#   define EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES    0
#   define EC_F_EC_KEY_SIMPLE_CHECK_KEY                     0
#   define EC_F_EC_KEY_SIMPLE_OCT2PRIV                      0
#   define EC_F_EC_KEY_SIMPLE_PRIV2OCT                      0
#   define EC_F_EC_PKEY_CHECK                               0
#   define EC_F_EC_PKEY_PARAM_CHECK                         0
#   define EC_F_EC_POINTS_MAKE_AFFINE                       0
#   define EC_F_EC_POINTS_MUL                               0
#   define EC_F_EC_POINT_ADD                                0
#   define EC_F_EC_POINT_BN2POINT                           0
#   define EC_F_EC_POINT_CMP                                0
#   define EC_F_EC_POINT_COPY                               0
#   define EC_F_EC_POINT_DBL                                0
#   define EC_F_EC_POINT_GET_AFFINE_COORDINATES             0
#   define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M        0
#   define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP         0
#   define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP    0
#   define EC_F_EC_POINT_INVERT                             0
#   define EC_F_EC_POINT_IS_AT_INFINITY                     0
#   define EC_F_EC_POINT_IS_ON_CURVE                        0
#   define EC_F_EC_POINT_MAKE_AFFINE                        0
#   define EC_F_EC_POINT_NEW                                0
#   define EC_F_EC_POINT_OCT2POINT                          0
#   define EC_F_EC_POINT_POINT2BUF                          0
#   define EC_F_EC_POINT_POINT2OCT                          0
#   define EC_F_EC_POINT_SET_AFFINE_COORDINATES             0
#   define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M        0
#   define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP         0
#   define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES         0
#   define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M    0
#   define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP     0
#   define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP    0
#   define EC_F_EC_POINT_SET_TO_INFINITY                    0
#   define EC_F_EC_PRE_COMP_NEW                             0
#   define EC_F_EC_SCALAR_MUL_LADDER                        0
#   define EC_F_EC_WNAF_MUL                                 0
#   define EC_F_EC_WNAF_PRECOMPUTE_MULT                     0
#   define EC_F_I2D_ECPARAMETERS                            0
#   define EC_F_I2D_ECPKPARAMETERS                          0
#   define EC_F_I2D_ECPRIVATEKEY                            0
#   define EC_F_I2O_ECPUBLICKEY                             0
#   define EC_F_NISTP224_PRE_COMP_NEW                       0
#   define EC_F_NISTP256_PRE_COMP_NEW                       0
#   define EC_F_NISTP521_PRE_COMP_NEW                       0
#   define EC_F_O2I_ECPUBLICKEY                             0
#   define EC_F_OLD_EC_PRIV_DECODE                          0
#   define EC_F_OSSL_ECDH_COMPUTE_KEY                       0
#   define EC_F_OSSL_ECDSA_SIGN_SIG                         0
#   define EC_F_OSSL_ECDSA_VERIFY_SIG                       0
#   define EC_F_PKEY_ECD_CTRL                               0
#   define EC_F_PKEY_ECD_DIGESTSIGN                         0
#   define EC_F_PKEY_ECD_DIGESTSIGN25519                    0
#   define EC_F_PKEY_ECD_DIGESTSIGN448                      0
#   define EC_F_PKEY_ECX_DERIVE                             0
#   define EC_F_PKEY_EC_CTRL                                0
#   define EC_F_PKEY_EC_CTRL_STR                            0
#   define EC_F_PKEY_EC_DERIVE                              0
#   define EC_F_PKEY_EC_INIT                                0
#   define EC_F_PKEY_EC_KDF_DERIVE                          0
#   define EC_F_PKEY_EC_KEYGEN                              0
#   define EC_F_PKEY_EC_PARAMGEN                            0
#   define EC_F_PKEY_EC_SIGN                                0
#   define EC_F_VALIDATE_ECX_DERIVE                         0
# endif

/*
 * EC reason codes.
 */
#  define EC_R_ASN1_ERROR                                  115
#  define EC_R_BAD_SIGNATURE                               156
#  define EC_R_BIGNUM_OUT_OF_RANGE                         144
#  define EC_R_BUFFER_TOO_SMALL                            100
#  define EC_R_CANNOT_INVERT                               165
#  define EC_R_COORDINATES_OUT_OF_RANGE                    146
#  define EC_R_CURVE_DOES_NOT_SUPPORT_ECDH                 160
#  define EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING              159
#  define EC_R_D2I_ECPKPARAMETERS_FAILURE                  117
#  define EC_R_DECODE_ERROR                                142
#  define EC_R_DISCRIMINANT_IS_ZERO                        118
#  define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE                119
#  define EC_R_FIELD_TOO_LARGE                             143
#  define EC_R_GF2M_NOT_SUPPORTED                          147
#  define EC_R_GROUP2PKPARAMETERS_FAILURE                  120
#  define EC_R_I2D_ECPKPARAMETERS_FAILURE                  121
#  define EC_R_INCOMPATIBLE_OBJECTS                        101
#  define EC_R_INVALID_ARGUMENT                            112
#  define EC_R_INVALID_COMPRESSED_POINT                    110
#  define EC_R_INVALID_COMPRESSION_BIT                     109
#  define EC_R_INVALID_CURVE                               141
#  define EC_R_INVALID_DIGEST                              151
#  define EC_R_INVALID_DIGEST_TYPE                         138
#  define EC_R_INVALID_ENCODING                            102
#  define EC_R_INVALID_FIELD                               103
#  define EC_R_INVALID_FORM                                104
#  define EC_R_INVALID_GROUP_ORDER                         122
#  define EC_R_INVALID_KEY                                 116
#  define EC_R_INVALID_OUTPUT_LENGTH                       161
#  define EC_R_INVALID_PEER_KEY                            133
#  define EC_R_INVALID_PENTANOMIAL_BASIS                   132
#  define EC_R_INVALID_PRIVATE_KEY                         123
#  define EC_R_INVALID_TRINOMIAL_BASIS                     137
#  define EC_R_KDF_PARAMETER_ERROR                         148
#  define EC_R_KEYS_NOT_SET                                140
#  define EC_R_LADDER_POST_FAILURE                         136
#  define EC_R_LADDER_PRE_FAILURE                          153
#  define EC_R_LADDER_STEP_FAILURE                         162
#  define EC_R_MISSING_PARAMETERS                          124
#  define EC_R_MISSING_PRIVATE_KEY                         125
#  define EC_R_NEED_NEW_SETUP_VALUES                       157
#  define EC_R_NOT_A_NIST_PRIME                            135
#  define EC_R_NOT_IMPLEMENTED                             126
#  define EC_R_NOT_INITIALIZED                             111
#  define EC_R_NO_PARAMETERS_SET                           139
#  define EC_R_NO_PRIVATE_VALUE                            154
#  define EC_R_OPERATION_NOT_SUPPORTED                     152
#  define EC_R_PASSED_NULL_PARAMETER                       134
#  define EC_R_PEER_KEY_ERROR                              149
#  define EC_R_PKPARAMETERS2GROUP_FAILURE                  127
#  define EC_R_POINT_ARITHMETIC_FAILURE                    155
#  define EC_R_POINT_AT_INFINITY                           106
#  define EC_R_POINT_COORDINATES_BLIND_FAILURE             163
#  define EC_R_POINT_IS_NOT_ON_CURVE                       107
#  define EC_R_RANDOM_NUMBER_GENERATION_FAILED             158
#  define EC_R_SHARED_INFO_ERROR                           150
#  define EC_R_SLOT_FULL                                   108
#  define EC_R_UNDEFINED_GENERATOR                         113
#  define EC_R_UNDEFINED_ORDER                             128
#  define EC_R_UNKNOWN_COFACTOR                            164
#  define EC_R_UNKNOWN_GROUP                               129
#  define EC_R_UNKNOWN_ORDER                               114
#  define EC_R_UNSUPPORTED_FIELD                           131
#  define EC_R_WRONG_CURVE_PARAMETERS                      145
#  define EC_R_WRONG_ORDER                                 130

# endif
#endif
