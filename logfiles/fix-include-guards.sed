# fix-include-guards.sed
s/([ !])HEADER_APPS_H/\1OSSL_APPS_APPS_H/g ;
s/([ !])HEADER_APPS_UI_H/\1OSSL_APPS_APPS_UI_H/g ;
s/([ !])HEADER_FMT_H/\1OSSL_APPS_FMT_H/g ;
s/([ !])APPS_FUNCTION_H/\1OSSL_APPS_FUNCTION_H/g ;
s/([ !])HEADER_OPT_H/\1OSSL_APPS_OPT_H/g ;
s/([ !])HEADER_PLATFORM_H/\1OSSL_APPS_PLATFORM_H/g ;
s/([ !])INCLUDED_TIMEOUTS_H/\1OSSL_APPS_TIMEOUTS_H/g ;
s/([ !])TERM_SOCK_H/\1OSSL_APPS_VMS_TERM_SOCK_H/g ;
s/([ !])HEADER_AES_LOCL_H/\1OSSL_CRYPTO_AES_LOCAL_H/g ;
s/([ !])__ARM_ARCH_H__/\1OSSL_CRYPTO_ARM_ARCH_H/g ;
s/([ !])OPENSSL_ASYNC_ARCH_ASYNC_POSIX_H/\1OSSL_CRYPTO_ASYNC_POSIX_H/g ;
s/([ !])HEADER_BF_LOCL_H/\1OSSL_CRYPTO_BF_LOCAL_H/g ;
s/([ !])HEADER_BN_LCL_H/\1OSSL_CRYPTO_BN_LOCAL_H/g ;
s/([ !])RSAZ_EXP_H/\1OSSL_CRYPTO_RSAZ_EXP_H/g ;
s/([ !])HEADER_CAMELLIA_LOCL_H/\1OSSL_CRYPTO_CMLL_LOCAL_H/g ;
s/([ !])OSSL_HEADER_CMP_INT_H/\1OSSL_CRYPTO_CMP_LOCAL_H/g ;
s/([ !])HEADER_CMS_LCL_H/\1OSSL_CRYPTO_CMS_LOCAL_H/g ;
s/([ !])OSSL_HEADER_CRMF_INT_H/\1OSSL_CRYPTO_CRMF_LOCAL_H/g ;
s/([ !])HEADER_DES_LOCL_H/\1OSSL_CRYPTO_DES_LOCAL_H/g ;
s/([ !])HEADER_ARCH_32_ARCH_INTRINSICS_H/\1OSSL_CRYPTO_ARCH_INTRINSICS_H/g ;
s/([ !])HEADER_ARCH_32_F_IMPL_H/\1OSSL_CRYPTO_F_IMPL_H/g ;
s/([ !])HEADER_CURVE448_LCL_H/\1OSSL_CRYPTO_CURVE448_LOCAL_H/g ;
s/([ !])HEADER_CURVE448UTILS_H/\1OSSL_CRYPTO_CURVE448UTILS_H/g ;
s/([ !])HEADER_ED448_H/\1OSSL_CRYPTO_ED448_H/g ;
s/([ !])HEADER_FIELD_H/\1OSSL_CRYPTO_FIELD_H/g ;
s/([ !])HEADER_POINT_448_H/\1OSSL_CRYPTO_POINT_448_H/g ;
s/([ !])HEADER_WORD_H/\1OSSL_CRYPTO_WORD_H/g ;
s/([ !])HEADER_ENGINE_INT_H/\1OSSL_CRYPTO_ENG_LOCAL_H/g ;
s/([ !])HEADER_HMAC_LCL_H/\1OSSL_CRYPTO_HMAC_LOCAL_H/g ;
s/([ !])__MIPS_ARCH_H__/\1OSSL_CRYPTO_MIPS_ARCH_H/g ;
s/([ !])HEADER_PPC_ARCH_H/\1OSSL_CRYPTO_PPC_ARCH_H/g ;
s/([ !])HEADER_RAND_LCL_H/\1OSSL_CRYPTO_RAND_LOCAL_H/g ;
s/([ !])HEADER_RC4_LOCL_H/\1OSSL_CRYPTO_RC4_LOCAL_H/g ;
s/([ !])RSA_LOCAL_HEADER_H/\1OSSL_CRYPTO_RSA_LOCAL_H/g ;
s/([ !])S390X_ARCH_H/\1OSSL_CRYPTO_S390X_ARCH_H/g ;
s/([ !])HEADER_SEED_LOCL_H/\1OSSL_CRYPTO_SEED_LOCAL_H/g ;
s/([ !])__SPARC_ARCH_H__/\1OSSL_CRYPTO_SPARC_ARCH_H/g ;
s/([ !])HEADER_UI_LOCL_H/\1OSSL_CRYPTO_UI_LOCAL_H/g ;
s/([ !])HEADER_V3_ADMISSION_H/\1OSSL_CRYPTO_V3_ADMIS_H/g ;
s/([ !])HEADER_E_OS_H/\1OSSL_E_OS_H/g ;
s/([ !])HEADER_AFALG_H/\1OSSL_ENGINES_E_AFALG_H/g ;
s/([ !])HEADER_AFALGERR_H/\1OSSL_ENGINES_E_AFALG_ERR_H/g ;
s/([ !])HEADER_CAPIERR_H/\1OSSL_ENGINES_E_CAPI_ERR_H/g ;
s/([ !])HEADER_DASYNCERR_H/\1OSSL_ENGINES_E_DASYNC_ERR_H/g ;
s/([ !])HEADER_OSSLTESTERR_H/\1OSSL_ENGINES_E_OSSLTEST_ERR_H/g ;
s/([ !])HEADER_ARIA_H/\1OSSL_CRYPTO_ARIA_H/g ;
s/([ !])HEADER_ASN1_DSA_H/\1OSSL_CRYPTO_ASN1_DSA_H/g ;
s/([ !])HEADER_BN_INT_H/\1OSSL_CRYPTO_BN_H/g ;
s/([ !])HEADER_BN_CONF_H/\1OSSL_CRYPTO_BN_CONF_H/g ;
s/([ !])HEADER_CHACHA_H/\1OSSL_CRYPTO_CHACHA_H/g ;
s/([ !])HEADER_INTERNAL_CIPHERMODE_PLATFORM_H/\1OSSL_CRYPTO_CIPHERMODE_PLATFORM_H/g ;
s/([ !])INTERNAL_CTYPE_H/\1OSSL_CRYPTO_CTYPE_H/g ;
s/([ !])HEADER_DSO_CONF_H/\1OSSL_CRYPTO_DSO_CONF_H/g ;
s/([ !])HEADER_OSSL_EC_INTERNAL_H/\1OSSL_CRYPTO_EC_H/g ;
s/([ !])INTERNAL_ERR_INT_H/\1OSSL_CRYPTO_ERR_H/g ;
s/([ !])INTERNAL_LHASH_H/\1OSSL_CRYPTO_LHASH_H/g ;
s/([ !])HEADER_RAND_INT_H/\1OSSL_CRYPTO_RAND_H/g ;
s/([ !])HEADER_INTERNAL_SHA_H/\1OSSL_CRYPTO_SHA_H/g ;
s/([ !])HEADER_SM2_H/\1OSSL_CRYPTO_SM2_H/g ;
s/([ !])HEADER_SM2ERR_H/\1OSSL_CRYPTO_SM2ERR_H/g ;
s/([ !])HEADER_SM4_H/\1OSSL_CRYPTO_SM4_H/g ;
s/([ !])HEADER_SPARSE_ARRAY_H/\1OSSL_CRYPTO_SPARSE_ARRAY_H/g ;
s/([ !])HEADER_STORE_H/\1OSSL_CRYPTO_STORE_H/g ;
s/([ !])HEADER_INTERNAL_BIO_H/\1OSSL_INTERNAL_BIO_H/g ;
s/([ !])HEADER_INTERNAL_CONF_H/\1OSSL_INTERNAL_CONF_H/g ;
s/([ !])HEADER_CONSTANT_TIME_LOCL_H/\1OSSL_INTERNAL_CONSTANT_TIME_H/g ;
s/([ !])HEADER_CRYPTLIB_H/\1OSSL_INTERNAL_CRYPTLIB_H/g ;
s/([ !])HEADER_INTERNAL_DANE_H/\1OSSL_INTERNAL_DANE_H/g ;
s/([ !])HEADER_DSO_H/\1OSSL_INTERNAL_DSO_H/g ;
s/([ !])HEADER_DSOERR_H/\1OSSL_INTERNAL_DSOERR_H/g ;
s/([ !])INTERNAL_ERR_H/\1OSSL_INTERNAL_ERR_H/g ;
s/([ !])HEADER_MD5_SHA1_H/\1OSSL_INTERNAL_MD5_SHA1_H/g ;
s/([ !])HEADER_NELEM_H/\1OSSL_INTERNAL_NELEM_H/g ;
s/([ !])HEADER_NUMBERS_H/\1OSSL_INTERNAL_NUMBERS_H/g ;
s/([ !])O_DIR_H/\1OSSL_INTERNAL_O_DIR_H/g ;
s/([ !])HEADER_PACKET_LOCL_H/\1OSSL_INTERNAL_PACKET_H/g ;
s/([ !])HEADER_PROPERTY_H/\1OSSL_INTERNAL_PROPERTY_H/g ;
s/([ !])HEADER_PROPERR_H/\1OSSL_INTERNAL_PROPERTYERR_H/g ;
s/([ !])HEADER_INTERNAL_REFCOUNT_H/\1OSSL_INTERNAL_REFCOUNT_H/g ;
s/([ !])HEADER_INTERNAL_SHA3_H/\1OSSL_INTERNAL_SHA3_H/g ;
s/([ !])HEADER_SM3_H/\1OSSL_INTERNAL_SM3_H/g ;
s/([ !])HEADER_INTERNAL_SOCKETS/\1OSSL_INTERNAL_SOCKETS_H/g ;
s/([ !])HEADER_SSLCONF_H/\1OSSL_INTERNAL_SSLCONF_H/g ;
s/([ !])HEADER_AES_H/\1OPENSSL_AES_H/g ;
s/([ !])HEADER_ASN1_H/\1OPENSSL_ASN1_H/g ;
s/([ !])HEADER_ASN1ERR_H/\1OPENSSL_ASN1ERR_H/g ;
s/([ !])HEADER_ASN1T_H/\1OPENSSL_ASN1T_H/g ;
s/([ !])HEADER_ASYNC_H/\1OPENSSL_ASYNC_H/g ;
s/([ !])HEADER_ASYNCERR_H/\1OPENSSL_ASYNCERR_H/g ;
s/([ !])HEADER_BIO_H/\1OPENSSL_BIO_H/g ;
s/([ !])HEADER_BIOERR_H/\1OPENSSL_BIOERR_H/g ;
s/([ !])HEADER_BLOWFISH_H/\1OPENSSL_BLOWFISH_H/g ;
s/([ !])HEADER_BN_H/\1OPENSSL_BN_H/g ;
s/([ !])HEADER_BNERR_H/\1OPENSSL_BNERR_H/g ;
s/([ !])HEADER_BUFFER_H/\1OPENSSL_BUFFER_H/g ;
s/([ !])HEADER_BUFERR_H/\1OPENSSL_BUFFERERR_H/g ;
s/([ !])HEADER_CAMELLIA_H/\1OPENSSL_CAMELLIA_H/g ;
s/([ !])HEADER_CAST_H/\1OPENSSL_CAST_H/g ;
s/([ !])HEADER_CMAC_H/\1OPENSSL_CMAC_H/g ;
s/([ !])OSSL_HEADER_CMP_H/\1OPENSSL_CMP_H/g ;
s/([ !])HEADER_CMPERR_H/\1OPENSSL_CMPERR_H/g ;
s/([ !])HEADER_CMS_H/\1OPENSSL_CMS_H/g ;
s/([ !])HEADER_CMSERR_H/\1OPENSSL_CMSERR_H/g ;
s/([ !])HEADER_COMP_H/\1OPENSSL_COMP_H/g ;
s/([ !])HEADER_COMPERR_H/\1OPENSSL_COMPERR_H/g ;
s/([ !])HEADER_CONF_H/\1OPENSSL_CONF_H/g ;
s/([ !])HEADER_CONF_API_H/\1OPENSSL_CONF_API_H/g ;
s/([ !])HEADER_CONFERR_H/\1OPENSSL_CONFERR_H/g ;
s/([ !])OSSL_CORE_H/\1OPENSSL_CORE_H/g ;
s/([ !])OSSL_CORE_NAMES_H/\1OPENSSL_CORE_NAMES_H/g ;
s/([ !])OSSL_CORE_NUMBERS_H/\1OPENSSL_CORE_NUMBERS_H/g ;
s/([ !])OSSL_HEADER_CRMF_H/\1OPENSSL_CRMF_H/g ;
s/([ !])HEADER_CRMFERR_H/\1OPENSSL_CRMFERR_H/g ;
s/([ !])HEADER_CRYPTO_H/\1OPENSSL_CRYPTO_H/g ;
s/([ !])HEADER_CRYPTOERR_H/\1OPENSSL_CRYPTOERR_H/g ;
s/([ !])HEADER_CT_H/\1OPENSSL_CT_H/g ;
s/([ !])HEADER_CTERR_H/\1OPENSSL_CTERR_H/g ;
s/([ !])HEADER_DES_H/\1OPENSSL_DES_H/g ;
s/([ !])HEADER_DH_H/\1OPENSSL_DH_H/g ;
s/([ !])HEADER_DHERR_H/\1OPENSSL_DHERR_H/g ;
s/([ !])HEADER_DSA_H/\1OPENSSL_DSA_H/g ;
s/([ !])HEADER_DSAERR_H/\1OPENSSL_DSAERR_H/g ;
s/([ !])HEADER_DTLS1_H/\1OPENSSL_DTLS1_H/g ;
s/([ !])HEADER_E_OS2_H/\1OPENSSL_E_OS2_H/g ;
s/([ !])HEADER_EBCDIC_H/\1OPENSSL_EBCDIC_H/g ;
s/([ !])HEADER_EC_H/\1OPENSSL_EC_H/g ;
s/([ !])HEADER_ECERR_H/\1OPENSSL_ECERR_H/g ;
s/([ !])HEADER_ENGINE_H/\1OPENSSL_ENGINE_H/g ;
s/([ !])HEADER_ENGINEERR_H/\1OPENSSL_ENGINEERR_H/g ;
s/([ !])HEADER_ERR_H/\1OPENSSL_ERR_H/g ;
s/([ !])HEADER_ESS_H/\1OPENSSL_ESS_H/g ;
s/([ !])HEADER_ESSERR_H/\1OPENSSL_ESSERR_H/g ;
s/([ !])HEADER_ENVELOPE_H/\1OPENSSL_EVP_H/g ;
s/([ !])HEADER_EVPERR_H/\1OPENSSL_EVPERR_H/g ;
s/([ !])OSSL_FIPS_NAMES_H/\1OPENSSL_FIPS_NAMES_H/g ;
s/([ !])HEADER_HMAC_H/\1OPENSSL_HMAC_H/g ;
s/([ !])HEADER_IDEA_H/\1OPENSSL_IDEA_H/g ;
s/([ !])HEADER_KDF_H/\1OPENSSL_KDF_H/g ;
s/([ !])HEADER_KDFERR_H/\1OPENSSL_KDFERR_H/g ;
s/([ !])HEADER_LHASH_H/\1OPENSSL_LHASH_H/g ;
s/([ !])HEADER_MD2_H/\1OPENSSL_MD2_H/g ;
s/([ !])HEADER_MD4_H/\1OPENSSL_MD4_H/g ;
s/([ !])HEADER_MD5_H/\1OPENSSL_MD5_H/g ;
s/([ !])HEADER_MDC2_H/\1OPENSSL_MDC2_H/g ;
s/([ !])HEADER_MODES_H/\1OPENSSL_MODES_H/g ;
s/([ !])HEADER_OBJECTS_H/\1OPENSSL_OBJECTS_H/g ;
s/([ !])HEADER_OBJERR_H/\1OPENSSL_OBJECTSERR_H/g ;
s/([ !])HEADER_OCSP_H/\1OPENSSL_OCSP_H/g ;
s/([ !])HEADER_OCSPERR_H/\1OPENSSL_OCSPERR_H/g ;
s/([ !])HEADER_OPENSSLCONF_H/\1OPENSSL_OPENSSLCONF_H/g ;
s/([ !])HEADER_OPENSSLV_H/\1OPENSSL_OPENSSLV_H/g ;
s/([ !])HEADER_PARAMS_H/\1OPENSSL_PARAMS_H/g ;
s/([ !])HEADER_PEM_H/\1OPENSSL_PEM_H/g ;
s/([ !])HEADER_PEM2_H/\1OPENSSL_PEM2_H/g ;
s/([ !])HEADER_PEMERR_H/\1OPENSSL_PEMERR_H/g ;
s/([ !])HEADER_PKCS12_H/\1OPENSSL_PKCS12_H/g ;
s/([ !])HEADER_PKCS12ERR_H/\1OPENSSL_PKCS12ERR_H/g ;
s/([ !])HEADER_PKCS7_H/\1OPENSSL_PKCS7_H/g ;
s/([ !])HEADER_PKCS7ERR_H/\1OPENSSL_PKCS7ERR_H/g ;
s/([ !])OSSL_PROVIDER_H/\1OPENSSL_PROVIDER_H/g ;
s/([ !])HEADER_RAND_H/\1OPENSSL_RAND_H/g ;
s/([ !])HEADER_DRBG_RAND_H/\1OPENSSL_RAND_DRBG_H/g ;
s/([ !])HEADER_RANDERR_H/\1OPENSSL_RANDERR_H/g ;
s/([ !])HEADER_RC2_H/\1OPENSSL_RC2_H/g ;
s/([ !])HEADER_RC4_H/\1OPENSSL_RC4_H/g ;
s/([ !])HEADER_RC5_H/\1OPENSSL_RC5_H/g ;
s/([ !])HEADER_RIPEMD_H/\1OPENSSL_RIPEMD_H/g ;
s/([ !])HEADER_RSA_H/\1OPENSSL_RSA_H/g ;
s/([ !])HEADER_RSAERR_H/\1OPENSSL_RSAERR_H/g ;
s/([ !])HEADER_SAFESTACK_H/\1OPENSSL_SAFESTACK_H/g ;
s/([ !])HEADER_SEED_H/\1OPENSSL_SEED_H/g ;
s/([ !])HEADER_SHA_H/\1OPENSSL_SHA_H/g ;
s/([ !])HEADER_SRP_H/\1OPENSSL_SRP_H/g ;
s/([ !])HEADER_D1_SRTP_H/\1OPENSSL_SRTP_H/g ;
s/([ !])HEADER_SSL_H/\1OPENSSL_SSL_H/g ;
s/([ !])HEADER_SSL2_H/\1OPENSSL_SSL2_H/g ;
s/([ !])HEADER_SSL3_H/\1OPENSSL_SSL3_H/g ;
s/([ !])HEADER_SSLERR_H/\1OPENSSL_SSLERR_H/g ;
s/([ !])HEADER_STACK_H/\1OPENSSL_STACK_H/g ;
s/([ !])HEADER_OSSL_STORE_H/\1OPENSSL_STORE_H/g ;
s/([ !])HEADER_OSSL_STOREERR_H/\1OPENSSL_STOREERR_H/g ;
s/([ !])HEADER_SYMHACKS_H/\1OPENSSL_SYMHACKS_H/g ;
s/([ !])HEADER_TLS1_H/\1OPENSSL_TLS1_H/g ;
s/([ !])OSSL_TRACE_H/\1OPENSSL_TRACE_H/g ;
s/([ !])HEADER_TS_H/\1OPENSSL_TS_H/g ;
s/([ !])HEADER_TSERR_H/\1OPENSSL_TSERR_H/g ;
s/([ !])HEADER_TXT_DB_H/\1OPENSSL_TXT_DB_H/g ;
s/([ !])HEADER_OPENSSL_TYPES_H/\1OPENSSL_TYPES_H/g ;
s/([ !])HEADER_UI_H/\1OPENSSL_UI_H/g ;
s/([ !])HEADER_UIERR_H/\1OPENSSL_UIERR_H/g ;
s/([ !])HEADER_WHRLPOOL_H/\1OPENSSL_WHRLPOOL_H/g ;
s/([ !])HEADER_X509_H/\1OPENSSL_X509_H/g ;
s/([ !])HEADER_X509_VFY_H/\1OPENSSL_X509_VFY_H/g ;
s/([ !])HEADER_X509ERR_H/\1OPENSSL_X509ERR_H/g ;
s/([ !])HEADER_X509V3_H/\1OPENSSL_X509V3_H/g ;
s/([ !])HEADER_X509V3ERR_H/\1OPENSSL_X509V3ERR_H/g ;
s/([ !])OSSL_DIGESTCOMMON_H/\1OSSL_PROVIDERS_DIGESTCOMMON_H/g ;
s/([ !])HEADER_PROVERR_H/\1OSSL_PROVIDERS_PROVIDERCOMMONERR_H/g ;
s/([ !])HEADER_BLAKE2_H/\1OSSL_BLAKE2_H/g ;
s/([ !])HEADER_SSL_LOCL_H/\1OSSL_SSL_SSL_LOCAL_H/g ;
s/([ !])DRBG_CAVS_DATA_H/\1OSSL_TEST_DRBG_CAVS_DATA_H/g ;
s/([ !])ECDSATEST_CAVS_H/\1OSSL_TEST_ECDSATEST_H/g ;
s/([ !])HEADER_HANDSHAKE_HELPER_H/\1OSSL_TEST_HANDSHAKE_HELPER_H/g ;
s/([ !])HEADER_ASYNC_BIO/\1OSSL_SHIM_TEST_ASYNC_BIO_H/g ;
s/([ !])OPENSSL_HEADER_BASE_H/\1OSSL_SHIM_TEST_BASE_H/g ;
s/([ !])HEADER_PACKETED_BIO/\1OSSL_SHIM_TEST_PACKETED_BIO_H/g ;
s/([ !])HEADER_TEST_CONFIG/\1OSSL_SHIM_TEST_TEST_CONFIG_H/g ;
s/([ !])HEADER_INTERNAL_ENDIAN_H/\1OSSL_TEST_OSSL_TEST_ENDIAN_H/g ;
s/([ !])HEADER_SSL_TEST_CTX_H/\1OSSL_TEST_SSL_TEST_CTX_H/g ;
s/([ !])HEADER_SSLTESTLIB_H/\1OSSL_TEST_SSLTESTLIB_H/g ;
s/([ !])HEADER_TESTUTIL_H/\1OSSL_TEST_TESTUTIL_H/g ;
s/([ !])HEADER_TU_OUTPUT_H/\1OSSL_TEST_OUTPUT_H/g ;
