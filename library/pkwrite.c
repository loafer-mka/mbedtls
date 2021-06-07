/*
 *  Public Key layer for writing key files and structures
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "common.h"

#if defined(MBEDTLS_PK_WRITE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/* Parameter validation macros based on platform_util.h */
#define PK_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_PK_BAD_INPUT_DATA )
#define PK_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#if defined(MBEDTLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                                mbedtls_rsa_context *rsa )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_mpi T;

    mbedtls_mpi_init( &T );

    /* Export E */
    if ( ( ret = mbedtls_rsa_export( rsa, NULL, NULL, NULL, NULL, &T ) ) != 0 ||
         ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export N */
    if ( ( ret = mbedtls_rsa_export( rsa, &T, NULL, NULL, NULL, NULL ) ) != 0 ||
         ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Do not write SEQUENCE header here - this function may be used as part
     * of storing the private key, where N and E are parts of entire key */

end_of_export:

    mbedtls_mpi_free( &T );
    if( ret < 0 )
        return( ret );

    return( (int) len );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * EC public key is an EC point
 */
static int pk_write_ec_pubkey( unsigned char **p, unsigned char *start,
                               mbedtls_ecp_keypair *ec )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    unsigned char buf[MBEDTLS_ECP_MAX_PT_LEN];

    if( ( ret = mbedtls_ecp_point_write_binary( &ec->grp, &ec->Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &len, buf, sizeof( buf ) ) ) != 0 )
    {
        return( ret );
    }

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */
static int pk_write_ec_param( unsigned char **p, unsigned char *start,
                              mbedtls_ecp_keypair *ec )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    if( ( ret = mbedtls_oid_get_oid_by_ec_grp( ec->grp.id, &oid, &oid_len ) ) != 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    return( (int) len );
}

/*
 * privateKey  OCTET STRING -- always of length ceil(log2(n)/8)
 */
static int pk_write_ec_private( unsigned char **p, unsigned char *start,
                                mbedtls_ecp_keypair *ec )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t byte_length = ( ec->grp.pbits + 7 ) / 8;
    unsigned char tmp[MBEDTLS_ECP_MAX_BYTES];

    ret = mbedtls_ecp_write_key( ec, tmp, byte_length );
    if( ret != 0 )
        goto exit;
    ret = mbedtls_asn1_write_octet_string( p, start, tmp, byte_length );

exit:
    mbedtls_platform_zeroize( tmp, byte_length );
    return( ret );
}
#endif /* MBEDTLS_ECP_C */

int mbedtls_pk_write_pubkey( unsigned char **p, unsigned char *start,
                             const mbedtls_pk_context *key )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    PK_VALIDATE_RET( p != NULL );
    PK_VALIDATE_RET( *p != NULL );
    PK_VALIDATE_RET( start != NULL );
    PK_VALIDATE_RET( key != NULL );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA ) {
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_rsa_pubkey( p, start, mbedtls_pk_rsa( *key ) ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                                     MBEDTLS_ASN1_SEQUENCE ) );
    } else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_ec_pubkey( p, start, mbedtls_pk_ec( *key ) ) );
    else
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_OPAQUE )
    {
        size_t buffer_size;
        psa_key_id_t* key_id = (psa_key_id_t*) key->pk_ctx;

        if ( *p < start )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

        buffer_size = (size_t)( *p - start );
        if ( psa_export_public_key( *key_id, start, buffer_size, &len )
             != PSA_SUCCESS )
        {
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
        }
        else
        {
            *p -= len;
            memmove( *p, start, len );
        }
    }
    else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

int mbedtls_pk_write_pubkey_der( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    mbedtls_pk_type_t pk_type;
    const char *oid;

    PK_VALIDATE_RET( key != NULL );
    if( size == 0 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    PK_VALIDATE_RET( buf != NULL );

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, key ) );

    if( c - buf < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

    pk_type = mbedtls_pk_get_type( key );
#if defined(MBEDTLS_ECP_C)
    if( pk_type == MBEDTLS_PK_ECKEY )
    {
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, mbedtls_pk_ec( *key ) ) );
    }
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( pk_type == MBEDTLS_PK_OPAQUE )
    {
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_type_t key_type;
        psa_key_id_t key_id;
        psa_ecc_family_t curve;
        size_t bits;

        key_id = *((psa_key_id_t*) key->pk_ctx );
        if( PSA_SUCCESS != psa_get_key_attributes( key_id, &attributes ) )
            return( MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED );
        key_type = psa_get_key_type( &attributes );
        bits = psa_get_key_bits( &attributes );
        psa_reset_key_attributes( &attributes );

        curve = PSA_KEY_TYPE_ECC_GET_FAMILY( key_type );
        if( curve == 0 )
            return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

        ret = mbedtls_psa_get_ecc_oid_from_id( curve, bits, &oid, &oid_len );
        if( ret != 0 )
            return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

        /* Write EC algorithm parameters; that's akin
         * to pk_write_ec_param() above. */
        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_oid( &c, buf,
                                                               oid, oid_len ) );

        /* The rest of the function works as for legacy EC contexts. */
        pk_type = MBEDTLS_PK_ECKEY;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( pk_type, &oid,
                                               &oid_len ) ) != 0 )
    {
        return( ret );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}


#if defined(MBEDTLS_RSA_C)
static int pk_write_rsa_key( unsigned char **p, unsigned char *start,
                                mbedtls_rsa_context *rsa )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_mpi T;

    /*
     * Export the parameters one after another to avoid simultaneous copies.
     */
    mbedtls_mpi_init( &T );

    /* private */
    /* Export QP */
    if( ( ret = mbedtls_rsa_export_crt( rsa, NULL, NULL, &T ) ) != 0 ||
        ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export DQ */
    if( ( ret = mbedtls_rsa_export_crt( rsa, NULL, &T, NULL ) ) != 0 ||
        ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export DP */
    if( ( ret = mbedtls_rsa_export_crt( rsa, &T, NULL, NULL ) ) != 0 ||
        ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export Q */
    if ( ( ret = mbedtls_rsa_export( rsa, NULL, NULL,
                                     &T, NULL, NULL ) ) != 0 ||
         ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export P */
    if ( ( ret = mbedtls_rsa_export( rsa, NULL, &T,
                                     NULL, NULL, NULL ) ) != 0 ||
         ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export D */
    if ( ( ret = mbedtls_rsa_export( rsa, NULL, NULL,
                                     NULL, &T, NULL ) ) != 0 ||
         ( ret = mbedtls_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* public; E and N */
    if ( ( ret = pk_write_rsa_pubkey( p, start, rsa ) ) < 0 )
        goto end_of_export;
    len += ret;

end_of_export:

    mbedtls_mpi_free( &T );
    if( ret < 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, 0 ) );

    return( (int) len );
}
#endif

#if defined(MBEDTLS_ECP_C)
static int pk_write_ec_key( unsigned char **p, unsigned char *start,
                            int has_parameters, mbedtls_ecp_keypair *ec )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    size_t pub_len = 0, par_len = 0;

    /*
     * RFC 5915, or SEC1 Appendix C.4
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     *    }
     */

    /* publicKey */
    MBEDTLS_ASN1_CHK_ADD( pub_len, pk_write_ec_pubkey( p, start, ec ) );

    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    *--(*p) = 0;
    pub_len += 1;

    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( p, start, pub_len ) );
    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( p, start, pub_len ) );
    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( p, start,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    len += pub_len;

    /* parameters */
    if ( has_parameters ) {
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( p, start, ec ) );

        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_len( p, start, par_len ) );
        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_tag( p, start,
                              MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
        len += par_len;
    }
    /* privateKey */
    MBEDTLS_ASN1_CHK_ADD( len, pk_write_ec_private( p, start, ec ) );

    /* version */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, 1 ) );

    return( (int) len );
}
#endif

int mbedtls_pk_write_key( unsigned char **p, unsigned char *start,
                          int has_parameters, const mbedtls_pk_context *key )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    PK_VALIDATE_RET( p != NULL );
    PK_VALIDATE_RET( *p != NULL );
    PK_VALIDATE_RET( start != NULL );
    PK_VALIDATE_RET( key != NULL );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_rsa_key( p, start, mbedtls_pk_rsa( *key ) ) );
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_ec_key( p, start, has_parameters, mbedtls_pk_ec( *key ) ) );
    else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedtls_pk_write_key_der( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0;

    PK_VALIDATE_RET( key != NULL );
    if( size == 0 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    PK_VALIDATE_RET( buf != NULL );

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_key( &c, buf, 1, key ) );

    return( (int) len );
}

int mbedtls_pk_write_key_pkcs8_der( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len, oid_len;
    mbedtls_pk_type_t pk_type;
    const char *oid;

    PK_VALIDATE_RET( key != NULL );
    if( size == 0 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    PK_VALIDATE_RET( buf != NULL );

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_key( &c, buf, 0, key ) );
/*
 *  RSAPkcs8Key ::= SEQUENCE {
 *      version           INTEGER, -- 00
 *      SEQUENCE {
 *          keyType           OBJECT,  -- rsaEncryption
 *          null              NULL
 *      },
 *      traditional       OCTET_STRING -- traditional RSA key
 *  }
 *
 *  ECPkcs8Key ::= SEQUENCE {
 *      version          INTEGER,      -- 00
 *      pub_ec_params    SEQUENCE {
 *          keyType          OBJECT,   -- id-ecPublicKey
 *          curve_id         OBJECT    -- curve oid
 *      }
 *      pub_and_priv     OCTET_STRING  -- note: this is reduced ECKey without 'parameters [0] ECParameters {{ NamedCurve }} OPTIONAL'
 *  }
 *
 *  reduced_ECKey ::= SEQUENCE {
 *      version          INTEGER,      -- 01
 *      private          OCTET_STRING, -- some data
 *      publicKey  [1]   BIT STRING
 *  }
 */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_OCTET_STRING ) );

    pk_type = mbedtls_pk_get_type( key );
#if defined(MBEDTLS_RSA_C)
    if( pk_type == MBEDTLS_PK_RSA ) {
        par_len = 0; /* so tag NULL will be added by mbedtls_asn1_write_algorithm_identifier */
    } else
#endif
#if defined(MBEDTLS_ECP_C)
    if( pk_type == MBEDTLS_PK_ECKEY ) {
        par_len = 0;
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, mbedtls_pk_ec( *key ) ) );
    } else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( pk_type, &oid,
                                               &oid_len ) ) != 0 )
    {
        return( ret );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

/*
 * Max sizes of key per types. Shown as tag + len (+ content).
 */

#if defined(MBEDTLS_RSA_C)
/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   ( 38 + 2 * MBEDTLS_MPI_MAX_SIZE )

/*
 * RSA private keys:
 *  RSAPrivateKey ::= SEQUENCE {                    1 + 3
 *      version           Version,                  1 + 1 + 1
 *      modulus           INTEGER,                  1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER,                  1 + 3 + MPI_MAX + 1
 *      privateExponent   INTEGER,                  1 + 3 + MPI_MAX + 1
 *      prime1            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      prime2            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent1         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent2         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      coefficient       INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
 *  }
 */
#define MPI_MAX_SIZE_2          ( MBEDTLS_MPI_MAX_SIZE / 2 + \
                                  MBEDTLS_MPI_MAX_SIZE % 2 )
#define RSA_PRV_DER_MAX_BYTES   ( 47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                   + 5 * MPI_MAX_SIZE_2 )
/*
 *  RSAPkcs8Key ::= SEQUENCE {                      1 + 2
 *      version           INTEGER,                  1 + 1 + 1
 *      SEQUENCE {                                  1 + 1
 *          keyType           OBJECT,               1 + 1 + 9
 *          null              NULL                  1 + 1
 *      },
 *      traditional       OCTET_STRING              1 + 2 + RSA_PRV_DER_MAX_BYTES
 *  }
 */
#define RSA_PKCS8_DER_MAX_BYTES ( 24 + RSA_PRV_DER_MAX_BYTES )
#else /* MBEDTLS_RSA_C */

#define RSA_PUB_DER_MAX_BYTES   0
#define RSA_PRV_DER_MAX_BYTES   0
#define RSA_PKCS8_DER_MAX_BYTES 0

#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   ( 30 + 2 * MBEDTLS_ECP_MAX_BYTES )

/*
 * EC private keys:
 * ECPrivateKey ::= SEQUENCE {                  1 + 2
 *      version        INTEGER ,                1 + 1 + 1
 *      privateKey     OCTET STRING,            1 + 1 + ECP_MAX
 *      parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
 *      publicKey  [1] BIT STRING OPTIONAL      1 + 2 + [1] above
 *    }
 */
#define ECP_PRV_DER_MAX_BYTES   ( 29 + 3 * MBEDTLS_ECP_MAX_BYTES )

/*
 *  ECPkcs8Key ::= SEQUENCE {                   1 + 2
 *      version          INTEGER,               1 + 1 + 1
 *      pub_ec_params    SEQUENCE {             1 + 1
 *          keyType          OBJECT,            1 + 1 + 7
 *          curve_id         OBJECT             (1 + 1 + 9)
 *      }
 *      pub_and_priv     OCTET_STRING           1 + 2 + ECPrivateKey - (parameters: 1 + 1 + (1 + 1 + 9))
 *  }
 */
#define ECP_PKCS8_DER_MAX_BYTES   ( 18 + ECP_PRV_DER_MAX_BYTES )

#else /* MBEDTLS_ECP_C */

#define ECP_PUB_DER_MAX_BYTES   0
#define ECP_PRV_DER_MAX_BYTES   0
#define ECP_PKCS8_DER_MAX_BYTES 0

#endif /* MBEDTLS_ECP_C */

#define PUB_DER_MAX_BYTES   ( RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                              RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES )
#define PRV_DER_MAX_BYTES   ( RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
                              RSA_PRV_DER_MAX_BYTES : ECP_PRV_DER_MAX_BYTES )
#define PKCS8_DER_MAX_BYTES ( RSA_PKCS8_DER_MAX_BYTES > ECP_PKCS8_DER_MAX_BYTES ? \
                              RSA_PKCS8_DER_MAX_BYTES : ECP_PKCS8_DER_MAX_BYTES )

#define PKCS8_ENC_SALT_BYTES   8

/*
 *  PBES1_PKCS12Key ::= SEQUENCE {                  1 + 2
 *      encryptionAlgirithm SEQUENCE {              1 + 1
 *          AlgirithmIdentifier OBJECT              1 + 1 + 10    (longest 1.2.840.113549.1.12.1.6)
 *          ContentEncryptiopn  SEQUENCE {          1 + 1
 *              salt                OCTET_STRING    1 + 1 + 8     (we use salt PKCS8_ENC_SALT_BYTES bytes)
 *              iterations          INTEGER         1 + 1 + 4     (really 2, default iterations 2048; millions may be...)
 *          }
 *      }
 *      pub_and_priv        OCTET_STRING            encrypted pkcs8 private key (pkcs8 length + padding up to block size)
 *  }
 *  35 + PKCS8_DER_MAX_BYTES
 *  supported ciphers:
 *      pkcs5 pbes1
 *        + 1.2.840.113549.1.5.3    MBEDTLS_OID_PKCS5_PBE_MD5_DES_CBC        (openssl pkcs8 -topk8 -v1 pbe-md5-des)
 *        - 1.2.840.113549.1.5.6    MBEDTLS_OID_PKCS5_PBE_MD5_RC2_CBC        (openssl pkcs8 -topk8 -v1 pbe-md5-rc2-64)
 *        + 1.2.840.113549.1.5.10   MBEDTLS_OID_PKCS5_PBE_SHA1_DES_CBC       (openssl pkcs8 -topk8 -v1 pbe-sha1-des)
 *        - 1.2.840.113549.1.5.11   MBEDTLS_OID_PKCS5_PBE_SHA1_RC2_CBC       (openssl pkcs8 -topk8 -v1 pbe-sha1-rc2-64)
 *      pkcs12
 *        + 1.2.840.113549.1.12.1.1 MBEDTLS_OID_PKCS12_PBE_SHA1_RC4_128      (openssl pkcs8 -topk8 -v1 pbe-sha1-rc4-128)
 *        - 1.2.840.113549.1.12.1.2 MBEDTLS_OID_PKCS12_PBE_SHA1_RC4_40       (openssl pkcs8 -topk8 -v1 pbe-sha1-rc4-40)
 *        + 1.2.840.113549.1.12.1.3 MBEDTLS_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC (openssl pkcs8 -topk8 -v1 pbe-sha1-3des)
 *        + 1.2.840.113549.1.12.1.4 MBEDTLS_OID_PKCS12_PBE_SHA1_DES2_EDE_CBC (openssl pkcs8 -topk8 -v1 pbe-sha1-2des)
 *        - 1.2.840.113549.1.12.1.5 MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_128_CBC  (openssl pkcs8 -topk8 -v1 pbe-sha1-rc2-128)
 *        - 1.2.840.113549.1.12.1.6 MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_40_CBC   (openssl pkcs8 -topk8 -v1 pbe-sha1-rc2-40)
 */

/*
 *  PBES2_Key ::= SEQUENCE {
 *      encryptionAlgirithm SEQUENCE {                          1 + 1
 *          AlgirithmIdentifier OBJECT                          1 + 1 + 9    (1.2.840.113549.1.5.13   MBEDTLS_OID_PKCS5_PBES2)
 *          ContentEncryptiopn  SEQUENCE {                      1 + 1
 *              kdf_parameters      SEQUENCE {                  1 + 1
 *                  kdf_type            OBJECT                  1 + 1 + 9    (1.2.840.113549.1.5.12   MBEDTLS_OID_PKCS5_PBKDF2)
 *                  kdf_info            SEQUENCE {              1 + 1
 *                      salt                OCTET_STRING        1 + 1 + 16    (up to iv size)
 *                      iterations          INTEGER             1 + 1 + 4    (really 2, default iterations 2048; millions may be...)
 * -------------------  keylen              INTEGER OPTIONAL    0            (will not be used; RC2 is not supported)
 *                  }
 *                  hmac_info           SEQUENCE {              1 + 1
 *                      hmac_type           OBJECT              1 + 1 + 8    (1.2.840.113549.2.9      MBEDTLS_OID_HMAC_SHA256)
 *                      hmac_parameters     NULL                1 + 1
 *                  }
 *              }
 *              cipher_parameters   SEQUENCE {                  1 + 1
 *                  ciper_type          OBJECT                  1 + 1 + 9    (2.16.840.1.101.3.4.1.42 MBEDTLS_OID_AES256_CBC)
 *                  iv                  OCTET_STRING            1 + 1 + 16   (16 bytes for aes-128 and aes-256; 8 for des, des3)
 * ---------------  in case of RC2 iv SEQUENCE { INTEGER, OCTET_STRING } instead of iv OCTET_STRING may be used; (rc2 is not supported)
 *              }
 *          }
 *      }
 *      pub_and_priv        OCTET_STRING                        encrypted pkcs8 private key (pkcs8 length + padding up to block size)
 *  }
 *  99 + PKCS8_DER_MAX_BYTES
 *  supported ciphers:
 *          1.2.840.113549.3.7      MBEDTLS_OID_DES_EDE3_CBC
 *          1.3.14.3.2.7            MBEDTLS_OID_DES_CBC
 *          2.16.840.1.101.3.4.1.2  MBEDTLS_OID_AES128_CBC
 *          2.16.840.1.101.3.4.1.42 MBEDTLS_OID_AES256_CBC
 */

#define PKCS8_ENC_DER_MAX_BYTES  ( 99 + PKCS8_DER_MAX_BYTES )

int mbedtls_pk_write_key_pkcs8_encrypted_der( const mbedtls_pk_context *key,
        mbedtls_pbes_t key_format, unsigned char **der_buf, size_t der_size,
        mbedtls_cipher_type_t enc_alg, mbedtls_md_type_t md_alg, int iterations,
        const unsigned char *pwd, size_t pwd_len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t der_len, oid_len, key_len, iv_len, salt_len;
    size_t len0, len1, len2, len3, len4, len5;
    unsigned char *der_beg, *der_end, *der_base;
    unsigned char *c;
    const char *oid;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_md_context_t md_ctx;
    unsigned char iv[ MBEDTLS_MAX_IV_LENGTH ];
    unsigned char salt[ MBEDTLS_MAX_IV_LENGTH ];
    unsigned char cipher_key[ MBEDTLS_MAX_KEY_LENGTH ];

    PK_VALIDATE_RET( key != NULL );
    PK_VALIDATE_RET( buf != NULL && *buf != NULL && size > 0 );
    PK_VALIDATE_RET( pwd != NULL && pwd_len != 0 );
    PK_VALIDATE_RET( f_rng != NULL );

    if ( iterations <= 0 ) iterations = 2048;

    cipher_info = mbedtls_cipher_info_from_type( enc_alg );
    if ( NULL == cipher_info ) return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    md_info = mbedtls_md_info_from_type( md_alg );
    if( NULL == md_info ) return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( der_size < MBEDTLS_MAX_BLOCK_LENGTH ) return( MBEDTLS_ERR_PK_BUF_TOO_SMALL );

    mbedtls_md_init( &md_ctx );
    mbedtls_cipher_init( &cipher_ctx );

    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        goto cipher_end;

    if( ( ret = mbedtls_cipher_setup( &cipher_ctx, cipher_info ) ) != 0 )
        goto cipher_end;

    iv_len = (size_t)mbedtls_cipher_get_iv_size( &cipher_ctx );
    if ( iv_len > sizeof(iv) ) {
        ret = MBEDTLS_ERR_PK_IV_TOO_LONG;
        goto cipher_end;
    }

    salt_len = iv_len ? iv_len : PKCS8_ENC_SALT_BYTES;
    if ( salt_len > sizeof(salt) ) salt_len = sizeof(salt);

    key_len = (size_t)mbedtls_cipher_get_key_bitlen( &cipher_ctx ) / 8;
    if ( key_len > sizeof(cipher_key) ) {
        ret = MBEDTLS_ERR_PK_KEY_TOO_LONG;
        goto cipher_end;
    }

    switch ( key_format ) {
    case ENCRYPTION_SCHEME_PBES1:
        if (0 != mbedtls_oid_get_oid_by_pkcs5_pbes1_alg( md_alg, enc_alg,
                                                        &oid, &oid_len ))
        {
            /* iv will be initialized later by key derivation procedure */
            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            goto cipher_end;
        }
        break;
    case ENCRYPTION_SCHEME_PKCS12:
        if (0 != mbedtls_oid_get_oid_by_pkcs12_pbe_alg( md_alg, enc_alg,
                                                        &oid, &oid_len ))
        {
            /* iv will be initialized later by key derivation procedure */
            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            goto cipher_end;
        }
	break;
    case ENCRYPTION_SCHEME_PBES2:
        /* generate IV */
        if( ( ret = f_rng( p_rng, iv, iv_len ) ) != 0 )
            goto cipher_end;
        break;
    default:
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cipher_end;
    }

    /* generate salt */
    if( ( ret = f_rng( p_rng, salt, salt_len ) ) != 0 )
        goto cipher_end;

    /* reserve padding space at the end of buffer */
    der_base = *der_buf;
    der_end = der_base + der_size - MBEDTLS_MAX_BLOCK_LENGTH;

    /* build plain der image */
    if( ( ret = mbedtls_pk_write_key_pkcs8_der( key, der_base, der_end - der_base ) ) < 0 )
        goto cipher_end;
    der_len = len0 = ret;
    der_beg = c = der_end - der_len;

    /* 
     * Note: mbedtls_pkcs5_pbes2() cannot be used for encrypting key: it does not
     * return actual length of encrypted data after padding, so we cannot assign
     * OCTET_STRING length after encryption.
     * Moreover: best way is to pad buffer manually and disable padding by cipher
     * because mbedtls_cipher_crypt() (like as mbedtls_cipher_update()) cannot pad
     * if in-place encrypting (input buffer == output buffer) used.
     */
    /* padding */
    len2 = cipher_info->block_size - der_len % cipher_info->block_size;
    der_len += len2;
    memset( der_end, (unsigned char)len2, len2 );

    /* code below is similary to mbedtls_pkcs5_pbes2() with minor changes */

    /* generate cipher key */
    switch ( key_format ) {
    case ENCRYPTION_SCHEME_PBES1:
        if( (ret = mbedtls_pkcs5_pbkdf1( md_alg, salt, salt_len, iterations,
                                         pwd, pwd_len, cipher_key, iv )) != 0 )
        {
            goto cipher_end;
        }
        break;
    case ENCRYPTION_SCHEME_PKCS12:
        if( ( ret = mbedtls_pkcs12_pbkdf( md_alg, pwd, pwd_len,
                                          salt, salt_len, iterations,
                                          cipher_key, key_len,
                                          iv, iv_len ) ) != 0 )
        {
            goto cipher_end;
        }
        break;
    case ENCRYPTION_SCHEME_PBES2:
        if( ( ret = mbedtls_pkcs5_pbkdf2_hmac( &md_ctx, pwd, pwd_len,
                                          salt, salt_len, iterations,
                                          (uint32_t)key_len, cipher_key ) ) != 0 )
        {
            goto cipher_end;
        }
        break;
    }

    if( ( ret = mbedtls_cipher_setkey( &cipher_ctx, cipher_key, (int)(8*key_len),
                                       MBEDTLS_ENCRYPT ) ) != 0 )
        goto cipher_end;

    if( ( ret = mbedtls_cipher_set_padding_mode( &cipher_ctx,
                                                 MBEDTLS_PADDING_NONE ) ) != 0)
        goto cipher_end;

    if( ( ret = mbedtls_cipher_crypt( &cipher_ctx, iv, iv_len,
                                      der_beg, der_len, der_beg, &len0 )) != 0)
        ret = MBEDTLS_ERR_PK_PASSWORD_MISMATCH;

cipher_end:
    mbedtls_md_free( &md_ctx );
    mbedtls_cipher_free( &cipher_ctx );
    mbedtls_platform_zeroize( cipher_key, sizeof(cipher_key) );

    /* end of similary to mbedtls_pkcs5_pbes2() block */
    if ( 0 != ret ) return( ret );

    MBEDTLS_ASN1_CHK_ADD( len0, mbedtls_asn1_write_len( &c, der_base, len0 ) );
    MBEDTLS_ASN1_CHK_ADD( len0, mbedtls_asn1_write_tag( &c, der_base,
                          MBEDTLS_ASN1_OCTET_STRING ) );

    len1 = len2 = 0;
    switch ( key_format ) {
    case ENCRYPTION_SCHEME_PBES1:
    case ENCRYPTION_SCHEME_PKCS12:
        /* iterations */
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_int( &c, der_base, iterations ) );
        /* salt */
        c -= salt_len;
        if ( c <= der_base ) return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        len2 += salt_len;
        memcpy( c, salt, salt_len );
        mbedtls_platform_zeroize( salt, salt_len );
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_len( &c, der_base,
                              salt_len ));
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_OCTET_STRING ));
        /* ContentEncryptiopn SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_len( &c, der_base, len2 ) );
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        /* encryptionIdentifier scheme */
        len1 += len2;
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_oid( &c, der_base, oid,
                              oid_len ));
        /* encryptionAlgirithm SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_len( &c, der_base,
                              len1 ));
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        break;
    case ENCRYPTION_SCHEME_PBES2:
        /* start new sequence with cipher info SEQUENCE { OID cipher, OCTET_STRING iv } */
        /* iv */
        len3 = iv_len;
        c -= iv_len;
        if ( c <= der_base ) return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        memcpy( c, iv, iv_len );
        mbedtls_platform_zeroize( iv, sizeof(iv) );
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_len( &c, der_base, 
                              iv_len ));
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_OCTET_STRING ));
        /* cipher id */
        if( (ret = mbedtls_oid_get_oid_by_cipher_alg( enc_alg, &oid,
                                                      &oid_len ) ) != 0 )
            return( ret );
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_oid( &c, der_base, oid,
                              oid_len ));
        /* cipher_parameters SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_len( &c, der_base,
                              len3 ) );
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED|MBEDTLS_ASN1_SEQUENCE ));
        len2 += len3;

        /* start new sequence with PBKDF info SEQUENCE { 
         *    OID PBKDFv2, SEQUENCE { 
         *        OCTET_STRING salt, INTEGER iterations, SEQUENCE hmac_info
         *    }
         * } */
        len3 = len4 = 0;

        /* fill hmac_info SEQUENCE { OID hmac_alg, NULL } */
        len5 = 0;
        /* NULL tag */
        MBEDTLS_ASN1_CHK_ADD( len5, mbedtls_asn1_write_len( &c, der_base, 0 ) );
        MBEDTLS_ASN1_CHK_ADD( len5, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_NULL ) );
        /* MD alg */
        if((ret = mbedtls_oid_get_oid_by_md_hmac(md_alg, &oid, &oid_len)) != 0)
            return( ret );
        MBEDTLS_ASN1_CHK_ADD( len5, mbedtls_asn1_write_oid( &c, der_base, oid,
                              oid_len ));
        /* hmac_info SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len5, mbedtls_asn1_write_len( &c, der_base,
                              len5 ) );
        MBEDTLS_ASN1_CHK_ADD( len5, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        len4 += len5;

        /* fill kdf_info SEQUENCE */
        /* iterations */
        MBEDTLS_ASN1_CHK_ADD( len4, mbedtls_asn1_write_int( &c, der_base,
                              iterations ) );
        /* salt */
        c -= salt_len;
        if ( c <= der_base ) return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        len4 += salt_len;
        memcpy( c, salt, salt_len );
        mbedtls_platform_zeroize( salt, salt_len );
        MBEDTLS_ASN1_CHK_ADD( len4, mbedtls_asn1_write_len( &c, der_base,
                              salt_len ));
        MBEDTLS_ASN1_CHK_ADD( len4, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_OCTET_STRING ));
        /* kdf_info SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len4, mbedtls_asn1_write_len( &c, der_base,
                              len4 ) );
        MBEDTLS_ASN1_CHK_ADD( len4, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        /* pbkdf2 oid */
        len3 += len4;
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_oid( &c, der_base,
                              MBEDTLS_OID_PKCS5_PBKDF2,
                              sizeof(MBEDTLS_OID_PKCS5_PBKDF2)-1 ));
        /* kdf_parameters SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_len( &c, der_base, len3 ) );
        MBEDTLS_ASN1_CHK_ADD( len3, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        /* ContentEncryptiopn SEQUENCE */
        len2 += len3;
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_len( &c, der_base, len2 ) );
        MBEDTLS_ASN1_CHK_ADD( len2, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        /* encryptionIdentifier := pbes2 oid */
        len1 += len2;
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_oid( &c, der_base,
                              MBEDTLS_OID_PKCS5_PBES2,
                              sizeof(MBEDTLS_OID_PKCS5_PBES2)-1 ));
        /* encryptionAlgirithm SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_len( &c, der_base, len1 ) );
        MBEDTLS_ASN1_CHK_ADD( len1, mbedtls_asn1_write_tag( &c, der_base,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
        break;
    }

    len0 += len1;
    MBEDTLS_ASN1_CHK_ADD( len0, mbedtls_asn1_write_len( &c, der_base, len0 ) );
    MBEDTLS_ASN1_CHK_ADD( len0, mbedtls_asn1_write_tag( &c, der_base,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));

    *der_buf = c;
    return( (int)len0 );
}


#if defined(MBEDTLS_PEM_WRITE_C)

#define PEM_BEGIN_PUBLIC_KEY        "-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY          "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY       "-----BEGIN PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY         "-----END PRIVATE KEY-----\n"
#define PEM_BEGIN_ENC_PRIVATE_KEY   "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
#define PEM_END_ENC_PRIVATE_KEY     "-----END ENCRYPTED PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"

#define PEM_PROC_TYPE	            "Proc-Type: 4,ENCRYPTED"
#define PEM_DEK_INFO                "DEK-Info: "

int mbedtls_pk_write_pubkey_pem( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char output_buf[PUB_DER_MAX_BYTES];
    size_t olen = 0;

    PK_VALIDATE_RET( key != NULL );
    PK_VALIDATE_RET( buf != NULL || size == 0 );

    if( ( ret = mbedtls_pk_write_pubkey_der( key, output_buf,
                                     sizeof(output_buf) ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int mbedtls_pk_write_key_pem( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char output_buf[PRV_DER_MAX_BYTES];
    const char *begin, *end;
    size_t olen = 0;

    PK_VALIDATE_RET( key != NULL );
    PK_VALIDATE_RET( buf != NULL || size == 0 );

    if( ( ret = mbedtls_pk_write_key_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_RSA;
        end = PEM_END_PRIVATE_KEY_RSA;
    }
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_EC;
        end = PEM_END_PRIVATE_KEY_EC;
    }
    else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    if( ( ret = mbedtls_pem_write_buffer( begin, end,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int mbedtls_pk_write_key_pkcs8_pem( const mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char output_buf[PKCS8_DER_MAX_BYTES];
    size_t olen = 0;

    PK_VALIDATE_RET( key != NULL );
    PK_VALIDATE_RET( buf != NULL || size == 0 );

    if( ( ret = mbedtls_pk_write_key_pkcs8_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
        return( ret );

    ret = mbedtls_pem_write_buffer( PEM_BEGIN_PRIVATE_KEY, PEM_END_PRIVATE_KEY,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen );
    return( ret );
}

int mbedtls_pk_write_key_encrypted_pem( const mbedtls_pk_context *ctx, 
                                  unsigned char *buf, size_t *psize, 
                                  mbedtls_cipher_type_t enc_alg, 
                                  const unsigned char *pwd, size_t pwd_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char der_buf[ PRV_DER_MAX_BYTES + MBEDTLS_MAX_BLOCK_LENGTH ];
    const char *begin, *end;
    size_t der_len, r;
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t cipher_ctx;
    unsigned char iv[ MBEDTLS_MAX_IV_LENGTH ];
    unsigned char cipher_key[ MBEDTLS_MAX_KEY_LENGTH ];
    char pem_header[ 256 ];
    char *pout;

    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( psize != NULL );
    PK_VALIDATE_RET( buf != NULL || size == 0 );
    PK_VALIDATE_RET( pwd != NULL && pwd_len == 0 );
    PK_VALIDATE_RET( f_rng != NULL );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( ctx ) == MBEDTLS_PK_RSA )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_RSA;
        end = PEM_END_PRIVATE_KEY_RSA;
    }
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( ctx ) == MBEDTLS_PK_ECKEY )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_EC;
        end = PEM_END_PRIVATE_KEY_EC;
    }
    else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    cipher_info = mbedtls_cipher_info_from_type( enc_alg );
    if ( NULL == cipher_info ) return( MBEDTLS_ERR_PK_INVALID_ALG );

    if( ( ret = mbedtls_pk_write_key_der( ctx, der_buf, sizeof(der_buf) ) ) < 0 )
        return( ret );
    der_len = (size_t)ret;
    /* 
     * Note: mbedtls_cipher_crypt() (like as mbedtls_cipher_upate()) may padd
     * if input buffer != output buffer; it is our case, so use embedded padding
     */

    f_rng( p_rng, iv, cipher_info->iv_size ); /* generate IV */

    pout = strcpy( pem_header, begin );
        pout += strlen((char*)pout); /* \n inside */
    strcpy( (char*)pout, PEM_PROC_TYPE ); pout += strlen((char*)pout);
        *pout++ = '\n';
    strcpy( (char*)pout, PEM_DEK_INFO ); pout += strlen((char*)pout);
    strcpy( (char*)pout, cipher_info->name ); pout += strlen((char*)pout);
    *pout++ = ',';
    for ( r = 0; r < cipher_info->iv_size; r++ ) {
        register char c = ( iv[r] >> 4 ) & 0x0F;

        *pout++ = c < 10 ? '0' + c : 'A' - 10 + c;
        c = iv[r] & 0x0F;
        *pout++ = c < 10 ? '0' + c : 'A' - 10 + c;
    }
    *pout++ = '\n';
    *pout++ = '\n';
    *pout = '\0';

    mbedtls_cipher_init( &cipher_ctx );
    mbedtls_cipher_setup( &cipher_ctx, cipher_info );

    if( ( ret = mbedtls_pem_pbkdf1( cipher_key, cipher_info->key_bitlen/8, 
                                    iv, pwd, pwd_len ) ) != 0 )
        goto cipher_exit;

    if( ( ret = mbedtls_cipher_setkey( &cipher_ctx, cipher_key,
                           cipher_info->key_bitlen, MBEDTLS_ENCRYPT ) ) != 0 )
        goto cipher_exit;

    /* padding will be used now; input buffer != output here
       note: mbedtls_cipher_crypt() cannot padd if in-place encrypting */
    ret = mbedtls_cipher_crypt( &cipher_ctx, iv, cipher_info->iv_size,
                                der_buf + sizeof(der_buf) - der_len, der_len,
                                der_buf, &r );

cipher_exit:
    mbedtls_cipher_free( &cipher_ctx );

    if( 0 == ret ) ret = mbedtls_pem_write_buffer( pem_header, end, der_buf, r,
                                  buf, *psize, psize );

    return( ret );
}

int mbedtls_pk_write_key_pkcs8_encrypted_pem( const mbedtls_pk_context *ctx, 
         mbedtls_pbes_t key_fmt, unsigned char *buf, size_t *psize, 
         mbedtls_cipher_type_t enc_alg, mbedtls_md_type_t md_alg, int iterations,
         const unsigned char *pwd, size_t pwd_len,
         int (*f_rng)(void *, unsigned char *, size_t),
         void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char der_buf[ PKCS8_ENC_DER_MAX_BYTES + MBEDTLS_MAX_BLOCK_LENGTH ];
    unsigned char *pder = der_buf;

    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( psize != NULL );
    PK_VALIDATE_RET( buf != NULL || size == 0 );
    PK_VALIDATE_RET( pwd != NULL && pwd_len == 0 );
    PK_VALIDATE_RET( f_rng != NULL );

    /* 'pder' will be updated by mbedtls_pk_write_key_pkcs8_encrypted_der()
     * because some padding will be reserved at the end of buffer */
    if( ( ret = mbedtls_pk_write_key_pkcs8_encrypted_der( ctx, key_fmt,
            &pder, sizeof(der_buf), enc_alg, md_alg, iterations,
            pwd, pwd_len, f_rng, p_rng ) ) < 0 ) return( ret );

    ret = mbedtls_pem_write_buffer( PEM_BEGIN_ENC_PRIVATE_KEY, PEM_END_ENC_PRIVATE_KEY,
                                    pder, (size_t)ret, buf, *psize, psize );

    return( ret );
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_PK_WRITE_C */
