/*
 *  Privacy Enhanced Mail (PEM) decoding
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

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)

#include "mbedtls/pem.h"
#include "mbedtls/base64.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/cipher.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
void mbedtls_pem_init( mbedtls_pem_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_pem_context ) );
}

#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_C)
/*
 * Read a 16-byte hex string and convert it to binary
 */
static int pem_get_iv( const unsigned char *s, unsigned char *iv,
                       size_t iv_len )
{
    size_t i, j, k;

    memset( iv, 0, iv_len );

    for( i = 0; i < iv_len * 2; i++, s++ )
    {
        if( *s >= '0' && *s <= '9' ) j = *s - '0'; else
        if( *s >= 'A' && *s <= 'F' ) j = *s - '7'; else
        if( *s >= 'a' && *s <= 'f' ) j = *s - 'W'; else
            return( MBEDTLS_ERR_PEM_INVALID_ENC_IV );

        k = ( ( i & 1 ) != 0 ) ? j : j << 4;

        iv[i >> 1] = (unsigned char)( iv[i >> 1] | k );
    }

    return( 0 );
}

int mbedtls_pem_pbkdf1( unsigned char *key, size_t keylen,
                       unsigned char *iv,
                       const unsigned char *pwd, size_t pwdlen )
{
    mbedtls_md5_context md5_ctx;
    unsigned char md5sum[16];
    size_t use_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md5_init( &md5_ctx );

    /*
     * key[ 0..15] = MD5(pwd || IV)
     */
    if( ( ret = mbedtls_md5_starts_ret( &md5_ctx ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_update_ret( &md5_ctx, pwd, pwdlen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_update_ret( &md5_ctx, iv,  8 ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_finish_ret( &md5_ctx, md5sum ) ) != 0 )
        goto exit;

    if( keylen <= 16 )
    {
        memcpy( key, md5sum, keylen );
        goto exit;
    }

    memcpy( key, md5sum, 16 );

    /*
     * key[16..23] = MD5(key[ 0..15] || pwd || IV])
     */
    if( ( ret = mbedtls_md5_starts_ret( &md5_ctx ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_update_ret( &md5_ctx, md5sum, 16 ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_update_ret( &md5_ctx, pwd, pwdlen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_update_ret( &md5_ctx, iv, 8 ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md5_finish_ret( &md5_ctx, md5sum ) ) != 0 )
        goto exit;

    use_len = 16;
    if( keylen < 32 )
        use_len = keylen - 16;

    memcpy( key + 16, md5sum, use_len );

exit:
    mbedtls_md5_free( &md5_ctx );
    mbedtls_platform_zeroize( md5sum, 16 );

    return( ret );
}

#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_C */

int mbedtls_pem_read_buffer( mbedtls_pem_context *ctx, const char *header, const char *footer,
                     const unsigned char *data, const unsigned char *pwd,
                     size_t pwdlen, size_t *use_len )
{
    int ret, enc;
    size_t len, iv_len = 0;
    unsigned char *buf;
    const unsigned char *s1, *s2, *end;
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_C)
    unsigned char pem_iv[16];
    const mbedtls_cipher_info_t *cipher_info = NULL;
#else
    ((void) pwd);
    ((void) pwdlen);
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_C */

    if( ctx == NULL )
        return( MBEDTLS_ERR_PEM_BAD_INPUT_DATA );

    s1 = (unsigned char *) strstr( (const char *) data, header );

    if( s1 == NULL )
        return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s2 = (unsigned char *) strstr( (const char *) data, footer );

    if( s2 == NULL || s2 <= s1 )
        return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s1 += strlen( header );
    if( *s1 == ' '  ) s1++;
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;
    else return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    end = s2;
    end += strlen( footer );
    if( *end == ' '  ) end++;
    if( *end == '\r' ) end++;
    if( *end == '\n' ) end++;
    *use_len = end - data;

    enc = 0;

    if( s2 - s1 >= 22 && memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
    {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_C)
        enc++;

        s1 += 22;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
        else return( MBEDTLS_ERR_PEM_INVALID_DATA );

        if( s2 - s1 >= 9 && memcmp( s1, "DEK-Info:", 9 ) == 0 )
        {
            unsigned char cipher[ 32 ];
            const unsigned char *tmp1 = s1 + 9;
            unsigned char *tmp2 = cipher;

            while ( tmp1 < s2 && ' ' == *tmp1 ) tmp1++;
            while ( tmp1 < s2 && tmp2 < cipher + sizeof(cipher)-1
                    && ',' != *tmp1 && ' ' < *tmp1 ) *tmp2++ = *tmp1++;
            *tmp2 = '\0';
            s1 = tmp1 + ( ',' == *tmp1 ? 1 : 0 ); /* skip comma */

            cipher_info = mbedtls_cipher_info_from_string((const char*)cipher);
            if ( NULL != cipher_info )
            {
                iv_len = cipher_info->iv_size;
                if ( 0 == iv_len ) iv_len = cipher_info->block_size;
                if( s2 - s1 < (int)iv_len*2
                    || pem_get_iv( s1, pem_iv, iv_len) != 0 )
                {
                    return( MBEDTLS_ERR_PEM_INVALID_ENC_IV );
                }
                s1 += iv_len*2;
            }
        }

        if( NULL == cipher_info )
            return( MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG );

        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
        else return( MBEDTLS_ERR_PEM_INVALID_DATA );
#else
        return( MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_C */
    }

    if( s1 >= s2 )
        return( MBEDTLS_ERR_PEM_INVALID_DATA );

    ret = mbedtls_base64_decode( NULL, 0, &len, s1, s2 - s1 );

    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PEM_INVALID_DATA, ret ) );

    if( ( buf = mbedtls_calloc( 1, len ) ) == NULL )
        return( MBEDTLS_ERR_PEM_ALLOC_FAILED );

    if( ( ret = mbedtls_base64_decode( buf, len, &len, s1, s2 - s1 ) ) != 0 )
    {
        mbedtls_platform_zeroize( buf, len );
        mbedtls_free( buf );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PEM_INVALID_DATA, ret ) );
    }

    if( enc != 0 )
    {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_C)
        if( pwd == NULL )
        {
            mbedtls_platform_zeroize( buf, len );
            mbedtls_free( buf );
            return( MBEDTLS_ERR_PEM_PASSWORD_REQUIRED );
        }

        ret = 0;

        if( NULL != cipher_info )
        {
            mbedtls_cipher_context_t cipher_ctx;
            unsigned char cipher_key[ MBEDTLS_MAX_KEY_LENGTH ];

            mbedtls_cipher_init( &cipher_ctx );
            mbedtls_cipher_setup( &cipher_ctx, cipher_info );

            if( ( ret = mbedtls_pem_pbkdf1( cipher_key, cipher_info->key_bitlen/8,
                            pem_iv, pwd, pwdlen ) ) != 0 )
                goto cipher_exit;

            if( ( ret = mbedtls_cipher_setkey( &cipher_ctx, cipher_key,
                            cipher_info->key_bitlen, MBEDTLS_DECRYPT ) ) != 0 )
                goto cipher_exit;

            /* encrypted buffer is padded, so in-place decrypting is OK */
            ret = mbedtls_cipher_crypt( &cipher_ctx, pem_iv, iv_len,
                            buf, len, buf, &len );

            /* on wrong (misaligned) length */
            if ( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA == ret )
                ret = MBEDTLS_ERR_PEM_INVALID_INPUT_LENGTH;

            /* dirty results and damaged padding bytes due to wrong password */
            if ( MBEDTLS_ERR_CIPHER_INVALID_PADDING == ret )
                ret = MBEDTLS_ERR_PEM_PASSWORD_MISMATCH;

        cipher_exit:
            mbedtls_cipher_free( &cipher_ctx );
            mbedtls_platform_zeroize( cipher_key, sizeof(cipher_key) );
        }

        if( ret != 0 )
        {
            mbedtls_free( buf );
            return( ret );
        }

        /*
         * The result will be ASN.1 starting with a SEQUENCE tag, with 1 to 3
         * length bytes (allow 4 to be sure) in all known use cases.
         *
         * Use that as a heuristic to try to detect password mismatches.
         */
        if( len <= 2 || buf[0] != 0x30 || buf[1] > 0x83 )
        {
            mbedtls_platform_zeroize( buf, len );
            mbedtls_free( buf );
            return( MBEDTLS_ERR_PEM_PASSWORD_MISMATCH );
        }
#else
        mbedtls_platform_zeroize( buf, len );
        mbedtls_free( buf );
        return( MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_C */
    }

    ctx->buf = buf;
    ctx->buflen = len;

    return( 0 );
}

void mbedtls_pem_free( mbedtls_pem_context *ctx )
{
    if ( ctx->buf != NULL )
    {
        mbedtls_platform_zeroize( ctx->buf, ctx->buflen );
        mbedtls_free( ctx->buf );
    }
    mbedtls_free( ctx->info );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pem_context ) );
}
#endif /* MBEDTLS_PEM_PARSE_C */

#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_pem_write_buffer( const char *header, const char *footer,
                      const unsigned char *der_data, size_t der_len,
                      unsigned char *buf, size_t buf_len, size_t *olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *encode_buf = NULL, *c, *p = buf;
    size_t len = 0, use_len, add_len = 0;

    mbedtls_base64_encode( NULL, 0, &use_len, der_data, der_len );
    add_len = strlen( header ) + strlen( footer ) + ( use_len / 64 ) + 1;

    if( use_len + add_len > buf_len )
    {
        *olen = use_len + add_len;
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    if( use_len != 0 &&
        ( ( encode_buf = mbedtls_calloc( 1, use_len ) ) == NULL ) )
        return( MBEDTLS_ERR_PEM_ALLOC_FAILED );

    if( ( ret = mbedtls_base64_encode( encode_buf, use_len, &use_len, der_data,
                               der_len ) ) != 0 )
    {
        mbedtls_free( encode_buf );
        return( ret );
    }

    memcpy( p, header, strlen( header ) );
    p += strlen( header );
    c = encode_buf;

    while( use_len )
    {
        len = ( use_len > 64 ) ? 64 : use_len;
        memcpy( p, c, len );
        use_len -= len;
        p += len;
        c += len;
        *p++ = '\n';
    }

    memcpy( p, footer, strlen( footer ) );
    p += strlen( footer );

    *p++ = '\0';
    *olen = p - buf;

     /* Clean any remaining data previously written to the buffer */
    memset( buf + *olen, 0, buf_len - *olen );

    mbedtls_free( encode_buf );
    return( 0 );
}
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_PEM_PARSE_C || MBEDTLS_PEM_WRITE_C */

