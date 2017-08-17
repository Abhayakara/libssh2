/*
 * Copyright (C) 2017 Edward W Lemon III
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <CommonCrypto/CommonDigest.h>

#define LIBSSH2_MD5 0

#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 0
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 0

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 0

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32

typedef CC_SHA1_CTX libssh2_sha1_ctx;
typedef CC_SHA256_CTX libssh2_sha256_ctx;
typedef CC_MD5_CTX libssh2_md5_ctx;
typedef CCHmacContext libssh2_hmac_ctx;

typedef CCCryptorRef _libssh2_cipher_ctx;
typedef SecKeyRef libssh2_rsa_ctx;

typedef struct {
  CCAlgorithm alg;
  CCMode mode;
  size_t keyLength;	
} _libssh2_iosc_cipher_type;

#define _libssh2_cipher_type(name) _libssh2_iosc_cipher_type name

extern _libssh2_cipher_type(_libssh2_cipher_aes256ctr);
extern _libssh2_cipher_type(_libssh2_cipher_aes192ctr);
extern _libssh2_cipher_type(_libssh2_cipher_aes128ctr);
extern _libssh2_cipher_type(_libssh2_cipher_aes256);
extern _libssh2_cipher_type(_libssh2_cipher_aes192);
extern _libssh2_cipher_type(_libssh2_cipher_aes128);

#define _libssh2_gcry_ciphermode(c,m) ((c << 8) | m)
#define _libssh2_gcry_cipher(c) (c >> 8)
#define _libssh2_gcry_mode(m) (m & 0xFF)

#define _libssh2_bn struct gcry_mpi
#define _libssh2_bn_ctx int

#define _libssh2_dh_ctx struct gcry_mpi *

