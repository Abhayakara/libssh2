/* Copyright (C) 2017 Edward W Lemon III
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

#include "libssh2_priv.h"

#ifdef LIBSSH2_IOSCRYPT /* compile only if we build with iOS crypto framework */

#include <string.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static int
error_to_libssh2_error(CFErrorRef error)
{
  CFStringRef *descrStr = CFErrorCopyDescription(error);
  const char *descr;
  char errbuf[512];
  
  descr = CFStringGetCStringPtr(descrStr, kCFStringEncodingUTF8);
  if (descr == NULL)
    {
      if (CFStringGetCString(descrStr,
			     errbuf, sizeof errbuf, kCFStringEncodingUTF8) == false)
	errbuf[(sizeof errbuf) - 1] = 0;
      descr = errbuf;
    }
  err = _libssh2_error(session, LIBSSH2_ERROR_INVAL, descr);
  CFRelease(error);
  CFRelease(descrStr);
}

void
_libssh2_random(unsigned char *buf, int len)
{
  if (errSecSuccess == SecRandomCopyBytes(kSecRandomDefault, len, buf))
    return;

  /* XXX
     In principle, the only thing that can cause an error return here is
     a bad parameter, which is to say a programming error.   It may be
     possible for there to be no entropy, but the API doesn't call that
     out as a possible failure mode.
     So on that assumption, all we can really do at this point is abort;
     to continue operation would fail insecure, at best. */
  abort();
}

void
libssh2_prepare_iovec(void *vec, size_t len)
{
  memset(vec, 0, len);
}

/* returns 0 in case of failure */
int
libssh2_sha1_init(libssh2_sha1_ctx *ctx)
{
  CC_SHA1_Init(ctx);
  return 1;
}

void
libssh2_sha1_update(libssh2_sha1_ctx *ctx, unsigned char *data, int len)
{
  CC_SHA1_Update(ctx, data, len);
}

void
libssh2_sha1_final(libssh2_sha1_ctx *ctx, unsigned char *out)
{
  CC_SHA1_Final(ctx, out);
}

void
libssh2_sha1(const unsigned char *message, unsigned long len, unsigned char *out)
{
  CC_SHA1(message, len, out);
}

/* returns 0 in case of failure */
int
libssh2_sha256_init(libssh2_sha256_ctx *ctx)
{
  CC_SHA256_Init(ctx);
  return 1;
}

void
libssh2_sha256_update(libssh2_sha256_ctx *ctx, unsigned char *data, int len)
{
  CC_SHA256_Update(ctx, data, len);
}

void
libssh2_sha256_final(libssh2_sha256_ctx *ctx, unsigned char *out)
{
  CC_SHA256_Final(ctx, out);
}

void
libssh2_sha256(const unsigned char *message, unsigned long len, unsigned char *out)
{
  CC_SHA256(message, len, out);
}


void
libssh2_hmac_ctx_init(libssh2_hmac_ctx *ctx)
{
  // The library initializes the context when the key initialization is done.
}

void
libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx, void *key, int keylen)
{
  CCHmacInit(ctx, kCCHmacSHA1, key, keylen);
}

void
libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx, void *key, int keylen)
{
  CCHmacInit(ctx, kCCHmacSHA256, key, keylen);
}

void
libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx, void *key, int keylen)
{
  CCHmacInit(ctx, kCCHmacSHA512, key, keylen);
}

void
libssh2_hmac_update(libssh2_hmac_ctx *ctx, unsigned char *data, int datalen)
{
  CCHmacUpdate(ctx, data, datalen);
}

void
libssh2_hmac_final(libssh2_hmac_ctx *ctx, void *out)
{
  CCHmacFinal(ctx, out);
}

void
libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx)
{
  /* The source code for the HMAC library seems to suggest that if
     CCHmacDestroy is called on the HMAC context, it will free it.
     That doesn't make sense since it never allocates it on init.
     So we just zero the memory. */
  memset(ctx, 0, sizeof *ctx);
}

_libssh2_cipher_type(_libssh2_cipher_aes256ctr);
_libssh2_cipher_type(_libssh2_cipher_aes192ctr);
_libssh2_cipher_type(_libssh2_cipher_aes128ctr);
_libssh2_cipher_type(_libssh2_cipher_aes256);
_libssh2_cipher_type(_libssh2_cipher_aes192);
_libssh2_cipher_type(_libssh2_cipher_aes128);

void
libssh2_crypto_init()
{
  _libssh2_cipher_aes256ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes256ctr.mode = kCCModeCTR;
  _libssh2_cipher_aes256ctr.keyLength = kCCKeySizeAES256;
  
  _libssh2_cipher_aes256ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes256ctr.mode = kCCModeCBC;
  _libssh2_cipher_aes256ctr.keyLength = kCCKeySizeAES256;
  
  _libssh2_cipher_aes192ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes192ctr.mode = kCCModeCTR;
  _libssh2_cipher_aes192ctr.keyLength = kCCKeySizeAES192;
  
  _libssh2_cipher_aes192ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes192ctr.mode = kCCModeCBC;
  _libssh2_cipher_aes192ctr.keyLength = kCCKeySizeAES192;
  
  _libssh2_cipher_aes128ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes128ctr.mode = kCCModeCTR;
  _libssh2_cipher_aes128ctr.keyLength = kCCKeySizeAES128;
  
  _libssh2_cipher_aes128ctr.alg = kCCAlgorithmAES;
  _libssh2_cipher_aes128ctr.mode = kCCModeCBC;
  _libssh2_cipher_aes128ctr.keyLength = kCCKeySizeAES128;
}  

void
libssh2_crypto_exit()
{
}

void _libssh2_init_aes_ctr(void)
{
}

// Creates an RSA public key object as in RFC8017 section 3.1, with
// d = /edata/, n = /ndata/, or else an RSA public/private key pair as
// in RFC8017 section 3.2 representation 2, with zero triplets.  These
// appear to only ever be used by hostkey.c.
//
// Actually, this only seems to ever be used to make a key object
// out of a public key.
//
// Stores an opaque pointer through /rsa/ with the key that's produced
// The key is subsequently freed by a call to _libssh2_rsa_free

int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
                 const unsigned char *edata,
                 unsigned long elen,
                 const unsigned char *ndata,
                 unsigned long nlen,
                 const unsigned char *ddata,
                 unsigned long dlen,
                 const unsigned char *pdata,
                 unsigned long plen,
                 const unsigned char *qdata,
                 unsigned long qlen,
                 const unsigned char *e1data,
                 unsigned long e1len,
                 const unsigned char *e2data,
                 unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
  CFNumberRef num;
  CFMutableDictionaryRef dict;
  int bits;
  unsigned char *buf = 0, *saved_buf;
  int buflen = 0, saved_len;
  int content_len = 0;
  int private = 0;
  CFDataRef cfdata;
  CFErrorRef error;
  SecKeyRef key;

 
  /* Figure out how big the key data is going to be. */
  if (ddata) {
    private = 1;
    content_len = (asn1_number(NULL, NULL, 1, '\0') +
		   asn1_number(NULL, NULL, nlen, ndata) +
		   asn1_number(NULL, NULL, elen, edata) +
		   asn1_number(NULL, NULL, dlen, ddata) +
		   asn1_number(NULL, NULL, plen, pdata) +
		   asn1_number(NULL, NULL, qlen, qdata) +
		   asn1_number(NULL, NULL, coefflen, coeffdata));
    buflen = asn1_sequence(NULL, NULL, content_len);
  } else {
    content_len = (asn1_number(NULL, NULL, nlen, ndata) +
		   asn1_number(NULL, NULL, elen, edata));
    buflen = asn1_sequence(NULL, NULL, content_len);
  }

  buf = malloc(buflen);
  if (buf == NULL) {
    *rsa = 0;
    return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
			  "Unable to allocate buffer for key ASN.1 DER");
  }

  saved_buf = buf;
  saved_len = buflen;

  /* Now copy the ASN.1 DER format key into the buffer. */
  if (ddata) {
    asn1_sequence(&buf, &buflen, content_len);
    asn1_number(&buf, &buflen, 1, '\0');
    asn1_number(&buf, &buflen, nlen, ndata);
    asn1_number(&buf, &buflen, elen, edata);
    asn1_number(&buf, &buflen, dlen, ddata);
    asn1_number(&buf, &buflen, plen, pdata);
    asn1_number(&buf, &buflen, qlen, qdata);
    asn1_number(&buf, &buflen, coefflen, coeffdata);
  } else {
    asn1_sequence(&buf, &buflen, content_len);
    asn1_number(&buf, &buflen, nlen, ndata);
    asn1_number(&buf, &buflen, elen, edata);
  }	   

  /* If the modulus begins with a zero byte, the actual number of bits in
     the number is (bytes-1)*8, rather than bytes*8. */
  if (ndata[0] == 0)
    bits = (nlen - 1) * 8;
  else
    bits = nlen * 8;
    
  /* Now we can ask the Security Framework to construct the key data structure. */
  dict = CFDictionaryCreateMutable(NULL, 3, &kCFCopyStringDictionaryKeyCallBacks, 
				   &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA);
  CFDictionarySetValue(dict, kSecAttrKeyClass,
		       private ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic);
  num = CFNumberCreate(NULL, kCFNumberIntType, &bits)
  CFDictionarySetValue(dict, kSecAttrKeySizeInBits, num);
  CFRelease(num);
  cfdata = CFDataCreateWithBytesNoCopy(NULL, save_data, save_len, kCFAllocatorNull);

  error = NULL;
  key = SecKeyCreateWithData(cfdata, dict, &error);
  CFRelease(cfdata);
  CFRelease(dict);

  if (!key)
    return error_to_libssh2_error(error);
  *rsa = key;
  return 0;
}

int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                         const unsigned char *sig,
                         unsigned long sig_len,
                         const unsigned char *m, unsigned long m_len)
{
    CFErrorRef error = NULL;
    CFDataRef signature = CFDataCreateWithBytesNoCopy(NULL, sig, sig_len, kCFAllocatorNull);
    CFDataRef message = CFDataCreateWithBytesNoCopy(NULL, m, m_len, kCFAllocatorNull);
    result = SecKeyVerifySignature(rsa, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
				   signature, message, &error);
    CFRelease(signature);
    CFRelease(message);

    if (!result)
      return error_to_libssh2_error(error);
    return 0;
}

int
_libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                         "Unable to extract private key from memory: "
                         "Method unimplemented in ioscrypt backend");
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, unsigned const char *passphrase)
{
    FILE *fp;
    unsigned char *data, *save_data;
    unsigned int datalen, save_len;
    int ret;
    unsigned char *n, *e, *d, *p, *q, *e1, *e2, *coeff;
    unsigned int nlen, elen, dlen, plen, qlen, e1len, e2len, coefflen;
    CFNumberRef num;
    CFMutableDictionaryRef dict;
    CFDataRef cfdata;
    CFErrorRef error;
    SecKeyRef key;

    fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    ret = _libssh2_pem_parse(session,
                             "-----BEGIN RSA PRIVATE KEY-----",
                             "-----END RSA PRIVATE KEY-----",
                             passphrase,
                             fp, &data, &datalen);
    fclose(fp);
    if (ret) {
        return -1;
    }

    save_data = data;
    save_len = len;

    /* Decode far enough to get the key length, which we need for the
       Security framework function.
       Skip over the sequence and validate that it is the entire
       data set. */
    if (_libssh2_pem_decode_sequence(&data, &datalen)) {
        ret = -1;
        goto fail;
    }

    /* Read the version (MBZ) */
    ret = _libssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if (ret != 0 || (nlen != 1 && *n != '\0')) {
        ret = -1;
        goto fail;
    }

    /* Get the modulus length. */
    ret = _libssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if (ret != 0) {
        ret = -1;
        goto fail;
    }

    /* Get the key length.  We assume that the length in bytes is
       eight times the length in bits; a 2047-bit modulus is not
       allowed.  If the leftmost nonzero bit of the modulus is set, it
       will be represented with a leading zero byte, meaning that the
       length will be (- (/ length-in-bits 8) 1), so we need to
       subtract 1 in that case. */
    if (*n == 0)
      bits = (nlen - 1) * 8;
    else
      bits = nlen * 8;
 
    dict = CFDictionaryCreateMutable(NULL, 3, &kCFCopyStringDictionaryKeyCallBacks, 
				     &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(dict, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    num = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(dict, kSecAttrKeySizeInBits, num);
    CFRelease(num);

    /* XXX I'm assuming that SecKeyCreateWithData doesn't hold a reference
       XXX to cfdata. */
    cfdata = CFDataCreateWithBytesNoCopy(NULL, save_data, save_len, kCFAllocatorNull);
    error = NULL;
    key = SecKeyCreateWithData(cfdata, dict, &error);

    CFRelease(cfdata);
    CFRelease(dict);
    LIBSSH2_FREE(session, save_data);
    if (!key)
      return error_to_libssh2_error(error);

    /* error should always be null in this case */
    *rsa = key;
    return 0;
}

int
_libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                         "Unable to extract public key from private key in memory: "
                         "Method unimplemented in libgcrypt backend");
}

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                         "Unable to extract public key from private key file: "
                         "Method unimplemented in libgcrypt backend");
}

void
_libssh2_rsa_free(libssh2_rsa_ctx *rsactx)
{
  CFrelease(*rsactx);
}

int
_libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                       libssh2_rsa_ctx * rsactx,
                       const unsigned char *hash,
                       size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    CFErrorRef error = NULL;
    CFDataRef sig;
    CFDataRef message = CFDataCreateWithBytesNoCopy(NULL, m, m_len, kCFAllocatorNull);
    int size;
    CFRange range;
    sig = SecKeyCreateSignature(rsactx, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
				message, &error);
    CFRelease(message);

    if (!sig)
      return error_to_libssh2_error(error);

    *size = CFDataGetLength(sig);
    *sig = LIBSSH2_ALLOC(session, size);
    if (*sig == 0) {
	CFRelease(sig);
	return LIBSSH2_ERR_ALLOC;
      }
    *signature_len = size;
    range = CFRangeMake(0, size);
    CFDataGetBytes(sig, range, *signature);
    CFRelease(sig);
    return 0;
}

int
_libssh2_cipher_init(_libssh2_cipher_ctx * h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
  CCCryptorStatus status;

  status = CCCryptorCreate(encrypt ? kCCEncrypt : kCCDecrypt,
			   algo->alg, 0, secret, algo->keyLength, iv, h);

  /* There are a variety of errors that can be returned here that
   * could be translated into libssh2 errors, but I don't think there's
   * much point; the only one that's not a programming error is "out of
   * memory", and there's limited value to calling that out specially.
   */
  if (status != kCCSuccess)
    return -1;
  return 0;
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blklen)
{
  CCCryptorStatus status;
  size_t moved;

  status = CCCryptorUpdate(*ctx, block, blklen, block, blklen, &moved);
  if (status != kCCSuccess)
    return -1;
  if (moved != blklen)
    return -1;
  return 0;
}

void
_libssh2_cipher_dtor(_libssh2_cipher_ctx ctx)
{
  CCCryptorRelease(ctx);
}

_libssh2_bn *
libssh2_bn_init(void)
{
  _libssh2_bn *rv = malloc(sizeof *rv);
  if (rv == NULL)
    return rv;
  memset(rv, 0, sizeof *rv);
  return rv;
}

void
libssh2_bn_free(_libssh2_bn *bn)
{
  if (bn->num)
    {
#ifdef LIBSSH2_CLEAR_MEMORY
      CCBigNumClear(bn->num);
#endif
      CCBigNumFree(bn->num);
    }
  free(bn);
}

void *
_libssh2_bn_ctx_new()
{
  return (void *)0;
}

void
_libssh2_bn_ctx_free(bnctx)
{
}

libssh2_bn *
libssh2_bn_init_from_bin()
{
  return libssh2_bn_init();
}

void
_libssh2_bn_set_word(_libssh2_bn *bn, unsigned long val)
{
  CCStatus status;
  char numbuf[20];
  snprintf(numbuf, sizeof numbuf, "%lu", val);
  bn->num = CCBigNumFromDecimalString(&status, numbuf);
  /* We don't have a way to indicate an error here. */
}

void
_libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const void *val)
{
  CCStatus status;
  bn->num = CCBigNumFromData(&status, val, len);
  /* We don't have a way to indicate an error here. */
}

void
_libssh2_bn_to_bin(_libssh2_bn *bn, const void *val)
{
  CCBugNumStatus status;
  if (bn->num)
    size_t len = CCBigNumToData(&status, bn->num, val);
}

int
libssh2_bn_bytes(_libssh2_bn *bn)
{
  if (!bn->num)
    return 0;
  return CCBigNumByteCount(bn->num);
}

uint32_t
_libssh2_bn_bits(_libssh2_bn *bn)
{
  if (!bn->num)
    return 0;
  return CCBigNumBitCount(bn->num);
}

#define libssh2_dh_init(dhctx) _libssh2_dh_init(dhctx)
#define libssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx) \
        _libssh2_dh_key_pair(dhctx, public, g, p, group_order)
#define libssh2_dh_secret(dhctx, secret, f, p, bnctx) \
        _libssh2_dh_secret(dhctx, secret, f, p)
#define libssh2_dh_dtor(dhctx) _libssh2_dh_dtor(dhctx)

void
_libssh2_dh_init(_libssh2_dh_ctx *dhctx)
{
  *dhctx = _libssh2_bn_new();
}

int
_libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                     _libssh2_bn *g, _libssh2_bn *p, int group_order)
{
  int bits = group_order * 8 - 1;
  CCStatus status;
  /* Generate x and e */
  (*dhctx)->num = CCBigNumCreateRandom(&status, bits, bits, 0);
  if (public->num || !g->num || !p->num)
    return LIBSSH2_ERROR_INVAL;
  public->num = CCCreateBigNum(&status);
  if (status != kCCSuccess)
    return LIBSSH2_ERROR_INVAL;
  status = CCBigNumModExp(public->num, g->num, (*dhctx)->num, p->num);
  if (status != kCCSuccess)
    return LIBSSH2_ERROR_INVAL;
  return 0;
}

int
_libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                   _libssh2_bn *f, _libssh2_bn *p)
{
  CCStatus status;
  /* Compute the shared secret */
  if (secret->num || !f->num || !(*dhctx)->num || !p->num)
    return LIBSSH2_ERROR_INVAL;
  public->num = CCCreateBigNum(&status);
  if (status != kCCSuccess)
    return LIBSSH2_ERROR_INVAL;
  status = CCBigNumModExp(secret->num, f, *dhctx, p);
  if (status != kCCSuccess)
    return LIBSSH2_ERROR_INVAL;
  return 0;
}

void
_libssh2_dh_dtor(_libssh2_dh_ctx *dhctx)
{
  _libssh2_bn_free(*dhctx);
  *dhctx = NULL;
}

#endif /* LIBSSH2_LIBGCRYPT */
