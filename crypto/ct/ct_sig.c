/*
 * Written by Rob Percival (robpercival@google.com) for the OpenSSL project
 * 2016.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifdef OPENSSL_NO_CT
# error "CT disabled"
#endif

#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

#include "ct_locl.h"

CT_SIGNATURE *CT_SIGNATURE_new(void)
{
    CT_SIGNATURE *ret;
 
    ret = OPENSSL_zalloc(sizeof(ret));
    if (ret == NULL) {
        CTerr(CT_F_CT_SIGNATURE_NEW, ERR_R_MALLOC_FAILURE);
    }

    return ret;
}

void CT_SIGNATURE_free(CT_SIGNATURE *sig)
{
    if (sig == NULL)
        return;

    OPENSSL_free(sig->value);
    OPENSSL_free(sig);
}

int CT_SIGNATURE_set_nid(CT_SIGNATURE *sig, int nid)
{
    switch (nid) {
    case NID_sha256WithRSAEncryption:
        sig->hash_alg = TLSEXT_hash_sha256;
        sig->sig_alg = TLSEXT_signature_rsa;
        return 1;
    case NID_ecdsa_with_SHA256:
        sig->hash_alg = TLSEXT_hash_sha256;
        sig->sig_alg = TLSEXT_signature_ecdsa;
        return 1;
    default:
        CTerr(CT_F_CT_SIGNATURE_SET_NID, CT_R_UNRECOGNIZED_SIGNATURE_NID);
        return 0;
    }
}

int CT_SIGNATURE_set1_value(CT_SIGNATURE *sig, const unsigned char *value,
                            size_t len)
{
    if (value == NULL) {
        sig->value = NULL;
        sig->len = 0;
        return 1;
    }

    sig->value = OPENSSL_memdup(value, len);
    sig->len = len;
    if (sig->value == NULL) {
        CTerr(CT_F_CT_SIGNATURE_SET1_VALUE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int CT_SIGNATURE_get_nid(const CT_SIGNATURE *sig)
{
    switch (sig->hash_alg) {
    case TLSEXT_hash_sha256:
        switch (sig->sig_alg) {
        case TLSEXT_signature_ecdsa:
            return NID_ecdsa_with_SHA256;
        case TLSEXT_signature_rsa:
            return NID_sha256WithRSAEncryption;
        default:
            return NID_undef;
        }
    default:
        return NID_undef;
    }
}

size_t CT_SIGNATURE_get0_value(const CT_SIGNATURE *sig, const unsigned char **value)
{
    *value = sig->value;
    return sig->len;
}

int ct_signature_is_complete(const CT_SIGNATURE *sig)
{
    return CT_SIGNATURE_get_nid(sig) != NID_undef &&
        sig->value != NULL && sig->len > 0;
}

