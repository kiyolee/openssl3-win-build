/*
 * Copyright 2018-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from pvkkdf.c.in for https://github.com/kiyolee/openssl3-win-build.git.
 */


#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include "internal/common.h"
#include "internal/numbers.h"    /* SIZE_MAX */
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"

static OSSL_FUNC_kdf_newctx_fn kdf_pvk_new;
static OSSL_FUNC_kdf_dupctx_fn kdf_pvk_dup;
static OSSL_FUNC_kdf_freectx_fn kdf_pvk_free;
static OSSL_FUNC_kdf_reset_fn kdf_pvk_reset;
static OSSL_FUNC_kdf_derive_fn kdf_pvk_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_pvk_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_pvk_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn kdf_pvk_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn kdf_pvk_get_ctx_params;

typedef struct {
    void *provctx;
    unsigned char *pass;
    size_t pass_len;
    unsigned char *salt;
    size_t salt_len;
    PROV_DIGEST digest;
} KDF_PVK;

static void kdf_pvk_init(KDF_PVK *ctx);

static void *kdf_pvk_new(void *provctx)
{
    KDF_PVK *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->provctx = provctx;
    kdf_pvk_init(ctx);
    return ctx;
}

static void kdf_pvk_cleanup(KDF_PVK *ctx)
{
    ossl_prov_digest_reset(&ctx->digest);
    OPENSSL_free(ctx->salt);
    OPENSSL_clear_free(ctx->pass, ctx->pass_len);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void kdf_pvk_free(void *vctx)
{
    KDF_PVK *ctx = (KDF_PVK *)vctx;

    if (ctx != NULL) {
        kdf_pvk_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

static void *kdf_pvk_dup(void *vctx)
{
    const KDF_PVK *src = (const KDF_PVK *)vctx;
    KDF_PVK *dest;

    dest = kdf_pvk_new(src->provctx);
    if (dest != NULL)
        if (!ossl_prov_memdup(src->salt, src->salt_len,
                              &dest->salt, &dest->salt_len)
                || !ossl_prov_memdup(src->pass, src->pass_len,
                                     &dest->pass , &dest->pass_len)
                || !ossl_prov_digest_copy(&dest->digest, &src->digest))
            goto err;
    return dest;

 err:
    kdf_pvk_free(dest);
    return NULL;
}

static void kdf_pvk_reset(void *vctx)
{
    KDF_PVK *ctx = (KDF_PVK *)vctx;
    void *provctx = ctx->provctx;

    kdf_pvk_cleanup(ctx);
    ctx->provctx = provctx;
    kdf_pvk_init(ctx);
}

static void kdf_pvk_init(KDF_PVK *ctx)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_LIB_CTX *provctx = PROV_LIBCTX_OF(ctx->provctx);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 SN_sha1, 0);
    if (!ossl_prov_digest_load_from_params(&ctx->digest, params, provctx))
        /* This is an error, but there is no way to indicate such directly */
        ossl_prov_digest_reset(&ctx->digest);
}

static int pvk_set_membuf(unsigned char **buffer, size_t *buflen,
                             const OSSL_PARAM *p)
{
    OPENSSL_clear_free(*buffer, *buflen);
    *buffer = NULL;
    *buflen = 0;

    if (p->data_size == 0) {
        if ((*buffer = OPENSSL_malloc(1)) == NULL)
            return 0;
    } else if (p->data != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)buffer, 0, buflen))
            return 0;
    }
    return 1;
}

static int kdf_pvk_derive(void *vctx, unsigned char *key, size_t keylen,
                             const OSSL_PARAM params[])
{
    KDF_PVK *ctx = (KDF_PVK *)vctx;
    const EVP_MD *md;
    EVP_MD_CTX *mctx;
    int res;

    if (!ossl_prov_is_running() || !kdf_pvk_set_ctx_params(ctx, params))
        return 0;

    if (ctx->pass == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return 0;
    }

    if (ctx->salt == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return 0;
    }

    md = ossl_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return 0;
    }
    res = EVP_MD_get_size(md);
    if (res <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return 0;
    }
    if ((size_t)res > keylen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return 0;
    }

    mctx = EVP_MD_CTX_new();
    res = mctx != NULL
          && EVP_DigestInit_ex(mctx, md, NULL)
          && EVP_DigestUpdate(mctx, ctx->salt, ctx->salt_len)
          && EVP_DigestUpdate(mctx, ctx->pass, ctx->pass_len)
          && EVP_DigestFinal_ex(mctx, key, NULL);
    EVP_MD_CTX_free(mctx);
    return res;
}

/* Machine generated by util/perl/OpenSSL/paramnames.pm */
#ifndef pvk_set_ctx_params_list
static const OSSL_PARAM pvk_set_ctx_params_list[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_END
};
#endif

#ifndef pvk_set_ctx_params_st
struct pvk_set_ctx_params_st {
    OSSL_PARAM *digest;
    OSSL_PARAM *engine;
    OSSL_PARAM *pass;
    OSSL_PARAM *propq;
    OSSL_PARAM *salt;
};
#endif

#ifndef pvk_set_ctx_params_decoder
static int pvk_set_ctx_params_decoder
    (const OSSL_PARAM *p, struct pvk_set_ctx_params_st *r)
{
    const char *s;

    memset(r, 0, sizeof(*r));
    if (p != NULL)
        for (; (s = p->key) != NULL; p++)
            switch(s[0]) {
            default:
                break;
            case 'd':
                if (ossl_likely(strcmp("igest", s + 1) == 0)) {
                    /* OSSL_KDF_PARAM_DIGEST */
                    if (ossl_unlikely(r->digest != NULL)) {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                       "param %s is repeated", s);
                        return 0;
                    }
                    r->digest = (OSSL_PARAM *)p;
                }
                break;
            case 'e':
                if (ossl_likely(strcmp("ngine", s + 1) == 0)) {
                    /* OSSL_ALG_PARAM_ENGINE */
                    if (ossl_unlikely(r->engine != NULL)) {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                       "param %s is repeated", s);
                        return 0;
                    }
                    r->engine = (OSSL_PARAM *)p;
                }
                break;
            case 'p':
                switch(s[1]) {
                default:
                    break;
                case 'a':
                    if (ossl_likely(strcmp("ss", s + 2) == 0)) {
                        /* OSSL_KDF_PARAM_PASSWORD */
                        if (ossl_unlikely(r->pass != NULL)) {
                            ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                           "param %s is repeated", s);
                            return 0;
                        }
                        r->pass = (OSSL_PARAM *)p;
                    }
                    break;
                case 'r':
                    if (ossl_likely(strcmp("operties", s + 2) == 0)) {
                        /* OSSL_KDF_PARAM_PROPERTIES */
                        if (ossl_unlikely(r->propq != NULL)) {
                            ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                           "param %s is repeated", s);
                            return 0;
                        }
                        r->propq = (OSSL_PARAM *)p;
                    }
                }
                break;
            case 's':
                if (ossl_likely(strcmp("alt", s + 1) == 0)) {
                    /* OSSL_KDF_PARAM_SALT */
                    if (ossl_unlikely(r->salt != NULL)) {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                       "param %s is repeated", s);
                        return 0;
                    }
                    r->salt = (OSSL_PARAM *)p;
                }
            }
    return 1;
}
#endif
/* End of machine generated */

static int kdf_pvk_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct pvk_set_ctx_params_st p;
    KDF_PVK *ctx = vctx;
    OSSL_LIB_CTX *provctx;

    if (ctx == NULL || !pvk_set_ctx_params_decoder(params, &p))
        return 0;

    provctx = PROV_LIBCTX_OF(ctx->provctx);

    if (!ossl_prov_digest_load(&ctx->digest, p.digest, p.propq, p.engine,
                               provctx))
        return 0;

    if (p.pass != NULL && !pvk_set_membuf(&ctx->pass, &ctx->pass_len, p.pass))
        return 0;

    if (p.salt != NULL && !pvk_set_membuf(&ctx->salt, &ctx->salt_len, p.salt))
        return 0;

    return 1;
}

static const OSSL_PARAM *kdf_pvk_settable_ctx_params(ossl_unused void *ctx,
                                                        ossl_unused void *p_ctx)
{
    return pvk_set_ctx_params_list;
}

/* Machine generated by util/perl/OpenSSL/paramnames.pm */
#ifndef pvk_get_ctx_params_list
static const OSSL_PARAM pvk_get_ctx_params_list[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
#endif

#ifndef pvk_get_ctx_params_st
struct pvk_get_ctx_params_st {
    OSSL_PARAM *size;
};
#endif

#ifndef pvk_get_ctx_params_decoder
static int pvk_get_ctx_params_decoder
    (const OSSL_PARAM *p, struct pvk_get_ctx_params_st *r)
{
    const char *s;

    memset(r, 0, sizeof(*r));
    if (p != NULL)
        for (; (s = p->key) != NULL; p++)
            if (ossl_likely(strcmp("size", s + 0) == 0)) {
                /* OSSL_KDF_PARAM_SIZE */
                if (ossl_unlikely(r->size != NULL)) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                   "param %s is repeated", s);
                    return 0;
                }
                r->size = (OSSL_PARAM *)p;
            }
    return 1;
}
#endif
/* End of machine generated */

static int kdf_pvk_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct pvk_get_ctx_params_st p;
    KDF_PVK *ctx = vctx;

    if (ctx == NULL || !pvk_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.size != NULL && !OSSL_PARAM_set_size_t(p.size, SIZE_MAX))
        return 0;
    return 1;
}

static const OSSL_PARAM *kdf_pvk_gettable_ctx_params(ossl_unused void *ctx,
                                                        ossl_unused void *p_ctx)
{
    return pvk_get_ctx_params_list;
}

const OSSL_DISPATCH ossl_kdf_pvk_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_pvk_new },
    { OSSL_FUNC_KDF_DUPCTX, (void(*)(void))kdf_pvk_dup },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_pvk_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_pvk_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_pvk_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_pvk_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_pvk_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_pvk_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_pvk_get_ctx_params },
    OSSL_DISPATCH_END
};
