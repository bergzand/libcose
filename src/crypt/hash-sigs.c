#include <stdint.h>
#include <hss.h>
#include <hash_sig_api.h>
#include "cose.h"

int cose_crypto_keypair_hsslms(cose_key_t *key)
{
    key->algo = COSE_ALGO_HSSLMS;
    int res = keygen(key->d, key->x);

    return res ? COSE_OK : COSE_ERR_CRYPTO;;
}

int cose_crypto_sign_hsslms(const cose_key_t *key, uint8_t *sig, size_t *siglen,
                            uint8_t *msg, unsigned long long int msglen)
{
    /* cose provides siglen as `size_t`, hash-sigs uses `long long unsigned` ... */
    unsigned long long siglen_tmp = *siglen;

    int res = sign(sig, &siglen_tmp, msg, msglen, key->d);

    *siglen = siglen_tmp;

    return res ? COSE_OK : COSE_ERR_CRYPTO;;
}

int cose_crypto_verify_hsslms(const cose_key_t *key, const uint8_t *sig,
                              size_t siglen, uint8_t *msg, uint64_t msglen)
{
    int res = verify(key->d, (unsigned char *)sig, siglen, msg, msglen);
    return res ? COSE_OK : COSE_ERR_CRYPTO;;
}

size_t cose_crypto_sig_size_hsslms(void)
{
    return CRYPTO_BYTES;
}
