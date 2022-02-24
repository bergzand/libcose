
#include "cose.h"
#include <hss.h>
#include <hash_sig_api.h>


int keygen_hss(unsigned char *sk, unsigned char *pk)
{
	return keygen(sk, pk);
}

int sign_hss(unsigned char *signed_message, unsigned long long *signed_message_len, const unsigned char *message, unsigned long long message_len, unsigned char *private_key)
{
	return sign(signed_message, signed_message_len, message, message_len, private_key);
}

int verify_hss(unsigned char *pk, unsigned char *sig, unsigned long long signature_len, unsigned char *message, unsigned long long message_len)
{
	return verify(pk, sig, signature_len, message, message_len);
}

size_t cose_crypto_sig_size_hss(void)
{
	return CRYPTO_BYTES;
}

#endif /*CRYPTO_HSS */
