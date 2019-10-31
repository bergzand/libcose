#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cose/crypto.h>

int test() {
    uint8_t out[100];
    uint8_t salt[] = "1234567890abcdefghijklmnopqrstuv";
    uint8_t ikm[] = "abcdefghijklmnopqrst";
    uint8_t info[] = "HKDF TEST";
    size_t salt_len = 32;
    size_t ikm_len = 20;
    size_t info_len = 9;

    uint8_t expected[] = "\x20\xb5\x23\xe5\x51\x29\xf1\xdb\x54\xfe\xa4\xbd\x60\x84\xf2\x74\xb5\xc9\xcd\x91\xf1\xde\xc7\x3b\x37\xa8\xd4\x8d\x5d\xeb\xc5\xf3\x06\xa1\x10\x90\x05\x88\x5b\x38\x40\x2f\x6d\x86\x49\xd1\x0e\x44\x55\x76\xfb\xb9\x3d\x1d\x42\xa9\x06\x96\xe9\x40\x7f\xd8\x79\xe4\xad\x6e\xae\xc8\x81\x93\x41\xa7\x06\x35\xf4\xd0\x53\x62\xb5\xce\x18\x3b\x98\xc5\xf6\x92\x02\xb2\xe8\x7e\xc1\xfd\x45\xf9\x48\x1c\x39\x0a\xa7\x4f";
    uint8_t expected_nosalt[] = "\x4e\xc9\x5f\x9d\xa4\x02\x4d\x42\xe9\xd8\xce\x26\x1e\x9d\xc1\xaa\xd9\x35\x04\xbb\x02\xe3\xf5\x84\x31\x45\x78\x60\x47\xf3\xc4\x22\x23\x6e\x60\x5c\x92\xf6\xaa\x44\x2f\xf3\xa2\x4e\x26\x3b\xf4\xa9\x57\x89\xa7\xe9\x51\x75\xb1\x5d\xa3\x6f\x31\xc5\xc2\xf8\x93\xfd\x80\x65\x54\x7b\xde\xa5\x04\xe9\x33\x57\x0f\x33\x13\x96\x70\x46\x2d\xdf\x57\xb4\xe7\x3e\x6c\x06\x36\x79\xa3\x54\xc6\x89\x0d\x51\x2c\x5e\x3b\x3b";

    size_t out_len = 10;
    cose_crypto_hkdf_derive(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected, out_len) == 0);
    cose_crypto_hkdf_derive(salt, 0, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected_nosalt, out_len) == 0);

    out_len = 64;
    cose_crypto_hkdf_derive(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected, out_len) == 0);
    cose_crypto_hkdf_derive(salt, 0, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected_nosalt, out_len) == 0);

    out_len = 100;
    cose_crypto_hkdf_derive(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected, out_len) == 0);
    cose_crypto_hkdf_derive(salt, 0, ikm, ikm_len, info, info_len, out, out_len, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected_nosalt, out_len) == 0);


    uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t master_salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
    uint8_t skey_info[9] = {0x85, 0x40, 0xf6, 0x0a, 0x63, 0x4b, 0x65, 0x79, 0x10};
    uint8_t expected_key_S[16] = {0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
                                  0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff};
    cose_crypto_hkdf_derive(master_salt, 8, master_secret, 16, skey_info, 9, out, 16, COSE_ALGO_HMAC256);
    assert(memcmp(out, expected_key_S, 16) == 0);

    return 0;
}

int main() {
    test();
    printf("Success\n");
}
