#ifndef RSA_ENCDEC_H
#define RSA_ENCDEC_H
#include "rsa_key.h"
#include "util.h"


// ---
// Primary function
// ---

int rsa_encrypt_block(rsa_pub_s *pubk, BYTE *dst, BYTE *src);

int rsa_decrypt_block(rsa_prv_s *prvk, BYTE *dst, BYTE *src);


// ---
// User friendly function
// ---

size_t rsa_encrypt_final_size(rsa_pub_s *pubk, size_t inlen);

int rsa_encrypt(rsa_pub_s *pubk, BYTE *dst, BYTE *src, size_t *len);

size_t rsa_decrypt_final_maxsize(rsa_pub_s *prvk, size_t inlen);

int rsa_decrypt(rsa_prv_s *prvk, BYTE *dst, BYTE *src, size_t *len);


#endif /// #ifndef RSA_ENCDEC_H
