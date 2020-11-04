#ifndef RSA_KEY_H
#define RSA_KEY_H
#include "util.h"


struct rsa_pub
{
    mpz_t e;
    mpz_t n;
};
typedef struct rsa_pub rsa_pub_s;

struct rsa_prv
{
    mpz_t d;
    mpz_t n;
};
typedef struct rsa_prv rsa_prv_s;


int rsa_init_pub(rsa_pub_s *pubk);

int rsa_init_prv(rsa_prv_s *prvk);


#endif /// #ifndef RSA_KEY_H
