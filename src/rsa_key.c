#include "rsa.h"


int rsa_init_pub(rsa_pub_s *pubk)
{
    mpz_inits(pubk->e, pubk->n, NULL);
    return 0;
}

int rsa_init_prv(rsa_prv_s *prvk)
{
    mpz_inits(prvk->d, prvk->n, NULL);
    return 0;
}
