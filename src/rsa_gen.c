#include "rsa.h"


// ---
// Private function declaration
// ---

void memrand(void *dst, size_t len);

int rsa_gen(rsa_pub_s *pubk, rsa_prv_s *prvk, uint16_t sbitk)
{
    size_t keysize = (sbitk / 8);
    size_t pqsize = keysize / 2;
    mpz_t p, q;
    mpz_t p_1, q_1;
    mpz_t phi;
    mpz_t n;
    mpz_t e;
    mpz_t d;
    mpz_t gcd;

    mpz_inits(p, q, p_1, q_1, phi, n, e, d, gcd, NULL);

    uint8_t *buf = malloc(pqsize+1); // + 1 for have enough big number

    // ---
    // Generate p prime number
    // ---

    memrand(buf+1, pqsize);
    buf[0] = 0x01; // Make sure the key will be larger than sbitk bits
    buf[pqsize] &= 0xFE;

    // Buf contain a random number at the desired size
    mpz_import(p, pqsize+1, 1, sizeof(buf[0]), 0, 0, buf);

    // Choice next prime for p
    mpz_nextprime(p, p);

    // ---
    // Generate q prime number
    // ---

    memrand(buf+1, pqsize);
    buf[0] = 0x01; // Make sure the key will be larger than sbitk bits
    buf[pqsize] &= 0xFE;

    // Buf contain a random number at the desired size
    mpz_import(q, pqsize+1, 1, sizeof(buf[0]), 0, 0, buf);

    // Choice next prime for q
    mpz_nextprime(q, q);

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     * 
     * All necessary numbers are generated at this state.
     * 
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/

    // ---
    // Calculate n = p * q
    // ---

    mpz_mul(n, p, q);

    // ---
    // Calculate phi(n) = (p-1)(q-1)
    // ---

    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(phi, p_1, q_1);
    
    // ---
    // Calculate e
    // ---

    // Init random state of GMP
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, rand());

    do
    {
        mpz_urandomm(e, state, phi);
        mpz_gcd(gcd, e, phi);
    } while (mpz_cmp_ui(gcd, 1) != 0 || mpz_cmp_ui(e, 0) == 0);

    // ---
    // Calculate d
    // ---

    if (mpz_invert(d, e, phi) == 0)
    { // Invert failed
        // Free buffers and tempory variable
        free(buf);
        gmp_randclear(state);
        mpz_clears(p, q, p_1, q_1, phi, n, e, d, gcd, NULL);
        return 1;
    }

    // ---
    // Key generation finish let's save
    // ---

    // Assign e and n for public key
    mpz_set(pubk->e, e);
    mpz_set(pubk->n, n);

    // Assign d and n for private key
    mpz_set(prvk->d, d);
    mpz_set(prvk->n, n);

    // Free buffers and tempory variable
    free(buf);
    gmp_randclear(state);
    mpz_clears(p, q, p_1, q_1, phi, n, e, d, gcd, NULL);
    return 0;
}

// ---
// Private function implementation
// ---

void memrand(void *dst, size_t len)
{
    for (uint16_t i = 0; i < len; i++)
    {
        ((char *)dst)[i] = rand() % 0xFF;
    }
}
