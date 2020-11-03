#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <gmp.h>

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

int init_rsa(void); // rand init etc etc, return 1 if error occured

// gen rsa key, return 1 if error occured
int gen_rsa(rsa_pub_s *pubk, rsa_prv_s *prvk, uint16_t keysize);

int main(void)
{
    if (init_rsa() != 0) /* There is an error */
    {
        printf("Error an occured when initializing\n");
        exit(EXIT_FAILURE);
    }

    rsa_pub_s pubk;
    rsa_prv_s prvk;

    if (gen_rsa(&pubk, &prvk, 16) != 0)
    {
        printf("Error an occured when generate key\n");
        exit(EXIT_FAILURE);
    }
    if (gen_rsa(&pubk, &prvk, 16) != 0)
    {
        printf("Error an occured when generate key\n");
        exit(EXIT_FAILURE);
    }
    if (gen_rsa(&pubk, &prvk, 16) != 0)
    {
        printf("Error an occured when generate key\n");
        exit(EXIT_FAILURE);
    }
    if (gen_rsa(&pubk, &prvk, 16) != 0)
    {
        printf("Error an occured when generate key\n");
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

int init_rsa(void)
{
    srand(time(NULL));

    return 0;
}

int gen_rsa(rsa_pub_s *pubk, rsa_prv_s *prvk, uint16_t sbitk)
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

    for (uint16_t i = 1; i < pqsize+1; i++)
    {
        buf[i] = rand() % 0xFF;
    }

    buf[0] = 0x01; // Make sure the key will be larger than sbitk bits
    buf[pqsize] &= 0xFE;

    // Buf contain a random number at the desired size
    mpz_import(p, pqsize+1, 1, sizeof(buf[0]), 0, 0, buf);

    // Choice next prime for p
    mpz_nextprime(p, p);

    // ---
    // Generate q prime number
    // ---

    for (uint16_t i = 1; i < pqsize+1; i++)
    {
        buf[i] = rand() % 0xFF;
    }

    buf[0] = 0x01; // Make sure the key will be larger than sbitk bits
    buf[pqsize] &= 0xFE;

    // Buf contain a random number at the desired size
    mpz_import(q, pqsize+1, 1, sizeof(buf[0]), 0, 0, buf);

    // Choice next prime for q
    mpz_nextprime(q, q);

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

    char test[10000] = {0};
    mpz_get_str(test, 10, p);
    printf("P : %s\n", test);
    mpz_get_str(test, 10, q);
    printf("Q : %s\n", test);
    mpz_get_str(test, 10, n);
    printf("N : %s\n", test);
    
    // ---
    // Calculate e
    // ---

    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, rand());

    do
    {
        mpz_urandomm(e, state, phi);
        mpz_gcd(gcd, e, phi);
    } while (mpz_cmp_ui(gcd, 1) != 0 || mpz_cmp_ui(e, 0) == 0);

    mpz_get_str(test, 10, e);
    printf("E : %s\n", test);

    if (mpz_invert(d, e, phi) == 0)
    {
        printf("Invert failed\n");
    }

    mpz_get_str(test, 10, d);
    printf("D : %s\n\n", test);

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
    mpz_clears(p, q, p_1, q_1, phi, n, e, d, gcd, NULL);
    return 0;
}