#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <gmp.h>

typedef uint8_t BYTE;

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

// ---
// return 1 if error occured
// ---

int rsa_init(void);

int rsa_init_pub(rsa_pub_s *pubk);

int rsa_init_prv(rsa_prv_s *prvk);

int rsa_encrypt_block(rsa_pub_s *pubk, BYTE *dst, BYTE *src, size_t len);

int rsa_decrypt_block(rsa_prv_s *prvk, BYTE *dst, BYTE *src, size_t len);

int rsa_gen(rsa_pub_s *pubk, rsa_prv_s *prvk, uint16_t keysize);


int main(void)
{
    if (rsa_init() != 0) /* There is an error */
    {
        printf("Error an occured when initializing\n");
        exit(EXIT_FAILURE);
    }

    rsa_pub_s pubk;
    rsa_init_pub(&pubk);
    rsa_prv_s prvk;
    rsa_init_prv(&prvk);

    if (rsa_gen(&pubk, &prvk, 4096) != 0)
    {
        printf("Error an occured when generate key\n");
        exit(EXIT_FAILURE);
    }

    char buf[10000] = {0};
    mpz_get_str(buf, 16, pubk.e);
    printf("E : %s\n", buf);
    mpz_get_str(buf, 16, prvk.d);
    printf("D : %s\n", buf);
    mpz_get_str(buf, 16, pubk.n);
    printf("N : %s\n", buf);

    return EXIT_SUCCESS;
}

int rsa_init(void)
{
    srand(time(NULL));

    return 0;
}

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

int rsa_encrypt_block(rsa_pub_s *pubk, BYTE *dst, BYTE *src, size_t len) // M^e % n
{
    mpz_t m;
    mpz_init(m);

    mpz_import(m, len, 1, sizeof(src[0]), 0, 0, src);

    mpz_powm(m, m, pubk->e, pubk->n);

    // TODO : export

    return 0;
}

int rsa_decrypt_block(rsa_prv_s *prvk, BYTE *dst, BYTE *src, size_t len) // M^d % n
{
    mpz_t c;
    mpz_init(c);

    mpz_powm(c, c, prvk->d, prvk->n);

    return 0;
}

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
    {
        printf("Invert failed\n");
        // Free buffers and tempory variable
        free(buf);
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
    mpz_clears(p, q, p_1, q_1, phi, n, e, d, gcd, NULL);
    return 0;
}