#include "rsa.h"


int rsa_encrypt_block(rsa_pub_s *pubk, BYTE *dst, BYTE *src) // M^e % n
{
    size_t blocksize = ((mpz_sizeinbase(pubk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(pubk->n, 2) + 7) / 8;
    mpz_t m;
    mpz_init(m);

    mpz_import(m, blocksize, 1, sizeof(src[0]), 0, 0, src);

    mpz_powm(m, m, pubk->e, pubk->n); // encrypt

    size_t writtensize = keysize;
    mpz_export(dst + keysize - ((mpz_sizeinbase(m, 2) + 7) / 8), 
        &writtensize, 1, sizeof(dst[0]), 0, 0, m);
    memset(dst, 0x00, keysize - writtensize);

    mpz_clear(m);

    return 0;
}

int rsa_decrypt_block(rsa_prv_s *prvk, BYTE *dst, BYTE *src) // M^d % n
{
    size_t blocksize = ((mpz_sizeinbase(prvk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(prvk->n, 2) + 7) / 8;
    mpz_t c;
    mpz_init(c);

    mpz_import(c, keysize, 1, sizeof(src[0]), 0, 0, src);

    mpz_powm(c, c, prvk->d, prvk->n);

    if (((mpz_sizeinbase(c, 2) + 7) / 8) > blocksize)
    {
        return 1;
        mpz_clear(c);
    }

    size_t writtensize = keysize;
    mpz_export(dst + blocksize - ((mpz_sizeinbase(c, 2) + 7) / 8), 
        &writtensize, 1, sizeof(dst[0]), 0, 0, c);
    memset(dst, 0x00, blocksize - writtensize);

    mpz_clear(c);

    return 0;
}


size_t rsa_encrypt_final_size(rsa_pub_s *pubk, size_t inlen)
{
    size_t blocksize = ((mpz_sizeinbase(pubk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(pubk->n, 2) + 7) / 8;
    return ((inlen / blocksize) + 1) * keysize;
}

int rsa_encrypt(rsa_pub_s *pubk, BYTE *dst, BYTE *src, size_t *len)
{
    size_t blocksize = ((mpz_sizeinbase(pubk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(pubk->n, 2) + 7) / 8;
    size_t finaldstlen = rsa_encrypt_final_size(pubk, *len);

    size_t offdst = 0;
    size_t offsrc = 0;
    while (offdst < finaldstlen)
    {
        if (offsrc + blocksize > *len)
        { // Byte padding will be used and break
            BYTE *buf = malloc(blocksize);
            memset(buf, 0x00, blocksize);
            memcpy(buf, src+offsrc, *len - offsrc);
            buf[*len - offsrc] = 0x01;

            rsa_encrypt_block(pubk, dst+offdst, buf);
            offdst += keysize;

            break;
        }
        
        if (rsa_encrypt_block(pubk, dst+offdst, src+offsrc) != 0)
        {
            return 1;
        }

        offdst += keysize;
        offsrc += blocksize;
    }

    *len = finaldstlen;

    return 0;
}

size_t rsa_decrypt_final_maxsize(rsa_pub_s *prvk, size_t inlen)
{
    size_t blocksize = ((mpz_sizeinbase(prvk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(prvk->n, 2) + 7) / 8;
    return (inlen / keysize) * blocksize;
}

int rsa_decrypt(rsa_prv_s *prvk, BYTE *dst, BYTE *src, size_t *len)
{
    size_t blocksize = ((mpz_sizeinbase(prvk->n, 2) + 7) / 8) - 1;
    size_t keysize = (mpz_sizeinbase(prvk->n, 2) + 7) / 8;
    size_t finaldstlen = rsa_decrypt_final_maxsize(prvk, *len);

    size_t offdst = 0;
    size_t offsrc = 0;
    while (offdst < finaldstlen)
    {
        
        if (rsa_decrypt_block(prvk, dst+offdst, src+offsrc) != 0)
        {
            return 1;
        }

        offdst += blocksize;
        offsrc += keysize;
    }

    // ---
    // Processing padding
    // ---

    size_t index = 1;
    while (dst[offdst-index] != 0x01)
    {
        if (dst[offdst-index] != 0x00)
        {
            return 1;
        }
        index++;
    }

    *len = finaldstlen - index;

    return 0;
}
