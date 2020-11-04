#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"


int main(void)
{
    size_t bitkey = 2048;
    if (rsa_init() != 0) /* There is an error */
    {
        printf("Error an occured when initializing\n");
        exit(EXIT_FAILURE);
    }

    rsa_pub_s pubk;
    rsa_init_pub(&pubk);
    rsa_prv_s prvk;
    rsa_init_prv(&prvk);

    if (rsa_gen(&pubk, &prvk, bitkey) != 0)
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

    BYTE data[1000]; // data are on 2 byte

    if (scanf("%s", &data) == 0)
    {
        printf("Error read\n");
        exit(EXIT_FAILURE);
    }

    printf("MESSAGE NO ENCRYPTED : ");
    for (size_t i = 0; i < strlen(data); i++)
    {
        printf("0x%02x ", data[i]);
    }
    printf("\n");

    size_t encrypt_size = rsa_encrypt_final_size(&pubk, strlen(data));
    BYTE *cdata = malloc(encrypt_size);

    size_t len = strlen(data);
    rsa_encrypt(&pubk, cdata, data, &len);

    printf("MESSAGE ENCRYPTED :    ");
    for (size_t i = 0; i < len; i++)
    {
        printf("0x%02x ", cdata[i]);
    }
    printf("\n");

    size_t decrypt_size = rsa_decrypt_final_maxsize(&prvk, encrypt_size);
    BYTE *dcdata = malloc(decrypt_size);

    len = encrypt_size;
    rsa_decrypt(&prvk, dcdata, cdata, &len);

    printf("MESSAGE DECRYPTED :    ");
    for (size_t i = 0; i < len; i++)
    {
        printf("0x%02x ", dcdata[i]);
    }
    printf("\n");

    free(cdata);
    free(dcdata);
    return EXIT_SUCCESS;
}
