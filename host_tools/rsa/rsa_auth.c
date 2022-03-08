#ifdef _AUTH_

/***********************************************************************************
 * 
 * This file is used to verify the signed messages
 * Input: cipher (should be written by sss.py, raw data)
 * Output: decipher (decrypted messages, will be read by sss.py to verify the header)
 * Usage: ./auth ${SCEWL_ID}

***********************************************************************************/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include "rsa.h"

int main(int argc, char *argv[])
{
    rsa_pk pk;

    DTYPE msg[MAX_MODULUS_LENGTH] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

    char message[MAX_MODULUS_LENGTH * 2] = {0};
    char publickey[300] = {0};
    char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

    char challenge_signed_file[100] = "challenge_signed";
    char challenge_auth_file[100] = "challenge_auth";
    char pub_file[100] = "host_publicKey";
    char pri_file[100] = "host_privateKey";

    memset(&pk, 0, sizeof(rsa_pk));

    // if (argc < 2)
    // {
    //     printf("usage: ./auth ${SCEWL_ID}\n");
    //     return -1;
    // }

    FILE *fp;

    //read public key from file
    fp = fopen(pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", pub_file);
        return -1;
    }

    fread(&pk, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    // configure the e
    BN_init(pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    pk.e[MAX_PRIME_LENGTH - 2] = 1;
    pk.e[MAX_PRIME_LENGTH - 1] = 1;

    //read ciphertext from file
    fp = fopen(challenge_signed_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_signed_file);
        return -1;
    }
    fread(cipher, sizeof(cipher), 1, fp);
    fclose(fp);

    //printf("%s: Decryption starts...\n", argv[1]);
    rsa_encrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &pk);
    printf("====Auth===== %s: Decryption done...\n\n", argv[1]);
    fflush(stdout);

    //write plaintext into file
    hex_to_string(plainmsg, plaintext);
    fp = fopen(challenge_auth_file, "wb");

    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_auth_file);
        return -1;
    }
    fwrite(plainmsg, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);
    printf("====Auth===== %s: successful...\n\n", argv[1]);
    return 0;
}

#endif