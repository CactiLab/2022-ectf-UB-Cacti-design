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

int auth_pk(char *challenge_file, char *challenge_signed_file)
{

    rsa_pk host_pub;

    uint8_t chall[16];

    char *host_pub_file = "host_publicKey";
    // char *tmp = "rsa/tmp";
    char tmp[100] = {0};
    unsigned char output[64] = {0};

    DTYPE msg[MAX_MODULUS_LENGTH * 2] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    DTYPE decipher[MAX_MODULUS_LENGTH] = {0};

    memset(&host_pub, 0, sizeof(rsa_pk));

    sprintf(tmp, "%s_tmp", challenge_signed_file);

    FILE *fp;

    //read host public key from file
    fp = fopen(host_pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", host_pub_file);
        return -1;
    }

    fread(&host_pub, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    //read challenge from file
    fp = fopen(challenge_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_file);
        return -1;
    }

    fread(chall, sizeof(uint8_t) * 16, 1, fp);
    fclose(fp);

    // configure the e
    BN_init(host_pub.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    host_pub.e[MAX_PRIME_LENGTH - 2] = 1;
    host_pub.e[MAX_PRIME_LENGTH - 1] = 1;

    //read target signed public key from file
    fp = fopen(challenge_signed_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_signed_file);
        return -1;
    }

    // fread(chall, sizeof(rsa_pk), 1, fp);
    fread(cipher, MAX_MODULUS_LENGTH * 2, 1, fp);
    fclose(fp);

    printf("SHA1 of the target string...\n");
#ifdef DEBUG
    printf("challenge:\n");
    for (size_t i = 0; i < 16; i++)
    {
        printf("%02x", chall[i]);
    }
    printf("\n");
#endif
    // SHA_Simple(chall, sizeof(chall), output);
    MD5Calc(chall, sizeof(chall), output);
    // memcpy(output, chall, sizeof(chall));
#ifdef DEBUG
    printf("sign hash:\n");
    for (size_t i = 0; i < 64; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
#endif
    printf("auth the target string digest...\n");
    rsa_encrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &host_pub);

    fp = fopen(tmp, "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tmp);
        return -1;
    }

    // write sha1 to the file
    fwrite(output, 1, 64, fp);
    //write signed digest into file
    fwrite(decipher, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);
#ifdef DEBUG
    printf("decipher:\n");
    for (size_t i = 0; i < sizeof(decipher); i++)
    {
        printf("%02x", decipher[i]);
    }
    printf("\n");
#endif
    if (BN_cmp(decipher, MAX_MODULUS_LENGTH, (DTYPE *)&output, MAX_MODULUS_LENGTH) == 0)
    {
        printf("\nAfter decryption, plaintext equal to message.\n");
    }
    else
    {
        printf("\nAfter decryption, wrong answer.\n");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // rsa_pk pk;

    // DTYPE msg[MAX_MODULUS_LENGTH] = {0};
    // DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    // DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

    // char message[MAX_MODULUS_LENGTH * 2] = {0};
    // char publickey[300] = {0};
    // char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

    // char challenge_signed_file[100] = "challenge_signed";
    // char challenge_auth_file[100] = "challenge_auth";
    // char pub_file[100] = "host_publicKey";
    // char pri_file[100] = "host_privateKey";

    // memset(&pk, 0, sizeof(rsa_pk));

    char challenge_file[100] = "challenge";
    char challenge_signed_file[100] = "challenge_signed";

    auth_pk(challenge_file, challenge_signed_file);

    // if (argc < 2)
    // {
    //     printf("usage: ./auth ${SCEWL_ID}\n");
    //     return -1;
    // }

    // FILE *fp;

    // //read public key from file
    // fp = fopen(pub_file, "rb");
    // if (fp == NULL)
    // {
    //     printf("Cannot open file %s\n", pub_file);
    //     return -1;
    // }

    // fread(&pk, sizeof(rsa_pk), 1, fp);
    // fclose(fp);

    // // configure the e
    // BN_init(pk.e, MAX_PRIME_LENGTH);
    // //e=2^16+1
    // pk.e[MAX_PRIME_LENGTH - 2] = 1;
    // pk.e[MAX_PRIME_LENGTH - 1] = 1;

    // //read ciphertext from file
    // fp = fopen(challenge_signed_file, "rb");
    // if (fp == NULL)
    // {
    //     printf("Cannot open file %s\n", challenge_signed_file);
    //     return -1;
    // }
    // fread(cipher, sizeof(cipher), 1, fp);
    // fclose(fp);

    // //printf("%s: Decryption starts...\n", argv[1]);
    // rsa_encrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &pk);
    // printf("====Auth===== %s: Decryption done...\n\n", argv[1]);
    // fflush(stdout);

    // //write plaintext into file
    // hex_to_string(plainmsg, plaintext);
    // fp = fopen(challenge_auth_file, "wb");

    // if (fp == NULL)
    // {
    //     printf("Cannot open file %s\n", challenge_auth_file);
    //     return -1;
    // }
    // fwrite(plainmsg, 1, MAX_MODULUS_LENGTH * 2, fp);
    // fclose(fp);
    // printf("====Auth===== %s: successful...\n\n", argv[1]);
    return 0;
}

#endif