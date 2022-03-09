#ifdef _SIGN_

/***********************************************************************************
 * 
 * This file is used to sign the target pk
 * Input: ${FILE_NAME}_publicKey
 * Output: ${FILE_NAME}_publicKey_signed (signed target pk, will be responsed to the registered SED)
 * Usage: ./sign ${FILE_NAME}

***********************************************************************************/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include "rsa.h"
#include "sha1.h"
#include "md5.h"
#include "rsa_pk_sign.h"

#define CHALLENGE_SIZE 16

#define DEBUG

int sign_pk(char *challenge_file, char *challenge_signed_file)
{
    rsa_sk host_pri;

    unsigned char chall[16] = {0};
    unsigned char output[64] = {0};
    char *host_pri_file = "/host_tools/rsa/host_privateKey";

    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};

    memset(&host_pri, 0, sizeof(rsa_sk));

    FILE *fp;

    //read sss private key from file
    fp = fopen(host_pri_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", host_pri_file);
        return -1;
    }

    fread(&host_pri, sizeof(rsa_sk), 1, fp);
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

#ifdef DEBUG
    printf("challenge:\n");
    for (size_t i = 0; i < CHALLENGE_SIZE; i++)
    {
        printf("%02x", chall[i]);
    }
    printf("\n");
#endif
    // printf("SHA1 of the target pk starts...\n");
    // SHA_Simple(chall, CHALLENGE_SIZE, output);
    // MD5Calc(chall, CHALLENGE_SIZE, output);
    memcpy(output, chall, CHALLENGE_SIZE);

    // printf("sign the target pk digest...\n");
    rsa_decrypt(cipher, MAX_MODULUS_LENGTH, (DTYPE *)&output, MAX_MODULUS_LENGTH, &host_pri);
#ifdef DEBUG
    printf("cipher:\n");
    for (size_t i = 0; i < sizeof(cipher); i++)
    {
        printf("%02x", cipher[i]);
    }
    printf("\n");
#endif
    fp = fopen(challenge_signed_file, "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_signed_file);
        return -1;
    }

    // write pk to the file
    // fwrite(&chall, 1, sizeof(rsa_pk), fp);
    //write signed digest into file
    fwrite(cipher, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);

    return 0;
}

int auth_pk(char *challenge_file, char *challenge_signed_file)
{

    rsa_pk host_pub;

    uint8_t chall[16];

    char *host_pub_file = "/host_tools/rsa/host_publicKey";
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
    for (size_t i = 0; i < CHALLENGE_SIZE; i++)
    {
        printf("%02x", chall[i]);
    }
    printf("\n");
#endif
    // SHA_Simple(chall, CHALLENGE_SIZE, output);
    // MD5Calc(chall, CHALLENGE_SIZE, output);
    memcpy(output, chall, CHALLENGE_SIZE);

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
    char challenge_file[100] = "/host_tools/rsa/challenge";
    char challenge_signed_file[100] = "/host_tools/rsa/challenge_signed";

    // if (argc < 2)
    // {
    //     printf("usage: ./auth ${FILE_NAME}\n");
    //     return -1;
    // }

    // sprintf(challenge_file, "publicKey");
    // sprintf(challenge_signed_file, "%s_publicKey_signed", argv[1]);

    sign_pk(challenge_file, challenge_signed_file);
    auth_pk(challenge_file, challenge_signed_file);

    return 0;
}

#endif