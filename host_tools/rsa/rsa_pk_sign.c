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

#define CHALLENGE_SIZE 64
// #define TEST

#define DEBUG

int sign_pk(char *challenge_file, char *challenge_signed_file)
{
    rsa_sk host_pri;

    uint8_t chall[CHALLENGE_SIZE] = {0};
    uint8_t input[CHALLENGE_SIZE] = {0};
#ifdef TEST
    char *host_pri_file = "host_privateKey";
#else
    char *host_pri_file = "/host_tools/rsa/host_privateKey";
#endif

    uint8_t challenge_signed[CHALLENGE_SIZE] = {0};

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

    fread(chall, CHALLENGE_SIZE, 1, fp);
    fclose(fp);

#ifdef DEBUG
    printf("challenge:\n");
    for (size_t i = 0; i < sizeof(chall); i++)
    {
        printf("%02x", chall[i]);
    }
    printf("\n");
#endif
    // printf("SHA1 of the target pk starts...\n");
    // SHA_Simple(chall, CHALLENGE_SIZE, challenge_auth);
    // MD5Calc(chall, CHALLENGE_SIZE, challenge_auth);
    // memcpy(input, chall, CHALLENGE_SIZE);

    // printf("sign the target pk digest...\n");
    rsa_decrypt((DTYPE *)&challenge_signed, MAX_MODULUS_LENGTH, (DTYPE *)&chall, MAX_MODULUS_LENGTH, &host_pri);
#ifdef DEBUG
    printf("challenge_signed:\n");
    for (size_t i = 0; i < sizeof(challenge_signed); i++)
    {
        printf("%02x", challenge_signed[i]);
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
    printf("write challenge_signed to file:\n");
    fwrite(challenge_signed, 1, sizeof(challenge_signed), fp);
    fclose(fp);

    return 0;
}

int auth_pk(char *challenge_file, char *challenge_signed_file)
{

    rsa_pk host_pub;

    uint8_t chall[CHALLENGE_SIZE];
    uint8_t challenge_signed[CHALLENGE_SIZE] = {0};
    uint8_t challenge_auth[CHALLENGE_SIZE] = {0};
    uint8_t chall_auth[CHALLENGE_SIZE] = {0};
#ifdef TEST
    char *host_pub_file = "host_publicKey";
    char *challenge_auth_file = "challenge_auth2";
#else
    char *host_pub_file = "/host_tools/rsa/host_publicKey";
    char *challenge_auth_file = "/host_tools/rsa/challenge_auth2";
#endif

    memset(&host_pub, 0, sizeof(rsa_pk));

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

    fread(chall, CHALLENGE_SIZE, 1, fp);
    fclose(fp);

    // configure the e
    BN_init(host_pub.e, MAX_PRIME_LENGTH);
    //e=2^CHALLENGE_SIZE+1
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
    fread(challenge_signed, CHALLENGE_SIZE, 1, fp);
    fclose(fp);

#ifdef DEBUG
    printf("auth the signed challenge:\n");
    for (size_t i = 0; i < sizeof(challenge_signed); i++)
    {
        printf("%02x", challenge_signed[i]);
    }
    printf("\n");
#endif

#ifdef DEBUG
    printf("challenge:\n");
    for (size_t i = 0; i < sizeof(chall); i++)
    {
        printf("%02x", chall[i]);
    }
    printf("\n");
#endif
    // SHA_Simple(chall, CHALLENGE_SIZE, challenge_auth);
    // MD5Calc(chall, CHALLENGE_SIZE, challenge_auth);

    printf("auth the target string...\n");
    rsa_encrypt((DTYPE *)&challenge_auth, MAX_MODULUS_LENGTH, (DTYPE *)&challenge_signed, MAX_MODULUS_LENGTH, &host_pub);

#ifdef TEST


    for (size_t i = 0; i < 20; i++)
    {
        printf("%x ", host_pub.n[i]);
    }

    fp = fopen(challenge_auth_file, "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_auth_file);
        return -1;
    }

    // hex_to_string(chall_msg, chall);
    fwrite(challenge_auth, 1, sizeof(challenge_auth), fp);
    fclose(fp);
#endif

#ifdef DEBUG
    printf("chall_auth:\n");
    for (size_t i = 0; i < sizeof(challenge_auth); i++)
    {
        printf("%02x", challenge_auth[i]);
    }
    printf("\n");
#endif
    // if (BN_cmp((DTYPE *)&chall_auth, CHALLENGE_SIZE, (DTYPE *)&chall, CHALLENGE_SIZE) == 0)
    if (memcmp(challenge_auth, chall, CHALLENGE_SIZE) == 0)
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

#ifdef TEST
    char challenge_file[100] = "challenge";
    char challenge_signed_file[100] = "challenge_signed";
#else
    char challenge_file[100] = "/host_tools/rsa/challenge";
    char challenge_signed_file[100] = "/host_tools/rsa/challenge_signed";
#endif

    // if (argc < 2)
    // {
    //     printf("usage: ./auth ${FILE_NAME}\n");
    //     return -1;
    // }

    // sprintf(challenge_file, "publicKey");
    // sprintf(challenge_signed_file, "%s_publicKey_signed", argv[1]);

#ifdef TEST
    FILE *fp;
    fp = fopen("challenge", "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", challenge_signed_file);
        return -1;
    }

    uint8_t chall_msg[CHALLENGE_SIZE] = "asfascnlkvadfasdfgadhgadhbadbzvfadgaedhgadhgfagfdbgsddfgdshsdhkv";
    // uint8_t chall_msg[CHALLENGE_SIZE] = {0};
    // uint8_t chall_msg[CHALLENGE_SIZE] = {0x8a, 0xdf, 0x82, 0xe5, 0x4d, 0xbb, 0xe3, 0x71, 0x07, 0x75, 0xe5, 0x82, 0x49, 0x24, 0xd7, 0x5c};
    // uint8_t chall_msg[CHALLENGE_SIZE] = {0x21, 0xb1, 0x2b, 0xb8, 0x7a, 0xb8, 0x2e, 0xed, 0x5e, 0xf5, 0xc9, 0xc1, 0xfe, 0xdf, 0x92, 0x1f, 0x35, 0xcf, 0x70, 0xbe, 0xc8, 0xee, 0xc5, 0x36, 0xe6, 0xe9, 0x1c, 0xae, 0x86, 0x90, 0x21, 0x71, 0x74, 0x33, 0xe3, 0xe9, 0xff, 0xf3, 0xc7, 0x42, 0x41, 0x91, 0xf0, 0xb1, 0xe3, 0xf3, 0x47, 0xff, 0x21, 0xa6, 0xf9, 0x2a, 0xb9, 0x6e, 0x67, 0xa4, 0xdd, 0xd6, 0xb2, 0x56, 0x53, 0xb8, 0xe9, 0x1d};

    // hex_to_string(chall_msg, chall);
    fwrite(chall_msg, 1, CHALLENGE_SIZE, fp);
    fclose(fp);

#endif

    sign_pk(challenge_file, challenge_signed_file);
    auth_pk(challenge_file, challenge_signed_file);

    return 0;
}

#endif