//
//  rsa_test.c
//  RSAProject
//
//  Created by guozhicheng on 5/9/16.
//  Copyright © 2016 guozhicheng. All rights reserved.
//

#include "rsa_test.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "sha1.h"

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL)
        rng_state = NULL;

    while (len > 0)
    {
        use_len = len;
        if (use_len > sizeof(int))
            use_len = sizeof(int);

        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return (0);
}

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N "9292758453063D803DD603D5E777D788" \
              "8ED1D5BF35786190FA2F23EBC0848AEA" \
              "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
              "7130B9CED7ACDF54CFC7555AC14EEBAB" \
              "93A89813FBF3C4F8066D2D800F7C38A8" \
              "1AE31942917403FF4946B0A83D3D3E05" \
              "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
              "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E "10001"

#define RSA_D "24BF6185468786FDD303083D25E64EFC" \
              "66CA472BC44D253102F8B4A9D3BFA750" \
              "91386C0077937FE33FA3252D28855837" \
              "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
              "DF79C5CE07EE72C7F123142198164234" \
              "CABB724CF78B8173B9F880FC86322407" \
              "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
              "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
              "2C01CAD19EA484A87EA4377637E75500" \
              "FCB2005C5C7DD6EC4AC023CDA285D796" \
              "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q "C000DF51A7C77AE8D7C7370C1FF55B69" \
              "E211C2B9E5DB1ED0BF61D0D9899620F4" \
              "910E4168387E3C30AA1E00C339A79508" \
              "8452DD96A9A5EA5D9DCA68DA636032AF"

#define PT_LEN 64
// #define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

unsigned char rsa_plaintext[PT_LEN];
unsigned char rsa_decrypted[PT_LEN];
unsigned char rsa_ciphertext[KEY_LEN];
#if defined(MBEDTLS_SHA1_C)
unsigned char sha1sum[20];
#endif

/*
 * Checkup routine
 */
int mbedtls_rsa_self_test(int verbose)
{
    int ret = 0;
#if defined(MBEDTLS_PKCS1_V15)
    size_t len;
    mbedtls_rsa_context rsa;

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, &K, NULL, NULL, NULL, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, &K, NULL, NULL, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, &K, NULL, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, &K, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_E));
    MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, NULL, &K));

    MBEDTLS_MPI_CHK(mbedtls_rsa_complete(&rsa));

    if (verbose != 0)
        printf("  RSA key validation: ");

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0)
        printf("passed\n  PKCS#1 encryption : ");

    size_t i = 0;
    srand(time(NULL));
    for (i = 0; i < MSG_SIZE;)
    {
        // msg[i] = 0xa3;
        uint32_t tmp = rand();
        rsa_plaintext[i++] = *(((unsigned char *)&tmp) + 0);
        rsa_plaintext[i++] = *(((unsigned char *)&tmp) + 1);
        rsa_plaintext[i++] = *(((unsigned char *)&tmp) + 2);
        rsa_plaintext[i++] = *(((unsigned char *)&tmp) + 3);
    }
    // memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    printf("Plaintext\n");
    for (size_t i = 0; i < MSG_SIZE; i++)
    {
        printf("%x ", rsa_plaintext[i]);
    }
    printf("\n");

    if (mbedtls_rsa_pkcs1_encrypt(&rsa, myrand, NULL,
                                  PT_LEN, rsa_plaintext,
                                  rsa_ciphertext) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0)
        printf("passed\n  PKCS#1 decryption : ");

    if (mbedtls_rsa_pkcs1_decrypt(&rsa, myrand, NULL,
                                  &len, rsa_ciphertext, rsa_decrypted,
                                  sizeof(rsa_decrypted)) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (memcmp(rsa_decrypted, rsa_plaintext, len) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0)
        printf("passed\n");

#if defined(MBEDTLS_SHA1_C)
    if (verbose != 0)
        printf("  PKCS#1 data sign  : ");

    if (mbedtls_sha1(rsa_plaintext, PT_LEN, sha1sum) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        return (1);
    }

    if (mbedtls_rsa_pkcs1_sign(&rsa, myrand, NULL,
                               MBEDTLS_MD_SHA1, 20,
                               sha1sum, rsa_ciphertext) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0)
        printf("passed\n  PKCS#1 sig. verify: ");

    if (mbedtls_rsa_pkcs1_verify(&rsa, MBEDTLS_MD_SHA1, 20,
                                 sha1sum, rsa_ciphertext) != 0)
    {
        if (verbose != 0)
            printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0)
        printf("passed\n");
#endif /* MBEDTLS_SHA1_C */

    if (verbose != 0)
        printf("\n");

cleanup:
    mbedtls_mpi_free(&K);
    mbedtls_rsa_free(&rsa);
#else  /* MBEDTLS_PKCS1_V15 */
    ((void)verbose);
#endif /* MBEDTLS_PKCS1_V15 */
    return (ret);
}

void pubEn()
{
    int ret;
    mbedtls_rsa_context pubRsa, priRsa;
    memset(&pubRsa, 0, sizeof(mbedtls_rsa_context));
    memset(&priRsa, 0, sizeof(mbedtls_rsa_context));

    getRsaKeys(&pubRsa, &priRsa);

    if (mbedtls_rsa_check_pub_priv(&pubRsa, &priRsa) == 0)
    {
        printf("get rsa key sucess\n");
    }
    unsigned char msg[MSG_SIZE] = "hello world!";
    unsigned char output[1000];
    unsigned char outputPri[1000];

    memset(output, 0x00, 1000);
    memset(outputPri, 0x00, 1000);

    srand(time(NULL));

    // *((uint32_t *)msg) = 0xaaaaaaaa;
    // size_t i = 0;
    // for (i = 0; i < MSG_SIZE;)
    // {
    //     // msg[i] = 0xa3;
    //     uint32_t tmp = rand();
    //     msg[i++] = *(((unsigned char *)&tmp) + 0);
    //     msg[i++] = *(((unsigned char *)&tmp) + 1);
    //     msg[i++] = *(((unsigned char *)&tmp) + 2);
    //     msg[i++] = *(((unsigned char *)&tmp) + 3);
    // }
    // printf("\ni: %d\n", i);

    //    mbedtls_rsa_public(&pubRsa, msg, output);
    //    mbedtls_rsa_private(&priRsa, NULL, NULL, output, outputPri);
    printf("Plaintext\n");
    for (size_t i = 0; i < MSG_SIZE; i++)
    {
        printf("%x ", rsa_plaintext[i]);
    }
    printf("\n");

    ret = mbedtls_rsa_private(&priRsa, myrand, NULL, rsa_plaintext, output);
    if (ret != 0)
    {
        printf("sign failed. %d\n", ret);
        return;
    }
    ret = mbedtls_rsa_public(&pubRsa, output, outputPri);
    if (ret != 0)
    {
        printf("auth failed. %d\n", ret);
    }

    printf("Cipher\n");
    for (size_t i = 0; i < MSG_SIZE; i++)
    {
        printf("%x ", output[i]);
    }
    printf("\n");

    printf("Decipher\n");
    for (size_t i = 0; i < MSG_SIZE; i++)
    {
        printf("%x ", outputPri[i]);
    }
    printf("\n");
}

void privateEn()
{
}

void initPubKey()
{

    char *pub_file = "./test/pub.txt";
    char *prv_file = "./test/private.txt";
    int ret;

    mbedtls_pk_context pub, prv, alt;

    mbedtls_pk_init(&pub);
    mbedtls_pk_init(&prv);
    mbedtls_pk_init(&alt);

    if (mbedtls_pk_parse_public_keyfile(&pub, pub_file) == 0)
    {
        printf("sucess\n");
    }
    if (mbedtls_pk_parse_keyfile(&prv, prv_file, "", mbedtls_ctr_drbg_random, NULL) == 0)
    {
        printf("sucess\n");
    }

    if (mbedtls_pk_check_pair(&pub, &prv, NULL, NULL) == ret)
    {
        printf("sucess\n");
    }

    if (mbedtls_rsa_check_pub_priv(mbedtls_pk_rsa(pub), mbedtls_pk_rsa(prv)) == 0)
    {
        printf("check rsa key sucess\n");
    }

    mbedtls_pk_free(&pub);
    mbedtls_pk_free(&prv);
    mbedtls_pk_free(&alt);
}

void generateRSAKeys()
{

    const char *privateKeyFile = "./test/private.txt";
    const char *pubKeyFile = "./test/pub.txt";

    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    FILE *fpub = NULL;
    FILE *fpriv = NULL;

    const char *pers = "rsa_genkey_rsa_video_qqq";

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const uint8_t *)pers,
                                     strlen(pers))) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);
    // MBEDTLS_RSA_PKCS_V15
    mbedtls_rsa_init(&rsa);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0)
    {
        printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    key.MBEDTLS_PRIVATE(pk_ctx) = &rsa;

    printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    write_private_key(&key, privateKeyFile);
    write_pub_key(&key, pubKeyFile);

    fflush(stdout);
    if ((fpub = fopen("./test/rsa_pub.txt", "wb+")) == NULL)
    {
        printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
        ret = 1;
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &rsa.MBEDTLS_PRIVATE(N), 16, fpub)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &rsa.MBEDTLS_PRIVATE(E), 16, fpub)) != 0)
    {
        printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("./test/rsa_priv.txt", "wb+")) == NULL)
    {
        printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
        ret = 1;
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &rsa.MBEDTLS_PRIVATE(N), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &rsa.MBEDTLS_PRIVATE(E), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &rsa.MBEDTLS_PRIVATE(D), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &rsa.MBEDTLS_PRIVATE(P), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &rsa.MBEDTLS_PRIVATE(Q), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &rsa.MBEDTLS_PRIVATE(DP), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &rsa.MBEDTLS_PRIVATE(DQ), 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &rsa.MBEDTLS_PRIVATE(QP), 16, fpriv)) != 0)
    {
        printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n\n");

exit:

    if (fpub != NULL)
        fclose(fpub);

    if (fpriv != NULL)
        fclose(fpriv);

    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
    printf("  Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    return;
}

void getRsaKeys(mbedtls_rsa_context *pubRsa, mbedtls_rsa_context *priRsa)
{
    char *pub_file = "./test/pub.txt";
    char *prv_file = "./test/private.txt";

    mbedtls_pk_context pub, prv;

    mbedtls_pk_init(&pub);
    mbedtls_pk_init(&prv);

    if (mbedtls_pk_parse_public_keyfile(&pub, pub_file) == 0)
    {
        printf("parse publick key sucess\n");
    }
    if (mbedtls_pk_parse_keyfile(&prv, prv_file, "", mbedtls_ctr_drbg_random, NULL) == 0)
    {
        printf("parse provite key sucess\n");
    }

    *pubRsa = *mbedtls_pk_rsa(pub);
    *priRsa = *mbedtls_pk_rsa(prv);
}

int write_pub_key(mbedtls_pk_context *key, const char *output_file)
{

    int ret;
    FILE *f;
    uint8_t output_buf[16000];
    uint8_t *c = output_buf;
    size_t len = 0;

    if ((ret = mbedtls_pk_write_pubkey_pem(key, output_buf, 16000)) != 0)
        return (ret);

    len = strlen((char *)output_buf);

    if ((f = fopen(output_file, "wb")) == NULL)
        return (-1);

    if (fwrite(c, 1, len, f) != len)
    {
        fclose(f);
        return (-1);
    }

    fclose(f);

    return 0;
}

int write_private_key(mbedtls_pk_context *key, const char *output_file)
{

    int ret;
    FILE *f;
    uint8_t output_buf[16000];
    uint8_t *c = output_buf;
    size_t len = 0;

    if ((ret = mbedtls_pk_write_key_pem(key, output_buf, 16000)) != 0)
        return (ret);

    len = strlen((char *)output_buf);

    if ((f = fopen(output_file, "wb")) == NULL)
        return (-1);

    if (fwrite(c, 1, len, f) != len)
    {
        fclose(f);
        return (-1);
    }

    fclose(f);

    return 0;
}

void testprint()
{
    printf("test generated key\n");
    mbedtls_rsa_self_test(1);

    pubEn();
}