#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define GCM 1
#define AES256
#define msg_size 15200

#include "gcm.h"
#include "aestest.h"
#include "aes-gcm.h"

// prints string as hex
static void phex(const uint8_t* str, unsigned int len)
{

// #if defined(AES256)
//     uint8_t len = 32;
// #elif defined(AES192)
//     uint8_t len = 24;
// #elif defined(AES128)
//     uint8_t len = 16;
// #endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

/******************************************************************************
For example, a section of the 256-bit encryption test looks like this:

[Keylen = 256]
[IVlen = 96]
[PTlen = 128]
[AADlen = 128]
[Taglen = 120]

Count = 0
Key = 7f7168a406e7c1ef0fd47ac922c5ec5f659765fb6aaa048f7056f6c6b5d8513d
IV = b8b5e407adc0e293e3e7e991
PT = b706194bb0b10c474e1b2d7b2278224c
AAD = ff7628f6427fbcef1f3b82b37404e116
CT = 8fada0b8e777a829ca9680d3bf4f3574
Tag = daca354277f6335fc8bec90886da70

The header block specifies the lengths of the various parameters and is
then followed by 15 sets of parameters of that length numbered by the
0-based "Count" from 0 to 14.

The abbreviations have the following meanings (all lengths are in bits):

Keylen    key length                                                256
IVlen     initialization vector length                              96
PTlen     plaintext length                                          -
AADlen    associated data length                                    -
Taglen    authentication tag length                                 -

Count     count (0-14) of the data within the parameter set
Key       key data
IV        initialization vector data
PT        plaintext data
AAD       associated authenticated data
CT        ciphertext data
Tag       authentication tag data

---------------------------------------------------------------------------

The file compiled by the "rsp_processor.pl" PERL file consists of a series of
variable-length blocks with one block per test. The blocks have the following
format (all lengths are in byte counts):

block_type	- one byte block type
key_length	- one byte key length
key			- key
iv_length	- one byte initialization vector length
iv			- initialization vector
aad_length	- one byte associated authenticated data length
aad			- associated authenticated data
pt_length	- one byte plaintext data length
pt			- plaintext data
ct_length	- one byte ciphertext data length
ct			- ciphertext data
tag_length	- one byte authentication tag length
tag			- authentication tag

Four block types are defined:

0: end-of-file. This signals that all blocks have been processed.
1: data encryption. Plaintext is encrypted, ciphertext & auth tag are verified.
2: data decryption. Ciphertext is decrypted, Plaintext & auth tag are verified.
3: data decryption with AUTH FAILURE. Ciphertext is decrypted, failure verified.

******************************************************************************/


static int test_gcm_encryption(
        const uint8_t *key,       // pointer to the cipher key
        size_t key_len,         // byte length of the key
        const uint8_t *iv,        // pointer to the initialization vector
        size_t iv_len,          // byte length of the initialization vector
        const uint8_t *aad,       // pointer to the non-ciphered additional data
        size_t aad_len,         // byte length of the additional AEAD data
        const uint8_t *pt,        // pointer to the plaintext SOURCE data
        uint8_t *ct,        // pointer to the CORRECT cipher data
        size_t ct_len,          // byte length of the cipher data
        uint8_t *tag,       // pointer to the CORRECT tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    // uint8_t ct_buf[32];          // cipher text results for comparison
    // uint8_t tag_buf[16];          // tag result buffer for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // encrypt the NIST-provided plaintext into the local ct_buf and
    // tag_buf ciphertext and authentication tag buffers respectively.
    ret = gcm_crypt_and_tag( &ctx, ENCRYPT, iv, iv_len, aad, aad_len,
                             pt, ct, ct_len, tag, tag_len);
    // memcpy( ct, ct_buf, ct_len );
    // memcpy( tag, tag_buf, tag_len ); 
    // printf("ciphertext:\n");
    // phex(ct_buf, 16);
    // printf("tag:\n");
    // phex(tag_buf, 16);
    // ret |= memcmp( ct_buf, ct, ct_len );    // verify correct ciphertext
    // ret |= memcmp( tag_buf, tag, tag_len ); // verify correct authentication tag

    gcm_zero_ctx( &ctx );       // not really necessary here, but good to do

    return ( ret );             // return any error 'OR' generated above
}

static int test_gcm_decryption(
        const uint8_t *key,       // pointer to the cipher key
        size_t key_len,         // byte length of the key
        const uint8_t *iv,        // pointer to the initialization vector
        size_t iv_len,          // byte length of the initialization vector
        const uint8_t *aad,       // pointer to the non-ciphered additional data
        size_t aad_len,         // byte length of the additional AEAD data
        const uint8_t *pt,        // pointer to the plaintext SOURCE data
        const uint8_t *ct,        // pointer to the CORRECT cipher data
        size_t ct_len,          // byte length of the cipher data
        const uint8_t *tag,       // pointer to the CORRECT tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    uint8_t pt_buf[ctLen];          // plaintext results for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // decrypt the NIST-provided ciphertext and auth tag into the local pt_buf 
    ret = gcm_auth_decrypt( &ctx, iv, iv_len, aad, aad_len,
                             ct, pt_buf, ct_len, tag, tag_len);
    ret |= memcmp( pt_buf, pt, ct_len );
    if (ret == 0)
    {
        printf("Success!\n");
        // printf("plaintext:\n");
        // phex(pt_buf, ctLen);
    }
    
    gcm_zero_ctx( &ctx );

    return ( ret );             // return any error 'OR' generated above
}


/*
[Keylen = 256]
[IVlen = 96]
[PTlen = 128]
[AADlen = 0]
[Taglen = 128]

Count = 0
Key = 31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22
IV = 0d18e06c7c725ac9e362e1ce
PT = 2db5168e932556f8089a0622981d017d
AAD = 
CT = fa4362189661d163fcd6a56d8bf0405a
Tag = d636ac1bbedd5cc3ee727dc2ab4a9489
*/

int main(void)
{
    // int exit;

    int ret = 0;                // our function return status
    // uint8_t RecordType;           // 0 for end of file
                                // 1 for encrypt and/or auth
                                // 2 for decrypt and/or auth CORRECTLY
                                // 3 for decrypt and/or auth --FAIL--

    // declarations for the lengths and pointers to our test vectorse the le
    // size_t key_len, iv_len, aad_len, pt_len, ct_len, tag_len;
    // uint8_t *key, *iv, *aad, *pt, *ct, *tag;    
    // msg_buff msg_buffer;

#if defined(AES256)
    printf("\nTesting AES256\n\n");
#elif defined(AES192)
    printf("\nTesting AES192\n\n");
#elif defined(AES128)
    printf("\nTesting AES128\n\n");
#else
    printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
    return 0;
#endif
    FILE *ptr = NULL;
    uint8_t key[32];
    uint8_t keyv[32];
    uint8_t fw_magic [2];
    uint8_t prot_fw [1500];
    uint8_t tag[16];
    uint32_t fw_size = 0;
    const uint8_t iv[12];
    printf("OK\n");
    ptr = fopen("fw.prot","rb");  // r for read, b for binary
    if (ptr == NULL)
    {
    	printf("FIle failed to open");
    }
    printf("OK\n");

    fread(fw_magic, sizeof(fw_magic), 1, ptr); 
    printf("read magic\n");
    for (int i = 0; i < 2; i++)
    {
        printf("%c ", fw_magic[i]);
    }
    if (fseek(ptr,2, SEEK_SET) == 0)
        printf("\nseek success\n");
    printf("\nFw size : %d\n", fw_size);
    fread(&fw_size, sizeof(fw_size), 1, ptr); 
    printf("\nFw size : %d\n", fw_size);

    if (fseek(ptr,6, SEEK_SET) == 0)
        printf("\nseek success\n");
    fread(&iv, sizeof(iv), 1, ptr); 


    printf("\nIV\n");
    for (int i = 0; i < sizeof(iv); i++)
    {
        printf("%x ", iv[i]);
    }

     if (fseek(ptr,18, SEEK_SET) == 0)
        printf("\nseek success\n");
    fread(&tag, sizeof(tag), 1, ptr); 


    printf("\ntagv\n");
    for (int i = 0; i < sizeof(tag); i++)
    {
        printf("%x ", tag[i]);
    }

    FILE * ptr1 = fopen("keyv.bin","rb");  // r for read, b for binary
    if (ptr1 == NULL)
    {
    	printf("FIle failed to open");
    }
    fread(keyv, sizeof(keyv),1,ptr1); 
    fclose(ptr1);
    printf("\nKEY :\n");
    phex(keyv, keyLen);
    uint8_t output[20];
    uint8_t ct[20];

    if (fseek(ptr,34, SEEK_SET) == 0)
        printf("\nseek success\n");
    fread(&ct, sizeof(ct), 1, ptr); 
    printf("\nCipher :\n");
    phex(ct, 20);
    gcm_initialize();
    ret = aes_gcm_decrypt_auth(output, ct, 20, keyv, keyLen, iv, ivLen, tag, tagLen);
    if (ret != 0)
    {
        printf("Authentication Failure!\n");
        return (GCM_AUTH_FAILURE);
    }
    else{
         printf("SUCCESS!\n");
    }

    ptr = fopen("keyf.bin","rb");  // r for read, b for binary
    if (ptr == NULL)
    {
    	printf("FIle failed to open");
    }
    fread(key, sizeof(key),1,ptr); 
    fclose(ptr);
    /*for(int i = 0; i < 32; i++)
    {
    	printf("%x ", key[i]);
    }*/
    //return;
    

    uint8_t pt[26];
    ptr = fopen("plaintext.bin","rb");  // r for read, b for binary
    if (ptr == NULL)
    {
    	printf("FIle failed to open");
    }
    fread(pt, sizeof(pt),1,ptr);
    fclose(ptr);
    

    

    // memset(ct, 0, 12);
    memset(tag, 0, 16);
    memset(output, 0, ctLen);
    


    // printf("plaintext:\n");
    // phex(pt, ctLen);
    printf("key:\n");
    phex(key, keyLen);
    printf("iv:\n");
    phex(iv, 12);

    // printf("TEST ENCRYPTION:\n");
    // ret = test_gcm_encryption(key, keyLen, iv, ivLen, aad, aadLen, pt, ct, ctLen, tag, tagLen);
    // printf("ciphertext:\n");
    // phex(ct, 16);
    // printf("tag:\n");
    // phex(tag, 16);

    // printf("TEST DECRYPTION:\n");
    // ret = test_gcm_decryption(key, keyLen, iv, ivLen, aad, aadLen, pt, ct, ctLen, tag, tagLen);

    //ret = aes_gcm_encrypt_tag(ct, pt, ptLen, key, keyLen, iv, ivLen, tag, tagLen);
    // printf("ciphertext:\n");
    // phex(output, ctLen);
    // ptr = fopen("tag.bin","rb");  // r for read, b for binary
    // if (ptr == NULL)
    // {
    // 	printf("FIle failed to open");
    // }
    // fread(tag, sizeof(tag),1,ptr);
    // fclose(ptr);
    printf("tag:\n");
    phex(tag, 16);

    ptr = fopen("ciphertext.bin","rb");  // r for read, b for binary
    if (ptr == NULL)
    {
    	printf("FIle failed to open");
    }
    fread(ct, sizeof(ct),1,ptr);
    fclose(ptr);
    printf("cipher:\n");
    phex(ct, 32);
    // memset(output, 0, ctLen);
 
    ret = aes_gcm_decrypt_auth(output, ct, ctLen, key, keyLen, iv, ivLen, tag, tagLen);
    if (ret != 0)
    {
        printf("Authentication Failure!\n");
        return (GCM_AUTH_FAILURE);
    }

    printf("Authentication Success!\n");
    ret |= memcmp( output, pt, ctLen );
    if (ret == 0)
    {
        printf("Success!\n");
        // printf("plaintext:\n");
        // phex(pt_buf, ctLen);
    }
    printf("plaintext:\n");
    phex(output, ctLen);
    // printf("tag:\n");
    // phex(tag, 16);


    return ret;
}
