//
//  rsa_test.h
//  RSAProject
//
//  Created by guozhicheng on 5/9/16.
//  Copyright © 2016 guozhicheng. All rights reserved.
//

#ifndef rsa_test_h
#define rsa_test_h

#include <inttypes.h>
#include <stdio.h>

#define KEY_SIZE 2048
#define EXPONENT 65537
#define MSG_SIZE 64

int mbedtls_rsa_self_test( int verbose );

void testprint();

void generateRSAKeys();

void initPubKey();

void pubEn() ;

typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

#endif /* rsa_test_h */
