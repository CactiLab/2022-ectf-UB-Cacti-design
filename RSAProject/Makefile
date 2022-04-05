CC=gcc
CFLAGS=-Wall
TARGET=rsatest
# OBJS=main.o rsa_test.o rsa.object

SRCS = main.c	\
	rsa_test.c	\
	aes/aes.c	\
	aes/aesni.c	\
	aes/padlock.c	\
	md5/md5.c	\
	rsa/pk.c	\
	rsa/pkparse.c	\
	rsa/pk_wrap.c	\
	rsa/asn1write.c	\
	rsa/base64.c	\
	rsa/cipher.c	\
	rsa/cipher_wrap.c	\
	rsa/des.c	\
	rsa/pem.c	\
	rsa/pkwrite.c	\
	rsa/asn1parse.c	\
	rsa/bignum.c	\
	rsa/ctr_drbg.c	\
	rsa/entropy.c	\
	rsa/entropy_poll.c	\
	rsa/md_wrap.c	\
	rsa/md.c	\
	rsa/oid.c	\
	rsa/rsa.c	\
	rsa/timing.c	\
	sha/sha256.c

INC+=-I./rsa -I./aes -I./sha -I./md5

# SRCS := $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# all: ${BINS}

$(TARGET):$(OBJS)
	@echo "Checking.."
	${CC} ${INC} -o $@ $^

%.o: %.c
	@echo "Creating object.."
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<


# aestest: $(OBJS)

# test: rsatest
# 	./rsatest

clean:
	rm -rf $(TARGET) $(OBJS)

# INC=
# gcc main.c rsa_test.c rsa/rsa.c -Irsa -Iaes -Imd5 -Isha