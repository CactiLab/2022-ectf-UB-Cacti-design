#  2022 eCTF
#  Bootloader Makefile
#  Kyle Scaplen
#
#  (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

# define the part type and base directory - must be defined for makedefs to work
PART=TM4C123GH6PM
CFLAGSgcc=-DTARGET_IS_TM4C123_RB1
ROOT=.

# Uncomment to enable debug symbols
DEBUG=1

# additional base directories
TIVA_ROOT=${ROOT}/lib/tivaware

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src
VPATH+=${TIVA_ROOT}

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc
IPATH+=${TIVA_ROOT}

# Include common makedefs
include ${TIVA_ROOT}/makedefs

# add initial firmware version
CFLAGS+=-DOLDEST_VERSION=${OLDEST_VERSION}

# this rule must come first in `all`
all: ${COMPILER}

# this must be the last build rule of `all`
all:  ${COMPILER}/md5.o ${COMPILER}/bn.o ${COMPILER}/keys.o ${COMPILER}/rsa.o ${COMPILER}/aes.o ${COMPILER}/aes-gcm.o ${COMPILER}/gcm.o ${COMPILER}/bootloader.axf


################ start crypto example ################
# example AES rules to build in tiny-AES-c: https://github.com/kokke/tiny-AES-c
# make sure submodule has been pulled (run `git submodule update --init`)
# uncomment next line to activate
# EXAMPLE_AES=foo
ifdef EXAMPLE_AES
# path to crypto library
CRYPTOPATH=${ROOT}/lib/tiny-AES-c
AES_GCM_CRYPTOPATH=${ROOT}/lib/aes256-gcm
# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}
VPATH+=${AES_GCM_CRYPTOPATH}
# add crypto library to includes path
IPATH+=${CRYPTOPATH}
IPATH+=${AES_GCM_CRYPTOPATH}
# add crypto object file to includes path
# LDFLAGS+=${COMPILER}/aes.o

# add compiler flag to enable example AES code 
CFLAGS+=-DEXAMPLE_AES

# add rule to build crypto library
${COMPILER}/bootloader.axf: ${COMPILER}/aes.o
endif
################ end crypto example ################
#ADD AES_GCM crypto

AES_GCM_CRYPTOPATH=${ROOT}/lib/aes256-gcm

IPATH+=${AES_GCM_CRYPTOPATH}
VPATH+=${AES_GCM_CRYPTOPATH}

# add crypto object file to includes path
LDFLAGS+=${COMPILER}/aes.o
LDFLAGS+=${COMPILER}/aes-gcm.o
LDFLAGS+=${COMPILER}/gcm.o
#ADD AES_GCM crypto end


################ add RSA ################
# path to auth library
RSAPATH=${ROOT}/lib/rsa
# add path to auth source files to source path
VPATH+=${RSAPATH}
# add auth library to includes path
IPATH+=${RSAPATH}
# add auth object file to includes path
LDFLAGS+=${COMPILER}/bn.o 
LDFLAGS+=${COMPILER}/keys.o 
LDFLAGS+=${COMPILER}/rsa.o

# ################ add sha1 ################
# path to auth library
MD5PATH=${ROOT}/lib/auth
# add path to auth source files to source path
VPATH+=${MD5PATH}
# add auth library to includes path
IPATH+=${MD5PATH}
# add auth object file to includes path
LDFLAGS+=${COMPILER}/md5.o

################ end adding RSA ################

# build libraries
${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a:
	${MAKE} -C ${TIVA_ROOT}/driverlib

tivaware: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a

# clean the libraries
clean_tivaware:
	${MAKE} -C ${TIVA_ROOT}/driverlib clean

# clean all build products
clean: clean_tivaware
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}


# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))
arg_check:
	$(call check_defined, OLDEST_VERSION)


# for each source file that needs to be compiled besides the file that defines `main`

# Check arguments
${COMPILER}/bootloader.axf: arg_check
${COMPILER}/bootloader.axf: ${COMPILER}/flash.o
${COMPILER}/bootloader.axf: ${COMPILER}/mpu_init.o
${COMPILER}/bootloader.axf: ${COMPILER}/uart.o
${COMPILER}/bootloader.axf: ${COMPILER}/bootloader.o
${COMPILER}/bootloader.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/bootloader.axf: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a


SCATTERgcc_bootloader=${TIVA_ROOT}/bootloader.ld
ENTRY_bootloader=Bootloader_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
