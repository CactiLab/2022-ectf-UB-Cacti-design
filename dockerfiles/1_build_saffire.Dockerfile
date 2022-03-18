# 2022 eCTF
# Host-Tools and Bootloader Creation Dockerfile
# Jake Grycel
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

FROM ubuntu:focal

# Add environment customizations here
# NOTE: do this first so Docker can used cached containers to skip reinstalling everything
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y python3 \
    binutils-arm-none-eabi gcc-arm-none-eabi make && \
    apt-get -y install python3-pip

RUN apt-get install wget -y
RUN wget https://ughe.github.io/data/2018/ld-linux-aarch64.so.1
RUN wget https://ughe.github.io/data/2018/libc.so.6
RUN mv ld-linux-aarch64.so.1 /lib/
RUN mv libc.so.6 /lib64/

#install pycrypto
RUN pip3 install pycryptodome
# Create bootloader binary folder
RUN mkdir /bootloader

# Add any system-wide secrets here
RUN mkdir /secrets

# Add host tools and bootloader source to container
ADD host_tools/ /host_tools
ADD bootloader /bl_build

# Generate Secrets
WORKDIR /host_tools/rsa
RUN make
WORKDIR /
RUN python3 /host_tools/generate_secrets
# Create EEPROM contents
RUN mv /secrets/eeprom.bin /bootloader/eeprom.bin
# Compile bootloader
WORKDIR /bl_build

ARG OLDEST_VERSION
RUN make OLDEST_VERSION=${OLDEST_VERSION}
RUN mv /bl_build/gcc/bootloader.bin /bootloader/bootloader.bin
RUN mv /bl_build/gcc/bootloader.axf /bootloader/bootloader.elf
