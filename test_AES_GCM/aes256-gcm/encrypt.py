#!/usr/bin/python3
import os
import math
from Crypto.Cipher import AES

FILE_NAME = 'file'
AES_KEY_SIZE = 32
IV_SIZE = 12
BLOCK_SIZE = 8192

def write_key_bin(key, file_name):
    try:
        with open(file_name, "wb") as file:
            # Print the success message
            file.write(key)
    # Raise error if the file is opened before
    except IOError:
        print("Failed to open the file.")

def main():
    iv =  os.urandom(IV_SIZE)
    key = os.urandom(AES_KEY_SIZE)
    write_key_bin(key, 'key.bin')
    write_key_bin(iv, 'iv.bin')

    with open(FILE_NAME, "rb") as file:
        data = file.read()
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    print(data[0:2].hex())
    print(data[2:3].hex())
    fw_ciphertext = b''
    tags = b''
    blocks = math.ceil(len(data) / BLOCK_SIZE)
    print(blocks)
    for x in range(blocks):
        if x == range(blocks)[-1]:
            partial_data = data[BLOCK_SIZE * x:]
        else:
            partial_data = data[BLOCK_SIZE * x: BLOCK_SIZE * (x+1)]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        fw_partial, tagf = cipher.encrypt_and_digest(partial_data)
        tags += tagf
        print(fw_partial[0:16].hex())
        fw_ciphertext += fw_partial
        
    # for x in range(8):
    #     partial_data = data[8192 * x: 8192 * (x+1)]
    #     cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    #     fw_partial, tagf = cipher.encrypt_and_digest(partial_data)
    #     print(fw_partial[0:16].hex())
    #     fw_ciphertext = fw_ciphertext + fw_partial
    print(tagf.hex())
    write_key_bin(fw_ciphertext, 'cipher.bin')
    write_key_bin(tags, 'tag.bin')
    print(data[0:16].hex())
    print(fw_ciphertext[0:16].hex())

if __name__ == "__main__":
    main()
