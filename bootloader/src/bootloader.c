/**
 * @file bootloader.c
 * @author Kyle Scaplen
 * @brief Bootloader implementation
 * @date 2022
 * 
 * This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 * 
 * @copyright Copyright (c) 2022 The MITRE Corporation
 */

#include <stdint.h>
#include <stdbool.h>

#include "driverlib/interrupt.h"
#include "driverlib/sysctl.h"
#include "driverlib/eeprom.h"
#include "flash.h"
#include "uart.h"
#include "aes-gcm.h"
#include "aestest.h"
#include "bootLoaderHeader.h"
// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"
#endif


// Storage layout

/*
 * Firmware:
 *      Version: 0x0002B400 : 0x0002B404 (4B)
 *      Size:    0x0002B404 : 0x0002B408 (4B)
 *      Msg:     0x0002B408 : 0x0002BC00 (~2KB = 1KB + 1B + pad)
 *      Fw:      0x0002BC00 : 0x0002FC00 (16KB)
 * Configuration:
 *      Size:    0x0002FC00 : 0x0003000 (1KB = 4B + pad)
 *      Cfg:     0x00030000 : 0x0004000 (64KB)
 */
#define FIRMWARE_METADATA_PTR      ((uint32_t)(FLASH_START + 0x0002B400))
#define FIRMWARE_SIZE_PTR          ((uint32_t)(FIRMWARE_METADATA_PTR + 0))
#define FIRMWARE_VERSION_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + 4))
#define FIRMWARE_RELEASE_MSG_PTR   ((uint32_t)(FIRMWARE_METADATA_PTR + 8))
#define FIRMWARE_RELEASE_MSG_PTR2  ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE))

#define FIRMWARE_STORAGE_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + (FLASH_PAGE_SIZE*2)))
#define FIRMWARE_BOOT_PTR          ((uint32_t)0x20004000)

#define CONFIGURATION_METADATA_PTR ((uint32_t)(FIRMWARE_STORAGE_PTR + (FLASH_PAGE_SIZE*16)))
#define CONFIGURATION_SIZE_PTR     ((uint32_t)(CONFIGURATION_METADATA_PTR + 0))

#define CONFIGURATION_STORAGE_PTR  ((uint32_t)(CONFIGURATION_METADATA_PTR + FLASH_PAGE_SIZE))


// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01


/**
 * @brief Boot the firmware.
 */
/*While generating secrets genereate 64 bytes of garbage that will be on block 0, put the secrect starting from location 64*/
void eeprom_data_handling()
{
    uint8_t eeprom_read[EEPROM_BLOCK_SIZE];
    //uint32_t eeprom_size = EEPROMSizeGet();
    //uint32_t block_count =  EEPROMBlockCountGet();

    EEPROMRead(eeprom_read, 0x0, sizeof(eeprom_read)); /*EEPROM block hiding first block does not work*/
    EEPROMRead(eeprom_read, BOOTLOADER_SECRET_DATA_PTR, sizeof(eeprom_read)); /*EEPROM block hiding*/
    memset(eeprom_read, 0, sizeof(eeprom_read));
    EEPROMBlockHide(EEPROM_SECRET_BLOCK_START);
    EEPROMRead(eeprom_read, BOOTLOADER_SECRET_DATA_PTR, sizeof(eeprom_read)); /*EEPROM block hiding*/
    uint32_t protec_ret;
    for (uint32_t i = 0; i < 32; i++)
    {
        protec_ret = EEPROMBlockProtectGet(i);
    }
}

void handle_boot(void)
{    
    uint32_t size;
    uint32_t i = 0;
    uint8_t *rel_msg;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // Find the metadata
    size = *((uint32_t *)FIRMWARE_SIZE_PTR);

    // Copy the firmware into the Boot RAM section
    for (i = 0; i < size; i++) {
        *((uint8_t *)(FIRMWARE_BOOT_PTR + i)) = *((uint8_t *)(FIRMWARE_STORAGE_PTR + i));
    }

    uart_writeb(HOST_UART, 'M');

    // Print the release message
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;
    while (*rel_msg != 0) {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');

    // Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}


/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void)
{
    uint8_t region;
    uint8_t *address;
    uint32_t size = 0;
    
    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F') {
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        // Acknowledge the hose
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }

    // Receive the size to send back to the host
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Read out the memory
    uart_write(HOST_UART, address, size);
}


/**
 * @brief Read data from a UART interface and program to flash memory.
 * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
void load_data(uint32_t interface, uint32_t dst, uint32_t size)
{
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }
}
bool check_FW_magic(protected_fw_format *fw_meta)
{
    if (fw_meta->FW_magic[0] == 'F' && fw_meta->FW_magic[1] == 'W')
        return true;
    return false;
}
/**
 * @brief Update the firmware.
 */
void handle_update(void)
{
    //eeprom_data_handling();
    // metadata
    int ret = 0;  
    uint32_t current_version;
    uint32_t version = 0;
    uint32_t size = 0;
    uint32_t rel_msg_size = 0;
    uint8_t rel_msg[1025]; // 1024 + terminator
    protected_fw_format fw_meta;
    uint8_t version_cipher_data[VERSION_CIPHER_SIZE];
    uint8_t output[VERSION_CIPHER_SIZE];
    //uint8_t received_magic [FW_MAGIC_LEN];
    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');
    uart_read(HOST_UART, &fw_meta, FW_META_INFO); /*READ 34 Bytes: MAGIC(2) +  FW_SIZE(4) + IVF(12) + tagv(16)

    /*STOP udpate if magic is wrong*/ 
    if (!check_FW_magic(&fw_meta))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    uart_read(HOST_UART, version_cipher_data, VERSION_CIPHER_SIZE);

    // Get keyv from eeprom
    EEPROMRead(keyv, 0x0, AES_KEY_LEN);
    gcm_initialize();

    memset(output, 0, VERSION_CIPHER_SIZE);

    ret = aes_gcm_decrypt_auth(output, version_cipher_data, VERSION_CIPHER_SIZE, keyv, AES_KEY_LEN, fw_meta.IVf, IV_SIZE, fw_meta.tagv, TAG_SIZE);
    if (ret != 0)
    {
        // Authentication failure of version data
        uart_writeb(HOST_UART, FRAME_BAD);
        return;

    }
    memcpy(&fw_meta.version_number, output, VERSION_CIPHER_SIZE);

        // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg) + 1; // Include terminator
    
    // Receive size
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Receive version
    version = ((uint32_t)uart_readb(HOST_UART)) << 8;
    version |= (uint32_t)uart_readb(HOST_UART);

 


    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((version != 0) && (version < current_version)) {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Only save new version if it is not 0
    if (version != 0) {
        flash_write_word(version, FIRMWARE_VERSION_PTR);
    } else {
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Save size
    flash_write_word(size, FIRMWARE_SIZE_PTR);

    // Write release message
    uint8_t *rel_msg_read_ptr = rel_msg;
    uint32_t rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR;
    uint32_t rem_bytes = rel_msg_size;

    // If release message goes outside of the first page, write the first full page
    if (rel_msg_size > (FLASH_PAGE_SIZE-8)) {

        // Write first page
        flash_write((uint32_t *)rel_msg, FIRMWARE_RELEASE_MSG_PTR, (FLASH_PAGE_SIZE-8) >> 2); // This is always a multiple of 4

        // Set up second page
        rem_bytes = rel_msg_size - (FLASH_PAGE_SIZE-8);
        rel_msg_read_ptr = rel_msg + (FLASH_PAGE_SIZE-8);
        rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR2;
        flash_erase_page(rel_msg_write_ptr);
    }

    // Program last or only page of release message
    if (rem_bytes % 4 != 0) {
        rem_bytes += 4 - (rem_bytes % 4); // Account for partial word
    }
    flash_write((uint32_t *)rel_msg_read_ptr, rel_msg_write_ptr, rem_bytes >> 2);

    // Acknowledge
    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve firmware
    load_data(HOST_UART, FIRMWARE_STORAGE_PTR, size);
}


/**
 * @brief Load configuration data.
 */
void handle_configure(void)
{
    uint32_t size = 0;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    // Receive size
    size = (((uint32_t)uart_readb(HOST_UART)) << 24);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    size |= ((uint32_t)uart_readb(HOST_UART));

    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write_word(size, CONFIGURATION_SIZE_PTR);

    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve configuration
    load_data(HOST_UART, CONFIGURATION_STORAGE_PTR, size);
}


/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 * 
 * @return int
 */
int main(void) {

    uint8_t cmd = 0;

#ifdef EXAMPLE_AES
    // -------------------------------------------------------------------------
    // example encryption using tiny-AES-c
    // -------------------------------------------------------------------------
    struct AES_ctx ctx;
    uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
                        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    uint8_t plaintext[16] = "0123456789abcdef";

    // initialize context
    AES_init_ctx(&ctx, key);

    // encrypt buffer (encryption happens in place)
    AES_ECB_encrypt(&ctx, plaintext);

    // decrypt buffer (decryption happens in place)
    AES_ECB_decrypt(&ctx, plaintext);
    // -------------------------------------------------------------------------
    // end example
    // -------------------------------------------------------------------------
#endif

    // Initialize IO components
    uart_init();
    // SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    // uint8_t inItRet = EEPROMInit();
    // Handle host commands
    while (1) {
        cmd = uart_readb(HOST_UART);

        switch (cmd) {
        case 'C':
            handle_configure();
            break;
        case 'U':
            handle_update();
            break;
        case 'R':
            handle_readback();
            break;
        case 'B':
            handle_boot();
            break;
        default:
            break;
        }
    }
}
