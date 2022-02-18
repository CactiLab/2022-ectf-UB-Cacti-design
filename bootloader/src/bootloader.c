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

#include "bootLoaderHeader.h"
// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"
#endif


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
    uint8_t *FW_cipher;
    int ret = 0;

    size = *((uint32_t *)FIRMWARE_SIZE_PTR);

    uint8_t FW_plaintext [size];
    // Get keyf from eeprom
    EEPROMRead(keyf, EEPROM_KEYF_ADDRESS, AES_KEY_LEN);
    // gcm_initialize();

    FW_cipher = (uint8_t *)FIRMWARE_STORAGE_PTR;
    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    if (!verify_saffire_cipher(size, FW_cipher, FW_plaintext, &(boot_meta.IVf), &(boot_meta.tagf), keyf, (uint32_t)EEPROM_KEYF_ADDRESS))
    {
        uart_writeb(HOST_UART, 'X');
        return;
    }

    // Copy the firmware into the Boot RAM section
    for (i = 0; i < size; i++) {
        *((uint8_t *)(FIRMWARE_BOOT_PTR + i)) = FW_plaintext[i];
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
// void load_data_original(uint32_t interface, uint32_t dst, uint32_t size)
// {
//     int i;
//     uint32_t frame_size;
//     uint8_t page_buffer[FLASH_PAGE_SIZE];

//     while(size > 0) {
//         // calculate frame size
//         frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
//         // read frame into buffer
//         uart_read(HOST_UART, page_buffer, frame_size);
//         // pad buffer if frame is smaller than the page
//         for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
//             page_buffer[i] = 0xFF;
//         }
//         // clear flash page
//         flash_erase_page(dst);
//         // write flash page
//         flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
//         // next page and decrease size
//         dst += FLASH_PAGE_SIZE;
//         size -= frame_size;
//         // send frame ok
//         uart_writeb(HOST_UART, FRAME_OK);
//     }
// }

void load_verified_data_on_flash(uint8_t *source, uint32_t dst, uint32_t size)
{
    int i;
    uint32_t indx = 0;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        
        memcpy(page_buffer, &source[indx], frame_size);
        indx += frame_size;
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
    }
}

void handle_CFG_verification_response(protected_cfg_format *cfg_meta)
{
    int i;
    uint32_t frame_size, current_indx = 0;
    uint32_t c_size = cfg_meta->CFG_size;
    uint8_t cfg_plaintext[c_size];
    uint8_t cfg_cipher[c_size];
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(c_size > 0) 
    {
        // calculate frame size
        frame_size = c_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : c_size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        memcpy(&cfg_cipher[current_indx], page_buffer, frame_size);
        c_size -= frame_size;
        current_indx += frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }
    //read encrypted cfg cipher
    if (verify_saffire_cipher(cfg_meta->CFG_size, cfg_cipher, cfg_plaintext, &(cfg_meta->IVc), &(cfg_meta->tagc), keyc, (uint32_t)EEPROM_KEYC_ADDRESS))
    {
        memset(cfg_plaintext, 0, cfg_meta->CFG_size);
        load_verified_data_on_flash(cfg_cipher, CONFIGURATION_STORAGE_PTR, cfg_meta->CFG_size);
        uart_writeb(HOST_UART, FRAME_OK);
    }
    else
    {
        /*configuration data verification failed notification*/
        uart_writeb(HOST_UART, FRAME_BAD);
    }
}

bool verify_saffire_cipher(uint32_t size, uint8_t *cipher, uint8_t *plaintext, uint8_t *IV, uint8_t *tag, uint8_t *key, uint32_t key_address)
{
    int ret = 0;
    // Get keyf from eeprom
    EEPROMRead(key, key_address, AES_KEY_LEN);
    // gcm_initialize();
    ret = aes_gcm_decrypt_auth(plaintext, cipher, size, keyf, AES_KEY_LEN, IV, IV_SIZE, tag, TAG_SIZE);

    memset(keyf, 0, AES_KEY_LEN);

    if (ret != 0)
    {
        // Authentication failure of version data
        return false;
    }
    //Firmware data aunthentication success
    return true;
}
void handle_FW_verification_response(protected_fw_format *fw_meta)
{
    int i;
    uint32_t frame_size, current_indx = 0;
    uint32_t f_size = fw_meta->FW_size;
    uint8_t FW_plaintext[f_size];
    uint8_t FW_cipher[f_size];
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(f_size > 0) {
        // calculate frame size
        frame_size = f_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : f_size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        memcpy(&FW_cipher[current_indx], page_buffer, frame_size);
        f_size -= frame_size;
        current_indx += frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }
    //read encrypted fw cipher
    if (verify_saffire_cipher(fw_meta->FW_size, FW_cipher, FW_plaintext, &(fw_meta->IVf), &(fw_meta->tagf), keyf, (uint32_t)EEPROM_KEYF_ADDRESS))
    {
        memset(FW_plaintext, 0, fw_meta->FW_size);
        load_verified_data_on_flash(FW_cipher, FIRMWARE_STORAGE_PTR, fw_meta->FW_size);
        uart_writeb(HOST_UART, FRAME_OK);
    }
    else
    {
        /*Firmware data verification failed notification*/
        uart_writeb(HOST_UART, FRAME_BAD);
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
    // metadata
    int ret = 0;  
    uint32_t current_version;
    uint32_t rel_msg_size = 0;
    uint8_t rel_msg[MAX_RELEASE_MESSAGE_SIZE]; // 1024 + terminator
    protected_fw_format fw_meta;
    uint8_t version_cipher_data[VERSION_CIPHER_SIZE];
    uint8_t output[VERSION_CIPHER_SIZE];

    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    uart_read(HOST_UART, &fw_meta, FW_META_INFO); /*READ 34 Bytes: MAGIC(2) +  FW_SIZE(4) + IVF(12) + tagv(16)

    /*STOP udpate if magic is wrong*/ 
    if (!check_FW_magic(&fw_meta))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    //Acknowledge magic number verification
    uart_writeb(HOST_UART, FRAME_OK);
    uart_read(HOST_UART, version_cipher_data, VERSION_CIPHER_SIZE);

    // Get keyv from eeprom
    EEPROMRead(keyv, EEPROM_KEYV_ADDRESS, AES_KEY_LEN);
    gcm_initialize();

    memset(output, 0, VERSION_CIPHER_SIZE);

    ret = aes_gcm_decrypt_auth(output, version_cipher_data, VERSION_CIPHER_SIZE, keyv, AES_KEY_LEN, &fw_meta.IVf, IV_SIZE, &fw_meta.tagv, TAG_SIZE);

    if (ret != 0)
    {
        // Authentication failure of version data
        uart_writeb(HOST_UART, FRAME_BAD);
        return;

    }
    //Clear the version number key
    memset(keyv, 0, AES_KEY_LEN);

    //Acknowledge version data verification success
    uart_writeb(HOST_UART, FRAME_OK);

    memcpy((uint32_t)&fw_meta.version_number, output, sizeof(int));
    memcpy(&fw_meta.tagf, &output[sizeof(int)] , VERSION_CIPHER_SIZE - sizeof(int));

    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg) + 1; // Include terminator
    
    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((fw_meta.version_number != 0) && (fw_meta.version_number < current_version)) {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Only save new version if it is not 0
    if (fw_meta.version_number != 0) {
        flash_write_word(fw_meta.version_number, FIRMWARE_VERSION_PTR);
    } else {
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Save size
    flash_write_word(fw_meta.FW_size, FIRMWARE_SIZE_PTR);

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

    // Acknowledge release message
    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve firmware
    handle_FW_verification_response(&fw_meta);
    memcpy(&boot_meta.IVf, &fw_meta.IVf, IV_SIZE);
    memcpy(&boot_meta.tagf, &fw_meta.tagf, TAG_SIZE);
}


bool check_CFG_magic(protected_cfg_format *cfg_meta)
{
    if (cfg_meta->CFG_magic[0] == 'C' && cfg_meta->CFG_magic[1] == 'F' && cfg_meta->CFG_magic[2] == 'G')
        return true;
    return false;
}

/**
 * @brief Load configuration data.
 */
void handle_configure(void)
{
    protected_cfg_format cfg_meta;
    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    uart_read(HOST_UART, &cfg_meta, CFG_META_INFO); /*READ 35 Bytes: MAGIC(3) +  FW_SIZE(4) + IVF(12) + tagv(16)*/
    
    if (!check_CFG_magic(&cfg_meta))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
     //Acknowledge magic number verification
    uart_writeb(HOST_UART, FRAME_OK);

    // // Receive size
    // size = (((uint32_t)uart_readb(HOST_UART)) << 24);
    // size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    // size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    // size |= ((uint32_t)uart_readb(HOST_UART));

    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write_word(cfg_meta.CFG_size, CONFIGURATION_SIZE_PTR);

    // uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve configuration
    handle_CFG_verification_response(&cfg_meta);
    // load_data_original(HOST_UART, CONFIGURATION_STORAGE_PTR, size);
    memcpy(&cfg_boot_meta.IVc, &cfg_meta.IVc, IV_SIZE);
    memcpy(&cfg_boot_meta.tagc, &cfg_meta.tagc, TAG_SIZE);
    uart_writeb(HOST_UART, FRAME_OK); /*remove this later*/

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
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    uint8_t inItRet = EEPROMInit();
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
