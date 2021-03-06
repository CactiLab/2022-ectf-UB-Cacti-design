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
#include "rsa.h"

#include "bootLoaderHeader.h"
// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"
#endif

#ifdef RSA_AUTH
uint8_t challenge[CHALLENGE_SIZE] = {0};
uint8_t challenge_signed[CHALLENGE_SIZE] = {0};
uint8_t challenge_auth[CHALLENGE_SIZE] = {0};
// read public key from eeprom
rsa_pk host_pub;
#endif

/**
 * @brief Boot the firmware.
 */
// void systick_handler()
// {
//     SysTickPeriodSet(SYSTICK_HIGHEST_VALUE);
// }

void handle_boot(void)
{
    uint32_t fw_size = 0, cfg_size = 0, blocks = 0, block_size = 0;
    uint32_t i = 0;
    uint8_t *rel_msg;
    uint8_t *FW_cipher;
    uint8_t *CFG_cipher;
    int ret = 0;

    uint8_t *plaintext = (uint8_t *)DUMMY_PLAINTEXT;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // handle configuration data verification
    cfg_size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
    CFG_cipher = (uint8_t *)CONFIGURATION_STORAGE_PTR;
    EEPROMRead(&cfg_boot_meta, EEPROM_BOOT_CFG_META_DATA_ADDRESS, BOOT_CFG_META_SIZE);
    if (!verify_saffire_cipher(cfg_size, CFG_cipher, plaintext, &(cfg_boot_meta.IVc), &(cfg_boot_meta.tagc), (uint32_t)EEPROM_KEYC_ADDRESS))
    {
        uart_writeb(HOST_UART, 'Y');
        return;
    }

    // handle firmware data verification
    fw_size = *((uint32_t *)FIRMWARE_SIZE_PTR);
    FW_cipher = (uint8_t *)FIRMWARE_STORAGE_PTR;
    EEPROMRead(&boot_meta, EEPROM_BOOT_FW_META_DATA_ADDRESS, BOOT_FW_META_SIZE);
    if (!verify_saffire_cipher(fw_size, FW_cipher, plaintext, &(boot_meta.IVf), &(boot_meta.tagf), (uint32_t)EEPROM_KEYF_ADDRESS))
    {
        uart_writeb(HOST_UART, 'X');
        return;
    }

    // write cfg data as plain text
    memset(plaintext, 0, MAX_BLOCK_SIZE);
    blocks = (cfg_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    for (uint32_t i = 0; i < blocks; i++)
    {
        if (i == blocks - 1)
        {
            block_size = cfg_size - i * MAX_BLOCK_SIZE;
        }
        else
        {
            block_size = MAX_BLOCK_SIZE;
        }
        verify_saffire_cipher(block_size, &CFG_cipher[i * MAX_BLOCK_SIZE], plaintext, &(cfg_boot_meta.IVc), &(cfg_boot_meta.tagc[i * TAG_SIZE]), (uint32_t)EEPROM_KEYC_ADDRESS);
        load_data_on_flash(plaintext, (uint32_t)(CONFIGURATION_STORAGE_PTR + i * MAX_BLOCK_SIZE), block_size);
    }
    // update crypto flag for configuration
    cfg_boot_meta.cyrpto_flag = 0x1;
    EEPROMProgram(&cfg_boot_meta.cyrpto_flag, EEPROM_BOOT_CFG_META_DATA_ADDRESS + 268, sizeof(uint32_t));

    // get plaintext of the firmware
    memset(plaintext, 0, MAX_BLOCK_SIZE * 4);
    blocks = (fw_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    for (uint32_t i = 0; i < blocks; i++)
    {
        if (i == blocks - 1)
        {
            block_size = fw_size - i * MAX_BLOCK_SIZE;
        }
        else
        {
            block_size = MAX_BLOCK_SIZE;
        }
        verify_saffire_cipher(block_size, &FW_cipher[i * MAX_BLOCK_SIZE], &plaintext[i * MAX_BLOCK_SIZE], &(boot_meta.IVf), &(boot_meta.tagf[i * TAG_SIZE]), (uint32_t)EEPROM_KEYF_ADDRESS);
    }

    uart_writeb(HOST_UART, 'M');

    // Print the release message
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;
    while (*rel_msg != 0)
    {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');
    // SysTickDisable();
    //  Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}

#ifdef RSA_AUTH
void random_generate(uint8_t *challenge)
{
    // uint32_t seed = SysTickValueGet();
    // uint32_t tmp = 0;
    // srand(seed);
    for (uint32_t i = 0; i < CHALLENGE_SIZE; i++)
    {
        challenge[i] = i;
        // tmp = rand();
        // challenge[i++] = *(((uint8_t *)&tmp)+0);
        // challenge[i++] = *(((uint8_t *)&tmp)+1);
        // challenge[i++] = *(((uint8_t *)&tmp)+2);
        // challenge[i++] = *(((uint8_t *)&tmp)+3);
    }
}
#endif

/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void)
{
    uint8_t region;
    uint8_t *address;
    uint32_t size = 0;
    uint32_t total_size;
    uint8_t *readback_data = (uint8_t *)DUMMY_PLAINTEXT;
    memset(readback_data, 0, MAX_BLOCK_SIZE * 4);
#ifdef MPU_ENABLED
    uint32_t mpu_change_ap_flag = 0;
#endif

    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

#ifdef RSA_AUTH
    EEPROMRead(&host_pub, EEPROM_PUBLIC_KEY_ADDRESS, EEPROM_HOST_PUBKEY_SIZE);
    // add verification: send challenge
    random_generate(challenge);
    // send the challenge
    uart_write(HOST_UART, challenge, CHALLENGE_SIZE);

    // receive the signature from host: chellenge_signed
    uart_read(HOST_UART, challenge_signed, MAX_MODULUS_LENGTH * 2);

    rsa_encrypt((DTYPE *)&challenge_auth, MAX_MODULUS_LENGTH, (DTYPE *)&challenge_signed, MAX_MODULUS_LENGTH, &host_pub);
    int ret = memcmp(challenge_auth, challenge, CHALLENGE_SIZE);
    if (ret != 0)
    {
        uart_writeb(HOST_UART, 'A');
        return;
    }
    uart_writeb(HOST_UART, 'S');
#endif

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F')
    {
#ifdef MPU_ENABLED
        mpu_change_ap_flag = 3;
        mpu_ap_change(31);
#endif
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        total_size = *((uint32_t *)FIRMWARE_SIZE_PTR);
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    }
    else if (region == 'C')
    {
#ifdef MPU_ENABLED
        mpu_change_ap_flag = 4;
        mpu_ap_change(41);
#endif
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        total_size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
        // Acknowledge the hose
        uart_writeb(HOST_UART, 'C');
    }
    else
    {
#ifdef MPU_ENABLED
        mpu_change_ap_flag = 0;
#endif
        return;
    }

    // Receive the size to send back to the host
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    if (size > total_size)
        return;

    uint32_t readback_blocks = (size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    uint32_t total_blocks = (total_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    uint32_t block_size = 0;

    EEPROMRead(&boot_meta, EEPROM_BOOT_FW_META_DATA_ADDRESS, BOOT_FW_META_SIZE);
    EEPROMRead(&cfg_boot_meta, EEPROM_BOOT_CFG_META_DATA_ADDRESS, BOOT_CFG_META_SIZE);

    for (uint32_t i = 0; i < total_blocks && i < readback_blocks; i++)
    {
        if (i == total_blocks - 1)
        {
            block_size = total_size - i * MAX_BLOCK_SIZE;
        }
        else
        {
            block_size = MAX_BLOCK_SIZE;
        }
        if (region == 'C')
        {
            if (!verify_saffire_cipher(block_size, &address[i * MAX_BLOCK_SIZE], readback_data, &(cfg_boot_meta.IVc), &(cfg_boot_meta.tagc[i * TAG_SIZE]), (uint32_t)EEPROM_KEYC_ADDRESS))
                return;
        }
        else if (region == 'F')
        {
            if (!verify_saffire_cipher(block_size, &address[i * MAX_BLOCK_SIZE], readback_data, &(boot_meta.IVf), &(boot_meta.tagf[i * TAG_SIZE]), (uint32_t)EEPROM_KEYF_ADDRESS))
                return;
        }

        uart_write(HOST_UART, readback_data, block_size < size ? block_size : size);
        size -= block_size;
    }
    // Read out the memory
#ifdef MPU_ENABLED
    if (mpu_change_ap_flag != 0)
        MPURegionDisable(mpu_change_ap_flag);
#endif
}

/**
 * @brief Read data from a UART interface and program to flash memory.
 *
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */

void load_data_on_flash(uint8_t *source, uint32_t dst, uint32_t size)
{
    int i;
    uint32_t indx = 0;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while (size > 0)
    {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;

        memcpy(page_buffer, &source[indx], frame_size);
        indx += frame_size;
        // pad buffer if frame is smaller than the page
        for (i = frame_size; i < FLASH_PAGE_SIZE; i++)
        {
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

bool verify_saffire_cipher(uint32_t size, uint8_t *cipher, uint8_t *plaintext, uint8_t *IV, uint8_t *tag, uint32_t key_address)
{
    int ret = 0;
    uint8_t key[AES_KEY_LEN];
    // Get keyf from eeprom
    EEPROMRead(key, key_address, AES_KEY_LEN);

    int blocks = (size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    int block_size;
    for (int i = 0; i < blocks; i++)
    {
        if (i == blocks - 1)
        {
            block_size = size - i * MAX_BLOCK_SIZE;
        }
        else
        {
            block_size = MAX_BLOCK_SIZE;
        }
        ret = aes_gcm_decrypt_auth(plaintext, &cipher[i * MAX_BLOCK_SIZE], block_size, key, AES_KEY_LEN, IV, IV_SIZE, &tag[i * TAG_SIZE], TAG_SIZE);
        if (ret != 0)
        {
            // Authentication failure of version data
            return false;
        }
    }
    // Firmware data aunthentication success
    return true;
}

void handle_CFG_verification_response(protected_cfg_format *cfg_meta)
{
    int i;
    uint32_t frame_size = 0;
    uint32_t c_size = cfg_meta->CFG_size;
    uint32_t dst = CONFIGURATION_STORAGE_PTR;
    uint8_t *cfg_plaintext = (uint8_t *)DUMMY_PLAINTEXT;
    memset(cfg_plaintext, 0, MAX_BLOCK_SIZE * 4);
    // uint8_t cfg_cipher[MAX_BLOCK_SIZE];
    uint8_t page_buffer[FLASH_PAGE_SIZE] = {0};

    while (c_size > 0)
    {
        // calculate frame size
        frame_size = c_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : c_size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for (i = frame_size; i < FLASH_PAGE_SIZE; i++)
        {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        c_size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }

    c_size = cfg_meta->CFG_size;
    int blocks = (c_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    int block_size;
    uint8_t *cipher_ptr = (uint8_t *)CONFIGURATION_STORAGE_PTR;
    if (!verify_saffire_cipher(c_size, cipher_ptr, cfg_plaintext, &(cfg_meta->IVc), &(cfg_meta->tagc), (uint32_t)EEPROM_KEYC_ADDRESS))
    {
        dst = CONFIGURATION_STORAGE_PTR;
        while (c_size > 0)
        {
            frame_size = c_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : c_size;
            flash_erase_page(dst);
            dst += FLASH_PAGE_SIZE;
            c_size -= frame_size;
        }
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);
}

void handle_FW_verification_response(protected_fw_format *fw_meta)
{
    int i;
    uint32_t frame_size;
    uint32_t f_size = fw_meta->FW_size;
    uint32_t dst = FIRMWARE_STORAGE_PTR;
    uint8_t *fw_plaintext = (uint8_t *)DUMMY_PLAINTEXT;
    memset(fw_plaintext, 0, MAX_BLOCK_SIZE * 4);
    // uint8_t FW_cipher[f_size];
    uint8_t page_buffer[FLASH_PAGE_SIZE] = {0};

    while (f_size > 0)
    {
        // calculate frame size
        frame_size = f_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : f_size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for (i = frame_size; i < FLASH_PAGE_SIZE; i++)
        {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        f_size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }

    f_size = fw_meta->FW_size;
    int blocks = (f_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
    int block_size;
    uint8_t *cipher_ptr = (uint8_t *)FIRMWARE_STORAGE_PTR;
    if (!verify_saffire_cipher(f_size, cipher_ptr, fw_plaintext, &(fw_meta->IVf), &(fw_meta->tagf), (uint32_t)EEPROM_KEYF_ADDRESS))
    {
        dst = FIRMWARE_STORAGE_PTR;
        while (f_size > 0)
        {
            frame_size = f_size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : f_size;
            flash_erase_page(dst);
            dst += FLASH_PAGE_SIZE;
            f_size -= frame_size;
        }
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);
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
    uint32_t current_version = 0;
    uint32_t rel_msg_size = 0;
    uint8_t rel_msg[MAX_RELEASE_MESSAGE_SIZE] = {0}; // 1024 + terminator
    protected_fw_format fw_meta;
    uint8_t version_cipher_data[VERSION_CIPHER_SIZE] = {0};
    uint8_t output[VERSION_CIPHER_SIZE] = {0};

    memset(&fw_meta, 0, sizeof(protected_fw_format));
    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    uart_read(HOST_UART, &fw_meta, FW_META_INFO); /*READ 34 Bytes: MAGIC(2) +  FW_SIZE(4) + IVF(12) + tagv(16)

    /*STOP udpate if magic is wrong*/
    if (!check_FW_magic(&fw_meta))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    // Acknowledge magic number verification
    uart_writeb(HOST_UART, FRAME_OK);
    uart_read(HOST_UART, version_cipher_data, VERSION_CIPHER_SIZE);

    memset(output, 0, VERSION_CIPHER_SIZE);

    if (!verify_saffire_cipher(VERSION_CIPHER_SIZE, version_cipher_data, output, &(fw_meta.IVf), &(fw_meta.tagv), (uint32_t)EEPROM_KEYV_ADDRESS))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    // Acknowledge version data verification success
    uart_writeb(HOST_UART, FRAME_OK);

    // Check the version
    memcpy((uint32_t)&fw_meta.version_number, output, sizeof(int));
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF)
    {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((fw_meta.version_number != 0) && (fw_meta.version_number < current_version))
    {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Acknowledge version number checking success
    uart_writeb(HOST_UART, FRAME_OK);

    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg) + 1; // Include terminator

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Only save new version if it is not 0
    if (fw_meta.version_number != 0)
    {
        flash_write_word(fw_meta.version_number, FIRMWARE_VERSION_PTR);
    }
    else
    {
        // stored_version = current_version;
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Save size
    flash_write_word(fw_meta.FW_size, FIRMWARE_SIZE_PTR);

    // Write release message
    uint8_t *rel_msg_read_ptr = rel_msg;
    uint32_t rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR;
    uint32_t rem_bytes = rel_msg_size;

    // If release message goes outside of the first page, write the first full page
    if (rel_msg_size > (FLASH_PAGE_SIZE - 8))
    {

        // Write first page
        flash_write((uint32_t *)rel_msg, FIRMWARE_RELEASE_MSG_PTR, (FLASH_PAGE_SIZE - 8) >> 2); // This is always a multiple of 4

        // Set up second page
        rem_bytes = rel_msg_size - (FLASH_PAGE_SIZE - 8);
        rel_msg_read_ptr = rel_msg + (FLASH_PAGE_SIZE - 8);
        rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR2;
        flash_erase_page(rel_msg_write_ptr);
    }

    // Program last or only page of release message
    if (rem_bytes % 4 != 0)
    {
        rem_bytes += 4 - (rem_bytes % 4); // Account for partial word
    }
    flash_write((uint32_t *)rel_msg_read_ptr, rel_msg_write_ptr, rem_bytes >> 2);

    // Acknowledge release message
    uart_writeb(HOST_UART, FRAME_OK);

    // Retrieve firmware
    memcpy(&fw_meta.tagf, &output[sizeof(int)], VERSION_CIPHER_SIZE - sizeof(int));
    handle_FW_verification_response(&fw_meta);

    memcpy(&boot_meta.IVf, &fw_meta.IVf, IV_SIZE);
    memcpy(&boot_meta.tagf, &output[sizeof(int)], TAG_SIZE * MAX_FW_TAG_NUM);
    EEPROMProgram(&boot_meta, EEPROM_BOOT_FW_META_DATA_ADDRESS, BOOT_FW_META_SIZE);
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
    memset(&cfg_meta, 0, sizeof(protected_cfg_format));
    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    uart_read(HOST_UART, &cfg_meta, CFG_META_INFO); /*READ 275 Bytes: MAGIC(3) +  FW_SIZE(4) + IVF(12) + tagv(16 * 16)*/

    if (!check_CFG_magic(&cfg_meta))
    {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    // Acknowledge magic number verification
    uart_writeb(HOST_UART, FRAME_OK);

    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write_word(cfg_meta.CFG_size, CONFIGURATION_SIZE_PTR);

    // Retrieve configuration
    handle_CFG_verification_response(&cfg_meta);
    memcpy(&cfg_boot_meta.IVc, &cfg_meta.IVc, IV_SIZE);
    memcpy(&cfg_boot_meta.tagc, &cfg_meta.tagc, TAG_SIZE * MAX_CFG_TAG_NUM);
    cfg_boot_meta.cyrpto_flag = 0xFFFFFFFF;
    EEPROMProgram(&cfg_boot_meta, EEPROM_BOOT_CFG_META_DATA_ADDRESS, BOOT_CFG_META_SIZE);
    uart_writeb(HOST_UART, FRAME_OK); /*remove this later*/
}
void cfg_initialize()
{
    EEPROMRead(&cfg_boot_meta.cyrpto_flag, EEPROM_BOOT_CFG_META_DATA_ADDRESS + 268, BOOT_CFG_META_SIZE);
    if (cfg_boot_meta.cyrpto_flag == 0x1)
    {
        uint32_t cfg_size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
        uint8_t *CFG_DATA = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        uint8_t *CFG_cipher = (uint8_t *)DUMMY_PLAINTEXT;
        uint8_t key[AES_KEY_LEN] = {0};
        uint32_t blocks = (cfg_size + (MAX_BLOCK_SIZE - 1)) / MAX_BLOCK_SIZE;
        uint32_t block_size = 0;

        EEPROMRead(key, (uint32_t)EEPROM_KEYC_ADDRESS, AES_KEY_LEN);

        for (uint32_t i = 0; i < blocks; i++)
        {
            if (i == blocks - 1)
            {
                block_size = cfg_size - i * MAX_BLOCK_SIZE;
            }
            else
            {
                block_size = MAX_BLOCK_SIZE;
            }
            // ret = aes_gcm_decrypt_auth(plaintext, &cipher[i * MAX_BLOCK_SIZE], block_size, key, AES_KEY_LEN, IV, IV_SIZE, &tag[i * TAG_SIZE], TAG_SIZE);
            aes_gcm_encrypt_tag(&CFG_cipher[i * MAX_BLOCK_SIZE], &CFG_DATA[i * MAX_BLOCK_SIZE], block_size, key, AES_KEY_LEN, &(cfg_boot_meta.IVc), IV_SIZE, &(cfg_boot_meta.tagc[i * TAG_SIZE]), TAG_SIZE);
            load_data_on_flash(&CFG_cipher[i * MAX_BLOCK_SIZE], &CFG_DATA[i * MAX_BLOCK_SIZE], block_size);
        }
        cfg_boot_meta.cyrpto_flag = 0xFFFFFFFF;
        EEPROMProgram(&cfg_boot_meta, EEPROM_BOOT_CFG_META_DATA_ADDRESS, BOOT_CFG_META_SIZE);
    }

    return;
}
/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 *
 * @return int
 */
int main(void)
{

    uint8_t cmd = 0;

    // SysTickPeriodSet(SYSTICK_HIGHEST_VALUE);
    // SysTickIntRegister(systick_handler);
    // SysTickIntEnable();
    // SysTickEnable();
    // Initialize IO components
    uart_init();
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    uint8_t inItRet = EEPROMInit();
    gcm_initialize();
    cfg_initialize();

#ifdef MPU_ENABLED
    mpu_init();
#endif
    // Handle host commands
    while (1)
    {
        cmd = uart_readb(HOST_UART);

        switch (cmd)
        {
        case 'C':
#ifdef MPU_ENABLED
            mpu_ap_change(40);
#endif
            handle_configure();
#ifdef MPU_ENABLED
            MPURegionDisable(4);
#endif
            break;
        case 'U':
#ifdef MPU_ENABLED
            mpu_ap_change(30);
#endif
            handle_update();
#ifdef MPU_ENABLED
            MPURegionDisable(3);
#endif
            break;
        case 'R':
            handle_readback();
            break;
        case 'B':
#ifdef MPU_ENABLED
            mpu_ap_change(30);
            mpu_ap_change(40);
            // mpu_ap_change(50);
#endif
            handle_boot();
#ifdef MPU_ENABLED
            MPURegionDisable(3);
            MPURegionDisable(4);
#endif
            break;
        default:
            break;
        }
    }
}