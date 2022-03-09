#ifndef BOOT_LOADER_HEADER
#define BOOT_LOADER_HEADER

/* macros */
#define MPU_ENABLED
// #define RSA_AUTH
#include "../lib/rsa/keys.h"
// Storage layout

/*
 * FLASH:
 *      Bootstrap Vector Tbl: 0x00000000 : 0x0000026C
 *      Bootstrapper:         0x0000026C : 0x00005800 
 *      Bootloader:           0x00005800 : 0x0002B400 ()
 * Firmware:
 *      Version: 0x0002B400 : 0x0002B404 (4B)
 *      Size:    0x0002B404 : 0x0002B408 (4B)
 *      Msg:     0x0002B408 : 0x0002BC00 (~2KB = 1KB + 1B + pad)
 *      Fw:      0x0002BC00 : 0x0002FC00 (16KB)
 * Configuration:
 *      Size:    0x0002FC00 : 0x0003000 (1KB = 4B + pad)
 *      Cfg:     0x00030000 : 0x0004000 (64KB)
 */

#define BOOTLOADER_PTR             ((uint32_t)(FLASH_START + 0x00005800))
#define FIRMWARE_METADATA_PTR      ((uint32_t)(FLASH_START + 0x0002B400))
#define FIRMWARE_SIZE_PTR          ((uint32_t)(FIRMWARE_METADATA_PTR + 0))
#define FIRMWARE_VERSION_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + 4))
#define FIRMWARE_RELEASE_MSG_PTR   ((uint32_t)(FIRMWARE_METADATA_PTR + 8))
#define FIRMWARE_RELEASE_MSG_PTR2  ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE))

#define FIRMWARE_STORAGE_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + (FLASH_PAGE_SIZE*2)))

#define CONFIGURATION_METADATA_PTR ((uint32_t)(FIRMWARE_STORAGE_PTR + (FLASH_PAGE_SIZE*16)))
#define CONFIGURATION_SIZE_PTR     ((uint32_t)(CONFIGURATION_METADATA_PTR + 0))

#define CONFIGURATION_STORAGE_PTR  ((uint32_t)(CONFIGURATION_METADATA_PTR + FLASH_PAGE_SIZE))

/*
 * SRAM:
 *      Stack:                0x20000000 : 0x20004000
 *      Firmware:             0x20004000 : 0x20008000
 */
#define STACK_PTR                  ((uint32_t)0x20000000)
#define FIRMWARE_BOOT_PTR          ((uint32_t)0x20004000)

// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01

#define BOOTLOADER_SECRET_DATA_PTR 0x40 /*We cannot start from zero as block 0 cannot be hidden. */
#define EEPROM_SECRET_BLOCK_START 0x1
#define EEPROM_BLOCK_SIZE 64
#define EEPROM_KEYV_ADDRESS 0x0
#define EEPROM_KEYF_ADDRESS 0x20
#define EEPROM_KEYC_ADDRESS 0x40
#define EEPROM_PUBLIC_KEY_ADDRESS 0x5a
#define FW_MAGIC_LEN 2
#define CFG_MAGIC_LEN 3
#define IV_SIZE 12
#define TAG_SIZE 16
#define VERSION_CIPHER_SIZE 20
#define AES_KEY_LEN 32
#define FW_META_INFO (FW_MAGIC_LEN + 4  + IV_SIZE + TAG_SIZE)
#define CFG_META_INFO (CFG_MAGIC_LEN + 4  + IV_SIZE + TAG_SIZE)
#define MAX_RELEASE_MESSAGE_SIZE 1025


typedef struct __attribute__((packed))
{
  uint8_t FW_magic[FW_MAGIC_LEN]; // 2 bytes
  uint32_t FW_size; // 4 bytes (2 + 4)
  uint8_t IVf[IV_SIZE]; // 12 bytes -> 18
  uint8_t tagv[TAG_SIZE]; // 16 bytes -> 34
  uint32_t version_number;
  uint8_t tagf[TAG_SIZE];
} protected_fw_format;

typedef struct __attribute__((packed))
{
  uint8_t CFG_magic[CFG_MAGIC_LEN]; // 3 bytes
  uint32_t CFG_size; // 4 bytes (3 + 4)
  uint8_t IVc[IV_SIZE]; // 12 bytes -> 19
  uint8_t tagc[TAG_SIZE]; // 16 bytes -> 35
} protected_cfg_format;

typedef struct __attribute__((packed))
{
  uint8_t IVc[IV_SIZE]; // 12 bytes -> 18
  uint8_t tagc[TAG_SIZE];
} cfg_boot_meta_data;

typedef struct __attribute__((packed))
{
  uint8_t IVf[IV_SIZE]; // 12 bytes -> 18
  uint8_t tagf[TAG_SIZE];
} fw_boot_meta_data;

fw_boot_meta_data boot_meta;
cfg_boot_meta_data cfg_boot_meta;
rsa_pk rsa_public_key;
//FUNCTIONS in bootloader.c

void handle_boot(void);
void handle_readback(void);
// void load_data_original(uint32_t interface, uint32_t dst, uint32_t size);
void load_verified_data_on_flash(uint8_t *source, uint32_t dst, uint32_t size);
bool verify_saffire_cipher(uint32_t size, uint8_t *cipher, uint8_t *plaintext, uint8_t *IV, uint8_t *tag, uint32_t key_address);
void handle_FW_verification_response(protected_fw_format *fw_meta);
bool check_FW_magic(protected_fw_format *fw_meta);
bool check_CFG_magic(protected_cfg_format *cfg_meta);
void handle_update(void);
void handle_configure(void);
void handle_CFG_verification_response(protected_cfg_format *cfg_meta);

void mpu_init();

#endif
