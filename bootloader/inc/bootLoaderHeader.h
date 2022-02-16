#ifndef BOOT_LOADER_HEADER
#define BOOT_LOADER_HEADER


#define BOOTLOADER_SECRET_DATA_PTR 0x40 /*We cannot start from zero as block 0 cannot be hidden. */
#define EEPROM_SECRET_BLOCK_START 0x1
#define EEPROM_BLOCK_SIZE 64
#define FW_MAGIC_LEN 2
#define CFG_MAGIC_LEN 3
#define IV_SIZE 12
#define TAG_SIZE 16
#define VERSION_CIPHER_SIZE 20
#define AES_KEY_LEN 32
#define FW_META_INFO (FW_MAGIC_LEN + 4  + IV_SIZE + TAG_SIZE)
// #define FW_META_INFO 12
// The key values will be populated from EEPROM data
uint8_t keyv[AES_KEY_LEN];
uint8_t keyf[AES_KEY_LEN];
uint8_t keyc[AES_KEY_LEN];

typedef struct __attribute__((packed))
{
  uint8_t FW_magic[FW_MAGIC_LEN]; // 2 bytes
  uint32_t FW_size; // 4 bytes (2 + 4)
  uint8_t IVf[IV_SIZE]; // 12 bytes -> 18
  uint8_t tagv[TAG_SIZE]; // 16 bytes -> 34
  uint32_t version_number;
  uint8_t tagf[TAG_SIZE];
} protected_fw_format;
#endif