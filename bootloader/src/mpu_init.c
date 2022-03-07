#include <stdint.h>
#include <stdbool.h>
#include "bootLoaderHeader.h"
#include "driverlib/debug.h"
#include "driverlib/mpu.h"
//#include "flash.h"
// #define MPU_BASE_PTR      ((uint32_t)(0xE000ED90UL))

#define MPU_RGN_SIZE_19K MPU_RGN_SIZE_16K + MPU_RGN_SIZE_2K + MPU_RGN_SIZE_1K
#define MPU_RGN_SIZE_83K MPU_RGN_SIZE_64K + MPU_RGN_SIZE_19K
#define MPU_RGN_SIZE_151K MPU_RGN_SIZE_128K + MPU_RGN_SIZE_19K + MPU_RGN_SIZE_4K

#define MPU_FLASH_FIRMWARE_FLAG_RW MPU_RGN_SIZE_19K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW
#define MPU_FLASH_FIRMWARE_FLAG_RO MPU_RGN_SIZE_19K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_RO
#define MPU_FLASH_FLIGHT_CFG_FLAG_RW MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW
#define MPU_FLASH_FLIGHT_CFG_FLAG_RO MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_RO
#define MPU_SRAM_FIRMWARE_FLAG MPU_RGN_SIZE_16K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW

void mpu_handler()
{
    ASSERT(MPU_RGN_SIZE_19K);
}

void mpu_init()
{
    uint32_t mpu_flag = 0;
    if (MPURegionCountGet < 8)
    {
        return -1;
    }
    /* Disable MPU */
    MPUDisable();
    // ARM_MPU_Disable();

    /*
    Configure region 0 to cover bootloader region 0x5800- 0x2b400: 151KB
    size: MPU_RGN_SIZE_151K
    executable: yes
    AP: MPU_RGN_PERM_PRV_RW_USR_RW
    */
    mpu_flag = MPU_RGN_SIZE_151K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE;
    MPURegionSet(0, 0x00005800, mpu_flag);
    MPURegionEnable(0);

    /*
    Configure region 1 to cover firmware and flight cfg 0x2b400-0x40000: 83KB
    size: MPU_RGN_SIZE_83K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_83K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_NO_USR_NO | MPU_RGN_ENABLE;
    MPURegionSet(1, 0x2b400, mpu_flag);
    MPURegionEnable(1);

    /*
    Configure region 2 to cover sram for firmware to boot 0x20004000-0x20008000: 16KB
    size: MPU_RGN_SIZE_81K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_16K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_NO_USR_NO | MPU_RGN_ENABLE;
    MPURegionSet(2, 0x20004000, mpu_flag);
    MPURegionEnable(2);

    /*----------------------------------------------------------------------------------------------*/
    /*
    Configure region 3 to cover Firmware 0x2b400-0x30000: 19KB
    size: MPU_RGN_SIZE_19K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_19K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW;
    MPURegionSet(3, 0x0002b400, mpu_flag);
    MPURegionDisable(3);

    /*
    Configure region 4 to cover Flight Cfg 0x30000-0x40000: 64KB
    size: MPU_RGN_SIZE_19K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW;
    MPURegionSet(4, 0x00030000, mpu_flag);
    MPURegionDisable(4);

    /*
    Configure region 5 to cover firmware for boot 0x20004000-0x20008000: 16KB
    size: MPU_RGN_SIZE_16K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_16K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW;
    MPURegionSet(5, 0x20004000, mpu_flag);
    MPURegionDisable(5);

    MPUIntRegister((void *)mpu_handler);
    MPUEnable(MPU_CONFIG_PRIV_DEFAULT);
}

void mpu_ap_change(uint32_t opt)
{
    switch (opt)
    {
    case 30:
        MPURegionSet(3, 0x0002b400, MPU_FLASH_FIRMWARE_FLAG_RW);
        MPURegionEnable(3);
        break;
    case 31:
        MPURegionSet(3, 0x0002b400, MPU_FLASH_FIRMWARE_FLAG_RO);
        MPURegionEnable(3);
        break;
    case 40:
        MPURegionSet(4, 0x00030000, MPU_FLASH_FLIGHT_CFG_FLAG_RW);
        MPURegionEnable(4);
        break;
    case 41:
        MPURegionSet(4, 0x00030000, MPU_FLASH_FLIGHT_CFG_FLAG_RO);
        MPURegionEnable(4);
        break;
    case 50:
        MPURegionEnable(5);
        break;
    default:
        MPURegionDisable(3);
        MPURegionDisable(4);
        MPURegionDisable(5);
        break;
    }
}