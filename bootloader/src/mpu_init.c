#include <stdint.h>
#include <stdbool.h>
#include "bootLoaderHeader.h"
#include "driverlib/mpu.h"
//#include "flash.h"
// #define MPU_BASE_PTR      ((uint32_t)(0xE000ED90UL))

#define MPU_RGN_SIZE_17K MPU_RGN_SIZE_16K + MPU_RGN_SIZE_1K
#define MPU_RGN_SIZE_81K MPU_RGN_SIZE_64K + MPU_RGN_SIZE_17K
#define MPU_RGN_SIZE_153K MPU_RGN_SIZE_128K + MPU_RGN_SIZE_17K + MPU_RGN_SIZE_8K

#define MPU_FLASH_FIRMWARE_FLAG MPU_RGN_SIZE_17K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE
#define MPU_FLASH_FLIGHT_CFG_FLAG MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE
#define MPU_SRAM_FIRMWARE_FLAG MPU_RGN_SIZE_256K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE

void mpu_handle()
{
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
    Configure region 0 to cover bootloader region 0x5800- 0x2b400: 153KB
    size: MPU_RGN_SIZE_153K
    executable: yes
    AP: MPU_RGN_PERM_PRV_RW_USR_RW
    */
    mpu_flag = MPU_RGN_SIZE_153K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE;
    MPURegionSet(0, 0x00005800, mpu_flag);
    MPURegionEnable(0);

    /*
    Configure region 1 to cover firmware and flight cfg 0x2bc00-0x40000: 81KB
    size: MPU_RGN_SIZE_81K
    executable: no
    AP: NO
    */
    mpu_flag = MPU_RGN_SIZE_81K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_NO_USR_NO | MPU_RGN_ENABLE;
    MPURegionSet(1, 0x2bc00, mpu_flag);
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
    Configure region 3 to cover Firmware 0x2bc00-0x30000: 17KB
    size: MPU_RGN_SIZE_17K
    executable: no
    AP: NO
    */
    // mpu_flag = MPU_RGN_SIZE_17K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE;
    // MPURegionSet(3, 0x0002bc00, mpu_flag);
    // MPURegionDisable(3);

    // /*
    // Configure region 4 to cover Flight Cfg 0x30000-0x40000: 64KB
    // size: MPU_RGN_SIZE_17K
    // executable: no
    // AP: NO
    // */
    // mpu_flag = MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE;
    // MPURegionSet(4, 0x00030000, mpu_flag);
    // MPURegionDisable(4);

    // /*
    // Configure region 5 to cover firmware for boot 0x20040000-0x20008000: 64KB
    // size: MPU_RGN_SIZE_64K
    // executable: no
    // AP: NO
    // */
    // mpu_flag = MPU_RGN_SIZE_256K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE;
    // MPURegionSet(5, 0x20004000, mpu_flag);
    // MPURegionDisable(5);

    MPUEnable(MPU_CONFIG_PRIV_DEFAULT);
    // MPUIntRegister((void *)mpu_handle);
}

/*
 * region 3: flash firmware
 * region 4: flight cfg
 * region 5: sram firmware for booting
 * input: option. 0x - give AP, 1x - restore AP, disable region
 */
void mpu_change_ap(uint32_t opt)
{
    uint32_t mpu_flag = 0;
    /* Disable MPU */
    MPUDisable();
    switch (opt)
    {
    case 3:
        MPURegionSet(opt, 0x0002bc00, MPU_FLASH_FIRMWARE_FLAG);
    case 4:
        MPURegionSet(opt, 0x00030000, MPU_FLASH_FLIGHT_CFG_FLAG);
    case 5:
        MPURegionSet(opt, 0x20004000, MPU_SRAM_FIRMWARE_FLAG);
        MPURegionEnable(opt);
        break;
    case 13:
    case 14:
    case 15:
        MPURegionDisable(opt - 10);
        break;
    case 34:
        MPURegionSet(opt, 0x0002bc00, MPU_FLASH_FIRMWARE_FLAG);
        MPURegionSet(opt, 0x00030000, MPU_FLASH_FLIGHT_CFG_FLAG);
        MPURegionEnable(3);
        MPURegionEnable(4);
        break;
    case 134:
        MPURegionDisable(3);
        MPURegionDisable(4);
        break;
    default:
        break;
    }
    MPUEnable(MPU_CONFIG_PRIV_DEFAULT);
}