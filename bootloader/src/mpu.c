#include "mpu.h"
//#include "flash.h"
#define MPU_BASE_PTR      ((uint32_t)(0xE000ED90UL))

void mpu_init()
{
    // volatile MPU_Type *MPUptr __attribute__((section(".ARM.__at_0xE000ED90")));
    MPU_Type *MPUptr = (MPU_Type *)MPU_BASE_PTR;
    /* Disable MPU */
    MPUptr->CTRL = 0;
    // ARM_MPU_Disable();

    /*
    Configure region 0 to cover 256KB Flash (Normal, Non-Shared, Executable, Read-only)
    0x0000_0000- 0x0003_FFFF: 192KB
    */
   MPUptr->RBAR = 0x00000000 | REGION_VALID | 0;
   MPUptr->RASR = REGION_ENABLE | NORMAL | ARM_MPU_REGION_SIZE_256KB | ARM_MPU_AP_FULL;
//    ARM_MPU_SetRegionEx(0, ARM_MPU_RBAR(0, 0x00000000), ARM_MPU_RASR(0, ARM_MPU_AP_FULL, NORMAL, 1, 1, 1, 1, ARM_MPU_REGION_SIZE_128KB + ARM_MPU_REGION_SIZE_64KB));

    /*
    Configure region 1 to cover Flight Configuration (Normal, Non-Shared, Executable, Read-only)
    0x00030000-0x00040000
    */
    // ARM_MPU_SetRegionEx(1, ARM_MPU_RBAR(1, 0x00030000), ARM_MPU_RASR(1, ARM_MPU_AP_FULL, NORMAL, 1, 1, 1, 1, ARM_MPU_REGION_SIZE_64KB));
    /*
    Configure region 2 to cover SRAM stack (Normal, Non-Shared, Executable, Read-only)
    0x2000 0000 - 0x2000 4000: 16KB
    */
//    ARM_MPU_SetRegionEx(2, ARM_MPU_RBAR(2, 0x20000000), ARM_MPU_RASR(1, ARM_MPU_AP_FULL, NORMAL, 1, 1, 1, 1, ARM_MPU_REGION_SIZE_16KB));
    // // UART0: 0x4000C000
    // /* Enable MPU */
    // ARM_MPU_Enable(1);
    MPUptr->CTRL = 0x1;
    __ISB();
    __DSB();
}

void mpu_test()
{
}