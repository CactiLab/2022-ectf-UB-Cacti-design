#ifndef MPU_H
#define MPU_H

#include <stdint.h>

//#define MPU_ENABLED

#define REGION_Enabled  0x01
#define REGION_Valid 0x10

/*---------------------------------------------------------------------------
    System MPU configuration
    Refer to Connect ARMv7-M Memory Protection Unit User Guide V2.0
 *---------------------------------------------------------------------------*/

/* following defines should be used for structure members */
#define __IM volatile const /*! Defines 'read only' structure member permissions */
#define __OM volatile       /*! Defines 'write only' structure member permissions */
#define __IOM volatile      /*! Defines 'read / write' structure member permissions */
#ifndef __ASM
#define __ASM __asm
#endif
#ifndef __INLINE
#define __INLINE inline
#endif
#ifndef __STATIC_INLINE
#define __STATIC_INLINE static inline
#endif
#ifndef __STATIC_FORCEINLINE
#define __STATIC_FORCEINLINE __attribute__((always_inline)) static inline
#endif
#ifndef __RESTRICT
#define __RESTRICT __restrict
#endif

/**
  \brief   Instruction Synchronization Barrier
  \details Instruction Synchronization Barrier flushes the pipeline in the processor,
           so that all instructions following the ISB are fetched from cache or memory,
           after the instruction has been completed.
 */
__STATIC_FORCEINLINE void __ISB(void)
{
    __ASM volatile("isb 0xF" ::
                       : "memory");
}

/**
  \brief   Data Synchronization Barrier
  \details Acts as a special kind of Data Memory Barrier.
           It completes when all explicit memory accesses before this instruction complete.
 */
__STATIC_FORCEINLINE void __DSB(void)
{
    __ASM volatile("dsb 0xF" ::
                       : "memory");
}

__STATIC_FORCEINLINE void __DMB(void)
{
    __ASM volatile("dmb 0xF" ::
                       : "memory");
}

/**
  \brief  Structure type to access the Memory Protection Unit (MPU).
 */
typedef struct __attribute__((packed))
{
    __IM uint32_t TYPE;     /*!< Offset: 0x000 (R/ )  MPU Type Register */
    __IOM uint32_t CTRL;    /*!< Offset: 0x004 (R/W)  MPU Control Register */
    __IOM uint32_t RNR;     /*!< Offset: 0x008 (R/W)  MPU Region RNRber Register */
    __IOM uint32_t RBAR;    /*!< Offset: 0x00C (R/W)  MPU Region Base Address Register */
    __IOM uint32_t RASR;    /*!< Offset: 0x010 (R/W)  MPU Region Attribute and Size Register */
    __IOM uint32_t RBAR_A1; /*!< Offset: 0x014 (R/W)  MPU Alias 1 Region Base Address Register */
    __IOM uint32_t RASR_A1; /*!< Offset: 0x018 (R/W)  MPU Alias 1 Region Attribute and Size Register */
    __IOM uint32_t RBAR_A2; /*!< Offset: 0x01C (R/W)  MPU Alias 2 Region Base Address Register */
    __IOM uint32_t RASR_A2; /*!< Offset: 0x020 (R/W)  MPU Alias 2 Region Attribute and Size Register */
    __IOM uint32_t RBAR_A3; /*!< Offset: 0x024 (R/W)  MPU Alias 3 Region Base Address Register */
    __IOM uint32_t RASR_A3; /*!< Offset: 0x028 (R/W)  MPU Alias 3 Region Attribute and Size Register */
} MPU_Type;

#define MPU_BASE (0xE000ED90UL) /*!< Memory Protection Unit */
#define MPU ((MPU_Type *)MPU_BASE)     /*!< Memory Protection Unit */

#define MPU_TYPE_RALIASES 4U

/* MPU Type Register Definitions */
#define MPU_TYPE_IREGION_Pos 16U                              /*!< MPU TYPE: IREGION Position */
#define MPU_TYPE_IREGION_Msk (0xFFUL << MPU_TYPE_IREGION_Pos) /*!< MPU TYPE: IREGION Mask */

#define MPU_TYPE_DREGION_Pos 8U                               /*!< MPU TYPE: DREGION Position */
#define MPU_TYPE_DREGION_Msk (0xFFUL << MPU_TYPE_DREGION_Pos) /*!< MPU TYPE: DREGION Mask */

#define MPU_TYPE_SEPARATE_Pos 0U                                 /*!< MPU TYPE: SEPARATE Position */
#define MPU_TYPE_SEPARATE_Msk (1UL /*<< MPU_TYPE_SEPARATE_Pos*/) /*!< MPU TYPE: SEPARATE Mask */

/* MPU Control Register Definitions */
#define MPU_CTRL_PRIVDEFENA_Pos 2U                               /*!< MPU CTRL: PRIVDEFENA Position */
#define MPU_CTRL_PRIVDEFENA_Msk (1UL << MPU_CTRL_PRIVDEFENA_Pos) /*!< MPU CTRL: PRIVDEFENA Mask */

#define MPU_CTRL_HFNMIENA_Pos 1U                             /*!< MPU CTRL: HFNMIENA Position */
#define MPU_CTRL_HFNMIENA_Msk (1UL << MPU_CTRL_HFNMIENA_Pos) /*!< MPU CTRL: HFNMIENA Mask */

#define MPU_CTRL_ENABLE_Pos 0U                               /*!< MPU CTRL: ENABLE Position */
#define MPU_CTRL_ENABLE_Msk (1UL /*<< MPU_CTRL_ENABLE_Pos*/) /*!< MPU CTRL: ENABLE Mask */

/* MPU Region Number Register Definitions */
#define MPU_RNR_REGION_Pos 0U                                 /*!< MPU RNR: REGION Position */
#define MPU_RNR_REGION_Msk (0xFFUL /*<< MPU_RNR_REGION_Pos*/) /*!< MPU RNR: REGION Mask */

/* MPU Region Base Address Register Definitions */
#define MPU_RBAR_ADDR_Pos 5U                                 /*!< MPU RBAR: ADDR Position */
#define MPU_RBAR_ADDR_Msk (0x7FFFFFFUL << MPU_RBAR_ADDR_Pos) /*!< MPU RBAR: ADDR Mask */

#define MPU_RBAR_VALID_Pos 4U                          /*!< MPU RBAR: VALID Position */
#define MPU_RBAR_VALID_Msk (1UL << MPU_RBAR_VALID_Pos) /*!< MPU RBAR: VALID Mask */

#define MPU_RBAR_REGION_Pos 0U                                 /*!< MPU RBAR: REGION Position */
#define MPU_RBAR_REGION_Msk (0xFUL /*<< MPU_RBAR_REGION_Pos*/) /*!< MPU RBAR: REGION Mask */

/* MPU Region Attribute and Size Register Definitions */
#define MPU_RASR_ATTRS_Pos 16U                              /*!< MPU RASR: MPU Region Attribute field Position */
#define MPU_RASR_ATTRS_Msk (0xFFFFUL << MPU_RASR_ATTRS_Pos) /*!< MPU RASR: MPU Region Attribute field Mask */

#define MPU_RASR_XN_Pos 28U                      /*!< MPU RASR: ATTRS.XN Position */
#define MPU_RASR_XN_Msk (1UL << MPU_RASR_XN_Pos) /*!< MPU RASR: ATTRS.XN Mask */

#define MPU_RASR_AP_Pos 24U                        /*!< MPU RASR: ATTRS.AP Position */
#define MPU_RASR_AP_Msk (0x7UL << MPU_RASR_AP_Pos) /*!< MPU RASR: ATTRS.AP Mask */

#define MPU_RASR_TEX_Pos 19U                         /*!< MPU RASR: ATTRS.TEX Position */
#define MPU_RASR_TEX_Msk (0x7UL << MPU_RASR_TEX_Pos) /*!< MPU RASR: ATTRS.TEX Mask */

#define MPU_RASR_S_Pos 18U                     /*!< MPU RASR: ATTRS.S Position */
#define MPU_RASR_S_Msk (1UL << MPU_RASR_S_Pos) /*!< MPU RASR: ATTRS.S Mask */

#define MPU_RASR_C_Pos 17U                     /*!< MPU RASR: ATTRS.C Position */
#define MPU_RASR_C_Msk (1UL << MPU_RASR_C_Pos) /*!< MPU RASR: ATTRS.C Mask */

#define MPU_RASR_B_Pos 16U                     /*!< MPU RASR: ATTRS.B Position */
#define MPU_RASR_B_Msk (1UL << MPU_RASR_B_Pos) /*!< MPU RASR: ATTRS.B Mask */

#define MPU_RASR_SRD_Pos 8U                           /*!< MPU RASR: Sub-Region Disable Position */
#define MPU_RASR_SRD_Msk (0xFFUL << MPU_RASR_SRD_Pos) /*!< MPU RASR: Sub-Region Disable Mask */

#define MPU_RASR_SIZE_Pos 1U                            /*!< MPU RASR: Region Size Field Position */
#define MPU_RASR_SIZE_Msk (0x1FUL << MPU_RASR_SIZE_Pos) /*!< MPU RASR: Region Size Field Mask */

#define MPU_RASR_ENABLE_Pos 0U                               /*!< MPU RASR: Region enable bit Position */
#define MPU_RASR_ENABLE_Msk (1UL /*<< MPU_RASR_ENABLE_Pos*/) /*!< MPU RASR: Region enable bit Disable Mask */

/* General MPU Masks */
#define REGION_VALID 0x10
#define NORMAL (8 << 16)         // TEX:0b001 S:0b0 C:0b0 B:0b0
#define FULL_ACCESS (0x03 << 24) // Privileged Read Write, Unprivileged Read Write
#define NOT_EXEC (0x01 << 28)    // All Instruction fetches abort

#define REGION_ENABLE 0x00000001
/* Shareability */
#define NON_SHAREABLE 0x00
#define RESERVED 0x08
#define OUTER_SHAREABLE 0x10
#define INNER_SHAREABLE 0x18

#define ARM_MPU_REGION_SIZE_32B ((uint8_t)0x04U)   ///!< MPU Region Size 32 Bytes
#define ARM_MPU_REGION_SIZE_64B ((uint8_t)0x05U)   ///!< MPU Region Size 64 Bytes
#define ARM_MPU_REGION_SIZE_128B ((uint8_t)0x06U)  ///!< MPU Region Size 128 Bytes
#define ARM_MPU_REGION_SIZE_256B ((uint8_t)0x07U)  ///!< MPU Region Size 256 Bytes
#define ARM_MPU_REGION_SIZE_512B ((uint8_t)0x08U)  ///!< MPU Region Size 512 Bytes
#define ARM_MPU_REGION_SIZE_1KB ((uint8_t)0x09U)   ///!< MPU Region Size 1 KByte
#define ARM_MPU_REGION_SIZE_2KB ((uint8_t)0x0AU)   ///!< MPU Region Size 2 KBytes
#define ARM_MPU_REGION_SIZE_4KB ((uint8_t)0x0BU)   ///!< MPU Region Size 4 KBytes
#define ARM_MPU_REGION_SIZE_8KB ((uint8_t)0x0CU)   ///!< MPU Region Size 8 KBytes
#define ARM_MPU_REGION_SIZE_16KB ((uint8_t)0x0DU)  ///!< MPU Region Size 16 KBytes
#define ARM_MPU_REGION_SIZE_32KB ((uint8_t)0x0EU)  ///!< MPU Region Size 32 KBytes
#define ARM_MPU_REGION_SIZE_64KB ((uint8_t)0x0FU)  ///!< MPU Region Size 64 KBytes
#define ARM_MPU_REGION_SIZE_128KB ((uint8_t)0x10U) ///!< MPU Region Size 128 KBytes
#define ARM_MPU_REGION_SIZE_256KB ((uint8_t)0x11U) ///!< MPU Region Size 256 KBytes
#define ARM_MPU_REGION_SIZE_512KB ((uint8_t)0x12U) ///!< MPU Region Size 512 KBytes
#define ARM_MPU_REGION_SIZE_1MB ((uint8_t)0x13U)   ///!< MPU Region Size 1 MByte
#define ARM_MPU_REGION_SIZE_2MB ((uint8_t)0x14U)   ///!< MPU Region Size 2 MBytes
#define ARM_MPU_REGION_SIZE_4MB ((uint8_t)0x15U)   ///!< MPU Region Size 4 MBytes
#define ARM_MPU_REGION_SIZE_8MB ((uint8_t)0x16U)   ///!< MPU Region Size 8 MBytes
#define ARM_MPU_REGION_SIZE_16MB ((uint8_t)0x17U)  ///!< MPU Region Size 16 MBytes
#define ARM_MPU_REGION_SIZE_32MB ((uint8_t)0x18U)  ///!< MPU Region Size 32 MBytes
#define ARM_MPU_REGION_SIZE_64MB ((uint8_t)0x19U)  ///!< MPU Region Size 64 MBytes
#define ARM_MPU_REGION_SIZE_128MB ((uint8_t)0x1AU) ///!< MPU Region Size 128 MBytes
#define ARM_MPU_REGION_SIZE_256MB ((uint8_t)0x1BU) ///!< MPU Region Size 256 MBytes
#define ARM_MPU_REGION_SIZE_512MB ((uint8_t)0x1CU) ///!< MPU Region Size 512 MBytes
#define ARM_MPU_REGION_SIZE_1GB ((uint8_t)0x1DU)   ///!< MPU Region Size 1 GByte
#define ARM_MPU_REGION_SIZE_2GB ((uint8_t)0x1EU)   ///!< MPU Region Size 2 GBytes
#define ARM_MPU_REGION_SIZE_4GB ((uint8_t)0x1FU)   ///!< MPU Region Size 4 GBytes

#define ARM_MPU_AP_NONE 0U ///!< MPU Access Permission no access
#define ARM_MPU_AP_PRIV 1U ///!< MPU Access Permission privileged access only
#define ARM_MPU_AP_URO 2U  ///!< MPU Access Permission unprivileged access read-only
#define ARM_MPU_AP_FULL 3U ///!< MPU Access Permission full access
#define ARM_MPU_AP_PRO 5U  ///!< MPU Access Permission privileged access read-only
#define ARM_MPU_AP_RO 6U   ///!< MPU Access Permission read-only access

/** MPU Region Base Address Register Value
 *
 * \param Region The region to be configured, number 0 to 15.
 * \param BaseAddress The base address for the region.
 */
#define ARM_MPU_RBAR(Region, BaseAddress) \
    (((BaseAddress)&MPU_RBAR_ADDR_Msk) |  \
     ((Region)&MPU_RBAR_REGION_Msk) |     \
     (MPU_RBAR_VALID_Msk))

/**
 * MPU Memory Access Attributes
 *
 * \param TypeExtField      Type extension field, allows you to configure memory access type, for example strongly ordered, peripheral.
 * \param IsShareable       Region is shareable between multiple bus masters.
 * \param IsCacheable       Region is cacheable, i.e. its value may be kept in cache.
 * \param IsBufferable      Region is bufferable, i.e. using write-back caching. Cacheable but non-bufferable regions use write-through policy.
 */
#define ARM_MPU_ACCESS_(TypeExtField, IsShareable, IsCacheable, IsBufferable) \
    ((((TypeExtField) << MPU_RASR_TEX_Pos) & MPU_RASR_TEX_Msk) |              \
     (((IsShareable) << MPU_RASR_S_Pos) & MPU_RASR_S_Msk) |                   \
     (((IsCacheable) << MPU_RASR_C_Pos) & MPU_RASR_C_Msk) |                   \
     (((IsBufferable) << MPU_RASR_B_Pos) & MPU_RASR_B_Msk))

/**
 * MPU Region Attribute and Size Register Value
 *
 * \param DisableExec       Instruction access disable bit, 1= disable instruction fetches.
 * \param AccessPermission  Data access permissions, allows you to configure read/write access for User and Privileged mode.
 * \param AccessAttributes  Memory access attribution, see \ref ARM_MPU_ACCESS_.
 * \param SubRegionDisable  Sub-region disable field.
 * \param Size              Region size of the region to be configured, for example 4K, 8K.
 */
#define ARM_MPU_RASR_EX(DisableExec, AccessPermission, AccessAttributes, SubRegionDisable, Size)      \
    ((((DisableExec) << MPU_RASR_XN_Pos) & MPU_RASR_XN_Msk) |                                         \
     (((AccessPermission) << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk) |                                    \
     (((AccessAttributes) & (MPU_RASR_TEX_Msk | MPU_RASR_S_Msk | MPU_RASR_C_Msk | MPU_RASR_B_Msk))) | \
     (((SubRegionDisable) << MPU_RASR_SRD_Pos) & MPU_RASR_SRD_Msk) |                                  \
     (((Size) << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk) |                                            \
     (((MPU_RASR_ENABLE_Msk))))

/**
 * MPU Region Attribute and Size Register Value
 *
 * \param DisableExec       Instruction access disable bit, 1= disable instruction fetches.
 * \param AccessPermission  Data access permissions, allows you to configure read/write access for User and Privileged mode.
 * \param TypeExtField      Type extension field, allows you to configure memory access type, for example strongly ordered, peripheral.
 * \param IsShareable       Region is shareable between multiple bus masters.
 * \param IsCacheable       Region is cacheable, i.e. its value may be kept in cache.
 * \param IsBufferable      Region is bufferable, i.e. using write-back caching. Cacheable but non-bufferable regions use write-through policy.
 * \param SubRegionDisable  Sub-region disable field.
 * \param Size              Region size of the region to be configured, for example 4K, 8K.
 */
#define ARM_MPU_RASR(DisableExec, AccessPermission, TypeExtField, IsShareable, IsCacheable, IsBufferable, SubRegionDisable, Size) \
    ARM_MPU_RASR_EX(DisableExec, AccessPermission, ARM_MPU_ACCESS_(TypeExtField, IsShareable, IsCacheable, IsBufferable), SubRegionDisable, Size)

/**
 * MPU Memory Access Attribute for strongly ordered memory.
 *  - TEX: 000b
 *  - Shareable
 *  - Non-cacheable
 *  - Non-bufferable
 */
#define ARM_MPU_ACCESS_ORDERED ARM_MPU_ACCESS_(0U, 1U, 0U, 0U)

/**
 * MPU Memory Access Attribute for device memory.
 *  - TEX: 000b (if shareable) or 010b (if non-shareable)
 *  - Shareable or non-shareable
 *  - Non-cacheable
 *  - Bufferable (if shareable) or non-bufferable (if non-shareable)
 *
 * \param IsShareable Configures the device memory as shareable or non-shareable.
 */
#define ARM_MPU_ACCESS_DEVICE(IsShareable) ((IsShareable) ? ARM_MPU_ACCESS_(0U, 1U, 0U, 1U) : ARM_MPU_ACCESS_(2U, 0U, 0U, 0U))

/**
 * MPU Memory Access Attribute for normal memory.
 *  - TEX: 1BBb (reflecting outer cacheability rules)
 *  - Shareable or non-shareable
 *  - Cacheable or non-cacheable (reflecting inner cacheability rules)
 *  - Bufferable or non-bufferable (reflecting inner cacheability rules)
 *
 * \param OuterCp Configures the outer cache policy.
 * \param InnerCp Configures the inner cache policy.
 * \param IsShareable Configures the memory as shareable or non-shareable.
 */
#define ARM_MPU_ACCESS_NORMAL(OuterCp, InnerCp, IsShareable) ARM_MPU_ACCESS_((4U | (OuterCp)), IsShareable, ((InnerCp) >> 1U), ((InnerCp)&1U))

/**
 * MPU Memory Access Attribute non-cacheable policy.
 */
#define ARM_MPU_CACHEP_NOCACHE 0U

/**
 * MPU Memory Access Attribute write-back, write and read allocate policy.
 */
#define ARM_MPU_CACHEP_WB_WRA 1U

/**
 * MPU Memory Access Attribute write-through, no write allocate policy.
 */
#define ARM_MPU_CACHEP_WT_NWA 2U

/**
 * MPU Memory Access Attribute write-back, no write allocate policy.
 */
#define ARM_MPU_CACHEP_WB_NWA 3U

/**
 * Struct for a single MPU Region
 */
typedef struct
{
    uint32_t RBAR; //!< The region base address register value (RBAR)
    uint32_t RASR; //!< The region attribute and size register value (RASR) \ref MPU_RASR
} ARM_MPU_Region_t;

/** Enable the MPU.
 * \param MPU_Control Default access permissions for unconfigured regions.
 */
__STATIC_INLINE void ARM_MPU_Enable(uint32_t MPU_Control)
{
    __DMB();
    MPU->CTRL = MPU_Control | MPU_CTRL_ENABLE_Msk;
#ifdef SCB_SHCSR_MEMFAULTENA_Msk
    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;
#endif
    __DSB();
    __ISB();
}

/** Disable the MPU.
 */
__STATIC_INLINE void ARM_MPU_Disable(void)
{
    __DMB();
#ifdef SCB_SHCSR_MEMFAULTENA_Msk
    SCB->SHCSR &= ~SCB_SHCSR_MEMFAULTENA_Msk;
#endif
    MPU->CTRL &= ~MPU_CTRL_ENABLE_Msk;
    __DSB();
    __ISB();
}

/** Clear and disable the given MPU region.
 * \param rnr Region number to be cleared.
 */
__STATIC_INLINE void ARM_MPU_ClrRegion(uint32_t rnr)
{
    MPU->RNR = rnr;
    MPU->RASR = 0U;
}

/** Configure an MPU region.
 * \param rbar Value for RBAR register.
 * \param rasr Value for RASR register.
 */
__STATIC_INLINE void ARM_MPU_SetRegion(uint32_t rbar, uint32_t rasr)
{
    MPU->RBAR = rbar;
    MPU->RASR = rasr;
}

/** Configure the given MPU region.
 * \param rnr Region number to be configured.
 * \param rbar Value for RBAR register.
 * \param rasr Value for RASR register.
 */
__STATIC_INLINE void ARM_MPU_SetRegionEx(uint32_t rnr, uint32_t rbar, uint32_t rasr)
{
    MPU->RNR = rnr;
    MPU->RBAR = rbar;
    MPU->RASR = rasr;
}

/** Memcpy with strictly ordered memory access, e.g. used by code in ARM_MPU_Load().
 * \param dst Destination data is copied to.
 * \param src Source data is copied from.
 * \param len Amount of data words to be copied.
 */
__STATIC_INLINE void ARM_MPU_OrderedMemcpy(volatile uint32_t *dst, const uint32_t *__RESTRICT src, uint32_t len)
{
    uint32_t i;
    for (i = 0U; i < len; ++i)
    {
        dst[i] = src[i];
    }
}

/** Load the given number of MPU regions from a table.
 * \param table Pointer to the MPU configuration table.
 * \param cnt Amount of regions to be configured.
 */
__STATIC_INLINE void ARM_MPU_Load(ARM_MPU_Region_t const *table, uint32_t cnt)
{
    const uint32_t rowWordSize = sizeof(ARM_MPU_Region_t) / 4U;
    while (cnt > MPU_TYPE_RALIASES)
    {
        ARM_MPU_OrderedMemcpy(&(MPU->RBAR), &(table->RBAR), MPU_TYPE_RALIASES * rowWordSize);
        table += MPU_TYPE_RALIASES;
        cnt -= MPU_TYPE_RALIASES;
    }
    ARM_MPU_OrderedMemcpy(&(MPU->RBAR), &(table->RBAR), cnt * rowWordSize);
}

void mpu_init();

#endif