//
// RDNA3Probe.cpp — RDNA3 (GFX11) 探针驱动 · 阶段 1
//
// 目标：验证最低限度的硬件访问能力
//   1. 匹配 Radeon 780M (1002:1900)
//   2. 读取 PCI 配置空间
//   3. 映射 BAR0（MMIO）并读取寄存器
//   4. 打印所有关键信息到内核日志
//
// 不做：不写任何寄存器、不加载固件、不碰显示
// 风险：零（纯只读）
//

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>

#define PROBE_TAG "RDNA3Probe"
#define PLOG(fmt, ...) IOLog(PROBE_TAG ": " fmt "\n", ##__VA_ARGS__)

// ---------------------------------------------------------------------------
// RDNA3 / GFX11 关键寄存器（来自 Linux amdgpu include/mp_11_0_offset.h）
// ---------------------------------------------------------------------------
static constexpr uint32_t kMP0_SMN_C2PMSG_35 = 0x0063;  // PSP 命令
static constexpr uint32_t kMP0_SMN_C2PMSG_36 = 0x0064;  // PSP 地址
static constexpr uint32_t kMP0_SMN_C2PMSG_81 = 0x0091;  // PSP 响应

// SOC15 基址（MP0 块的偏移，Linux: soc15_reg_offset）
static constexpr uint32_t kMP0_BASE = 0x16000;

class RDNA3Probe : public IOService
{
    OSDeclareDefaultStructors(RDNA3Probe)

public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;

private:
    IOPCIDevice        *fPCIDevice   = nullptr;
    IOMemoryMap        *fBAR0Map     = nullptr;
    volatile uint32_t  *fBAR0        = nullptr;
    IOPhysicalAddress   fBAR0Phys    = 0;
    IOByteCount         fBAR0Size    = 0;

    bool  mapBAR0();
    void  unmapBAR0();
    uint32_t readReg(uint32_t offset);
    void  dumpPCIHeader();
    void  dumpRegisters();
};

OSDefineMetaClassAndStructors(RDNA3Probe, IOService)

// ---------------------------------------------------------------------------

bool RDNA3Probe::start(IOService *provider)
{
    if (!IOService::start(provider)) {
        PLOG("IOService::start failed");
        return false;
    }

    PLOG("================ START ================");

    fPCIDevice = OSDynamicCast(IOPCIDevice, provider);
    if (!fPCIDevice) {
        PLOG("provider is not IOPCIDevice");
        return false;
    }

    // 开启设备（需要 memory space 才能映射 BAR）
    fPCIDevice->setMemoryEnable(true);
    fPCIDevice->setBusMasterEnable(true);

    dumpPCIHeader();

    if (!mapBAR0()) {
        PLOG("mapBAR0 failed");
        return false;
    }

    dumpRegisters();

    PLOG("================  DONE  ================");

    registerService();
    return true;
}

void RDNA3Probe::stop(IOService *provider)
{
    PLOG("stop");
    unmapBAR0();
    IOService::stop(provider);
}

// ---------------------------------------------------------------------------

void RDNA3Probe::dumpPCIHeader()
{
    UInt16 vendor = fPCIDevice->configRead16(kIOPCIConfigVendorID);
    UInt16 device = fPCIDevice->configRead16(kIOPCIConfigDeviceID);
    UInt16 subsysV = fPCIDevice->configRead16(kIOPCIConfigSubSystemVendorID);
    UInt16 subsysD = fPCIDevice->configRead16(kIOPCIConfigSubSystemID);
    UInt8  rev = fPCIDevice->configRead8(kIOPCIConfigRevisionID);
    UInt16 cmd = fPCIDevice->configRead16(kIOPCIConfigCommand);
    UInt8  hdr = fPCIDevice->configRead8(kIOPCIConfigHeaderType);

    PLOG("vendor=0x%04X device=0x%04X rev=0x%02X", vendor, device, rev);
    PLOG("subsystem=0x%04X:0x%04X headerType=0x%02X", subsysV, subsysD, hdr);
    PLOG("command=0x%04X mem=%d busmaster=%d",
         cmd, (cmd & 0x2) ? 1 : 0, (cmd & 0x4) ? 1 : 0);

    // BAR 地址
    for (int i = 0; i < 6; i++) {
        UInt32 bar = fPCIDevice->configRead32(kIOPCIConfigBaseAddress0 + i * 4);
        if (bar == 0) {
            PLOG("BAR%d = (empty)", i);
        } else if (bar == 0xFFFFFFFF) {
            PLOG("BAR%d = (not implemented)", i);
        } else if (bar & 0x1) {
            PLOG("BAR%d = 0x%08X (I/O)", i, bar & ~0x3);
        } else if ((bar & 0x6) == 0x4) {
            UInt32 hi = fPCIDevice->configRead32(kIOPCIConfigBaseAddress0 + (i + 1) * 4);
            PLOG("BAR%d = 0x%08X%08X (MMIO 64-bit)", i, hi, bar & ~0xF);
            i++;
        } else {
            PLOG("BAR%d = 0x%08X (MMIO 32-bit)", i, bar & ~0xF);
        }
    }
}

bool RDNA3Probe::mapBAR0()
{
    IODeviceMemory *mem = fPCIDevice->getDeviceMemoryWithIndex(0);
    if (!mem) {
        PLOG("getDeviceMemoryWithIndex(0) = null");
        return false;
    }

    fBAR0Size = mem->getLength();
    fBAR0Phys = mem->getPhysicalAddress();
    PLOG("BAR0 phys=0x%llX size=0x%llX (%llu MB)",
         (unsigned long long)fBAR0Phys,
         (unsigned long long)fBAR0Size,
         (unsigned long long)(fBAR0Size / (1024 * 1024)));

    fBAR0Map = fPCIDevice->mapDeviceMemoryWithIndex(0);
    if (!fBAR0Map) {
        PLOG("mapDeviceMemoryWithIndex failed");
        return false;
    }

    fBAR0 = reinterpret_cast<volatile uint32_t *>(fBAR0Map->getVirtualAddress());
    PLOG("BAR0 virt=%p", (void *)fBAR0);
    return fBAR0 != nullptr;
}

void RDNA3Probe::unmapBAR0()
{
    if (fBAR0Map) {
        fBAR0Map->release();
        fBAR0Map = nullptr;
    }
    fBAR0 = nullptr;
}

uint32_t RDNA3Probe::readReg(uint32_t offset)
{
    if (!fBAR0 || offset + 4 > fBAR0Size)
        return 0xFFFFFFFF;
    return fBAR0[offset / 4];
}

void RDNA3Probe::dumpRegisters()
{
    PLOG("--- PSP mailbox (read-only) ---");

    // 只读，不写。用于确认 MMIO 通路正常。
    uint32_t r35 = readReg(kMP0_BASE + kMP0_SMN_C2PMSG_35);
    uint32_t r36 = readReg(kMP0_BASE + kMP0_SMN_C2PMSG_36);
    uint32_t r81 = readReg(kMP0_BASE + kMP0_SMN_C2PMSG_81);

    PLOG("C2PMSG_35 (cmd)    = 0x%08X", r35);
    PLOG("C2PMSG_36 (addr)   = 0x%08X", r36);
    PLOG("C2PMSG_81 (resp)   = 0x%08X", r81);

    // 判断 MMIO 是否真的能读
    if (r35 == 0xFFFFFFFF && r36 == 0xFFFFFFFF && r81 == 0xFFFFFFFF) {
        PLOG("WARNING: all 0xFFFFFFFF, MMIO may not be mapped correctly");
    } else {
        PLOG("OK: MMIO readback looks sane");
    }

    PLOG("--- first 16 dwords of BAR0 ---");
    for (int i = 0; i < 16; i++) {
        PLOG("  [0x%04X] = 0x%08X", i * 4, readReg(i * 4));
    }
}
