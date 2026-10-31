//
// RDNA3Probe.cpp — 阶段 1 探针（诊断增强版）
//
// 目的：确定性地回答"kext 到底加载了没有"
//   1. 若 kext 加载 → panic，panic 信息带 PCI 数据，留在屏幕最底部
//   2. 若 kext 未加载 → 无 panic，说明注入链路有问题
//
// 这是最强的信号：不需要滚动、不需要日志文件、不会被 ACM 日志淹没。
//

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>

// ---------------------------------------------------------------------------
// KMOD_INFO_64_V1
//
// The kernel identifies a kext solely by the exported "_kmod_info" symbol.
// clang -mkernel does NOT synthesize it, so every hand-built kext must
// define it. Layout below is copied verbatim from XNU osfmk/mach/kmod.h
// (see OpenCorePkg Include/Apple/IndustryStandard/AppleKmodInfo.h) and is
// #pragma pack(4) — note ReferenceListAddr starts at offset 148, not 152.
// ---------------------------------------------------------------------------
#define KMOD_MAX_NAME 64

#pragma pack(4)
struct KmodInfo64V1 {
    uint64_t NextAddr;
    int32_t  InfoVersion;
    uint32_t Id;
    uint8_t  Name[KMOD_MAX_NAME];
    uint8_t  Version[KMOD_MAX_NAME];
    int32_t  ReferenceCount;
    uint64_t ReferenceListAddr;
    uint64_t Address;
    uint64_t Size;
    uint64_t HdrSize;
    uint64_t StartAddr;
    uint64_t StopAddr;
};
#pragma pack()

extern "C" {

// IMPORTANT: name the variable `kmod_info` (NO leading underscore) so the
// emitted C symbol is exactly `_kmod_info`. OpenCore compares that literal
// string with AsciiStrCmp; declaring `_kmod_info` in C produces the double
// underscore symbol `__kmod_info`, which never matches and yields
// "Prelinked Injection ... - Invalid Parameter".
// Placed in __DATA/__data so the value is a real in-range address
// (N_SECT|N_EXT), exactly like Lilu's symbol.
__attribute__((used, visibility("default"), section("__DATA,__data")))
KmodInfo64V1 kmod_info = {
    /* NextAddr          */ 0,
    /* InfoVersion       */ 1,
    /* Id                */ 0,
    /* Name              */ "com.local.RDNA3Probe",
    /* Version           */ "0.2.0",
    /* ReferenceCount    */ 0,
    /* ReferenceListAddr */ 0,
    /* Address           */ 0,
    /* Size              */ 0,
    /* HdrSize           */ 0,
    /* StartAddr         */ 0,
    /* StopAddr          */ 0,
};

}

#define PROBE_TAG "RDNA3Probe"
#define PLOG(fmt, ...) IOLog(PROBE_TAG ": " fmt "\n", ##__VA_ARGS__)

class RDNA3Probe : public IOService
{
    OSDeclareDefaultStructors(RDNA3Probe)

public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;

private:
    IOPCIDevice       *fPCIDevice = nullptr;
    IOMemoryMap       *fBAR0Map   = nullptr;
    volatile uint32_t *fBAR0      = nullptr;
};

OSDefineMetaClassAndStructors(RDNA3Probe, IOService)

bool RDNA3Probe::start(IOService *provider)
{
    if (!IOService::start(provider)) {
        return false;
    }

    // 第一行标记：立刻可见
    PLOG("###################### KEXT LOADED ######################");

    fPCIDevice = OSDynamicCast(IOPCIDevice, provider);
    if (!fPCIDevice) {
        PLOG("provider is not IOPCIDevice");
        return false;
    }

    fPCIDevice->setMemoryEnable(true);
    fPCIDevice->setBusMasterEnable(true);

    UInt16 vendor = fPCIDevice->configRead16(kIOPCIConfigVendorID);
    UInt16 device = fPCIDevice->configRead16(kIOPCIConfigDeviceID);
    UInt8  rev    = fPCIDevice->configRead8(kIOPCIConfigRevisionID);

    PLOG("PCI: vendor=0x%04X device=0x%04X rev=0x%02X", vendor, device, rev);

    UInt64 bar0phys = 0;
    UInt64 bar0size = 0;

    IODeviceMemory *mem = fPCIDevice->getDeviceMemoryWithIndex(0);
    if (mem) {
        bar0phys = mem->getPhysicalAddress();
        bar0size = mem->getLength();
        PLOG("BAR0: phys=0x%llX size=0x%llX",
             (unsigned long long)bar0phys, (unsigned long long)bar0size);

        fBAR0Map = fPCIDevice->mapDeviceMemoryWithIndex(0);
        if (fBAR0Map) {
            fBAR0 = reinterpret_cast<volatile uint32_t *>(fBAR0Map->getVirtualAddress());
            PLOG("BAR0: virt=%p", (void *)fBAR0);
        } else {
            PLOG("BAR0: map FAILED");
        }
    } else {
        PLOG("BAR0: no device memory");
    }

    UInt32 r35 = 0xDEADBEEF;
    UInt32 r81 = 0xDEADBEEF;
    if (fBAR0) {
        r35 = fBAR0[(0x16000 + 0x63) / 4];
        r81 = fBAR0[(0x16000 + 0x91) / 4];
        PLOG("PSP: C2PMSG_35=0x%08X  C2PMSG_81=0x%08X", r35, r81);
    }

    PLOG("=== ABOUT TO PANIC FOR DIAGNOSTICS ===");

    panic("RDNA3Probe: LOADED vendor=0x%04X dev=0x%04X rev=0x%02X BAR0phys=0x%llX BAR0size=0x%llX PSP35=0x%08X PSP81=0x%08X",
          vendor, device, rev,
          (unsigned long long)bar0phys,
          (unsigned long long)bar0size,
          r35, r81);

    return true;
}

void RDNA3Probe::stop(IOService *provider)
{
    PLOG("stop");
    if (fBAR0Map) {
        fBAR0Map->release();
        fBAR0Map = nullptr;
    }
    IOService::stop(provider);
}
