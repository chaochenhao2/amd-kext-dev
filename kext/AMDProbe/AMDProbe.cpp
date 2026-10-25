//
// AMDProbe.cpp — 780M 探针 kext（只读，零风险）
//
// 目的：验证三件事
//   1. kext 能否被 OpenCore 注入并加载
//   2. 能否匹配到 Radeon 780M（50:1900）
//   3. 显存 BAR 的物理地址是多少
//
// 不做的：不映射显存、不写寄存器、不碰显示控制器
//

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>

#define PLOG(fmt, ...) IOLog("AMDProbe: " fmt "\n", ##__VA_ARGS__)

class AMDProbe : public IOService
{
    OSDeclareDefaultStructors(AMDProbe)

public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(AMDProbe, IOService)

bool AMDProbe::start(IOService *provider)
{
    if (!IOService::start(provider)) {
        PLOG("IOService::start failed");
        return false;
    }

    PLOG("========== START ==========");

    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci) {
        PLOG("provider is NOT IOPCIDevice, abort");
        return false;
    }

    // ---- 设备身份 ----
    UInt16 vendor = pci->configRead16(kIOPCIConfigVendorID);
    UInt16 device = pci->configRead16(kIOPCIConfigDeviceID);
    UInt16 subsysV = pci->configRead16(kIOPCIConfigSubSystemVendorID);
    UInt16 subsysD = pci->configRead16(kIOPCIConfigSubSystemID);
    UInt8  rev     = pci->configRead8(kIOPCIConfigRevisionID);

    PLOG("vendor=0x%04X device=0x%04X rev=0x%02X", vendor, device, rev);
    PLOG("subsystem=0x%04X:0x%04X", subsysV, subsysD);

    // ---- BAR 地址（只需要地址，不映射）----
    for (int i = 0; i < 6; i++) {
        UInt32 bar = pci->configRead32(kIOPCIConfigBaseAddress0 + (i * 4));
        if (bar == 0) {
            PLOG("BAR%d = 0x00000000  (empty)", i);
        } else if (bar == 0xFFFFFFFF) {
            PLOG("BAR%d = 0xFFFFFFFF  (not implemented)", i);
        } else if (bar & 0x1) {
            PLOG("BAR%d = 0x%08X  (I/O port)", i, bar);
        } else {
            PLOG("BAR%d = 0x%08X  (MMIO%s)", i, bar,
                 ((bar & 0x6) == 0x4) ? ", 64-bit low" : "");
        }
    }

    // ---- 命令寄存器：确认 MEM 空间已启用 ----
    UInt16 cmd = pci->configRead16(kIOPCIConfigCommand);
    PLOG("command=0x%04X  memEnable=%d  ioEnable=%d  busMaster=%d",
         cmd, (cmd & 0x0002) ? 1 : 0, (cmd & 0x0001) ? 1 : 0, (cmd & 0x0004) ? 1 : 0);

    // ---- 本 kext 的设备路径，便于后续定位 ----
    PLOG("provider class = %s", provider->getMetaClass()->getClassName());

    PLOG("========== DONE ==========");

    // 让 IORegistry 里能看到这个节点
    registerService();

    return true;
}

void AMDProbe::stop(IOService *provider)
{
    PLOG("stop called");
    IOService::stop(provider);
}
