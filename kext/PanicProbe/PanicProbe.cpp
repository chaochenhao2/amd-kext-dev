//
// PanicProbe.cpp — 诊断用：加载即 panic
//
// 目的：判断内核是否活着、IOKit 是否还在做匹配。
//
// 匹配 IOResources（最基础的 provider，不依赖任何硬件驱动），
// 在 start() 里立刻 panic。panic 画面会留在屏幕最底部。
//
// 三种结果：
//   1. 出现 panic 画面  -> 内核活着，IOKit 正常工作，问题在 GPU/显示
//   2. 还是停在原处    -> 内核在 IOKit 匹配前就死了，需要换方向
//   3. 出现其他报错    -> 读取报错内容
//

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>

#define PP_TAG "PanicProbe"
#define PLOG(fmt, ...) IOLog(PP_TAG ": " fmt "\n", ##__VA_ARGS__)

// KMOD_INFO_64_V1，布局与 XNU osfmk/mach/kmod.h 一致（#pragma pack(4)）。
// 变量必须命名为 kmod_info，这样 C 符号才是 _kmod_info。
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

__attribute__((used, visibility("default"), section("__DATA,__data")))
KmodInfo64V1 kmod_info = {
    0, 1, 0,
    "com.local.PanicProbe",
    "1.0.0",
    0, 0, 0, 0, 0, 0, 0,
};

}

class PanicProbe : public IOService
{
    OSDeclareDefaultStructors(PanicProbe)

public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(PanicProbe, IOService)

bool PanicProbe::start(IOService *provider)
{
    if (!IOService::start(provider)) {
        return false;
    }

    // 到达这里说明 IOKit 匹配成功、服务已实例化
    PLOG("==================================================");
    PLOG("  PANICPROBE REACHED start() — IOKit IS ALIVE");
    PLOG("==================================================");

    // 立刻 panic，把证据钉在屏幕最底部
    panic("PanicProbe: IOKit matching works. macOS kernel is alive at this point.");

    return true;
}

void PanicProbe::stop(IOService *provider)
{
    IOService::stop(provider);
}
