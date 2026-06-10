// AMD SVM hvstub — Hyper-V VMEXIT dispatcher hook stub.
//
// Compiled as a PE DLL with no imports. AhePkg copies the .text section into
// the HV image's .rsrc section at boot time. The shim in hvpatch.c handles
// push/pop calling convention and relays to the original dispatcher.

#include <intrin.h>

typedef unsigned int        UINT32;
typedef unsigned long long  UINT64;

#include "../hvstub_protocol.h"

#define SVM_EXIT_CPUID   0x72

typedef struct _GUEST_REGS {
    UINT64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    UINT64 R8, R9, R10, R11, R12, R13, R14, R15;
} GUEST_REGS;

typedef struct _SVM_VP_CTX {
    GUEST_REGS* GpRegs;
} SVM_VP_CTX;

// AMD SVM: void SvmExitDispatcher(PlsCtx*, SvmVpCtx*)
// RCX = PlsCtx*, RDX = SvmVpCtx*
__declspec(dllexport) void HvStubEntry(
    void* PlsCtx,
    SVM_VP_CTX* VpCtx)
{
    (void)PlsCtx;

    GUEST_REGS* Regs = VpCtx->GpRegs;
    if (Regs->R10 != AHE_CPUID_MAGIC)
        return;

    UINT64 VpBase = *(UINT64*)((char*)VpCtx + 0x70);
    if (VpBase == 0) return;
    UINT64 ActiveCtx = *(UINT64*)((char*)VpBase + 0x3C0);
    if (ActiveCtx == 0) return;
    UINT64 PlatCtx = *(UINT64*)((char*)ActiveCtx + 0x08);
    if (PlatCtx == 0) return;
    UINT64 ShadowCtx = *(UINT64*)PlatCtx;
    if (ShadowCtx == 0) return;
    UINT64 VmcbPtr = *(UINT64*)ShadowCtx;
    if (VmcbPtr == 0) return;

    if (*(UINT64*)((char*)VmcbPtr + 0x070) != SVM_EXIT_CPUID)
        return;

    if ((Regs->R11 & 0xFFFFFFFFFFFFFF00ULL) != AHE_CMD_MAGIC)
        return;

    switch ((UINT32)(Regs->R11 & 0xFF)) {
    case CMD_PING:
        Regs->R10 = AHE_CPUID_PONG;
        break;

    case CMD_VIRT_READ:
        Regs->R13 = *(volatile UINT64*)Regs->R12;
        Regs->R10 = STATUS_OK;
        break;

    case CMD_VIRT_WRITE:
        *(volatile UINT64*)Regs->R12 = Regs->R13;
        Regs->R10 = STATUS_OK;
        break;

    case CMD_VMREAD:
        // AMD: R12 is a VMCB field offset.
        Regs->R13 = *(UINT64*)((char*)VmcbPtr + Regs->R12);
        Regs->R10 = STATUS_OK;
        break;

    case CMD_VMWRITE:
        // AMD: R12 is a VMCB field offset.
        *(UINT64*)((char*)VmcbPtr + Regs->R12) = Regs->R13;
        Regs->R10 = STATUS_OK;
        break;

    case CMD_RDMSR:
        Regs->R13 = __readmsr((unsigned long)Regs->R12);
        Regs->R10 = STATUS_OK;
        break;

    case CMD_INVL_CACHES:
        __writecr3(__readcr3());
        Regs->R10 = STATUS_OK;
        break;

    default:
        Regs->R10 = STATUS_INVALID;
        break;
    }
}
