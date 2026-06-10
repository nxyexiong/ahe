// Intel VMX hvstub — Hyper-V VMEXIT dispatcher hook stub.
//
// Compiled as a PE DLL with no imports. AhePkg copies the .text section into
// the HV image's .rsrc section at boot time. The shim in hvpatch.c handles
// push/pop calling convention and relays to the original dispatcher.

#include <intrin.h>

typedef unsigned int        UINT32;
typedef unsigned long long  UINT64;
typedef unsigned __int64    size_t;

#include "../hvstub_protocol.h"

#define VMX_EXIT_CPUID   10

typedef struct _GUEST_REGS {
    UINT64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    UINT64 R8, R9, R10, R11, R12, R13, R14, R15;
} GUEST_REGS;

typedef struct _VMX_VP_CTX {
    GUEST_REGS* GpRegs;
} VMX_VP_CTX;

// Intel VMX: void VmxExitDispatcher(VmxVpCtx*, UINT32 ExitReason, UINT32 ExtendedReason)
__declspec(dllexport) void HvStubEntry(
    VMX_VP_CTX* VpCtx,
    UINT32 ExitReason,
    UINT32 ExtendedReason)
{
    (void)ExtendedReason;

    if (ExitReason != VMX_EXIT_CPUID)
        return;

    GUEST_REGS* Regs = VpCtx->GpRegs;
    if (Regs->R10 != AHE_CPUID_MAGIC)
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
        __vmx_vmread((size_t)Regs->R12, (size_t*)&Regs->R13);
        Regs->R10 = STATUS_OK;
        break;

    case CMD_VMWRITE:
        __vmx_vmwrite((size_t)Regs->R12, (size_t)Regs->R13);
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
