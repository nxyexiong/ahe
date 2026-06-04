// hvstub — Hyper-V VMEXIT dispatcher hook stub
//
// Compiled as a kernel driver (.sys) with no imports. AhePkg copies the
// .text section into the HV image's .rsrc section at boot time.
// The shim in hvpatch.c handles push/pop calling convention.
//
// RULE: No static/global variables except OrigDispatcherAddr — only .text
// is copied to .rsrc. All data must be local or #define.

#include <intrin.h>

typedef unsigned int        UINT32;
typedef unsigned long long  UINT64;
typedef unsigned __int64    size_t;

#define AHE_CPUID_MAGIC  0x41484500CAFE1337ULL
#define AHE_CPUID_PONG   0x504F4E47B00B1E55ULL
#define AHE_CMD_MAGIC    0xA4E0C0DECAFE1300ULL  // upper 56 bits; lower 8 = command
#define VMX_EXIT_CPUID   10

// command codes (R11)
#define CMD_PING         0xFF
#define CMD_VIRT_READ    0x01  // R12=HV VA -> R13=*(UINT64*)R12
#define CMD_VIRT_WRITE   0x02  // R12=HV VA, R13=value -> *(UINT64*)R12 = R13
#define CMD_VMREAD       0x03  // R12=field -> R13=value
#define CMD_VMWRITE      0x04  // R12=field, R13=value
#define CMD_RDMSR        0x05  // R12=MSR -> R13=value
#define CMD_INVL_CACHES  0x06  // flush TLB

// status codes (R10 output)
#define STATUS_OK       0x00
#define STATUS_INVALID  0x01

typedef struct _GUEST_REGS {
    UINT64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    UINT64 R8, R9, R10, R11, R12, R13, R14, R15;
} GUEST_REGS;

typedef struct _VMX_VP_CTX { GUEST_REGS* GpRegs; } VMX_VP_CTX;

__declspec(dllexport) UINT64 OrigDispatcherAddr = 0;

int DriverEntry(void* a, void* b) { (void)a; (void)b; return 0; }

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

    // R11 = AHE_CMD_MAGIC | cmd_code (lower byte)
    if ((Regs->R11 & 0xFFFFFFFFFFFFFF00ULL) != AHE_CMD_MAGIC)
        return;

    UINT32 Cmd = (UINT32)(Regs->R11 & 0xFF);

    switch (Cmd) {
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
