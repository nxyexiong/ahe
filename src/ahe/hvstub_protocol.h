// hvstub_protocol.h — shared CPUID backdoor protocol constants.
// Keep in sync with hvstub_protocol.inc (MASM version).
#ifndef HVSTUB_PROTOCOL_H
#define HVSTUB_PROTOCOL_H

// 64-bit magic in R10 to identify our CPUID call
#define AHE_CPUID_MAGIC  0x41484500CAFE1337ULL
// 64-bit reply in R10 on success
#define AHE_CPUID_PONG   0x504F4E47B00B1E55ULL
// Upper 56 bits of R11; lower 8 bits = command code
#define AHE_CMD_MAGIC    0xA4E0C0DECAFE1300ULL

// Command codes (lower 8 bits of R11)
#define CMD_VIRT_READ    0x01
#define CMD_VIRT_WRITE   0x02
#define CMD_VMREAD       0x03
#define CMD_VMWRITE      0x04
#define CMD_RDMSR        0x05
#define CMD_INVL_CACHES  0x06
#define CMD_PING         0xFF

// Status codes returned in R10
#define STATUS_OK        0x00
#define STATUS_INVALID   0x01

#endif // HVSTUB_PROTOCOL_H
