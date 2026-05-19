#pragma once

#include <stdint.h>

class Xfer;

// Build a WinDbg-compatible minidump for the given process and write it to `out_path`.
// Streams included: SystemInfoStream, ModuleListStream, Memory64ListStream covering
// all committed, readable regions. Thread state is not captured.
// Returns true on success.
bool write_minidump_to_file(Xfer& x, uint32_t pid, const char* out_path);
