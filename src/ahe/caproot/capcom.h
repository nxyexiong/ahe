#pragma once
#include <functional>

class Capcom {
public:
	using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
	using func_capcom_user = std::function<VOID(func_MmGetSystemRoutineAddressFunc)>;

	static bool load();
	static bool run_exploit(func_capcom_user func);
	static bool unload();
};
