#include "pch.h"
#include <winternl.h>
#include "driver_loader.h"

#define SERVICES_REG_PATH L"system\\CurrentControlSet\\Services"
#define SERVICES_REG_PATH_KERNEL L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\"

#pragma comment(lib, "ntdll.lib") // to get ZwLoadDriver, ZwUnloadDriver

extern "C" NTSTATUS NTAPI ZwLoadDriver(PUNICODE_STRING str);
extern "C" NTSTATUS NTAPI ZwUnloadDriver(PUNICODE_STRING str);

DriverLoader::DriverLoader(
	const std::wstring& drv_path,
	const std::wstring& svc_name,
	const std::wstring& group_name,
	DWORD start_type) {
	drv_path_ = drv_path;
	svc_name_ = svc_name;
	group_name_ = group_name;
	start_type_ = start_type;
}

bool DriverLoader::load() {
	if (!create_reg()) {
		printf("[-] cannot create registry keys\n");
		return false;
	}

	if (!set_load_drv_priv(true)) {
		printf("[-] cannot enable SeLoadDriverPrivilege\n");
		return false;
	}

	std::wstring reg_path = SERVICES_REG_PATH_KERNEL;
	reg_path += svc_name_;
	UNICODE_STRING reg_path_uni;
	RtlInitUnicodeString(&reg_path_uni, reg_path.c_str());
	auto status = ZwLoadDriver(&reg_path_uni);
	if (!NT_SUCCESS(status))
		printf("[-] ZwLoadDriver failed with %x\n", status);

	if (!set_load_drv_priv(false))
		printf("[!] cannot disable SeLoadDriverPrivilege\n");

	return NT_SUCCESS(status);
}

bool DriverLoader::unload() {
	if (!set_load_drv_priv(true)) {
		printf("[-] cannot enable SeLoadDriverPrivilege\n");
		return false;
	}

	std::wstring reg_path = SERVICES_REG_PATH_KERNEL;
	reg_path += svc_name_;
	UNICODE_STRING reg_path_uni;
	RtlInitUnicodeString(&reg_path_uni, reg_path.c_str());
	auto status = ZwUnloadDriver(&reg_path_uni);
	if (!NT_SUCCESS(status))
		printf("[-] ZwUnloadDriver failed with %x\n", status);

	if (!set_load_drv_priv(false))
		printf("[!] cannot disable SeLoadDriverPrivilege\n");

	if (!delete_reg())
		printf("[!] cannot delete registry keys\n");

	return NT_SUCCESS(status);
}

bool DriverLoader::create_reg() {
	HKEY key = nullptr;
	auto status = RegOpenKeyW(HKEY_LOCAL_MACHINE, SERVICES_REG_PATH, &key);
	if (status) {
		printf("[-] RegOpenKeyW failed with %x\n", status);
		return false;
	}

	HKEY svc_key = nullptr;
	status = RegCreateKeyW(key, svc_name_.c_str(), &svc_key);
	if (status) {
		printf("[-] RegCreateKeyW failed with %x\n", status);
		status = RegCloseKey(key);
		if (status) printf("[!] RegCloseKey failed with %x\n", status);
		return false;
	}

	std::wstring image_path = L"\\??\\" + drv_path_;
	DWORD error_control = 0;
	DWORD type = 1;
	LSTATUS rst = ERROR_SUCCESS;

	status = RegSetValueExW(svc_key, L"DisplayName", 0, REG_SZ, (const BYTE*)svc_name_.c_str(), sizeof(WCHAR) * (svc_name_.length() + 1));
	rst |= status;
	if (status) printf("[-] RegSetValueExW DisplayName failed with %x\n", status);

	status = RegSetValueExW(svc_key, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&error_control, sizeof(error_control));
	rst |= status;
	if (status) printf("[-] RegSetValueExW ErrorControl failed with %x\n", status);

	status = RegSetValueExW(svc_key, L"Group", 0, REG_SZ, (const BYTE*)group_name_.c_str(), sizeof(WCHAR) * (group_name_.length() + 1));
	rst |= status;
	if (status) printf("[-] RegSetValueExW Group failed with %x\n", status);

	status = RegSetValueExW(svc_key, L"ImagePath", 0, REG_SZ, (const BYTE*)image_path.c_str(), sizeof(WCHAR) * (image_path.length() + 1));
	rst |= status;
	if (status) printf("[-] RegSetValueExW ImagePath failed with %x\n", status);

	status = RegSetValueExW(svc_key, L"Start", 0, REG_DWORD, (const BYTE*)&start_type_, sizeof(start_type_));
	rst |= status;
	if (status) printf("[-] RegSetValueExW Start failed with %x\n", status);

	status = RegSetValueExW(svc_key, L"Type", 0, REG_DWORD, (const BYTE*)&type, sizeof(type));
	rst |= status;
	if (status) printf("[-] RegSetValueExW Type failed with %x\n", status);

	status = RegCloseKey(svc_key);
	if (status)
		printf("[!] RegCloseKey failed with %x\n", status);

	return rst == ERROR_SUCCESS;
}

bool DriverLoader::delete_reg() {
	HKEY key = nullptr;
	auto status = RegOpenKeyW(HKEY_LOCAL_MACHINE, SERVICES_REG_PATH, &key);
	if (status) {
		printf("[-] RegOpenKeyW failed with %x\n", status);
		return false;
	}

	auto rst = RegDeleteKeyW(key, svc_name_.c_str());
	if (rst)
		printf("[-] RegDeleteKeyW failed with %x\n", rst);

	status = RegCloseKey(key);
	if (status)
		printf("[!] RegCloseKey failed with %x\n", status);

	return rst == ERROR_SUCCESS;
}

bool DriverLoader::set_load_drv_priv(bool enable) {
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		printf("[-] OpenProcessToken failed\n");
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValue(NULL, L"SeLoadDriverPrivilege", &luid)) {
		printf("[-] LookupPrivilegeValue failed\n");
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[-] AdjustTokenPrivileges failed\n");
		return false;
	}

	auto err = GetLastError();
	if (err != ERROR_SUCCESS)
		printf("[-] AdjustTokenPrivileges failed with %x\n", err);

	return err == ERROR_SUCCESS;
}
