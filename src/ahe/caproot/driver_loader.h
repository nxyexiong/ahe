#pragma once
#include <string>

class DriverLoader {
public:
	DriverLoader(
		const std::wstring& drv_path,
		const std::wstring& svc_name,
		const std::wstring& group_name,
		DWORD start_type);
	bool load();
	bool unload();
private:
	std::wstring drv_path_;
	std::wstring svc_name_;
	std::wstring group_name_;
	DWORD start_type_;

	DriverLoader(const DriverLoader&) = delete;
	DriverLoader& operator=(const DriverLoader&) = delete;
	DriverLoader(DriverLoader&&) = delete;
	DriverLoader& operator=(DriverLoader&&) = delete;

	bool create_reg();
	bool delete_reg();
	bool set_load_drv_priv(bool enable);
};
