#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <string_view>
#include "crypt/XorStr.h"

#define IOCTL_ATTACH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ_SCHEMA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


struct ModuleInfo_t
{
	ModuleInfo_t() = default;
	ModuleInfo_t(std::uintptr_t uAddress, std::string strPath)
	{
		m_uAddress = uAddress;
		m_strPath = strPath;
	}

	~ModuleInfo_t()
	{
		m_uAddress = NULL;
		m_strPath = X("");
	}

	std::uintptr_t m_uAddress = NULL;
	std::string m_strPath = X("");
};

class CMemory
{
private:
	DWORD pProcessId = 0;
	HANDLE kernelDriver = nullptr;

	// Driver communication structures
	typedef struct _Request
	{
		HANDLE process_id;
		PVOID target;
		PVOID buffer;
		SIZE_T size;
	} Request, * PRequest;

	typedef struct _PID_PACK
	{
		UINT32 pid;
		WCHAR name[1024];
	} PID_PACK, * P_PID_PACK;

	typedef struct _MODULE_PACK {
		UINT32 pid;
		UINT64 baseAddress;
		SIZE_T size;
		WCHAR moduleName[1024];
	} MODULE_PACK, * P_MODULE_PACK;

	struct BatchReadRequest {
		DWORD64 address;
		SIZE_T size;
		SIZE_T offset_in_buffer;
	};

	struct BatchReadHeader {
		HANDLE process_id;
		UINT32 num_requests;
		SIZE_T total_buffer_size;
	};

	// Helper function to convert string to wstring
	std::wstring StringToWString(const std::string& str);
	std::wstring StringViewToWString(const std::string_view& str);

public:
	CMemory() = default;

	// Initialize driver connection and attach to process
	void Initialize(const std::string_view processName) noexcept;

	// Destructor that frees the opened handle
	~CMemory();

	// Connect to kernel driver
	bool ConnectDriver(const LPCWSTR driverName);

	// Disconnect from kernel driver
	bool DisconnectDriver();

	// Get process ID by name
	DWORD GetProcessID(const std::wstring& processName);

	// Attach to process
	bool Attach(const DWORD pid);

	// Returns the base address of a module by name
	const ModuleInfo_t GetModuleAddress(const std::string_view moduleName) const noexcept;

	// Read process memory
	template <typename T>
	constexpr const T Read(const std::uintptr_t& address) const noexcept
	{
		T value = {};
		if (kernelDriver != nullptr && pProcessId != 0)
		{
			if (address == 0 || address >= 0x7FFFFFFFFFFF) {
				return value;
			}

			Request readRequest;
			readRequest.process_id = ULongToHandle(pProcessId);
			readRequest.target = reinterpret_cast<PVOID>(address);
			readRequest.buffer = &value;
			readRequest.size = sizeof(T);

			DeviceIoControl(kernelDriver,
				IOCTL_READ,
				&readRequest,
				sizeof(readRequest),
				&readRequest,
				sizeof(readRequest),
				nullptr,
				nullptr);
		}
		return value;
	}

	// Read raw memory
	const bool ReadRaw(uintptr_t address, void* buffer, size_t size);

	// Read string from memory
	const std::string ReadString(std::uint64_t dst);

	// Trace address through pointer chain
	DWORD64 TraceAddress(DWORD64 BaseAddress, std::vector<DWORD> Offsets);



	

	// Write process memory (not safe, avoid using)
	template <typename T>
	constexpr void Write(const std::uintptr_t& address, const T& value) const noexcept
	{
		// Writing through kernel driver would require additional IOCTL implementation
		// For now, keeping this as a placeholder
	}

	// Pattern scanning (would need to be implemented differently for kernel driver)
	//std::uintptr_t PatternScan(std::uintptr_t moduleBase, size_t moduleSize, const char* szSignature);
	std::uintptr_t PatternScan(void* module, const char* szSignature);
	std::uintptr_t PatternScanRemote(std::uintptr_t moduleBase, size_t moduleSize, const char* szSignature);
	// Get absolute address from relative address
	template <typename T = std::uintptr_t>
	T* GetAbsoluteAddress(T* pRelativeAddress, int nPreOffset = 0x0, int nPostOffset = 0x0)
	{
		pRelativeAddress += nPreOffset;
		pRelativeAddress += sizeof(std::int32_t) + *reinterpret_cast<std::int32_t*>(pRelativeAddress);
		pRelativeAddress += nPostOffset;
		return pRelativeAddress;
	}

	// Resolve relative address
	std::uintptr_t ResolveRelativeAddress(std::uintptr_t nAddressBytes, std::uint32_t nRVAOffset, std::uint32_t nRIPOffset, std::uint32_t nOffset = 0);

	// Batch read operations
	bool BatchReadMemory(const std::vector<std::pair<DWORD64, SIZE_T>>& requests, void* output_buffer);

	size_t GetModuleSize(std::uintptr_t moduleBase);

	const bool ReadSchemaMemory(uintptr_t address, void* buffer, size_t size);

	template<typename T>
	bool BatchReadStructured(const std::vector<DWORD64>& addresses, std::vector<T>& results) {
		if (addresses.empty()) return false;

		std::vector<std::pair<DWORD64, SIZE_T>> requests;
		requests.reserve(addresses.size());

		for (DWORD64 addr : addresses) {
			requests.emplace_back(addr, sizeof(T));
		}

		results.resize(addresses.size());
		return BatchReadMemory(requests, results.data());
	}
};

inline CMemory g_Memory;