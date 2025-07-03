#include "Memory.h" // Assuming your header file is named CMemory.h
#include "../Precompiled.h"
#include <string>
std::wstring CMemory::StringToWString(const std::string& str)
{
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

std::wstring CMemory::StringViewToWString(const std::string_view& str)
{
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

void CMemory::Initialize(const std::string_view processName) noexcept
{
	// Connect to kernel driver
	if (!ConnectDriver(L"\\\\.\\laithdriver"))
	{
		Logging::Print(X("Failed to connect to KM driver"));
		return;
	}
	Logging::Print(X("Connected to KM driver"));
	// Convert process name to wide string
	std::wstring wProcessName = StringViewToWString(processName);

	// Get process ID
	DWORD processId = GetProcessID(wProcessName);
	if (processId == 0)
	{
		Logging::Print(X("GetProcessID is: 0 "));
		return;
	}

	Logging::Print("GetProcessID is: " + std::to_string(processId));

	// Attach to process
	Attach(processId);
}

CMemory::~CMemory()
{
	DisconnectDriver();
	pProcessId = 0;
}

bool CMemory::ConnectDriver(const LPCWSTR driverName)
{
	kernelDriver = CreateFile(driverName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (kernelDriver == INVALID_HANDLE_VALUE)
	{
		kernelDriver = nullptr;
		return false;
	}
	return true;
}

bool CMemory::DisconnectDriver()
{
	if (kernelDriver != nullptr)
	{
		BOOL result = CloseHandle(kernelDriver);
		kernelDriver = nullptr;
		return result == TRUE;
	}
	return false;
}

DWORD CMemory::GetProcessID(const std::wstring& processName)
{
	if (kernelDriver != nullptr)
	{
		PID_PACK PidPack;
		RtlZeroMemory(PidPack.name, 1024);
		wcsncpy_s(PidPack.name, 1024, processName.c_str(), _TRUNCATE);

		BOOL result = DeviceIoControl(kernelDriver,
			IOCTL_GET_PID,
			&PidPack,
			sizeof(PidPack),
			&PidPack,
			sizeof(PidPack),
			nullptr,
			nullptr);

		if (result == TRUE)
			return PidPack.pid;
		else
			return 0;
	}
	else
		return 0;
}

bool CMemory::Attach(const DWORD pid)
{
	if (pid == 0 || kernelDriver == nullptr)
		return false;

	Request attachRequest;
	attachRequest.process_id = ULongToHandle(pid);
	attachRequest.target = nullptr;
	attachRequest.buffer = nullptr;
	attachRequest.size = 0;

	BOOL result = DeviceIoControl(kernelDriver,
		IOCTL_ATTACH,
		&attachRequest,
		sizeof(attachRequest),
		&attachRequest,
		sizeof(attachRequest),
		nullptr,
		nullptr);

	if (result == TRUE)
	{
		pProcessId = pid;
		Logging::Print("Attach success: " + std::to_string(pid));

		return true;
	}

	Logging::Print("Attach failed: " + std::to_string(pid));
	return false;
}

const ModuleInfo_t CMemory::GetModuleAddress(const std::string_view moduleName) const noexcept
{
	if (kernelDriver != nullptr && pProcessId != 0)
	{
		MODULE_PACK ModulePack;
		DWORD64 address = 0;
		ModulePack.pid = pProcessId;
		ModulePack.baseAddress = address;
		RtlZeroMemory(ModulePack.moduleName, 1024);

		// Convert string_view to wstring
		std::wstring wModuleName = const_cast<CMemory*>(this)->StringViewToWString(moduleName);
		wcsncpy_s(ModulePack.moduleName, 1024, wModuleName.c_str(), _TRUNCATE);

		BOOL result = DeviceIoControl(kernelDriver,
			IOCTL_GET_MODULE_BASE,
			&ModulePack,
			sizeof(ModulePack),
			&ModulePack,
			sizeof(ModulePack),
			nullptr,
			nullptr);

		if (result == TRUE)
		{
			// Convert wstring back to string for path
			std::string modulePath;
			if (ModulePack.moduleName[0] != L'\0')
			{
				int size_needed = WideCharToMultiByte(CP_UTF8, 0, ModulePack.moduleName, -1, NULL, 0, NULL, NULL);
				modulePath.resize(size_needed - 1);
				WideCharToMultiByte(CP_UTF8, 0, ModulePack.moduleName, -1, &modulePath[0], size_needed, NULL, NULL);
			}
			return ModuleInfo_t(ModulePack.baseAddress, modulePath);
		}
	}
	return ModuleInfo_t(NULL, X(""));
}

const bool CMemory::ReadRaw(uintptr_t address, void* buffer, size_t size)
{
	if (kernelDriver != nullptr && pProcessId != 0)
	{
		if (address == 0 || address >= 0x7FFFFFFFFFFF || size == 0 || size > 0x1000) {
			return false;
		}

		if (address + size < address) {
			return false;
		}

		Request readRequest;
		readRequest.process_id = ULongToHandle(pProcessId);
		readRequest.target = reinterpret_cast<PVOID>(address);
		readRequest.buffer = buffer;
		readRequest.size = size;

		BOOL result = DeviceIoControl(kernelDriver,
			IOCTL_READ,
			&readRequest,
			sizeof(readRequest),
			&readRequest,
			sizeof(readRequest),
			nullptr,
			nullptr);
		return result == TRUE;
	}
	return false;
}

const std::string CMemory::ReadString(std::uint64_t dst)
{
	if (!dst)
		return X("**invalid**");

	char buf[256] = {};
	return (ReadRaw(dst, &buf, sizeof(buf)) ? std::string(buf) : X("**invalid**"));
}

DWORD64 CMemory::TraceAddress(DWORD64 BaseAddress, std::vector<DWORD> Offsets)
{
	DWORD64 Address = 0;

	if (Offsets.size() == 0)
		return BaseAddress;

	Address = Read<DWORD64>(BaseAddress);
	for (int i = 0; i < Offsets.size() - 1; i++)
		Address = Read<DWORD64>(Address + Offsets[i]);

	return Address == 0 ? 0 : Address + Offsets[Offsets.size() - 1];
}

std::uintptr_t CMemory::PatternScan(void* module, const char* szSignature)
{
	static auto PatternToBytes = [](const char* szPattern)
		{
			auto vecBytes = std::vector<int>{};
			auto szStart = const_cast<char*>(szPattern);
			auto szEnd = const_cast<char*>(szPattern) + CRT::StringLength(szPattern);

			for (auto szCurrent = szStart; szCurrent < szEnd; ++szCurrent)
			{
				if (*szCurrent == '?')
				{
					++szCurrent;

					if (*szCurrent == '?')
						++szCurrent;

					vecBytes.push_back(-1);
				}
				else
					vecBytes.push_back(strtoul(szCurrent, &szCurrent, 16));
			}
			return vecBytes;
		};

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module) + dosHeader->e_lfanew);

	DWORD dwSizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	std::vector<int> vecPatternBytes = PatternToBytes(szSignature);
	std::uint8_t* uScanBytes = reinterpret_cast<std::uint8_t*>(module);

	size_t uSize = vecPatternBytes.size();
	int* pData = vecPatternBytes.data();

	for (unsigned long i = 0ul; i < dwSizeOfImage - uSize; ++i)
	{
		bool bFound = true;
		for (unsigned long j = 0ul; j < uSize; ++j)
		{
			if (uScanBytes[i + j] != pData[j] && pData[j] != -1)
			{
				bFound = false;
				break;
			}
		}

		if (bFound)
			return reinterpret_cast<std::uintptr_t>(&uScanBytes[i]);
	}

	return NULL;
}

std::uintptr_t CMemory::ResolveRelativeAddress(std::uintptr_t nAddressBytes, std::uint32_t nRVAOffset, std::uint32_t nRIPOffset, std::uint32_t nOffset)
{
	const std::uintptr_t nRVA = Read<LONG>(nAddressBytes + nRVAOffset);
	const std::uintptr_t nRIP = nAddressBytes + nRIPOffset;

	if (nOffset)
		return Read<std::uintptr_t>(nRVA + nRIP) + nOffset;

	return nRVA + nRIP;
}

bool CMemory::BatchReadMemory(const std::vector<std::pair<DWORD64, SIZE_T>>& requests, void* output_buffer)
{
	if (kernelDriver == nullptr || pProcessId == 0 || requests.empty()) {
		return false;
	}

	// Calculate buffer size for output data only
	SIZE_T output_data_size = 0;
	for (const auto& req : requests) {
		output_data_size += req.second;
	}

	// Calculate total request structure size
	SIZE_T request_struct_size = sizeof(BatchReadHeader) +
		(requests.size() * sizeof(BatchReadRequest));

	// Total size includes both request structure and output buffer space
	SIZE_T total_buffer_size = request_struct_size + output_data_size;

	// Allocate buffer for the entire operation
	std::vector<BYTE> operation_buffer(total_buffer_size);

	BatchReadHeader* header = reinterpret_cast<BatchReadHeader*>(operation_buffer.data());
	BatchReadRequest* batch_requests = reinterpret_cast<BatchReadRequest*>(header + 1);

	// Fill header
	header->process_id = ULongToHandle(pProcessId);
	header->num_requests = static_cast<UINT32>(requests.size());
	header->total_buffer_size = output_data_size; // Size of output data only

	// Fill requests with correct offsets
	SIZE_T buffer_offset = 0;
	for (size_t i = 0; i < requests.size(); ++i) {
		batch_requests[i].address = requests[i].first;
		batch_requests[i].size = requests[i].second;
		batch_requests[i].offset_in_buffer = buffer_offset;
		buffer_offset += requests[i].second;
	}

	BOOL result = DeviceIoControl(
		kernelDriver,
		IOCTL_BATCH_READ,
		operation_buffer.data(),
		static_cast<DWORD>(total_buffer_size),
		operation_buffer.data(),
		static_cast<DWORD>(total_buffer_size),
		nullptr,
		nullptr
	);

	if (result) {
		// Copy output data (starts after the request structures)
		BYTE* output_start = operation_buffer.data() + request_struct_size;
		memcpy(output_buffer, output_start, output_data_size);
	}

	return result == TRUE;
}


std::uintptr_t CMemory::PatternScanRemote(std::uintptr_t moduleBase, size_t moduleSize, const char* szSignature)
{
	if (moduleBase == 0 || moduleSize == 0)
		return NULL;

	static auto PatternToBytes = [](const char* szPattern)
		{
			auto vecBytes = std::vector<int>{};
			auto szStart = const_cast<char*>(szPattern);
			auto szEnd = const_cast<char*>(szPattern) + CRT::StringLength(szPattern);

			for (auto szCurrent = szStart; szCurrent < szEnd; ++szCurrent)
			{
				if (*szCurrent == '?')
				{
					++szCurrent;
					if (*szCurrent == '?')
						++szCurrent;
					vecBytes.push_back(-1);
				}
				else
					vecBytes.push_back(strtoul(szCurrent, &szCurrent, 16));
			}
			return vecBytes;
		};

	std::vector<int> vecPatternBytes = PatternToBytes(szSignature);
	size_t patternSize = vecPatternBytes.size();

	if (patternSize == 0)
		return NULL;

	// Read module data in chunks to avoid large memory allocations
	const size_t chunkSize = 0x10000; // 64KB chunks
	std::vector<uint8_t> buffer(chunkSize + patternSize - 1); // Extra bytes for pattern overlap

	for (size_t offset = 0; offset < moduleSize; offset += chunkSize)
	{
		size_t readSize = std::min(chunkSize, moduleSize - offset);

		// Add overlap from previous chunk (except for first chunk)
		if (offset > 0)
		{
			// Move the last (patternSize-1) bytes to the beginning
			std::memmove(buffer.data(), buffer.data() + chunkSize, patternSize - 1);

			// Read new data after the overlap
			if (!ReadRaw(moduleBase + offset, buffer.data() + patternSize - 1, readSize))
				continue;

			readSize += patternSize - 1;
		}
		else
		{
			// First chunk - read normally
			if (!ReadRaw(moduleBase + offset, buffer.data(), readSize))
				continue;
		}

		// Search for pattern in current chunk
		for (size_t i = 0; i <= readSize - patternSize; ++i)
		{
			bool bFound = true;
			for (size_t j = 0; j < patternSize; ++j)
			{
				if (buffer[i + j] != vecPatternBytes[j] && vecPatternBytes[j] != -1)
				{
					bFound = false;
					break;
				}
			}

			if (bFound)
			{
				// Calculate actual address
				size_t actualOffset = (offset > 0) ? offset + i - (patternSize - 1) : offset + i;
				return moduleBase + actualOffset;
			}
		}
	}

	return NULL;
}