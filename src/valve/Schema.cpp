#include "../Precompiled.h"

// @credits: maecry (https://github.com/maecry/asphyxia-cs2/blob/3b0ccef9c3cc29b411d56bc0530bf12367fb33fb/cstrike/core/schema.cpp#L26-L114)
// @credits: mhalaider (https://yougame.biz/threads/290519/)
struct SchemaData_t
{
	FNV1A_t m_uHashedFieldName = 0x0ULL;
	std::uintptr_t m_uOffset = 0x0U;
};

static std::vector<SchemaData_t> vecSchemaData;
bool Schema::Setup(const wchar_t* wszFileName)
{
	HANDLE hOutFile = ::CreateFileW(Config::GetWorkingPath().append(wszFileName).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hOutFile == INVALID_HANDLE_VALUE)
		return false;

	// @todo: maybe remove this redundant? and put it inside CRT::String_t c'tor
	const std::time_t time = std::time(nullptr);
	std::tm timePoint;
	localtime_s(&timePoint, &time);

	CRT::String_t<64> szTimeBuffer(X("[%d-%m-%Y %T] External Base | schema dump\n\n"), &timePoint);

	// write current date, time and info
	::WriteFile(hOutFile, szTimeBuffer.Data(), szTimeBuffer.Length(), nullptr, nullptr);

	// Get schema system module info
	ModuleInfo_t schemaModule = g_Memory.GetModuleAddress("schemasystem.dll");
	if (schemaModule.m_uAddress == NULL)
	{
		Logging::PushConsoleColor(FOREGROUND_INTENSE_RED);
		Logging::Print(X("Failed to get schemasystem.dll module"));
		Logging::PopConsoleColor();
		::CloseHandle(hOutFile);
		return false;
	}

	// Read PE headers to get module size
	IMAGE_DOS_HEADER dosHeader = g_Memory.Read<IMAGE_DOS_HEADER>(schemaModule.m_uAddress);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		Logging::PushConsoleColor(FOREGROUND_INTENSE_RED);
		Logging::Print(X("Invalid DOS header for schemasystem.dll"));
		Logging::PopConsoleColor();
		::CloseHandle(hOutFile);
		return false;
	}

	IMAGE_NT_HEADERS ntHeaders = g_Memory.Read<IMAGE_NT_HEADERS>(schemaModule.m_uAddress + dosHeader.e_lfanew);
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		Logging::PushConsoleColor(FOREGROUND_INTENSE_RED);
		Logging::Print(X("Invalid NT headers for schemasystem.dll"));
		Logging::PopConsoleColor();
		::CloseHandle(hOutFile);
		return false;
	}

	DWORD moduleSize = ntHeaders.OptionalHeader.SizeOfImage;

	// Pattern scan in remote process memory
	std::uintptr_t patternAddress = g_Memory.PatternScanRemote(
		schemaModule.m_uAddress,
		moduleSize,
		X("48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 4C 89 74 24 ?")
	);

	if (patternAddress == NULL)
	{
		Logging::PushConsoleColor(FOREGROUND_INTENSE_RED);
		Logging::Print(X("Failed to find pattern in schemasystem.dll"));
		Logging::PopConsoleColor();
		::CloseHandle(hOutFile);
		return false;
	}

	// Resolve relative address to get base interface
	std::uintptr_t ptrToBaseInterface = g_Memory.ResolveRelativeAddress(patternAddress, 0x3, 0x7);

	Logging::PushConsoleColor(FOREGROUND_GREEN);
	Logging::Print(X("Found schema system interface at: 0x{:X}"), ptrToBaseInterface);
	Logging::PopConsoleColor();

	// Getting 51's element's address in _this ptr. This just some offset for CSchemaSystem class by Valv3
	std::uintptr_t ptrToListElement = g_Memory.Read<std::uintptr_t>(ptrToBaseInterface + 0x190);

	// Getting our type scope for "client.dll" module
	CSchemaSystemTypeScope* pTypeScope = g_Memory.Read<CSchemaSystemTypeScope*>(ptrToListElement + (0x10 * 8));
	auto pTable = pTypeScope->GetBindingsTable();

	Logging::PushConsoleColor(FOREGROUND_YELLOW);
	Logging::Print(X("found: {} schema classes in module"), pTable.Count());
	Logging::PopConsoleColor();

	std::unique_ptr<UtlTSHashHandle_t[]> pElements = std::make_unique_for_overwrite< UtlTSHashHandle_t[] >(pTable.Count());
	const int nElements = pTable.GetElements(0, pTable.Count(), pElements.get());

	for (int nElementIndex = 0; nElementIndex < nElements; nElementIndex++)
	{
		const UtlTSHashHandle_t hElement = pElements[nElementIndex];
		if (!hElement)
			continue;

		CSchemaClassBindingBase* const pClassBinding = pTable.Element(hElement);
		if (!pClassBinding)
			continue;

		if (!pClassBinding->GetNumFields())
			continue;

		CRT::String_t<MAX_PATH> szClassBuffer(X("class %s\n"), pClassBinding->GetName().c_str());
		::WriteFile(hOutFile, szClassBuffer.Data(), szClassBuffer.Length(), nullptr, nullptr);

		CSchemaField* pSchemaField = &pClassBinding->GetFields()[0];
		for (int nFieldIndex = 0; nFieldIndex < pClassBinding->GetNumFields(); nFieldIndex++)
		{
			if (!pSchemaField)
				continue;

			std::string name = pSchemaField->GetName();
			CRT::String_t<MAX_PATH> szFieldClassBuffer(X("%s->%s"), pClassBinding->GetName().c_str(), pSchemaField->GetName().c_str());

			// store field info
			vecSchemaData.emplace_back(FNV1A::Hash(szFieldClassBuffer.Data()), pSchemaField->GetOffset());

			CRT::String_t<MAX_PATH> szFieldBuffer(X("    %s %s = 0x%X\n"), pSchemaField->GetSchemaType()->GetName().c_str(), pSchemaField->GetName().c_str(), pSchemaField->GetOffset());
			// write field info
			::WriteFile(hOutFile, szFieldBuffer.Data(), szFieldBuffer.Length(), nullptr, nullptr);

			pSchemaField = reinterpret_cast<CSchemaField*>(std::uintptr_t(pSchemaField) + 0x20);
		}

		Logging::PushConsoleColor(FOREGROUND_YELLOW);
		Logging::Print(X("dumped: {}, total: {} fields"), pClassBinding->GetName().c_str(), pClassBinding->GetNumFields());
		Logging::PopConsoleColor();
	}

	::CloseHandle(hOutFile);
	return vecSchemaData.size() >= 1;
}
std::uintptr_t Schema::GetOffset(const FNV1A_t uHashedFieldName)
{
	if (const auto it = std::ranges::find_if(vecSchemaData, [uHashedFieldName](const SchemaData_t& data) { return data.m_uHashedFieldName == uHashedFieldName; }); it != vecSchemaData.end())
		return it->m_uOffset;

	Logging::PushConsoleColor(FOREGROUND_INTENSE_RED);
	Logging::Print(X("failed to find offset for field with hash: {}"), uHashedFieldName);
	Logging::PopConsoleColor();

	assert(false); // schema field not found
	return 0U;
}
