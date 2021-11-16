#include "Utilities.h"

void C_Utilities::WriteTextToFile(const char* m_szDumpInformation)
{
	std::ofstream file;
	file.open(OUTPUT_LOG_FILE_PATH, std::ios::app);
	file << m_szDumpInformation;
	file.close();
}

void C_Utilities::Log(const char* m_szLogInformation, ...)
{
	std::vector<char> temp = std::vector<char>{};
	std::size_t length = std::size_t{ 63 };
	va_list args;

	while (temp.size() <= length)
	{
		temp.resize(length + 1);
		va_start(args, m_szLogInformation);
		const int status = std::vsnprintf(temp.data(), temp.size(), m_szLogInformation, args);
		va_end(args);

		length = static_cast<std::size_t>(status);
	}
	std::string out{ temp.data(), length };

	this->WriteTextToFile(out.c_str());

//	if (bShouldPrint)
	{
		printf(out.c_str());
	}
}

HANDLE C_Utilities::GetProcess(const char* processName) 
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);

	do 
	{
		_bstr_t m_szEntryExeFile(entry.szExeFile);
		if (!strcmp(m_szEntryExeFile, processName)) 
		{
			TargetId = entry.th32ProcessID;
			CloseHandle(handle);
			TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
			return TargetProcess;
		}
	} while (Process32NextW(handle, &entry));

	return {};
}

C_Utilities::Module_t C_Utilities::GetModule(const char* moduleName) 
{
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do 
	{
		_bstr_t m_szEntryExePath(mEntry.szModule);
		if (!strcmp(m_szEntryExePath, moduleName)) 
		{
			CloseHandle(hmodule);
			TargetModule = { (DWORD)mEntry.hModule, mEntry.modBaseSize };
			return TargetModule;
		}
	} while (Module32NextW(hmodule, &mEntry));

	Module_t emptyModule = { 0 };
	return emptyModule;
}

bool C_Utilities::SetupDesiredModule(const char* m_szModuleName, Module_t* m_DummyModule)
{
	*m_DummyModule = this->GetModule(m_szModuleName);
	return m_DummyModule->dwBase != NULL && m_DummyModule->dwSize != NULL;
}

bool C_Utilities::SetupDesiredProcess(const char* m_szProcessName)
{
	const HANDLE m_hProcessHandle = this->GetProcess(m_szProcessName);
	return m_hProcessHandle && m_hProcessHandle != INVALID_HANDLE_VALUE;
}

bool C_Utilities::MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) 
{
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

DWORD C_Utilities::FindSignature(DWORD start, DWORD size, const char* sig, const char* mask) 
{
	BYTE* data = new BYTE[size];
	SIZE_T bytesRead;

	ReadProcessMemory(this->TargetProcess, (LPVOID)start, data, size, &bytesRead);

	for (DWORD i = 0; i < size; i++) {
		if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
			return start + i;
		}
	}
	delete[] data;
	return NULL;
}
