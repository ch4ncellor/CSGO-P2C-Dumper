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

bool C_Utilities::MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) 
{
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

DWORD C_Utilities::FindSignature(chdr::Process_t& m_Process, DWORD start, DWORD size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[size];

	SIZE_T bytesRead = m_Process.Read(
		(uintptr_t)start,
		data, 
		size
	);

	for (DWORD i = 0; i < size; i++) {
		if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
			return start + i;
		}
	}
	delete[] data;
	return NULL;
}
