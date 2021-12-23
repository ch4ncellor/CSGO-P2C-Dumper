#pragma once

#include "../CSGO-P2C-Dumper/Miscellaneous/Dependancies.h"
#include "../chdr/chdr.h"
class C_Dumper
{
	void PopulateCheatSignatureTable();

	int m_nPreInjectionPageCount = 0;
	int m_nPostInjectionPageCount = 0;
public:
	int ScanInitialAllocations(chdr::Process_t& m_Process);
	void DumpCheatModule_ByNewAllocations(chdr::Process_t &m_Process);
	bool DumpCheatModule_ByFoundDirectJmp(chdr::Process_t& m_Process);
	bool DumpCheatModule_ByPopularSignatures(chdr::Process_t& m_Process);

	struct AllocatedMemoryInformation_t
	{
		PVOID  BaseAddress;
		SIZE_T RegionSize;
	};

	std::vector<AllocatedMemoryInformation_t> m_PreInjectionAllocatedMemory;
	std::vector<AllocatedMemoryInformation_t> m_PostInjectionAllocatedMemory;

	std::vector<
		std::pair<
		const char*/*FunctionName*/,
		uint32_t/*AddressOfJmp*/>> m_FoundDirectJmpList;

	std::vector<
		std::tuple<
		const char*/*FunctionName*/,
		DWORD/*AddressOfFunction*/,
		BYTE*/*ByteArrayOfFunction*/>> m_InitialSavedFunctions;

	std::vector<
		std::tuple<
		const char*/*FunctionName*/,
		const char*/*Signature*/,
		const char*/*Mask*/>> m_PayCheatCommonSignatureList;

}; inline C_Dumper g_Dumper;