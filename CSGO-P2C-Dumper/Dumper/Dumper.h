#pragma once

#include "../CSGO-P2C-Dumper/Miscellaneous/Dependancies.h"

class C_Dumper
{
	BYTE ByteBuf[35000000/*Up to 35MB limit*/];
	BYTE m_ProcessBuffer[8000000/*Up to 8MB limit*/];
	void PopulateCheatSignatureTable();

	int m_nPreInjectionPageCount = 0;
	int m_nPostInjectionPageCount = 0;
public:
	int ScanInitialAllocations();
	void DumpCheatModule_ByNewAllocations();
	bool DumpCheatModule_ByFoundDirectJmp();
	bool DumpCheatModule_ByPopularSignatures();

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
		DWORD/*AddressOfFunction*/,
		BYTE*/*ByteArrayOfFunction*/>> m_EndingSavedFunctions;

	std::vector<
		std::tuple<
		const char*/*FunctionName*/,
		const char*/*Signature*/,
		const char*/*Mask*/>> m_PayCheatCommonSignatureList;

}; inline C_Dumper g_Dumper;