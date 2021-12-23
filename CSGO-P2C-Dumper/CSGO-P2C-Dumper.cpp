#include "Miscellaneous/Dependancies.h"

#define BYTES_TO_READ_FROM_FUNCTION 20

int main()
{
    SetConsoleTitleA(("CSGO-P2C-Dumper - github.com/ch4ncellor"));

    // Remove previous dump logs, and other shit.
    std::remove(OUTPUT_LOG_FILE_PATH);

    LOG("\n[!] CSGO-P2C-Dumper:  developed by github.com/ch4ncellor\n");
    LOG("\n[!] Please enter your desired dumping method:\n");

    LOG("[!] 1) SignatureBasedDump - Dumps a section of memory based on a set of popular signatures. This isn't ideal for smaller cheats.\n");
    LOG("[!] 2) HookBasedDump      - Dumps a section of memory based on direct JMP's found at desired checked function(s) first 20 bytes.\n");
    LOG("[!] 3) NewAllocationDump  - Dumps newly allocated memory. Process must be opened before cheat injection to do the pre-scan.\n");
    LOG("[!] 4) AllFeaturesDump    - Dumps utilizing all features mentioned above.\n");

    std::uint32_t m_eDumpTypes{};
    std::cin >> m_eDumpTypes;

    if (m_eDumpTypes <= 0 || m_eDumpTypes > 4)
    {
        LOG("[-] Decision index out of range...\n");
        PAUSE_SYSTEM_CMD(true);
    }

    std::filesystem::create_directory("Dumps");

     chdr::Process_t m_Process(
        L"csgo.exe", 
         chdr::PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_NONE // Don't parse PE header data out of the process.
     );

     if (!m_Process.IsValid())
     {
         LOG("[-] Couldn't find desired process...\n");
         PAUSE_SYSTEM_CMD(true);
     }

    if (m_eDumpTypes == eDumpType::DUMPTYPE_SIGNATUREBASED)
    {
        g_Dumper.DumpCheatModule_ByPopularSignatures(m_Process);

        // Cleanup, and finish off.
        LOG("[+] CSGO-P2C-Dumper finished...\n");

        PAUSE_SYSTEM_CMD(true);
        ExitProcess(0x69420); // Moreso here just so we can see that this scope returns from the main function :D
    }

    // Because fucking retarded std::tuple doesnt want to play nice with me..
    ZyanU8 SavedOriginalBuffers[0x1337][BYTES_TO_READ_FROM_FUNCTION];
    int nIteration = 0;

    if (m_eDumpTypes == eDumpType::DUMPTYPE_ALLOCATIONBASED ||
        m_eDumpTypes == eDumpType::DUMPTYPE_ALLFEATURES)
    {
        LOG("[+] Iterating and caching all allocated memory...\n");
        g_Dumper.ScanInitialAllocations(m_Process);
    }

    if (m_eDumpTypes == eDumpType::DUMPTYPE_HOOKBASED ||
        m_eDumpTypes == eDumpType::DUMPTYPE_ALLFEATURES)
    {
        LOG("[+] Iterating and caching desired functions...\n");

        for (auto [m_szModuleName, m_szFunctionName, m_szSignature, m_szMask] : g_Utilities.m_SignatureList)
        {
            struct { std::uint32_t m_nSize = 0u; std::uint32_t m_nBase = 0u; } TemporaryModuleData;
            for (const auto& ModuleData : m_Process.EnumerateModules(true))
            {
                if (std::strcmp(m_szModuleName, ModuleData.m_szName.c_str()) != 0)
                    continue;

                TemporaryModuleData = { ModuleData.m_nSize, ModuleData.m_BaseAddress };
                break;
            }

            const DWORD m_AddressOfFunction = g_Utilities.FindSignature( m_Process,
                TemporaryModuleData.m_nBase, TemporaryModuleData.m_nSize,
                m_szSignature, m_szMask
            );

            if (!m_AddressOfFunction)
            {
                LOG("[-] Couldn't find address in memory for function: %s...\n", m_szFunctionName);
                continue;
            }

            ZyanU8 pFirst15BytesOfFunction[BYTES_TO_READ_FROM_FUNCTION];
            std::size_t m_nReadBytes = m_Process.Read(
                (uintptr_t)m_AddressOfFunction,
                pFirst15BytesOfFunction,
                BYTES_TO_READ_FROM_FUNCTION
            );

            if (!m_nReadBytes)
            {
                LOG("[-] ReadProcessMemory failed with errorcode #%i...\n", GetLastError());
                continue;
            }

            for (int i = 0; i < BYTES_TO_READ_FROM_FUNCTION; ++i) 
                SavedOriginalBuffers[nIteration][i] = pFirst15BytesOfFunction[i];
       
            g_Dumper.m_InitialSavedFunctions.push_back({ m_szFunctionName, m_AddressOfFunction, pFirst15BytesOfFunction });
            ++nIteration;
        }    

        LOG("[+] Successfully cached %i function(s)...\n\n", g_Dumper.m_InitialSavedFunctions.size());
    }

    LOG("[+] Please inject your desired P2C, and press F5 to continue! :)\n\n");

    while (!GetAsyncKeyState(VK_F5)) 
        // Hold thread until user's okay.
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    
    if (m_eDumpTypes == eDumpType::DUMPTYPE_HOOKBASED ||
        m_eDumpTypes == eDumpType::DUMPTYPE_ALLFEATURES)
    {
        LOG("\n[+] Iterating through cached functions to find mismatches...\n");

        bool bHasFoundAtleastOneMismatch = false;
        uint32_t m_nFoundDirectJump = 0;

        nIteration = 0;
        for (auto [m_szFunctionName, m_AddressOfFunction, m_ByteArrayOfFunction] : g_Dumper.m_InitialSavedFunctions)
        {

            ZyanU8 pFirstBytesOfFunction[BYTES_TO_READ_FROM_FUNCTION];
            std::size_t m_nReadBytes = m_Process.Read(
                (uintptr_t)m_AddressOfFunction,
                pFirstBytesOfFunction,
                BYTES_TO_READ_FROM_FUNCTION
            );

            if (!m_nReadBytes)
            {
                LOG("[-] ReadProcessMemory failed with errorcode #%i...\n", GetLastError());
                continue;
            }

            bool bFoundMismatch = false;
            for (int i = 0; i < BYTES_TO_READ_FROM_FUNCTION && !bFoundMismatch; i++) 
                bFoundMismatch = pFirstBytesOfFunction[i] != SavedOriginalBuffers[nIteration][i];
         
            if (bFoundMismatch)
            {
                LOG("\n[!!] Found mismatch at function %s at address 0x%X.\n[!!] Original buffer: ", m_szFunctionName, m_AddressOfFunction);
                for (int i = 0; i < BYTES_TO_READ_FROM_FUNCTION; ++i) {
                    LOG("%02X ", SavedOriginalBuffers[nIteration][i]);

                }  LOG("\n\n=================================================================================\n\n");

                LOG("[!!] Modified Buffer: ");
                for (int i = 0; i < BYTES_TO_READ_FROM_FUNCTION; ++i) {
                    LOG("%02X ", pFirstBytesOfFunction[i]);
                }  LOG("\n\n");

                // Initialize decoder context
                ZydisDecoder decoder;
                ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZydisStackWidth::ZYDIS_STACK_WIDTH_32);

                // Initialize formatter. Only required when you actually plan to do instruction
                // formatting ("disassembling"), like we do here
                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

                // Loop over the instructions in our buffer.
                // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
                // visualize relative addressing
                ZyanU64 runtime_address = m_AddressOfFunction;
                ZyanUSize offset = 0;
                const ZyanUSize length = BYTES_TO_READ_FROM_FUNCTION;
                ZydisDecodedInstruction instruction;
                while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, pFirstBytesOfFunction + offset, length - offset, &instruction)))
                {
                    // Print current instruction pointer.
                    LOG("%010" "llx" "  ", runtime_address);

                    // Format & print the binary instruction structure to human readable format
                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);

                    LOG("%s\n", buffer);

                    // Found a direct JMP! This probably leads us right to their fucking cheat module's address space!!!
                    // So we can save the address off it's directly JMP'ing to, then later take that address, and dump around that region!
                    if (!m_nFoundDirectJump && instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JMP)
                    {
                        std::string szBufferToString = std::string(buffer);

                        std::stringstream meme(szBufferToString.substr(4).c_str());
                        meme >> std::hex >> m_nFoundDirectJump;
                    }

                    offset += instruction.length;
                    runtime_address += instruction.length;
                } LOG("\n");

                bHasFoundAtleastOneMismatch = true;
            }

            if (m_nFoundDirectJump != 0x0)
                // Found direct JMP in modified buffer, cache for later.
                g_Dumper.m_FoundDirectJmpList.push_back({ m_szFunctionName, m_nFoundDirectJump });

            m_nFoundDirectJump = 0;
            ++nIteration;
        }

        if (!bHasFoundAtleastOneMismatch)
        {
            LOG("\n[-] Couldn't find any mismatches in desired set of hooks...\n\n");
        } 
        else
        {
            g_Dumper.DumpCheatModule_ByFoundDirectJmp(m_Process);
        }
    }

    if (m_eDumpTypes == eDumpType::DUMPTYPE_ALLOCATIONBASED ||
        m_eDumpTypes == eDumpType::DUMPTYPE_ALLFEATURES)
    {
        g_Dumper.DumpCheatModule_ByNewAllocations(m_Process);
    }

    if (m_eDumpTypes == eDumpType::DUMPTYPE_ALLFEATURES)
    {
        g_Dumper.DumpCheatModule_ByPopularSignatures(m_Process);
    }

    // Cleanup, and finish off.
    {
        LOG("[+] CSGO-P2C-Dumper finished...\n");
    }


    PAUSE_SYSTEM_CMD(true);
}