#pragma once

#include "../Miscellaneous/Dependancies.h"

class C_Utilities
{
public:
	// datatype for a module in memory (dll, regular exe) 
	struct Module_t {
		DWORD dwBase;
		DWORD dwSize;
	};

	Module_t TargetModule;  // Hold target module
	HANDLE TargetProcess; // for target process
	DWORD  TargetId;      // for target process
private:

	HANDLE GetProcess(const char* m_szProcessName);
	Module_t GetModule(const char* m_szModuleName);
	bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask);

	void WriteTextToFile(const char* m_szDumpInformation);
public:
	bool SetupDesiredProcess(const char* m_szProcessName);
	bool SetupDesiredModule(const char* m_szModuleName, Module_t* m_DummyModule);
	DWORD FindSignature(DWORD start, DWORD size, const char* sig, const char* mask);
	void Log(const char* m_szLogInformation, ...);

#define CLIENT_DLL ("client.dll")
#define ENGINE_DLL ("engine.dll")
#define SERVER_DLL ("server.dll")

	struct SignatureListStruct
	{
		const char* Module;
		const char* FunctionName;
		const char* Signature;
		const char* Mask;
	};

	std::vector<std::tuple<
		const char*/*Module*/,
		const char*/*FunctionName*/,
		const char*/*Signature*/,
		const char*/*Mask*/>> m_SignatureList =
	{
		// client.dll functions.
		{CLIENT_DLL, ("C_CSPlayer::SetupVelocity"), ("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x30\x56\x57\x8B\x3D"), ("xxxxxxxxxxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::CalcAbsVelocity"), ("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x1C\x53\x56\x57\x8B\xF9\xF7"), ("xxxxxxxxxxxxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::ModifyEyePosition"), ("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x5C\x53\x8B\xD9\x56\x57\x83"), ("xxxxxxxxxxxxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::PhysicsSimulate"), ("\x56\x8B\xF1\x8B\x8E\x00\x00\x00\x00\x83\xF9\xFF\x74\x23"), ("xxxxx????xxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::ShouldSkipAnimationFrame"), ("\x57\x8B\xF9\x8B\x07\x8B\x80\x00\x00\x00\x00\xFF\xD0\x84\xC0\x75\x02"), ("xxxxxxx????xxxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::ProcessInterpolatedList"), ("\x0F\xB7\x05\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x74\x3F"), ("xxx????x????xx")},
		{CLIENT_DLL, ("C_CSPlayer::InterpolateServerEntities"), ("\x55\x8B\xEC\x83\xEC\x1C\x8B\x0D\x00\x00\x00\x00\x53\x56"), ("xxxxxxxx????xx")},

		{CLIENT_DLL, ("C_CSPlayer::UpdateClientsideAnimation"), ("\x55\x8B\xEC\x51\x56\x8B\xF1\x80\xBE\x00\x00\x00\x00\x00\x74\x36"), ("xxxxxxxxx?????xx") },
		{CLIENT_DLL, ("C_CSPlayer::SetupBones"), ("\x55\x8B\xEC\x83\xE4\xF0\xB8\xD8"), ("xxxxxxxx")},
		{CLIENT_DLL, ("C_CSPlayer::BuildTransformations"), ("\x55\x8B\xEC\x83\xE4\xF0\x81\xEC\x00\x00\x00\x00\x56\x57\x8B\xF9\x8B\x0D\x00\x00\x00\x00\x89\x7C\x24\x28"), ("xxxxxxxx????xxxxxx????xxxx") },

		{CLIENT_DLL, ("C_ClientModeShared::CreateMove"), ("\x55\x8B\xEC\x8B\x4D\x04\x8B"), ("xxxxxxx")},
		{CLIENT_DLL, ("C_ClientModeShared::GetViewmodelFOV "), ("\x55\x8B\xEC\x8B\x0D\x00\x00\x00\x00\x83\xEC\x08\x57"), ("xxxxx????xxxx")},
		{CLIENT_DLL, ("C_ClientModeShared::OverrideView"), ("\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x58\x56\x57\x8B\x3D"), ("xxxxxxxxxxxxx")},

		{CLIENT_DLL, ("CalcViewBob"), ("\x55\x8B\xEC\xA1\x00\x00\x00\x00\x83\xEC\x10\x56\x8B\xF1\xB9"), ("xxxx????xxxxxxx")},
		{CLIENT_DLL, ("CalcViewModelBob"), ("\x55\x8B\xEC\xA1\x00\x00\x00\x00\x83\xEC\x10\x8B\x40\x34"), ("xxxx????xxxxxx")},
		{CLIENT_DLL, ("SetViewmodelOffsets"), ("\x55\x8B\xEC\x8B\x45\x08\xF3\x0F\x7E\x45"), ("xxxxxxxxxx")},
		{CLIENT_DLL, ("InitNewParticles"), ("\x55\x8B\xEC\x83\xEC\x18\x56\x8B\xF1\xC7\x45"), ("xxxxxxxxxxx")},

		{CLIENT_DLL, ("C_BaseAnimating::StandardBlendingRules"), ("\x55\x8B\xEC\x83\xE4\xF0\xB8\xF8\x10"), ("xxxxxxxxx")},

		{CLIENT_DLL, ("CHLClient::WriteUserCmdDeltaToBuffer"), ("\x55\x8B\xEC\x83\xEC\x68\x53\x56\x8B\xD9\xC7"), ("xxxxxxxxxxx")},
		{CLIENT_DLL, ("CHLClient::FrameStageNotify"), ("\x55\x8B\xEC\x8B\x0D\x00\x00\x00\x00\x8B\x01\x8B\x80\x00\x00\x00\x00\xFF\xD0\xA2\x00\x00\x00\x00"), ("xxxxx????xxxx????xxx????")},

		// engine.dll functions.
		{ENGINE_DLL, ("INetChannel::SendNetMsg"), ("\x55\x8B\xEC\x83\xEC\x08\x56\x8B\xF1\x8B\x86\x00\x00\x00\x00\x85\xC0"), ("xxxxxxxxxxx????xx")},
		{ENGINE_DLL, ("INetChannel::SendDatagram "), ("\x55\x8B\xEC\x83\xE4\xF0\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x56\x57\x8B\xF9\x89\x7C\x24\x18"), ("xxxxxxx????x????xxxxxxxx")},
		{ENGINE_DLL, ("INetChannel::ProcessPacket"), ("\x55\x8B\xEC\x83\xE4\xC0\x81\xEC\x00\x00\x00\x00\x53\x56\x57\x8B\x7D\x08\x8B\xD9"), ("xxxxxxxx????xxxxxxxx")},

		{ENGINE_DLL, ("CheckFileCRCsWithServer"), ("\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x8B\xD9\x89\x5D\xF8\x80"), ("xxxxx????xxxxxxx")},
		{ENGINE_DLL, ("CL_Move"), ("\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x56\x57\x8B\x3D\x00\x00\x00\x00\x8A"), ("xxxxx????xxxxx????x")},
	};

}; inline C_Utilities g_Utilities;