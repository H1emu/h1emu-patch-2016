// proxydll.cpp
#include "stdafx.h"
#include "VCProxy.h"
#include "VCPatcher.h"
#include "HookFunction.h"
#include "Hooking.h"
#include "psapi.h"

// global variables
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
VCPatcher			gl_patcher;
#pragma data_seg ()

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	// to avoid compiler lvl4 warnings 
	LPVOID lpDummy = lpReserved;
	lpDummy = NULL;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: InitInstance(hModule); break;
	case DLL_PROCESS_DETACH: ExitInstance(); break;

	case DLL_THREAD_ATTACH:  break;
	case DLL_THREAD_DETACH:  break;
	}
	return TRUE;
}

bool bDelay, bRamMet;
DWORD WINAPI Init(LPVOID)
{
#if 1
	gl_patcher.PreHooks();

	if (!bDelay) {
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, NULL, 0, NULL);
		bDelay = true;
		return 0;
	}

	if (bDelay)
	{
		while (!bRamMet) {
			HANDLE hProc = GetCurrentProcess();
			PROCESS_MEMORY_COUNTERS_EX info;
			info.cb = sizeof(info);
			GetProcessMemoryInfo(hProc, (PROCESS_MEMORY_COUNTERS*)&info, info.cb);

			float virtualMemUsedByMe = floor(float(info.WorkingSetSize / 1024000));

			if (virtualMemUsedByMe > 400) {
				bRamMet = true;
				break;
			}
		}
	}

	if (bRamMet)
	{
#endif
		//Ready to go
		gl_patcher.Init();
		HookFunction::RunAll();
#if 1
	}
#endif
	return 0;
}

void InitInstance(HANDLE hModule)
{
	OutputDebugString("PROXYDLL: InitInstance called.\r\n");

	// Initialisation
	gl_hOriginalDll = NULL;
	gl_hThisInstance = NULL;

	// Storing Instance handle into global var
	gl_hThisInstance = (HINSTANCE)hModule;
	Init(NULL);
}

void ExitInstance()
{
	OutputDebugString("PROXYDLL: ExitInstance called.\r\n");
}

