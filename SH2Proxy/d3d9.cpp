#include "stdafx.h"
#include <windows.h>
#include <mmsystem.h>
#include <d3d9.h>
#include "Hooking.h"

#define D3D_SDK_VERSION   32

int WINAPI D3DPERF_EndEvent()
{
	return 0;
}

int WINAPI D3DPERF_BeginEvent(DWORD col, LPCWSTR wszName)
{
	return 0;
}

extern "C" {
	IDirect3D9* WINAPI D3D9_wrapper(UINT d3d_sdk_version) {
		char realLib[MAX_PATH] = { 0 };
		GetSystemDirectoryA(realLib, sizeof(realLib));
		strcat_s(realLib, MAX_PATH, "\\d3d9.dll");
		HMODULE hLibrary = LoadLibraryA(realLib);


		if (hLibrary)
		{
			FARPROC originalProc = GetProcAddress(hLibrary, "Direct3DCreate9");

			if (originalProc)
			{
				return ((IDirect3D9* (WINAPI*)(UINT))originalProc)(d3d_sdk_version);
			}
		}
	}
}