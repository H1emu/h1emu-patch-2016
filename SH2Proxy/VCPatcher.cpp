#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>
#include <windows.h>
#include <tlhelp32.h>
#include <MinHook.h>
#include "UdpPlatformAddress.h"
#include <chrono>

#include "../H1Z1/H1Z1.exe.h"
#include "../H1Z1/enums.h"

//FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

using namespace std;
#define CONSOLE_ENABLED_THAT_CRASHES

static bool consoleShowing = false;
static float lasttext;

intptr_t* MenuManager = (intptr_t*)0x868638;
void* ConnectionMgrDummy = (void*)0x143B3E498;

#include "timer.h"
#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
//#include <udis86.h>
#include "..\SH2Proxy\Vendor\udis86\udis86.h"
#pragma comment(lib, "ws2_32.lib")

static bool(*g_origSetupInitialConnection)(intptr_t a1);
static bool(*g_InitGameWorld)(intptr_t a1);
static bool(*g_orig_TrySignalLaunchPadEvent)(intptr_t a1, void* a2);
static bool(*g_RegisterCommands)();
static void(*g_InitCharacterStuff)(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4);
static void(*g_BeginZoningAreaWrapper)(intptr_t a1, float possiblyRadius);

void hexDump(const char* desc, const void* addr, const int len);


static void* FindCallFromAddress(void* methodPtr, ud_mnemonic_code mnemonic = UD_Icall, bool breakOnFirst = false)
{
	// return value holder
	void* retval = nullptr;

	// initialize udis86
	ud_t ud;
	ud_init(&ud);

	// set the correct architecture
	ud_set_mode(&ud, 64);

	// set the program counter
	ud_set_pc(&ud, reinterpret_cast<uint64_t>(methodPtr));

	// set the input buffer
	ud_set_input_buffer(&ud, reinterpret_cast<uint8_t*>(methodPtr), INT32_MAX);

	// loop the instructions
	while (true)
	{
		// disassemble the next instruction
		ud_disassemble(&ud);

		// if this is a retn, break from the loop
		if (ud_insn_mnemonic(&ud) == UD_Iint3 || ud_insn_mnemonic(&ud) == UD_Inop)
		{
			break;
		}

		if (ud_insn_mnemonic(&ud) == mnemonic)
		{
			// get the first operand
			auto operand = ud_insn_opr(&ud, 0);

			// if it's a static call...
			if (operand->type == UD_OP_JIMM)
			{
				// ... and there's been no other such call...
				if (retval == nullptr)
				{
					// ... calculate the effective address and store it
					retval = reinterpret_cast<void*>(ud_insn_len(&ud) + ud_insn_off(&ud) + operand->lval.sdword);

					if (breakOnFirst)
					{
						break;
					}
				}
				else
				{
					// return an empty pointer
					retval = nullptr;
					break;
				}
			}
		}
	}

	return retval;
}

intptr_t LaunchPadA1Ptr;
static bool TrySignalLaunchPadEvent(intptr_t a1, void* a2)
{
	LaunchPadA1Ptr = a1;
	//g_origSetupInitialConnection(a1);
	return g_orig_TrySignalLaunchPadEvent(a1, a2);
}

HANDLE h_console;
static void tryAllocConsole() {
	if (!consoleShowing)
	{
		//Allocate a console
		AllocConsole();
		AttachConsole(GetCurrentProcessId());
		freopen("conin$", "r+t", stdin);
		freopen("conout$", "w+t", stdout);
		freopen("conout$", "w+t", stderr);
		consoleShowing = true;
		h_console = GetStdHandle(STD_OUTPUT_HANDLE);
	}
}

std::string getTimeStr() {
	std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	std::string s(20, '\0');
	std::strftime(&s[0], s.size(), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
	return s;
}

static void doSomeLogging(const char* fmt, va_list args) {
	tryAllocConsole();

	FILE* logFile = _wfopen(L"GameMessages.log", L"a");
	if (logFile)
	{
		char buffer[2048 * 4], bufferNewLine[(2048 * 4) + 1];

		vsnprintf(buffer, sizeof(buffer), fmt, args);
		SetConsoleTextAttribute(h_console, 7);

		sprintf_s(bufferNewLine, "%s\n", buffer);
		vfprintf(logFile, bufferNewLine, args); //write to file

		va_end(args);

		fclose(logFile);
		std::cout << bufferNewLine;
		//printf_s(bufferNewLine);
	}
}

static void doSomeLoggingWithTimeStamps(const char* fmt, va_list args) {
	//tryAllocConsole();
	string dateTime = getTimeStr();
	FILE* logFile = _wfopen(L"GameMessages.log", L"a");
	if (logFile)
	{
		char buffer[2100 * 4], bufferNewLine[(2100 * 4) + 1];

		vsnprintf(buffer, sizeof(buffer), fmt, args);
		SetConsoleTextAttribute(h_console, 7);

		sprintf_s(bufferNewLine, "%s\n", buffer);
		vfprintf(logFile, bufferNewLine, args); //write to file

		va_end(args);

		fclose(logFile);
		std::cout << dateTime << ": " << bufferNewLine;
		//printf_s(bufferNewLine);
	}
}



#if 1
void logFuncCustom(intptr_t unka1, const char* logEntry, ...) {

	va_list args;
	va_start(args, logEntry);
	doSomeLogging(logEntry, args);
	va_end(args);

	return;
}
#endif

void logFuncCustomWithTimeStamps(intptr_t unka1, const char* logEntry, ...) {

	va_list args;
	va_start(args, logEntry);
	doSomeLoggingWithTimeStamps(logEntry, args);
	va_end(args);

	return;
}

static void(*logFuncCustom1_orig)(intptr_t a1, intptr_t size, const char* logEntry, ...);
static void logFuncCustom1(intptr_t a1, intptr_t size, const char* logEntry, ...) {

	logFuncCustom1_orig(a1, size, logEntry);

	va_list args;
	va_start(args, logEntry);
	doSomeLogging(logEntry, args);
	va_end(args);

	return;
}

static void(*logFuncCustom2_orig)(int loglevel, intptr_t* unka1, const char* logEntry, va_list args);
static void logFuncCustom2(int loglevel, intptr_t* unka1, const char* logEntry, va_list args) {
	printf("Return Address: %p\n", _ReturnAddress());

	logFuncCustom2_orig(loglevel, unka1, logEntry, args);

	doSomeLogging(logEntry, args);

	return;
}

static void(*logFuncCustom_orig3)(char* a1, char* a2, char* a3, int a4, va_list args);
static void logFuncCustom3(char* a1, char* a2, char* a3, int a4, va_list args) {

	logFuncCustom_orig3(a1, a2, a3, a4, args);

	doSomeLogging(a2, args);
	return;
}

static void(*logFuncCustom4_orig)(intptr_t* unka1, const char* logEntry, va_list args);
static void logFuncCustom4(intptr_t* unka1, const char* logEntry, va_list args) {

	logFuncCustom4_orig(unka1, logEntry, args);
	doSomeLogging(logEntry, args);
	return;
}

static void(*logFuncCustom_orig5)(char* a1, va_list args);
static void logFuncCustom5(char* a1, va_list args) {

	logFuncCustom_orig5(a1, args);

	doSomeLogging(a1, args);
	return;
}

static bool(*g_origRespawnWindow__DisplayRespawn)(intptr_t a1);
static bool RespawnWindow__DisplayRespawn(intptr_t a1)
{
	g_origRespawnWindow__DisplayRespawn(a1);
	return true; //never fail
}

static void(*g_origShowErrorCodeAndExitImmediately)(int code, char* reason, bool a3, bool* a4);
static void ShowErrorCodeAndExitImmediately(int code, char* reason, bool a3, bool* a4)
{
	if (code == 8) return;

	g_origShowErrorCodeAndExitImmediately(code, reason, a3, a4);
}

static void* (*g_origAllocSomeMemory)(int size);
static void* (*g_instanceUnknownClass)(void* a1);
void* unk_143B3E5B8 = (void*)0x143B3E5B8;
void* g_proxiedCharacter = (void*)0x143B3E438;

std::atomic<bool> alreadyDoneDeployment = false;
std::atomic<bool> waitingForZoneLoad = true;

bool alreadyDone = false;
static void(*g_origLoadConfigFile)(intptr_t a1, bool a2);
static void(*g_origOnGameStartup)(intptr_t a1);
static void OnGameStartup(intptr_t a1)
{



#ifdef CONSOLE_ENABLED_THAT_CRASHES
static HookFunction hookFunction([]()
	{
	});
#endif


extern VCPatcher gl_patcher;

static bool(*g_origConstructDisplay)(intptr_t a1);


static bool(*g_origOnReceiveServer)(void* a1, void* a2, void* a3);


static SOCKET g_gameSocket;

}

int __stdcall CfxBind(SOCKET s, sockaddr* addr, int addrlen)
{
	sockaddr_in* addrIn = (sockaddr_in*)addr;

	printf_s("binder on %i is %p, %p\n", htons(addrIn->sin_port), (void*)s, _ReturnAddress());

	//if (htons(addrIn->sin_port) == 34567)
	{
		//g_gameSocket = s;
	}

	return bind(s, addr, addrlen);
}



static void(*logFuncCustomCallOrig_orig)(void* a1, const char* fmt, va_list args);
static void logFuncCustomCallOrig(void* a1, const char* fmt, va_list args) {
	__try
	{
		doSomeLogging(fmt, args);
		logFuncCustomCallOrig_orig(a1, fmt, args);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("logFuncCustomCallOrig excepted, caught and returned.\n");
	}
}

//ANTI DEBUG
bool IsDebuggerPresentOurs() {
	return true;
}


typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      UINT             ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

int ProcessDebugPort2 = 7;

pfnNtQueryInformationProcess g_origNtQueryInformationProcess = NULL;


static ULONG ValueProcessBreakOnTermination = FALSE;
static bool IsProcessHandleTracingEnabled = false;

DWORD dwExplorerPid = 0;
WCHAR ExplorerProcessName[] = L"explorer.exe";

DWORD GetProcessIdByName(const WCHAR* processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!lstrcmpiW((LPCWSTR)pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}

DWORD GetExplorerProcessId()
{
	if (!dwExplorerPid)
	{
		dwExplorerPid = GetProcessIdByName(ExplorerProcessName);
	}
	return dwExplorerPid;
}

void SetupSetPEB() {
	// Thread Environment Block (TEB)
#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	// Process Environment Block (PEB)
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	pebPtr->BeingDebugged = false;
}

static LONG(*g_exceptionHandler)(EXCEPTION_POINTERS*);
static BOOLEAN(*g_origRtlDispatchException)(EXCEPTION_RECORD* record, CONTEXT* context);

static BOOLEAN RtlDispatchExceptionStub(EXCEPTION_RECORD* record, CONTEXT* context)
{
	// anti-anti-anti-anti-debug
	if (IsDebuggerPresentOurs() && (record->ExceptionCode == 0xc0000008/* || record->ExceptionCode == 0xc0000005*/))
	{
		return TRUE;
	}

	BOOLEAN success = g_origRtlDispatchException(record, context);
	//140533ae2
	if (IsDebuggerPresentOurs())
	{
		if (!success) {
			printf("Exception at: %p\n", record->ExceptionAddress);
		}
		return success;
	}

	static bool inExceptionFallback;

	if (!success)
	{
		if (!inExceptionFallback)
		{
			inExceptionFallback = true;

			//AddCrashometry("exception_override", "true");

			EXCEPTION_POINTERS ptrs;
			ptrs.ContextRecord = context;
			ptrs.ExceptionRecord = record;

			if (g_exceptionHandler)
			{
				g_exceptionHandler(&ptrs);
			}

			inExceptionFallback = false;
		}
	}

	return success;
}

void SetupHook()
{
	void* baseAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), "KiUserExceptionDispatcher");

	if (baseAddress)
	{
		void* internalAddress = FindCallFromAddress(baseAddress, UD_Icall, true);

		{
			MH_CreateHook(internalAddress, RtlDispatchExceptionStub, (void**)&g_origRtlDispatchException);
		}
	}

	MH_EnableHook(MH_ALL_HOOKS);
	return;
}

void VCPatcher::PreHooks() {
	SetupSetPEB();
	SetupHook();
}

static void WINAPI ExitProcessReplacement(UINT exitCode)
{
	TerminateProcess(GetCurrentProcess(), exitCode);
}

static void(*NetInfolog_orig)(char* a1, char* a2);
static void NetInfolog(char* a1, char* a2) {
	printf("%s : %s \n", a1,a2);

}
static void(*somefunc1_orig)(char* a1, char* a2, char* a3, char* a4);
static void somefunc1(char* a1, char* a2, char* a3, char* a4) {
	printf("%s : %s \n", a1, a2, a3, a4);

}

static void(*somefunc2_orig)(char* a1, char* a2, char* a3);
static void somefunc2(char* a1, char* a2, char* a3) {
	printf("%s %s %s \n", a1, a2, a3);

}

static void(*somefunc3_orig)(char* a1);
static void somefunc3(char* a1) {
	printf("%s\n", a1);

}

static void(*zoneinfo_orig)(char* a1, char* a2, char* a3, char* a4);
static void zoneinfo(char* a1, char* a2, char* a3, char* a4) {
	printf("%s : %s %s : %s \n", a1, a2, a3, a4);

}

ofstream logFile;

static void(*logs_orig)(int a1, int a2, int a3, int a4);
static void logs(int a1, int a2, int a3, int a4) {

}

static intptr_t(*g_ReturnFunctions)(char* a1);
intptr_t ReturnFunctions(char* a1) {
	//*(char*)(a1 + 0x38884) = true; //ReceivedPreloadDonePacket
	intptr_t returnVal = 0;
	__try
	{
		returnVal = g_ReturnFunctions(a1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return 1;
}

void gamelogsfunc() {
	MH_CreateHook((char*)0x1402655F0, logFuncCustomWithTimeStamps, (void**)&NetInfolog_orig);
	MH_CreateHook((char*)0x14039F140, logFuncCustomWithTimeStamps, (void**)&somefunc2_orig);
	MH_CreateHook((char*)0x140266960, logFuncCustomWithTimeStamps, (void**)&zoneinfo_orig);
}

void displayCommands() {

	cout << "SwitchCases\n";
	cout << "1 = GameLogs 'Prints all gamelogs to the console'\n";
	cout << "2 = ZoneLoaderFunctionLogs 'shows the game functions being called while loading zone\n";
	cout << "3 = DebugSwf 'Prints information about the currently used UI\n";
	
	cout << "\nEnter switch case: ";
}
/*
bool VCPatcher::Init()
{
	logFile.open("GameMessages.log");
	if (logFile.good()) {
		std::remove("GameMessages.log");
	}
	
	gamelogsfunc();
    tryAllocConsole();
	//displayCommands();

	logFile.open("GameMessages.log");

    char hook;
	cin >> hook;
	cout << "\n";
	switch (hook)
	{
	case '1': gamelogsfunc(); break;
	case '2': MH_CreateHook((char*)0x1406C7D90, logFuncCustom, (void**)&somefunc1_orig); break; // Prints information about zoneloader
	case '3': MH_CreateHook((char*)0x141819310, logFuncCustom, (void**)&somefunc2_orig); break; // Prints information about the current visible swf UI
	case '4': MH_CreateHook((char*)0x1406C9CD0, logFuncCustom5, (void**)&somefunc3_orig); break; //
	case '420': MH_CreateHook((char*)0x1402BE8F0, logFuncCustom, (void**)&somefunc2_orig); break; // Grass all over the screen??

	} 

	MH_CreateHookApi(L"kernel32.dll", "ExitProcess", ExitProcessReplacement, nullptr);

	MH_EnableHook(MH_ALL_HOOKS);

	return true;
}
*/
static intptr_t(*g_origWaitForWorldReady)(char* a1);
intptr_t WaitForWorldReady(char* a1) {
	//*(char*)(a1 + 0x38884) = true; //ReceivedPreloadDonePacket
	intptr_t returnVal = 0;
	__try
	{
		returnVal = g_origWaitForWorldReady(a1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("WaitForWorldReady excepted, caught and returned.\n");
	}
	return 1;
}

static bool(*File__Open_orig)(void* a1, char* filename, int a3, int a4);
bool File__Open(void* a1, char* filename, int a3, int a4) {
	bool open = File__Open_orig(a1, filename, a3, a4);
	printf("File::Open tried to open %s - result %d\n", filename, open);
	return open;
}

struct IncomingPacket
{
	BYTE gap0[8];
	DWORD packetType;
};
BaseClient* g_BaseClient;
static void(*handleIncomingZonePackets_orig)(BaseClient* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6);
static void handleIncomingZonePackets(BaseClient* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6) {
	g_BaseClient = thisPtr;
	// char* packetDumpOut;
	if (packet->packetType != 60) {
		printf("\n\n\n\n\n\n\n\n\n\n");
		printf("packetType: %d - Return Address: %p\n", packet->packetType, _ReturnAddress());

		if (packet->packetType == 22 || packet->packetType == 3) { //SendZoneDetails, sendself only
			printf("Calling hexDump\n");
			hexDump("data dump for netDataBuf:", data, dataLen);
			printf("\n\n");
			hexDump("data dump for ndbAtLen:", &data[dataLen], dataLen);
		}

		printf("\n\n\n\n\n\n\n\n\n\n");
	}
	handleIncomingZonePackets_orig(thisPtr, packet, data, dataLen, time, a6);
}

static bool(*g_origOnReceiveServer)(void* a1, void* a2, void* a3);
static bool OnReceiveServer(void* a1, void* a2, void* a3)
{
	return g_origOnReceiveServer(a1, a2, a3);
}

intptr_t CamTickCount = 0;
static void(*tickControllers_Orig)(void* a1, void* a2, void* a3, bool shouldProcessInput);
static void hook_tickControllers(void* a1, void* a2, void* a3, bool shouldProcessInput) {
	shouldProcessInput = GetTickCount64() - CamTickCount > 3000 ? true : false; //Wait 3 seconds before running this method, experimental
	tickControllers_Orig(a1, a2, a3, shouldProcessInput);
}

static void(*handleIncomingLoginPackets_orig)(void* a1, void* a2, unsigned int a3);
static void handleIncomingLoginPackets(void* a1, void* a2, unsigned int a3) {
	printf("handleIncomingLoginPackets: Return Address: %p\n", _ReturnAddress());
	handleIncomingLoginPackets_orig(a1, a2, a3);
}

static void(*onLoginCompleteStub_orig)(void* thisPtr);
static void onLoginCompleteStub(void* thisPtr) {
	printf("onLoginCompleteStub: Return Address: %p\n", _ReturnAddress());
	onLoginCompleteStub_orig(thisPtr);
}

static bool gameConsoleShowing = false;
static void(*executeLuaFunc_orig)(void* LuaVM, char* funcName, int a3, int a4);
static void executeLuaFuncStub(void* LuaVM, char* funcName, int a3, int a4) {
	void* retAddr = _ReturnAddress();
	if (retAddr != (void*)0x1403FD30D && retAddr != (void*)0x140BFEEA8 && retAddr != (void*)0x140CFBC62 && retAddr != (void*)0x14040DF7D){ // OnUpdate, GameEvents:GetInventoryShown, HudHandler:GetBattleRoyaleData
		printf("executeLuaFuncStub: %s - Return Address: %p\n", funcName, retAddr);
	}
	std::string func = funcName;
	if (func == "Console:StartDebugConsole") { // forces console to open when key pressed
		executeLuaFunc_orig(LuaVM, "Console:Show", 0, 0);
		gameConsoleShowing = !gameConsoleShowing;
	}
	else if ((func == "GameEvents:OnEscape" || func == "Console:OnSwfFocus") && gameConsoleShowing) { // closes console on ~ or escape
		executeLuaFunc_orig(LuaVM, "Console:Hide", 0, 0);
		executeLuaFunc_orig(LuaVM, funcName, a3, a4); // executes normal GameEvents:OnEscape / "Console:OnSwfFocus"
		gameConsoleShowing = !gameConsoleShowing;
	}
	else { // all other lua funcs
		executeLuaFunc_orig(LuaVM, funcName, a3, a4);
	}
}

static void(*TransitionClientRunState_orig)(BaseClient* a1, int state);
static void TransitionClientRunState(BaseClient* a1, int state) {

	printf("********TransitionClientRunState state: %u \n\n\n\n", state); // prints clientrunstate
	TransitionClientRunState_orig(a1, state);
}

bool characterLoginReply = false;
static void(*loginReadFuncs_orig)(int a1, char* a2, int a3);
static void loginReadFuncsStub(int a1, char* a2, int a3) {
	int opcode = *a2;
	printf("********loginReadFuncs called: %i \n\n\n\n", opcode);
	if (opcode == 8) {
		characterLoginReply = true;
	}
	loginReadFuncs_orig(a1, a2, a3);
}
/*
static void(*ClientRunStateManager_orig)(BaseClient* a1);
static void ClientRunStateManager(BaseClient* a1) {
	
	if (characterLoginReply) {
		// manually set guid
		// a1->guid = 722776196;

		HideLoadingscreen_orig(a1, "Has Character List");
		TransitionClientRunState_orig(a1, ClientRunStateNetInitialize);
		characterLoginReply = false;
	}
	
	DWORD state = a1->clientRunState;
	// printf("********ClientRunStateManager state: %u \n\n\n\n", state); // prints clientrunstate
	ClientRunStateManager_orig(a1);
}
*/

void OnIntentionalCrash() {
	printf("daybreak hates you\n");
	char buffer[512];
	sprintf(buffer, "Should have crashed, but will continue executing, return address is: %p\n", _ReturnAddress());
	/*MessageBox(
		NULL,
		buffer,
		"OnIntentionalCrash (0xBADF00D)",
		MB_ICONWARNING | MB_DEFBUTTON2
	);*/
}

void OnIntentionalCrash1() {
	printf("OnIntentionalCrash1\n");
	printf("Should have crashed, but will continue executing, return address is: %p\n", _ReturnAddress());
}

static void(*processInput_orig)(void* a1);
static void processInput(void* a1) {
	processInput_orig(a1);
}

static void(*SpawnLightweightPc_orig)(BaseClient* a1, LightweightPc* a2);
static void SpawnLightweightPc(BaseClient* a1, LightweightPc* a2) {
	printf("********SpawnLightweightPcReadFromPacket\n\n");
	SpawnLightweightPc_orig(a1, a2);
}

static void(*sub_14039E0A0_orig)(void* a1);
static void sub_14039E0A0(void* a1) {
	printf("********sub_14039E0A0\n\n"); // called within spawnlightweightpc and spawnlightweightnpc, makes sure correct checks are passed
	sub_14039E0A0_orig(a1);
}

// resources

static void(*resourceEventBaseRead_orig)(void* a1, void* a2, void* a3);
static void resourceEventBaseRead(void* a1, void* a2, void* a3) {
	printf("********resourceEventBaseRead\n\n");
	resourceEventBaseRead_orig(a1, a2, a3);
}

static void(*removeCharacterResourceRead_orig)(void* a1, void* a2, void* a3, void* a4);
static void removeCharacterResourceRead(void* a1, void* a2, void* a3, void* a4) {
	printf("********removeCharacterResourceRead\n\n");
	removeCharacterResourceRead_orig(a1, a2, a3, a4);
}

static void(*updateCharacterResourceRead_orig)(void* a1, void* a2, void* a3, void* a4);
static void updateCharacterResourceRead(void* a1, void* a2, void* a3, void* a4) {
	printf("********updateCharacterResourceRead\n\n");
	updateCharacterResourceRead_orig(a1, a2, a3, a4);
}

static void(*setCharacterResourceRead_orig)(void* a1, void* a2, void* a3, void* a4);
static void setCharacterResourceRead(void* a1, void* a2, void* a3, void* a4) {
	printf("********setCharacterResourceRead\n\n");
	setCharacterResourceRead_orig(a1, a2, a3, a4);
}

static void(*setCharacterResourcesRead_orig)(void* a1, void* a2, void* a3, void* a4);
static void setCharacterResourcesRead(void* a1, void* a2, void* a3, void* a4) {
	printf("********setCharacterResourcesRead\n\n");
	setCharacterResourcesRead_orig(a1, a2, a3, a4);
}

static void(*setCharacterResource_orig)(void* a1, void* a2, void* a3, void* characterResource);
static void setCharacterResource(void* a1, void* a2, void* a3, void* characterResource) {
	printf("********setCharacterResource\n\n");
	setCharacterResource_orig(a1, a2, a3, characterResource);
}

// end of resources





bool VCPatcher::Init()
{
	// #########################################################     Game patches     ########################################################
	// blocks 0xBADBEEF
	hook::jump(0x14032DC60, OnIntentionalCrash); //Should have crashed, but continue executing... (sendself, lightweightToFullPc triggers this)

	hook::jump(0x140C06FD0, OnIntentionalCrash1);// exception inside 140C06FD0 somewhere

	//hook::return_function_vp(0x1408B4230)

	// ###################################################     End of game patches     ############################################################


	// ###################################################     Game hooks     ############################################################

	// resources

	MH_CreateHook((char*)0x14058A4F0, resourceEventBaseRead, (void**)&resourceEventBaseRead_orig);

	MH_CreateHook((char*)0x14058A5F0, removeCharacterResourceRead, (void**)&removeCharacterResourceRead_orig);

	MH_CreateHook((char*)0x14058AAC0, updateCharacterResourceRead, (void**)&updateCharacterResourceRead_orig);

	MH_CreateHook((char*)0x14058A6E0, setCharacterResourceRead, (void**)&setCharacterResourceRead_orig);

	MH_CreateHook((char*)0x14058A8D0, setCharacterResourcesRead, (void**)&setCharacterResourcesRead_orig);


	
	MH_CreateHook((char*)0x14058B9C0, setCharacterResource, (void**)&setCharacterResource_orig);

	// end of resources

	//MH_CreateHook((char*)0x1403FA350, ClientRunStateManager, (void**)&ClientRunStateManager_orig);

	MH_CreateHook((char*)0x1403FD710, SpawnLightweightPc, (void**)&SpawnLightweightPc_orig);

	MH_CreateHook((char*)0x14039E0A0, sub_14039E0A0, (void**)&sub_14039E0A0_orig); // sanity check (Pc / Npc / Vehicle)

	MH_CreateHook((char*)0x140474DE0, TransitionClientRunState, (void**)&TransitionClientRunState_orig);

	//Confirm packet (still need this)
	MH_CreateHook((char*)0x140478080, WaitForWorldReady, (void**)&g_origWaitForWorldReady); //Needs the confirm packet (2016)

	MH_CreateHook((char*)0x140337AE0, File__Open, (void**)&File__Open_orig); //(2016)

	// auto loc = hook::pattern("48 83 EC 38 3B 0D ? ? ? ? 4D 8B").count(1).get(0).get<char>(0);
	// MH_CreateHook((char*)loc, logFuncCustom2, (void**)&logFuncCustom2_orig); //logging orig

	// login read funcs test
	MH_CreateHook((char*)0x14163EFA0, loginReadFuncsStub, (void**)&loginReadFuncs_orig);

	//Logging
	MH_CreateHook((char*)0x1402ED6F0, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); //hook absolutely every logging function
	//MH_CreateHook((char*)0x1400011FE, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); //Logs absolutely everything, even time (not updated yet)

	//Other
	MH_CreateHook((char*)0x140737C00, OnReceiveServer, (void**)&g_origOnReceiveServer);


	MH_CreateHook((char*)0x140433680, processInput, (void**)&processInput_orig);


	// MH_CreateHook((char*)0x140533A90, handleInitException, (void**)&handleInitException_orig); (not updated yet)

	// MH_CreateHook((char*)0x14127B830, readPayLoad, (void**)&readPayLoad_orig); (not updated yet)

	// MH_CreateHook((char*)0x14127C560, readPayLoad2, (void**)&readPayLoad2_orig); (not updated yet)

	MH_CreateHook((char*)0x1403FE210, handleIncomingZonePackets, (void**)&handleIncomingZonePackets_orig);

	MH_CreateHook((char*)0x14163EA20, handleIncomingLoginPackets, (void**)&handleIncomingLoginPackets_orig);

	MH_CreateHook((char*)0x140488CC0, executeLuaFuncStub, (void**)&executeLuaFunc_orig);

	MH_CreateHook((char*)0x1403D64A0, onLoginCompleteStub, (void**)&onLoginCompleteStub_orig);

	// ###################################################     End of game hooks     ############################################################

	MH_CreateHookApi(L"kernel32.dll", "ExitProcess", ExitProcessReplacement, nullptr);

	MH_EnableHook(MH_ALL_HOOKS);

	return true;
}
bool VCPatcher::PatchResolution(D3DPRESENT_PARAMETERS* pPresentationParameters)
{
	pPresentationParameters->Windowed = true;
	pPresentationParameters->Flags = 0;
	pPresentationParameters->FullScreen_RefreshRateInHz = 0;
	//pPresentationParameters->FullScreen_PresentationInterval = 0;

	SetWindowPos(pPresentationParameters->hDeviceWindow, HWND_NOTOPMOST, 0, 0, pPresentationParameters->BackBufferWidth, pPresentationParameters->BackBufferHeight, SWP_SHOWWINDOW);
	SetWindowLong(pPresentationParameters->hDeviceWindow, GWL_STYLE, WS_POPUP | WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU | WS_VISIBLE);
	return true;
}

void hexDump(const char* desc, const void* addr, const int len) {
	int i;
	unsigned char buff[17];
	const unsigned char* pc = (const unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Length checks.
	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	else if (len < 0) {
		printf("  NEGATIVE LENGTH: %d\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).
		if ((i % 16) == 0) {
			// Don't print ASCII buffer for the "zeroth" line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And buffer a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII buffer.
	printf("  %s\n", buff);
}

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;