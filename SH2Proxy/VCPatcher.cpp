#include "stdafx.h"
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <winternl.h>
#include <MinHook.h>
#include <iostream>
#include "udis86.h"

#include "../H1Z1/H1Z1.exe.h"
#include "../H1Z1/enums.h"

// Production hygiene: only open the debug console / enable base-patch logging in Debug builds.
// Release defines NDEBUG (not _DEBUG) -> CONSOLE_ENABLED stays undefined -> no AllocConsole, all
// #ifdef CONSOLE_ENABLED debug blocks compile out, and the #ifndef CONSOLE_ENABLED early-returns
// (doSomeLogging / hexDump) make logging a silent no-op. Emote/NV hooks run regardless (not gated on this).
#ifdef _DEBUG
#define CONSOLE_ENABLED
#endif

// DIAGNOSTIC in-process crash-trace logger. UNDEFINED by default (normal build unaffected); build the crash
// diagnostic with /DDIAG_CRASHLOG. When defined: installs a first-chance VECTORED exception handler that logs
// every fault (code, faulting instruction, AV read/write + data addr, module-relative backtrace) to
// h1-crash-trace.log and lets it crash naturally (EXCEPTION_CONTINUE_SEARCH); AND converts the two crash-site
// blockers (0x14032DC60 / 0x140C06FD0) from block-the-crash to LOG-caller-chain-then-call-original so we
// capture which packet handler tripped the assert even when the terminate is an uncatchable fastfail.
// #define DIAG_CRASHLOG

using namespace std;

static bool consoleShowing = false;

// luaVM ptr
void* L = nullptr;

long long g_BaseClientAddr = 0x142B19780;

static bool gameConsoleShowing = false;
static void(*executeLuaFunc_orig)(void* LuaVM, char* funcName, void* a3, void* a4);

std::string assetHashes = "";
bool pendingAssetCheck = false;

void* ConsoleRelated = nullptr;

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
		ud_disassemble(&ud);// disassemble the next instruction
		// if this is a retn, break from the loop
		if (ud_insn_mnemonic(&ud) == UD_Iint3 || ud_insn_mnemonic(&ud) == UD_Inop)
		{
			break;
		}
		if (ud_insn_mnemonic(&ud) == mnemonic)
		{
			auto operand = ud_insn_opr(&ud, 0); // get the first operand
			if (operand->type == UD_OP_JIMM) // if it's a static call...
			{
				if (retval == nullptr) // ... and there's been no other such call...
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
					retval = nullptr; // return an empty pointer
					break;
				}
			}
		}
	}
	return retval;
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

static void doSomeLogging(const char* fmt, va_list args) {
	#ifndef CONSOLE_ENABLED
		return;
	#endif
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

static void(*writeToLog_orig)(void* a1, void* a2, const char* fmt, va_list args);
static void writeToLog(void* a1, void* a2, const char* fmt, va_list args) {
	__try
	{
		doSomeLogging(fmt, args);
		writeToLog_orig(a1, a2, fmt, args);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("writeToLog excepted, caught and returned.\n");
	}
}


//ANTI DEBUG
bool IsDebuggerPresentOurs() {
	return true;
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
		{ // prints exceptions with address to console
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

ofstream logFile;

static bool(*File__Open_orig)(void* a1, char* filename, int a3, int a4);
bool File__Open(void* a1, char* filename, int a3, int a4) {
	bool open = File__Open_orig(a1, filename, a3, a4);
	printf("File::Open tried to open %s - result %d\n", filename, open);
	return open;
}

static void(*ReadStringFromBuffer_orig)(DataLoadByPacket* buffer, char* ptr);
static void ReadStringFromBuffer(DataLoadByPacket* buffer, char* ptr) {
	ReadStringFromBuffer_orig(buffer, ptr);
}

struct Buffer {
	char* pBuffer;
	int bufferSize;
	char* pBufferEnd;
	bool failFlag;
};

void ReadByteFromBuffer(Buffer* buffer, char* value = nullptr) {
	if (buffer->pBuffer + 1 <= buffer->pBufferEnd) {
		if (value) {
			*value = *buffer->pBuffer;
		}
		buffer->pBuffer += 1;
	}
	else {
		buffer->failFlag = true;
	}
}

void ReadDwordFromBuffer(Buffer* buffer, uint32_t* value = nullptr) {
	if (buffer->pBuffer + 4 <= buffer->pBufferEnd) {
		if (value) {
			*value = *buffer->pBuffer;
		}
		buffer->pBuffer += 4;
	}
	else {
		buffer->failFlag = true;
	}
}

void ReadStringFromBuffer(Buffer& buffer, std::string& str) {
	// Check if string length dword is valid
	if (4 > static_cast<uint32_t>(buffer.pBufferEnd - buffer.pBuffer)) {
		buffer.failFlag = true;
		return;
	}
	
	// Read the string length from the first 4 bytes of the buffer
	uint32_t strLength = 0;
	ReadDwordFromBuffer(&buffer, &strLength);

	// Check if the length is valid
	if (buffer.failFlag || strLength > static_cast<uint32_t>(buffer.pBufferEnd - buffer.pBuffer)) {
		buffer.failFlag = true;
		return;
	}

	// Copy the string to the output variable
	str = std::string(buffer.pBuffer, strLength);
	buffer.pBuffer += strLength;
}

static void (*onPrintConsole_orig)(void* a1, void* a2, char a3, void* a4);
static void handlePrintConsolePacket(Buffer* buffer) {
	std::string str;
	ReadStringFromBuffer(*buffer, str);

	char showConsole = 0;
	ReadByteFromBuffer(buffer, &showConsole);

	char clearOutput = 0;
	ReadByteFromBuffer(buffer, &clearOutput);

	if(showConsole > 0) {
		if (L && !gameConsoleShowing) {
			executeLuaFunc_orig(L, "Console:Show", 0, 0);
			gameConsoleShowing = true;
		}
	}

	if (ConsoleRelated && !buffer->failFlag) {
		std::string clear = "\n\n\n\n\n\n\n\n\n\n";
		onPrintConsole_orig(ConsoleRelated, (void*)((clearOutput? clear + str : str).c_str()), 0, 0);
	}
}

static void handleMessageBoxPacket(Buffer* buffer) {
	std::string title;
	ReadStringFromBuffer(*buffer, title);

	std::string message;
	ReadStringFromBuffer(*buffer, message);

	if (buffer->failFlag) return;

	MessageBox(NULL, message.c_str(), title.c_str(), MB_OK);
}

static void handleHadesInit(Buffer* buffer) {
	std::string authTicket;
	ReadStringFromBuffer(*buffer, authTicket);

	std::string gatewayServer;
	ReadStringFromBuffer(*buffer, gatewayServer);

	if (buffer->failFlag) return;

	printf("\n\n\n --------- hades init\n\n");
	std::string executablePath = ".\\H1Z1_BE.exe";
	std::string commandLine = executablePath + " -init " + authTicket + " " + gatewayServer;

	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInfo;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	int consoleFlag = CREATE_NO_WINDOW;
	#ifdef CONSOLE_ENABLED
		consoleFlag = 0;
	#endif

	if (!CreateProcessA(
		executablePath.c_str(),             // Path to the executable
		const_cast<LPSTR>(commandLine.c_str()),  // Command line arguments
		NULL,                               // Process handle not inheritable
		NULL,                               // Thread handle not inheritable
		FALSE,                              // Set handle inheritance to FALSE
		consoleFlag,                        // Create a new console window
		NULL,                               // Use parent's environment block
		NULL,                               // Use parent's starting directory
		&startupInfo,                       // Pointer to STARTUPINFO structure
		&processInfo                        // Pointer to PROCESS_INFORMATION structure
	))
	{
		std::cerr << "Failed to start H1Z1_BE.exe" << std::endl;
		return;
	}
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
}


static void handleHadesQuery(Buffer* buffer) {
	std::string authTicket;
	ReadStringFromBuffer(*buffer, authTicket);

	std::string gatewayServer;
	ReadStringFromBuffer(*buffer, gatewayServer);

	if (buffer->failFlag) return;

	if (pendingAssetCheck) {
		printf("[AssetValidator] Ignoring query due to pending check.\n");
		return;
	}

	if (assetHashes.length() > 1) {
		printf("[AssetValidator] Ignoring query due to cached assets.\n");
		return;
	}

	printf("\n\n\n --------- hades query\n\n");
	std::string executablePath = ".\\H1Z1_BE.exe";
	std::string commandLine = executablePath + " -assetcheck " + authTicket + " " + gatewayServer;

	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInfo;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	int consoleFlag = CREATE_NO_WINDOW;
	#ifdef CONSOLE_ENABLED
		consoleFlag = 0;
	#endif

	if (!CreateProcessA(
		executablePath.c_str(),             // Path to the executable
		const_cast<LPSTR>(commandLine.c_str()),  // Command line arguments
		NULL,                               // Process handle not inheritable
		NULL,                               // Thread handle not inheritable
		FALSE,                              // Set handle inheritance to FALSE
		consoleFlag,                        // Create a new console window CREATE_NO_WINDOW
		NULL,                               // Use parent's environment block
		NULL,                               // Use parent's starting directory
		&startupInfo,                       // Pointer to STARTUPINFO structure
		&processInfo                        // Pointer to PROCESS_INFORMATION structure
	))
	{
		std::cerr << "Failed to start H1Z1_BE.exe" << std::endl;
		return;
	}

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	pendingAssetCheck = true;
}

static void handleRequestAssetHashesPacket(Buffer* buffer);
static void handleH1emuCustomPackets(DataLoadByPacket* data, int bufferLen) {
	Buffer buffer = {
		(char*)data,
		bufferLen,
		(char*)data + bufferLen,
		false
	};

	ReadByteFromBuffer(&buffer); // 0x99 opcode
	char opcode = 0;
	ReadByteFromBuffer(&buffer, &opcode);

	if (buffer.failFlag) {
		printf("[ERROR] H1emu packet parse fail.\n");
		return;
	}
	switch (opcode) {
		case cPacketIdPrintToConsole:
			handlePrintConsolePacket(&buffer);
			break;
		case cPacketIdMessageBox:
			handleMessageBoxPacket(&buffer);
			break;
		case cPacketIdRequestAssetHashes:
			handleRequestAssetHashesPacket(&buffer);
			break;
		default:
			printf("[ERROR] Unhandled h1emu custom packet %02x\n", opcode);
			break;
	}
}

static void(*handleIncomingZonePackets_orig)(BaseClient* thisPtr, IncomingPacket* packet, DataLoadByPacket* buffer, int bufferLen, float time, int a6);
static void handleIncomingZonePackets(BaseClient* thisPtr, IncomingPacket* packet, DataLoadByPacket* buffer, int bufferLen, float time, int a6) {
	#ifdef CONSOLE_ENABLED
	// for debug print only
	switch (packet->packetType) {
		case 0x3C: // KeepAlive
		case 0x79: // PlayerUpdatePosition
			break;
		default:
			printf("packetType: %d - Return Address: %p\n", packet->packetType, _ReturnAddress());
			printf("\n\n\n\n\n");
	}
	#endif

	// custom packet handler
	switch (packet->packetType) {
		case 0x99: // H1emu custom
			handleH1emuCustomPackets(buffer, bufferLen);
			break;
	}
	handleIncomingZonePackets_orig(thisPtr, packet, buffer, bufferLen, time, a6);
}

static void handleH1emuConsoleCommand() {
	if (!L) return;

	executeLuaFunc_orig(L, gameConsoleShowing ? "Console:Hide" : "Console:Show", 0, 0);
	gameConsoleShowing = !gameConsoleShowing;
}


static void (*handleCommand_orig)(const char* commandPtr);
static void handleCommand(const char* commandPtr) {
	std::string command = commandPtr;
	if (command == "console") {
		handleH1emuConsoleCommand();
		return;
	}

	// flag used for sending custom packets from the client
	if (command == "!!h1custom!!") {
		return;
	}

	handleCommand_orig(commandPtr);
}


static void handleH1emuLoginPackets(Buffer* buffer, int bufferLen) {
	char opcode = 0;
	ReadByteFromBuffer(buffer, &opcode);

	if (buffer->failFlag) {
		printf("[ERROR] H1emu login packet parse fail.\n");
		return;
	}
	switch (opcode) {
	case cLoginPacketIdPrintToConsole:
		handlePrintConsolePacket(buffer);
		break;
	case cLoginPacketIdMessageBox:
		handleMessageBoxPacket(buffer);
		break;
	case cLoginPacketIdInitHades:
		//handleHadesInit(buffer);
		break;
	case cLoginPacketIdHadesQuery:
		handleHadesQuery(buffer);
		break;
	default:
		printf("[ERROR] Unhandled h1emu custom login packet %02x\n", opcode);
		break;
	}
}

static void(*handleIncomingLoginPackets_orig)(void* thisPtr, DataLoadByPacket* data, int bufferLen, void* callback);
static void handleIncomingLoginPackets(void* thisPtr, DataLoadByPacket* data, int bufferLen, void* callback) {
	Buffer buffer = {
		(char*)data,
		bufferLen,
		(char*)data + bufferLen,
		false
	};

	char opcode = 0;
	ReadByteFromBuffer(&buffer, &opcode);

	#ifdef CONSOLE_ENABLED
		printf("LOGIN packetType: %d - Return Address: %p\n", opcode, _ReturnAddress());
		printf("\n\n\n\n\n");
	#endif

	// custom packet handler
	// since loginserver opcodes serverside are only a byte, use 0x20 + for h1emu packets
	if (opcode >= 0x20) {
		handleH1emuLoginPackets(&buffer, bufferLen);
		return;
	}
	handleIncomingLoginPackets_orig(thisPtr, data, bufferLen, callback);
}

static void executeLuaFuncStub(void* LuaVM, char* funcName, void* a3, void* a4) {
	// set global LuaVM ptr
	if (!L) L = LuaVM;

	void* retAddr = _ReturnAddress();
	std::string func = funcName;
	switch ((unsigned long long)retAddr) {
		case 0x1403FD30D: // OnUpdate
		case 0x140BFEEA8: // GameEvents:GetInventoryShown
		case 0x140BFE1AD: // GameEvents:GetInventoryShown
		case 0x140BFEE2F: // GameEvents:GetInventoryShown
		case 0x140CFBC62: // HudHandler:GetBattleRoyaleData
		case 0x14040DF7D: // TooltipMethods:HideFromCode
			break;
		default:
			if (func != "BaseClient_Reticle_OnDataChanged") {
				printf("executeLuaFuncStub: %s - Return Address: %p\n", funcName, retAddr);
				if (func == "Console:StartDebugConsole") { // forces console to open when key pressed
					executeLuaFunc_orig(LuaVM, "Console:Show", 0, 0);
					gameConsoleShowing = !gameConsoleShowing;
					return;
				}
				// using Console:OnSwfFocus to close console breaks it, so it's disabled for now
				else if (func == "GameEvents:OnEscape" /* || func == "Console:OnSwfFocus")*/ && gameConsoleShowing) { // closes console on ~ or escape
					executeLuaFunc_orig(LuaVM, "Console:Hide", 0, 0);
					executeLuaFunc_orig(LuaVM, funcName, a3, a4); // executes normal GameEvents:OnEscape / "Console:OnSwfFocus"
					executeLuaFunc_orig(LuaVM, "Console:Update", 0, 0); // may not be needed
				
					gameConsoleShowing = !gameConsoleShowing;
					return;
				}
			}
			break;
	}
	executeLuaFunc_orig(LuaVM, funcName, a3, a4);
}

void OnIntentionalCrash() {
	printf("Should have crashed, but will continue executing, return address is: %p\n", _ReturnAddress());
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

// ============================================================================================================
// ===============   DIAG_CRASHLOG — in-process crash-trace logger (VEH + log-then-original hooks)   ===========
// ============================================================================================================
// Frida can't capture the zone-in crash (attach -> "Process Terminated", no exception, no hook fires:
// BattlEye/anti-tamper kills the injected process, or the fatal path is an uncatchable fastfail-style
// terminate). The dinput8 patch is already loaded and tolerated, so we capture the crash from IN-PROCESS:
// a first-chance VECTORED handler logs any AV (incl. the 0xBADBEEF null-write) and lets it crash; the two
// crash-site hooks log the CALLER chain + args BEFORE calling the original (which then terminates), so we
// still learn which handler tripped it even for a fastfail the VEH can't see. All addresses are logged
// module-relative (H1Z1.exe+0xOFF; IDA VA = 0x140000000 + OFF). Everything here is gated by DIAG_CRASHLOG.
#ifdef DIAG_CRASHLOG
static const wchar_t* kCrashLogPath = L"h1-crash-trace.log";   // relative -> client working dir (H1Z1.exe dir)
static uintptr_t g_mainBase = 0;                 // GetModuleHandleW(NULL) = H1Z1.exe base
static CRITICAL_SECTION g_crashCs;
static bool g_crashCsReady = false;
static __declspec(thread) int g_inCrashLog = 0;  // per-thread reentrancy guard (logging must not recurse in VEH)

// Append-open + WRITE + FlushFileBuffers + close PER call so the trace survives a hard terminate. Also mirror
// to the debugger via OutputDebugStringA.
static void CrashWriteRaw(const char* text)
{
	HANDLE h = CreateFileW(kCrashLogPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		DWORD wrote = 0;
		WriteFile(h, text, (DWORD)strlen(text), &wrote, NULL);
		FlushFileBuffers(h);   // force to disk before we return (survive the terminate)
		CloseHandle(h);
	}
	OutputDebugStringA(text);
}

// Format an address module-relative: "<module-basename>+0xOFF" (H1Z1.exe+0xOFF for main-module frames).
static void CrashFmtAddr(char* out, size_t outsz, void* addr)
{
	HMODULE m = NULL;
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)addr, &m) && m)
	{
		char path[MAX_PATH] = { 0 };
		GetModuleFileNameA(m, path, MAX_PATH);
		const char* bn = path;
		for (const char* p = path; *p; ++p) if (*p == '\\' || *p == '/') bn = p + 1;
		_snprintf_s(out, outsz, _TRUNCATE, "%s+0x%llX", bn, (unsigned long long)((uintptr_t)addr - (uintptr_t)m));
	}
	else
	{
		_snprintf_s(out, outsz, _TRUNCATE, "0x%llX", (unsigned long long)(uintptr_t)addr);
	}
}

// Timestamped single line.
static void CrashLogf(const char* fmt, ...)
{
	char body[3072];
	va_list ap; va_start(ap, fmt);
	_vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, ap);
	va_end(ap);
	SYSTEMTIME st; GetLocalTime(&st);
	char line[3200];
	_snprintf_s(line, sizeof(line), _TRUNCATE, "[%02d:%02d:%02d.%03d] %s\n",
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, body);
	bool locked = g_crashCsReady;
	if (locked) EnterCriticalSection(&g_crashCs);
	CrashWriteRaw(line);
	if (locked) LeaveCriticalSection(&g_crashCs);
}

// Capture + log a module-relative backtrace as ONE flushed block. framesToSkip drops the logger/dispatch frames.
static void CrashLogBacktrace(ULONG framesToSkip)
{
	void* frames[62];
	USHORT n = RtlCaptureStackBackTrace(framesToSkip, 62, frames, NULL);
	char buf[62 * 96 + 64];
	int off = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "    backtrace (%u frames):\n", n);
	for (USHORT i = 0; i < n && off > 0 && off < (int)sizeof(buf) - 128; ++i)
	{
		char a[160]; CrashFmtAddr(a, sizeof(a), frames[i]);
		int w = _snprintf_s(buf + off, sizeof(buf) - off, _TRUNCATE, "      [%02u] %s\n", i, a);
		if (w <= 0) break;
		off += w;
	}
	bool locked = g_crashCsReady;
	if (locked) EnterCriticalSection(&g_crashCs);
	CrashWriteRaw(buf);
	if (locked) LeaveCriticalSection(&g_crashCs);
}

// First-chance VECTORED exception handler: log-only, then EXCEPTION_CONTINUE_SEARCH (let it crash naturally).
static LONG CALLBACK CrashVeh(EXCEPTION_POINTERS* ep)
{
	if (g_inCrashLog) return EXCEPTION_CONTINUE_SEARCH;   // don't recurse if logging itself faults
	EXCEPTION_RECORD* er = ep ? ep->ExceptionRecord : NULL;
	if (!er) return EXCEPTION_CONTINUE_SEARCH;
	DWORD code = er->ExceptionCode;
	// Skip pure-noise debug codes (thread-name / OutputDebugString) so the real fault isn't buried.
	if (code == 0x40010006 /*DBG_PRINTEXCEPTION_C*/ || code == 0x4001000A /*DBG_PRINTEXCEPTION_WIDE_C*/ ||
		code == 0x406D1388 /*MS_VC thread name*/)
		return EXCEPTION_CONTINUE_SEARCH;

	g_inCrashLog = 1;
	__try
	{
		char faultAddr[160]; CrashFmtAddr(faultAddr, sizeof(faultAddr), er->ExceptionAddress);
		char detail[192]; detail[0] = 0;
		if (code == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
		{
			ULONG_PTR op = er->ExceptionInformation[0];
			const char* what = op == 0 ? "READ" : op == 1 ? "WRITE" : op == 8 ? "EXEC" : "?";
			_snprintf_s(detail, sizeof(detail), _TRUNCATE, " | AV %s data=0x%llX",
				what, (unsigned long long)er->ExceptionInformation[1]);
		}
		// Note C++ EH (0xE06D7363) is frequent+benign; still logged (compact) so the sequence is visible.
		bool benignCpp = (code == 0xE06D7363);
		CrashLogf("*** EXCEPTION code=0x%08X flags=0x%X at %s%s%s",
			code, er->ExceptionFlags, faultAddr, detail, benignCpp ? " (C++ EH)" : "");
		if (!benignCpp)
			CrashLogBacktrace(2);   // skip CrashVeh + ntdll dispatch frames
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { /* logging faulted; swallow */ }
	g_inCrashLog = 0;
	return EXCEPTION_CONTINUE_SEARCH;   // log-only — never handle; let the process crash as it would.
}

// Crash-site hook @0x14032DC60 (execUnrecoverableError; the 0xBADBEEF path). DIAG = log caller+args THEN
// call the original (let it proceed to terminate). x64 __fastcall; forward rcx/rdx/r8/r9.
static void(__fastcall* g_execUnrecoverableError_orig)(void*, void*, void*, void*) = nullptr;
static void __fastcall ExecUnrecoverableError_diag(void* a1, void* a2, void* a3, void* a4)
{
	char ret[160]; CrashFmtAddr(ret, sizeof(ret), _ReturnAddress());
	CrashLogf("### CRASH-SITE execUnrecoverableError (H1Z1.exe+0x32DC60) caller=%s args=(%p,%p,%p,%p)",
		ret, a1, a2, a3, a4);
	CrashLogBacktrace(1);
	g_execUnrecoverableError_orig(a1, a2, a3, a4);   // let it crash (do NOT block in the diag build)
}

// Crash-site hook @0x140C06FD0 (exception inside this fn). DIAG = log caller+args THEN call original.
static void(__fastcall* g_crash140C06FD0_orig)(void*, void*, void*, void*) = nullptr;
static void __fastcall Crash140C06FD0_diag(void* a1, void* a2, void* a3, void* a4)
{
	char ret[160]; CrashFmtAddr(ret, sizeof(ret), _ReturnAddress());
	CrashLogf("### CRASH-SITE sub_140C06FD0 (H1Z1.exe+0xC06FD0) caller=%s args=(%p,%p,%p,%p)",
		ret, a1, a2, a3, a4);
	CrashLogBacktrace(1);
	g_crash140C06FD0_orig(a1, a2, a3, a4);           // let it crash
}

// Install the VEH + logger. Called once from VCPatcher::Init() under DIAG_CRASHLOG.
static void CrashLog_Install()
{
	InitializeCriticalSection(&g_crashCs);
	g_crashCsReady = true;
	g_mainBase = (uintptr_t)GetModuleHandleW(NULL);
	AddVectoredExceptionHandler(1 /*first, first-chance*/, CrashVeh);
	CrashLogf("==================== DIAG_CRASHLOG session start ====================");
	CrashLogf("H1Z1.exe base=0x%llX  (module-relative frames: H1Z1.exe+0xOFF ; IDA VA = 0x140000000 + OFF)",
		(unsigned long long)g_mainBase);
	CrashLogf("VEH installed (first-chance, log-only); crash-site hooks 0x32DC60 / 0xC06FD0 = log-then-original.");
}
#endif // DIAG_CRASHLOG

//static void (*onPrintConsole_orig)(void* a1, void* a2, char a3, void* a4);
static void onPrintConsole(void* a1, void* a2, char a3, void* a4) {
	printf("********OnPrintConsole %p\n\n", _ReturnAddress());
	if (!ConsoleRelated) {
		ConsoleRelated = a1;
	}
	onPrintConsole_orig(a1, a2, a3, a4);
}

void CreateAssetValidatorPipe() {
	// Parent process code to set up a named pipe for communication
	HANDLE hPipe;
	DWORD bytesRead;

	// max buffer size for received hashes
	DWORD inBufferSize = 20000; // Initial buffer size
	DWORD outBufferSize = 20000; // Initial buffer size

	// Create the named pipe with initial buffer sizes
	hPipe = CreateNamedPipe(
		TEXT("\\\\.\\pipe\\AssetValidator"),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1,
		outBufferSize, // Set the output buffer size
		inBufferSize,  // Set the input buffer size
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL
	);

	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("Failed to create named pipe for AssetValidator\n");
		return;
	}

	printf("Waiting for the child process to connect to the named pipe AssetValidator...\n");
	ConnectNamedPipe(hPipe, NULL);

	// Dynamically determine the size of incoming data and adjust buffer sizes if needed
	if (ReadFile(hPipe, NULL, 0, &bytesRead, NULL)) {
		// bytesRead now contains the size of the incoming data
		inBufferSize = bytesRead;
		outBufferSize = bytesRead; // You can adjust the output buffer size as well

		// Close the existing named pipe
		CloseHandle(hPipe);

		// Recreate the named pipe with adjusted buffer sizes
		hPipe = CreateNamedPipe(
			TEXT("\\\\.\\pipe\\AssetValidator"),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			1,
			outBufferSize,
			inBufferSize,
			NMPWAIT_USE_DEFAULT_WAIT,
			NULL
		);
	}

	char* buf = new char[inBufferSize]; // Create a buffer with the updated size

	// Read data from the child process through the named pipe
	if (ReadFile(hPipe, buf, inBufferSize, &bytesRead, NULL)) {
		buf[bytesRead] = '\0';
		std::string hashes(buf);

		printf("[AssetValidator] Finished with file hashes\n");

		assetHashes = hashes;

		std::string header = "!!h1custom!! 01";
		header.append(hashes);
		handleCommand_orig(header.c_str());
	}
	else {
		printf("ReadFile failed for AssetValidator\n");
	}

	// Close the named pipe and release the dynamically allocated buffer
	CloseHandle(hPipe);
	delete[] buf;
	pendingAssetCheck = false;
}

static void handleRequestAssetHashesPacket(Buffer* buffer) {
	printf("RequestAssetHashes received from server\n");
	if (assetHashes.length() > 0) {
		std::string header = "!!h1custom!! 01";
		header.append(assetHashes);
		handleCommand_orig(header.c_str());
	}
}

// ############################################################################################################
// ###############   Dec-2016 EMOTE + NIGHT-VISION HOTKEY REPAIR (two surgical direct-send hooks)   ###########
// ############################################################################################################
//
// WHY THIS PATCH EXISTS
// ---------------------
// On the Dec-2016 H1Z1 client the EMOTE and NIGHT-VISION *hotkey* dispatch is BROKEN. This is officially
// acknowledged in the Feb-14-2017 patch notes:
//     - "Fixed Emotes (stopped working per account)"
//     - "Temporarily removed night vision goggles ... previous incarnation did not function as expected"
// i.e. the trigger that turns a hotkey press into the correct network send was bugged on this build and was
// fixed / removed in the following patch. The *working* send functions still exist in this binary and the
// server implements the intended design, so the fix is simply to drive those existing sends directly when the
// hotkey fires. THIS PATCH REPAIRS ONLY THE BROKEN HOTKEY TRIGGER — it has NO effect on any other client
// functionality (weapons, vehicles, other abilities, other action sets, non-hotkey emotes, etc.).
//
// Everything below is __fastcall (x64) and ASLR-rebased at runtime off H1Z1.exe (see REBASE()).
// MAIN-THREAD ONLY: both hooks trampoline functions that already run on the game main thread, so the calls
// into the proxied-char manager / emote tables / send queue are on the correct (non-thread-safe) thread.
// Every send is guarded by an in-world check; if not in world the hooks no-op and fall through safely.

// ---- debug logging gate (production = silent) ----
// EMOTENV_LOG 0 => production: the emote/NV hooks emit NOTHING at runtime.
// EMOTENV_LOG 1 => diagnostic: ENV_LOG(...) prints like printf AND the emote hook writes a per-press
//                  TABLE2 dump to emote_diag.log (see EmoteNv_DiagPress). Pre-existing (non-emote/NV)
//                  logging is unaffected. Override to 1 for a diagnostic build without editing this default.
#ifndef EMOTENV_LOG
#define EMOTENV_LOG 0
#endif
#define ENV_LOG(...) do { if (EMOTENV_LOG) printf(__VA_ARGS__); } while (0)

// ---- runtime ASLR rebase (delta applied to every IDA address, base 0x140000000) ----
static uintptr_t g_emoteNvDelta = 0;
static inline uintptr_t REBASE(uintptr_t idaAddr) { return idaAddr + g_emoteNvDelta; }

// ---- globals (IDA addresses, rebased at use) ----
//   g_ClientPcData @0x142B19BA0 : *(void**) -> ClientPcData (NULL until in-world). characterId @ pc+0x18.
//   g_Gateway      @0x142B19B98 : ZoneConnection = *(void**)(*(void**)g_Gateway + 8)
#define IDA_G_CLIENTPCDATA 0x142B19BA0
#define IDA_G_GATEWAY      0x142B19B98

// ---- working game functions we drive directly (v2, live-verified) ----
// Emote: LocalCharacter_PlayAnimationAndRequest @0x140576F50 — plays locally AND sends Animation.Request 0xf801.
typedef void(__fastcall* LocalCharacter_PlayAnimationAndRequest_t)(void* a0, int* animData, char send);
// NV: AbilityStore_LookupByNameHash @0x140565740 — resolves the ability instance for a nameHash.
typedef void*(__fastcall* AbilityStore_LookupByNameHash_t)(void* store, uint32_t nameHash);

// ---- DYNAMIC emote resolution (v4; re doc emote-dynamic-resolution.md / 852be7c) --------------------
// No hardcoded table: resolve nameHash -> emote itemDefinitionId at RUNTIME by walking the client's RESIDENT
// emote-availability map, so new/modded emotes work with ZERO patch changes (the server owns the mapping).
//
// Resident structure: emoteObj = ClientPcData + 0xF500 (populated by EmoteAvailabilityMap_ReadFromPacket
// @0x140381090 from SendSelf.skinItems.emotes). The emote-availability HashList sub-object lives at
// emoteObj + 0xA8 = pc + 0xF5A8. Full doubly-linked node list: head = *(pc + 0xF5A8 + 0x10); walk via
// node.listNext @ +0x08. EmoteAvailabilityNode: nameHash @ +0x00 (server-tagged), itemDef @ +0x04 (value),
// listNext @ +0x08, slotId @ +0x18 (emoteAnimSlotId key). This walk IS the emote-membership test.
//
// *** CUSTOM h1emu SERVER DEPENDENCY ***: node+0x00 is the emote-availability entry's normally-UNUSED
// `unknownDword2` field, which VANILLA leaves 0 (the client never reads it). The h1emu server CUSTOM-tags it
// with flhash(clientActionName). So this dynamic nameHash->itemDef resolution ONLY works against an h1emu
// server that tags unknownDword2; on a vanilla/untagged server the field is 0, every lookup misses, and
// emotes no-op. That is EXPECTED until the paired server change lands (deploy this WITH the server tagging).
//
// HEAD-OFFSET NOTE (load-bearing; verify via ida-pro-mcp on the 9.4 DB): the dynamic-resolution doc writes
// the head as *(map+0x10) with map=ClientPcData+0xF500. Cross-checking emote-fkey-final-gate.md (buckets @
// pc+0xF5D0 = HashList-dest+0x28  =>  HashList-dest = pc+0xF5A8) AND the v2 live-confirmed walk both place the
// actual full-list head at *(pc+0xF5A8+0x10) — the two agree on buckets (0xF5D0) and differ only on the head
// base (0xF500 vs 0xF5A8); the live-confirmed + bucket-geometry value 0xF5A8 is used here. ida-pro-mcp is not
// available in this (patch) workspace; the diagnostic build dumps the full walk from this head so the capture
// run confirms it empirically (sane nodes: itemDef in ~1999..5376, slotId 1..12). If the diag shows 0/garbage
// nodes, flip EMOTE_HASHLIST_OFF to 0xF500.
#define EMOTE_HASHLIST_OFF 0xF5A8   // emote-availability HashList sub-object = ClientPcData(pc) + 0xF500 + 0xA8

// Walk the resident emote-availability map for a node whose nameHash == the fired nameHash. HIT -> itemDef;
// MISS (empty/untagged map, not in world, or not an emote) -> 0 -> caller falls through to the original.
// SEH-guarded: a bad/empty map is treated as a miss, never a crash.
static int32_t ResolveEmoteItemDefDynamic(void* pc, uint32_t nameHash)
{
	if (!pc || nameHash == 0) return 0;   // nameHash 0 = vanilla/untagged node; never a real fired emote
	__try
	{
		void* node = *(void**)((char*)pc + EMOTE_HASHLIST_OFF + 0x10);   // full-list head = *(pc+0xF5A8+0x10)
		for (int guard = 0; node && guard < 256; ++guard)               // guard: never loop on a corrupt list
		{
			if (*(uint32_t*)((char*)node + 0x00) == nameHash)            // server-tagged nameHash
				return *(int32_t*)((char*)node + 0x04);                  // itemDefinitionId
			node = *(void**)((char*)node + 0x08);                        // listNext
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
	return 0;
}

#if EMOTENV_LOG
// Diagnostic (EMOTENV_LOG=1 only): per non-NV press log the fired nameHash + hit/miss + resolved itemDef, and
// ONCE (first populated map) dump the full resident-map walk (node, nameHash, itemDef, slotId) so the head/node
// offsets AND the server's unknownDword2 nameHash tagging can be verified end-to-end. File-only (no console).
static void EmoteNv_DiagResolve(void* pc, uint32_t nameHash, int32_t itemDef)
{
	FILE* f = fopen("emote_diag.log", "a");
	if (!f) return;
	fprintf(f, "RESOLVE nameHash=0x%08X -> %s itemDef=%d\n", nameHash, itemDef ? "HIT" : "MISS", itemDef);
	static bool s_dumped = false;
	if (!s_dumped && pc)
	{
		__try
		{
			void* node = *(void**)((char*)pc + EMOTE_HASHLIST_OFF + 0x10);   // head = *(pc+0xF5A8+0x10)
			if (node)
			{
				fprintf(f, "  --- resident EmoteAvailabilityMap (head *(pc+0xF5A8+0x10)) ---\n");
				int n = 0;
				for (; node && n < 64; ++n)
				{
					fprintf(f, "    [%2d] node=%p nameHash=0x%08X itemDef=%d slotId=%u\n",
						n, node, *(uint32_t*)((char*)node + 0x00),
						*(int32_t*)((char*)node + 0x04), *(uint32_t*)((char*)node + 0x18));
					node = *(void**)((char*)node + 0x08);   // listNext
				}
				fprintf(f, "    (%d nodes; nameHash=0 => server has NOT tagged unknownDword2 yet)\n", n);
				s_dumped = true;   // dump only after we've seen a populated map
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { fprintf(f, "  (map walk excepted)\n"); }
	}
	fclose(f);
}
#endif

// =====================================================================================================
// COMBINED HOOK — EMOTE + NIGHT VISION (v3, keybind-aware)  @ Ability_ActivateByNameHash 0x140931E10
// =====================================================================================================
// Dec-2016: BOTH the emote and NV *hotkeys* are broken on this client build (fixed/removed in the Feb-14-2017
// patch: "Fixed Emotes (stopped working per account)" / "Temporarily removed night vision goggles ... did not
// function as expected"). On a key press the game resolves the bound InputProfile action to its nameHash and
// calls Ability_ActivateByNameHash(ctrl, nameHash) — but the stock ability route never produces the correct
// network send for these two, so the emote never plays and NV never toggles. We intercept at that call and
// drive the working sends directly. Everything else (weapons, vehicles, all other abilities) calls the
// original untouched.
//
// EMOTE (repairs the broken hotkey -> Animation.Request 0xf801):
//   The fired emote's identity is its nameHash (hash of the InputProfile action name, e.g. "Laugh"), received
//   as the hook arg. v4 resolves nameHash -> emote itemDefinitionId DYNAMICALLY by walking the client's
//   RESIDENT emote-availability map (ResolveEmoteItemDefDynamic; see block above) — NO hardcoded table, so
//   new/modded emotes work with zero patch changes and the server owns the mapping. HIT ->
//   LocalCharacter_PlayAnimationAndRequest(0,&itemDef,1) @0x140576F50 (plays locally AND sends 0xf801 {itemDef}
//   via SendAnimationRequest @0x140576880 -> SendPacket @0x14063C180); server broadcasts Animation.Play 0xf802
//   (no grant gate). The walk IS the emote-membership test: MISS -> not an emote (NV/weapon/other) -> fall
//   through to the original (untouched). Keybind-aware by construction (the GAME did key->nameHash first).
//   *** Depends on the h1emu server tagging each emote's unknownDword2 = flhash(actionName); vanilla = 0 =>
//   every lookup misses (emotes no-op). Deploy WITH the paired server change. ***
//
// NV (repairs the broken hotkey -> Abilities.InitAbility 0xa101 {abilityId:1111272}):
//   NV instance member id is 0 -> Ability_ActivateCore BAIL-1a @0x140562e3f -> no send. Force-fix that ONE
//   field then let the game send its own correct packet (a hand-built 0xa101 crashed the serializer at +0x38):
//     1) resolve the NV instance via AbilityStore_LookupByNameHash @0x140565740 (store = pc+0xB618);
//     2) write member-list head (*(uint32_t*)node = 1111272) so member id > 0;
//     3) fall through to the ORIGINAL — with member>0, ActivateCore passes BAIL-1a and the game sends 0xa101
//        (NV def flags 0x49 = RUN_ON_SERVER); server toggles NV (== /nv). No crash. Unchanged from v2.
//
// SURGICAL: only known emote nameHashes and the NV nameHash are intercepted; all other nameHashes -> original.
static const int NV_NAME_HASH = 0x2be7f704;
static const uint32_t NV_ABILITY_ID = 1111272;

static void(__fastcall* Ability_ActivateByNameHash_orig)(long long localChar, int nameHash) = nullptr;
static void __fastcall Ability_ActivateByNameHash_hook(long long localChar, int nameHash)
{
	if (nameHash == NV_NAME_HASH)   // 0x2be7f704 — NV toggle (unchanged v2 behavior)
	{
		__try
		{
			void* pc = *(void**)REBASE(IDA_G_CLIENTPCDATA);   // in-world guard: NULL until in-world
			if (pc)
			{
				void* store = (char*)pc + 0xB618;             // &g_ClientPcData->gapB4F8[288] (ability store)
				void* INST = ((AbilityStore_LookupByNameHash_t)REBASE(0x140565740))(store, (uint32_t)NV_NAME_HASH);
				if (INST)
				{
					void* node = *(void**)((char*)INST + 0x18); // member-list head
					if (node)
					{
						*(uint32_t*)node = NV_ABILITY_ID;       // force member id (was 0 -> BAIL-1a)
						ENV_LOG("[EmoteNvPatch] NV hotkey: forced member id -> %u; letting game send 0xa101\n", NV_ABILITY_ID);
					}
				}
			}
			// null pc/INST/node: skip the write but STILL call the original (no crash, no send).
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ENV_LOG("[EmoteNvPatch] NV hook excepted, caught and returned.\n");
		}
		// DO NOT return: fall through so the game's own correct 0xa101 send fires.
	}
	else   // EMOTE (v4-dynamic): walk the resident emote-availability map for nameHash -> itemDef; non-emotes fall through.
	{
		void* pc = *(void**)REBASE(IDA_G_CLIENTPCDATA);              // ClientPcData (NULL until in-world)
		int32_t itemDef = ResolveEmoteItemDefDynamic(pc, (uint32_t)nameHash);   // resident-map walk = membership test
#if EMOTENV_LOG
		EmoteNv_DiagResolve(pc, (uint32_t)nameHash, itemDef);        // log fired nameHash + hit/miss + itemDef
#endif
		if (itemDef)   // itemDef != 0 implies pc != NULL (ResolveEmoteItemDefDynamic returns 0 when pc is null)
		{
			__try
			{
				int animData = itemDef;                             // send-path reads *(int*)animData = itemDefinitionId
				((LocalCharacter_PlayAnimationAndRequest_t)REBASE(0x140576F50))(0, &animData, 1); // plays + sends 0xf801
				ENV_LOG("[EmoteNvPatch] Emote nameHash=0x%08X -> PlayAnimationAndRequest itemDef=%d (0xf801)\n",
					(uint32_t)nameHash, itemDef);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ENV_LOG("[EmoteNvPatch] emote play excepted, caught and returned.\n");
			}
			return;                                                   // handled the emote; skip the broken original route
		}
		// MISS -> not a (tagged) emote (weapons/other abilities) -> fall through to the original, unaffected.
	}
	Ability_ActivateByNameHash_orig(localChar, nameHash); // NV (now member>0) + every non-emote ability unaffected
}

bool VCPatcher::Init()
{
	// #########################################################     Game patches     ########################################################

#ifdef DIAG_CRASHLOG
	// CRASH DIAGNOSTIC BUILD: install the VEH + logger, and convert the two crash blockers to
	// LOG-caller-chain-then-call-ORIGINAL (we WANT the crash — logged first). MinHook gives a trampoline so we
	// can call the original (hook::jump can't). The non-crash feature hooks stay active below so zone-in
	// reaches the crash point normally.
	CrashLog_Install();
	MH_CreateHook((char*)0x14032DC60, ExecUnrecoverableError_diag, (void**)&g_execUnrecoverableError_orig); // 0xBADBEEF site
	MH_CreateHook((char*)0x140C06FD0, Crash140C06FD0_diag,         (void**)&g_crash140C06FD0_orig);         // exception-inside site
#else
	// blocks 0xBADBEEF
	hook::jump(0x14032DC60, OnIntentionalCrash); //Should have crashed, but continue executing... (sendself, lightweightToFullPc triggers this)

	hook::jump(0x140C06FD0, OnIntentionalCrash1);// exception inside 140C06FD0 somewhere
#endif

	// ###################################################     End of game patches     ############################################################

	// ###################################################     Game hooks     ############################################################

	// ####################     Release hooks     ####################
	// ITEMDEFINITION: static 1-instruction cursor fix in ClientItemDefinitionManager::HandlePacket.
	// At 0x140903CA6 `mov [rbx+10h], rax` (48 89 43 10) rewinds the read cursor to BEFORE the u32 ID; NOP it
	// (90 90 90 90) so the cursor stays at pBuffer+4 (after the ID, set at 0x140903C8B) and the native reader
	// parses the u16 compression header + LZ4-decompresses correctly. The ID is still captured (edi
	// @0x140903C88, before the NOP). RE-confirmed (h1emu-re 9aa6ee1).
	hook::nopVP(0x140903CA6, 4);

	// LUA:
	MH_CreateHook((char*)0x140488CC0, executeLuaFuncStub, (void**)&executeLuaFunc_orig);

	// EMOTE + NIGHT-VISION HOTKEY REPAIR (Dec-2016 broken-trigger fix; see block above for full rationale):
	// resolve the ASLR delta once, then install the single combined trampoline on Ability_ActivateByNameHash.
	// The game resolves key -> bound InputProfile action -> nameHash before this call, so intercepting here is
	// keybind-aware: emote nameHashes -> direct 0xf801 play+send; NV nameHash -> force-member+original; all
	// other abilities -> original.
	g_emoteNvDelta = (uintptr_t)GetModuleHandleW(L"H1Z1.exe") - 0x140000000;
	MH_CreateHook((char*)REBASE(0x140931E10), Ability_ActivateByNameHash_hook, (void**)&Ability_ActivateByNameHash_orig); // emote 0xf801 + NV 0xa101{1111272}

	// CUSTOM PACKETS:

	MH_CreateHook((char*)0x1403FE210, handleIncomingZonePackets, (void**)&handleIncomingZonePackets_orig);

	MH_CreateHook((char*)0x14163EFA0, handleIncomingLoginPackets, (void**)&handleIncomingLoginPackets_orig);
	
	MH_CreateHook((char*)0x14099DC10, onPrintConsole, (void**)&onPrintConsole_orig);

	// CUSTOM COMMANDS:
	
	MH_CreateHook((char*)0x14133F230, handleCommand, (void**)&handleCommand_orig);

	// ####################     Debug hooks (CONSOLE_ENABLED only)     ####################
	#ifdef CONSOLE_ENABLED
	MH_CreateHook((char*)0x140337AE0, File__Open, (void**)&File__Open_orig);
	MH_CreateHook((char*)0x1402ED6F0, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); // hook every logging function
	MH_CreateHook((char*)0x14032FA90, writeToLog, (void**)&writeToLog_orig);                       // hook every file-logging function
	#endif
	
	// ###################################################     End of game hooks     ############################################################

	MH_EnableHook(MH_ALL_HOOKS);

	CreateAssetValidatorPipe();

	return true;
}

void hexDump(const char* desc, const void* addr, const int len) {
	#ifndef CONSOLE_ENABLED
	return;
	#endif
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