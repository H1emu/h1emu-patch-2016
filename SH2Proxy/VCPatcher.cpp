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

static intptr_t(*g_origWaitForWorldReady)(char* a1);
intptr_t WaitForWorldReady(char* a1) {
	*(char*)(a1 + 0x31500 + 0x1F) = true; //BaseClient->gap31500[0x1F]
	intptr_t returnVal = 0;
	__try
	{
		returnVal = g_origWaitForWorldReady(a1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("WaitForWorldReady excepted, caught and returned.\n");
	}
	return returnVal;
}

static intptr_t(*g_origWaitForWorldReadyProcess)(char* a1);
intptr_t WaitForWorldReadyProcess(char* a1) {
	intptr_t returnVal = 0;
	__try
	{
		returnVal = g_origWaitForWorldReadyProcess(a1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("WaitForWorldReadyProcess excepted, caught and returned.\n");
	}
	return 1;
}

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

static void(*containerEventBaseRead_orig)(void* a1, void* a2, void* a3);
static void containerEventBaseRead(void* a1, void* a2, void* a3) {
	printf("********containerEventBaseRead\n\n");
	containerEventBaseRead_orig(a1, a2, a3);
}
static void(*containerErrorRead_orig)(void* a1, void* a2, void* a3);
static void containerErrorRead(void* a1, void* a2, void* a3) {
	printf("********containerErrorRead\n\n");
	containerErrorRead_orig(a1, a2, a3);
}
static void(*containerAddContainerRead_orig)(void* a1, void* a2, void* a3);
static void containerAddContainerRead(void* a1, void* a2, void* a3) {
	printf("********containerAddContainerRead\n\n");
	containerAddContainerRead_orig(a1, a2, a3);
}

// equipment

static void(*setCharacterEquipmentSlot_orig)(void* a1, void* a2, void* a3);
static void setCharacterEquipmentSlot(void* a1, void* a2, void* a3) {
	printf("********setCharacterEquipmentSlot\n\n");
	setCharacterEquipmentSlot_orig(a1, a2, a3);
}

static void(*equipmentEventBase_orig)(void* a1, void* a2, void* a3);
static void equipmentEventBase(void* a1, void* a2, void* a3) {
	printf("********equipmentEventBase\n\n");
	equipmentEventBase_orig(a1, a2, a3);
}

// end of equipment

// loadout

static void(*loadoutBaseRead_orig)(void* a1, void* a2, void* a3);
static void loadoutBaseRead(void* a1, void* a2, void* a3) {
	printf("********loadoutBaseRead\n\n");
	loadoutBaseRead_orig(a1, a2, a3);
}

static void(*loadoutSelectLoadoutRead_orig)(void* a1, void* a2, void* a3);
static void loadoutSelectLoadoutRead(void* a1, void* a2, void* a3) {
	printf("********loadoutSelectLoadoutRead\n\n");
	loadoutSelectLoadoutRead_orig(a1, a2, a3);
}

static void(*loadoutSetCurrentLoadoutRead_orig)(void* a1, void* a2, void* a3);
static void loadoutSetCurrentLoadoutRead(void* a1, void* a2, void* a3) {
	printf("********loadoutSetCurrentLoadoutRead\n\n");
	loadoutSetCurrentLoadoutRead_orig(a1, a2, a3);
}

static void(*loadoutSelectSlotRead_orig)(void* a1, void* a2, void* a3);
static void loadoutSelectSlotRead(void* a1, void* a2, void* a3) {
	printf("********loadoutSelectSlotRead\n\n");
	loadoutSelectSlotRead_orig(a1, a2, a3);
}

// end of loadout

static char(*networkProximityUpdatesComplete_orig)(void* a1, void* a2, void* a3, void* a4);
static char networkProximityUpdatesComplete(void* a1, void* a2, void* a3, void* a4) {
	char ret = networkProximityUpdatesComplete_orig(a1, a2, a3, a4);
	printf("********networkProximityUpdatesComplete\n\n");
	printf("ret: %d\n", ret);
	return 1;
}

static void (*ItemAddBytesWithLengthRead_orig)(void* a1, void* a2);
static void ItemAddBytesWithLengthRead(void* a1, void* a2) {
	printf("********ItemAddBytesWithLengthRead\n\n");
	ItemAddBytesWithLengthRead_orig(a1, a2);
}

static void (*HandleItemAddData_orig)(void* a1, void* a2, void* a3);
static void HandleItemAddData(void* a1, void* a2, void* a3) {
	printf("********HandleItemAddData\n\n");
	HandleItemAddData_orig(a1, a2, a3);
}

static void*(*ClientPlayerItemManager__CreateItem_orig)(void* a1, void* a2);
static void* ClientPlayerItemManager__CreateItem(void* a1, void* a2) {
	void* ret = ClientPlayerItemManager__CreateItem_orig(a1, a2);
	printf("********ClientPlayerItemManager__CreateItem\n\n");
	return ret;
}

static void (*ReadItemDataFromBuffer_orig)(void* a1, void* a2);
static void ReadItemDataFromBuffer(void* a1, void* a2) {
	printf("********ReadItemDataFromBuffer\n\n");
	ReadItemDataFromBuffer_orig(a1, a2);
}

static void (*ConstructionPlacementFinalizePacket_orig)(constructionRelated__* a1);
static void ConstructionPlacementFinalizePacket(constructionRelated__ *a1) {
	printf("********ConstructionPlacementFinalizePacket\n\n");

	*(bool*)(a1 + 0xCC) = 1;
	*(bool*)(a1 + 0x169) = 0;
	ConstructionPlacementFinalizePacket_orig(a1);
}

static void (*BeginCharacterAccessRead_orig)(void* a1, void* a2);
static void BeginCharacterAccessRead(void* a1, void* a2) {
	printf("********BeginCharacterAccessRead\n\n");
	BeginCharacterAccessRead_orig(a1, a2);
}

static void (*ItemsReadFunc_orig)(void* a1, void* a2);
static void ItemsReadFunc(void* a1, void* a2) {
	printf("********ItemsReadFunc\n\n");
	ItemsReadFunc_orig(a1, a2);
}

static void (*sub_140BAA8C0_orig)(void* a1, void* a2);
static void sub_140BAA8C0(void* a1, void* a2) {
	printf("********sub_140BAA8C0\n\n");
	sub_140BAA8C0_orig(a1, a2);
}

static void (*sub_140447B70_orig)(void* a1, void* a2);
static void sub_140447B70(void* a1, void* a2) {
	printf("********sub_140447B70\n\n");
	sub_140447B70_orig(a1, a2);
}

static void (*sub_1405FC580_orig)(void* a1, void* a2, void* a3);
static void sub_1405FC580(void* a1, void* a2, void* a3) {
	printf("********sub_1405FC580\n\n");
	sub_1405FC580_orig(a1, a2, a3);
}

static ContainerDefinition *(*GetContainerDefinition_orig)(void* a1, unsigned int a2);
static ContainerDefinition *GetContainerDefinition(void* a1, unsigned int a2) {
	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n********ContainerDefinitionManager::GetContainerDefinition return address: %p\n\n", _ReturnAddress());
	printf("containerDefinitionId: %i\n", a2);
	/*
	char buffer[512];
	MessageBox(
		NULL,
		buffer,
		"ContainerDefinitionManager::GetContainerDefinition",
		MB_ICONWARNING | MB_DEFBUTTON2
	);
	*/
	ContainerDefinition* ret = GetContainerDefinition_orig(a1, a2);
	printf("MAXIMUM_SLOTS %i\n", ret->MAXIMUM_SLOTS);
	printf("MAX_BULK %i\n", ret->MAX_BULK);
	return ret;
}

static void* (*GetItemErrorMessage_orig)(unsigned int a1);
static void* GetItemErrorMessage(unsigned int a1) {
	void* ret = GetItemErrorMessage_orig(a1);
	printf("********GetItemErrorMessage return address: %p\n\n", _ReturnAddress());
	return ret;
}


static __int64 (*sub_1405FE160_orig)(void* a1, void* a2, void* a3, void* a4, double a5, void* a6, int a7, unsigned int a8);
static __int64 sub_1405FE160(void* a1, void* a2, void* a3, void* a4, double a5, void* a6, int a7, unsigned int a8) {
	__int64 ret = sub_1405FE160_orig(a1, a2, a3, a4, a5, a6, a7, a8);
	printf("********sub_1405FE160 return address: %p ret: %d\n\n", _ReturnAddress(), ret);
	return ret;
}



static void (*GetItemErrorMessageReturn_orig)(double a1, unsigned int a2);
static void GetItemErrorMessageReturn(double a1, unsigned int a2) {
	printf("********GetItemErrorMessageReturn return address: %p\n\n", _ReturnAddress());
	GetItemErrorMessageReturn_orig(a1, a2);
}

static void (*GetItemErrorMessageReturnReturn_orig)(void* a1, void* a2, void* a3, void* a4, double a5, void* a6, void* a7);
static void GetItemErrorMessageReturnReturn(void* a1, void* a2, void* a3, void* a4, double a5, void* a6, void* a7) {
	printf("********GetItemErrorMessageReturnReturn return address: %p\n\n", _ReturnAddress());
	GetItemErrorMessageReturnReturn_orig(a1, a2, a3, a4, a5, a6, a7);
}

static void (*sub_140B27400_orig)(void* a1, void* a2);
static void sub_140B27400(void* a1, void* a2) {
	printf("********sub_140B27400 return address: %p\n\n", _ReturnAddress());
	sub_140B27400_orig(a1, a2);
}

static bool (*LoadoutIdValidate_orig)(ClientLoadoutManager* a1);
static bool LoadoutIdValidate(ClientLoadoutManager* a1) {
	bool ret = LoadoutIdValidate_orig(a1);
	printf("********LoadoutIdValidate return address: %p, ret: %d\n\n", _ReturnAddress(), ret);
	printf("activeLoadoutSlots %d\n", a1->activeLoadoutSlots);
	printf("field_18 %d\n", a1->field_18);
	printf("loadoutId %d\n", a1->loadoutId);
	return true; // force loadoutId validation
}


static bool (*GetIsContainer_orig)(ClientItemDefinition* a1);
static bool GetIsContainer(ClientItemDefinition* a1) {
	bool ret = GetIsContainer_orig(a1);
	printf("********GetIsContainer return address: %p, ret: %d\n\n", _ReturnAddress(), ret);
	printf("ITEM_TYPE %d\n", a1->baseitemdefinition0.ITEM_TYPE);
	printf("ID %d\n", a1->baseitemdefinition0.dword8);
	return ret; 
}

//static void (*onPrintConsole_orig)(void* a1, void* a2, char a3, void* a4);
static void onPrintConsole(void* a1, void* a2, char a3, void* a4) {
	printf("********OnPrintConsole %p\n\n", _ReturnAddress());
	if (!ConsoleRelated) {
		ConsoleRelated = a1;
	}
	onPrintConsole_orig(a1, a2, a3, a4);
}

static void(*ItemDefinitionReadFromBuffer_orig)(ClientItemDefinition* a1, DataLoadByPacket* buffer);
static void ItemDefinitionReadFromBuffer(ClientItemDefinition* a1, DataLoadByPacket* buffer) {
	if (buffer->pBuffer + 4 <= buffer->pBufferEnd)
	{
		buffer->pBuffer = buffer->pBuffer + 4;                   // ID
	}
	else
	{
		buffer->failureFlag = 1;
		buffer->pBuffer = buffer->pBufferEnd;
	}
	ItemDefinitionReadFromBuffer_orig(a1, buffer);
}

static void(*sendGroupJoinPacket_orig)(void* a1, char joinState);
static void sendGroupJoinPacket(void* a1, char joinState) {
	const std::uintptr_t base = 0x1405F9190;

	hook::nopVP(base + 0xAB, 2);
	hook::nopVP(base + 0xC5, 2);
	hook::nopVP(base + 0xDB, 2);

	sendGroupJoinPacket_orig(a1, joinState);
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

// ---- keybind-aware emote resolution (v3, re-audited a041f64) -----------------------------------------
// The fired emote's identity is its nameHash = the ForgeLight/JOAAT hash of the InputProfile action name
// (e.g. "Laugh"). We do NOT hash at runtime; re baked the nameHash -> emote itemDefinitionId table below
// (36 render-verified emotes, sorted ascending by nameHash; validated vs live ground truth, e.g. Laugh->3281,
// NoWay->3282, Point->3283, Salute->3284, WaveHello->3276). show=0 dev-placeholder emotes and no-item emotes
// (e.g. HandsUp, DoubleBird, No, Cold, Listen) are intentionally NOT in the table -> nameHash not found ->
// fall through/no-op by design.
static const struct EmoteMapEntry { uint32_t nameHash; int32_t itemDef; const char* name; } kEmoteMap[] = {
	{ 0x10F0567A, 2438, "Beg" },
	{ 0x1980E542, 3350, "Wave" },              // F11 fix: item 3350 is really "Wave" (WaveHelloB is an alias, same clip)
	{ 0x1F1C05F5, 2006, "ScrewYou2" },
	{ 0x2186D966, 1999, "BirdCannon" },
	{ 0x226F13A2, 3155, "ListenToTheCrowd" },
	{ 0x2DD475B9, 2000, "BootySlap" },
	{ 0x323AC39D, 3281, "Laugh" },
	{ 0x364023C5, 2440, "Hump" },
	{ 0x39816F62, 2007, "ShimmyDance" },
	{ 0x412E9EAA, 3819, "RaiseCrown" },
	{ 0x433A86B6, 3277, "Applause" },
	{ 0x4E08AED5, 3287, "WaveBye" },
	{ 0x52BAA064, 3350, "WaveHelloB" },
	{ 0x64A654B4, 3288, "AirGuitar" },
	{ 0x6A398C1B, 2001, "CrotchChop" },
	{ 0x6F33E763, 3279, "CutThroat" },
	{ 0x71312F42, 3154, "FlexPoint" },
	{ 0x77DCC6C1, 3291, "Bow" },
	{ 0x78AD4259, 3282, "NoWay" },
	{ 0x86637979, 3280, "TeaBag" },
	{ 0xA2D40486, 2004, "PelvicThrust" },
	{ 0xA6CF6426, 3348, "Violin" },
	{ 0xA9BEC11F, 3283, "Point" },
	{ 0xB490E0F7, 5376, "DoubleBird" },        // server-only item (ITEM_TYPE-53 id 5376, PARAM1=4 -> anim 4;
	                                           //   ACTIVATABLE_ABILITY_ID 1111392). The client does NOT know item
	                                           //   5376 (Command.ItemDefinitions is disabled; not in packed
	                                           //   ClientItemDefinitions), so the LOCAL play may not resolve it -
	                                           //   but LocalCharacter_PlayAnimationAndRequest sends 0xf801 {5376}
	                                           //   UNCONDITIONALLY (verified: send gated only on sendToServer=1,
	                                           //   itemDef copied raw, no client-item lookup/bail), so the server's
	                                           //   Animation.Play 0xf802 round-trip renders DoubleBird for the emoter.
	{ 0xB50423E3, 2441, "Flex" },
	{ 0xB5678C7E, 3276, "WaveHello" },
	{ 0xC0805836, 2439, "Fisticuffs" },
	{ 0xC0B85592, 3342, "TeabagLight" },
	{ 0xC7B4BEFC, 3285, "Agree" },
	{ 0xD89D0FFC, 3284, "Salute" },
	{ 0xDEEBB36C, 3278, "Beckon" },
	{ 0xE2E985D4, 2002, "CryBaby" },
	{ 0xE2EC3B6E, 3286, "DanceA" },
	{ 0xE550423D, 2005, "SarcasmDance" },
	{ 0xEB330C10, 2008, "WereNotWorthy" },
	{ 0xECB157F4, 2003, "Grind" },
};
static const int kEmoteMapCount = (int)(sizeof(kEmoteMap) / sizeof(kEmoteMap[0]));

// nameHash -> emote itemDefinitionId (0 = not an emote / not in table). Sorted table -> binary search.
static int32_t ResolveEmoteItemDef(uint32_t nameHash)
{
	int lo = 0, hi = kEmoteMapCount - 1;
	while (lo <= hi)
	{
		int mid = (lo + hi) >> 1;
		uint32_t h = kEmoteMap[mid].nameHash;
		if (h == nameHash) return kEmoteMap[mid].itemDef;
		if (h < nameHash) lo = mid + 1; else hi = mid - 1;
	}
	return 0;
}

#if EMOTENV_LOG
static const char* EmoteName(uint32_t nameHash)
{
	for (int i = 0; i < kEmoteMapCount; ++i) if (kEmoteMap[i].nameHash == nameHash) return kEmoteMap[i].name;
	return nullptr;
}
// Diagnostic (EMOTENV_LOG=1 only): append every emote-nameHash press to emote_diag.log with the resolved
// itemDef + emote name (or "no map entry -> no-op"). Observe-only; writes to file via fopen, no console.
static void EmoteNv_DiagEmote(uint32_t nameHash, int32_t itemDef)
{
	FILE* f = fopen("emote_diag.log", "a");
	if (!f) return;
	const char* nm = EmoteName(nameHash);
	if (itemDef) fprintf(f, "EMOTE nameHash=0x%08X -> itemDef=%d  (%s)\n", nameHash, itemDef, nm ? nm : "?");
	else         fprintf(f, "EMOTE nameHash=0x%08X -> (no map entry -> no-op)\n", nameHash);
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
//   The fired emote's identity is its nameHash (hash of the InputProfile action name, e.g. "Laugh"). This is
//   why the earlier raw-F-key->TABLE2-slot patch mis-mapped every key: it ignored the keybind and played the
//   server's fixed slot order. v3 resolves nameHash -> emote itemDefinitionId via the baked kEmoteMap and
//   calls LocalCharacter_PlayAnimationAndRequest(0,&itemDef,1) @0x140576F50 — plays locally AND sends 0xf801
//   {itemDef} (via SendAnimationRequest @0x140576880 -> SendPacket @0x14063C180); server broadcasts
//   Animation.Play 0xf802 (no grant gate — plays granted or not; confirmed no server-side grant check). This
//   is keybind-aware by construction: any key bound to an emote action (incl. non-F keys) resolves correctly,
//   because the GAME did the key->nameHash resolution before this call. nameHash not in kEmoteMap -> fall
//   through to the original (untouched). 5 emote names have no item and no-op by design.
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
	else   // EMOTE (v3): keybind-aware nameHash -> itemDef -> direct play+send; non-emotes fall through.
	{
		int32_t itemDef = ResolveEmoteItemDef((uint32_t)nameHash);
#if EMOTENV_LOG
		if (itemDef) EmoteNv_DiagEmote((uint32_t)nameHash, itemDef);   // only log recognized emote presses
#endif
		if (itemDef)
		{
			__try
			{
				void* pc = *(void**)REBASE(IDA_G_CLIENTPCDATA);       // in-world guard (NULL until in-world)
				if (pc)
				{
					int animData = itemDef;                           // send-path reads *(int*)animData = itemDefinitionId
					((LocalCharacter_PlayAnimationAndRequest_t)REBASE(0x140576F50))(0, &animData, 1); // plays + sends 0xf801
					ENV_LOG("[EmoteNvPatch] Emote nameHash=0x%08X -> PlayAnimationAndRequest itemDef=%d (0xf801)\n",
						(uint32_t)nameHash, itemDef);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ENV_LOG("[EmoteNvPatch] emote play excepted, caught and returned.\n");
			}
			return;                                                   // handled the emote; skip the broken original route
		}
		// nameHash not a known emote -> fall through to the original (all other abilities unaffected).
	}
	Ability_ActivateByNameHash_orig(localChar, nameHash); // NV (now member>0) + every non-emote ability unaffected
}

bool VCPatcher::Init()
{
	// #########################################################     Game patches     ########################################################

	// blocks 0xBADBEEF
	hook::jump(0x14032DC60, OnIntentionalCrash); //Should have crashed, but continue executing... (sendself, lightweightToFullPc triggers this)

	hook::jump(0x140C06FD0, OnIntentionalCrash1);// exception inside 140C06FD0 somewhere

	// WaitForWorldReady patches
	MH_CreateHook((char*)0x140478080, WaitForWorldReady, (void**)&g_origWaitForWorldReady); //Needs the confirm packet (2016)
	//MH_CreateHook((char*)0x140478560, WaitForWorldReadyProcess, (void**)&g_origWaitForWorldReadyProcess); //Needs the confirm packet (2016)
	MH_CreateHook((char*)0x140389E10, networkProximityUpdatesComplete, (void**)&networkProximityUpdatesComplete_orig);

	// ###################################################     End of game patches     ############################################################

	// ###################################################     Game hooks     ############################################################

	// ####################     Release hooks     ####################
	// ITEMDEFINITION HOOKS:
	MH_CreateHook((char*)0x1406F3DA0, ItemDefinitionReadFromBuffer, (void**)&ItemDefinitionReadFromBuffer_orig);

	// LUA:
	MH_CreateHook((char*)0x140488CC0, executeLuaFuncStub, (void**)&executeLuaFunc_orig);

	// GROUP:
	MH_CreateHook((char*)0x1405F9190, sendGroupJoinPacket, (void**)&sendGroupJoinPacket_orig);

	// EMOTE + NIGHT-VISION HOTKEY REPAIR (Dec-2016 broken-trigger fix; see block above for full rationale):
	// resolve the ASLR delta once, then install the single combined trampoline on Ability_ActivateByNameHash.
	// The game resolves key -> bound InputProfile action -> nameHash before this call, so intercepting here is
	// keybind-aware: emote nameHashes -> direct 0xf801 play+send; NV nameHash -> force-member+original; all
	// other abilities -> original. (The old raw-F-key->slot ProcessInput hook is removed; it mis-mapped keys.)
	g_emoteNvDelta = (uintptr_t)GetModuleHandleW(L"H1Z1.exe") - 0x140000000;
	MH_CreateHook((char*)REBASE(0x140931E10), Ability_ActivateByNameHash_hook, (void**)&Ability_ActivateByNameHash_orig); // emote 0xf801 + NV 0xa101{1111272}

	// CUSTOM PACKETS:

	MH_CreateHook((char*)0x1403FE210, handleIncomingZonePackets, (void**)&handleIncomingZonePackets_orig);

	MH_CreateHook((char*)0x14163EFA0, handleIncomingLoginPackets, (void**)&handleIncomingLoginPackets_orig);
	
	MH_CreateHook((char*)0x14099DC10, onPrintConsole, (void**)&onPrintConsole_orig);

	// CUSTOM COMMANDS:
	
	MH_CreateHook((char*)0x14133F230, handleCommand, (void**)&handleCommand_orig);

	// ####################     Debug hooks     ####################
	#ifdef CONSOLE_ENABLED

	// testing



	//MH_CreateHook((char*)0x140B339D0, GetIsContainer, (void**)&GetIsContainer_orig);

	//MH_CreateHook((char*)0x14178F530, LoadoutIdValidate, (void**)&LoadoutIdValidate_orig);

	
	//MH_CreateHook((char*)0x141787620, GetItemErrorMessage, (void**)&GetItemErrorMessage_orig);

	//MH_CreateHook((char*)0x1405B9680, GetItemErrorMessageReturn, (void**)&GetItemErrorMessageReturn_orig);

	//MH_CreateHook((char*)0x1405BC490, GetItemErrorMessageReturnReturn, (void**)&GetItemErrorMessageReturnReturn_orig);

	//MH_CreateHook((char*)0x140B27400, sub_140B27400, (void**)&sub_140B27400_orig);

	//MH_CreateHook((char*)0x1405FE160, sub_1405FE160, (void**)&sub_1405FE160_orig);

	// ACCESSEDCHARACTERBASE HOOKS

	//MH_CreateHook((char*)0x140602BE0, BeginCharacterAccessRead, (void**)&BeginCharacterAccessRead_orig);
	//MH_CreateHook((char*)0x140374DF0, ItemsReadFunc, (void**)&ItemsReadFunc_orig);
	//MH_CreateHook((char*)0x140BAA8C0, sub_140BAA8C0, (void**)&sub_140BAA8C0_orig);

	// CONSTRUCTION HOOKS:

	//MH_CreateHook((char*)0x140773B60, ConstructionPlacementFinalizePacket, (void**)&ConstructionPlacementFinalizePacket_orig);

	// INVENTORY HOOKS:

	//MH_CreateHook((char*)0x14036C1F0, ItemAddBytesWithLengthRead, (void**)&ItemAddBytesWithLengthRead_orig);
	//MH_CreateHook((char*)0x140630DA0, HandleItemAddData, (void**)&HandleItemAddData_orig);
	//MH_CreateHook((char*)0x14049DBD0, ClientPlayerItemManager__CreateItem, (void**)&ClientPlayerItemManager__CreateItem_orig);
	//MH_CreateHook((char*)0x14036FE50, ReadItemDataFromBuffer, (void**)&ReadItemDataFromBuffer_orig);
	
	// LOADOUT HOOKS:

	//MH_CreateHook((char*)0x1405C9770, loadoutBaseRead, (void**)&loadoutBaseRead_orig);
	//MH_CreateHook((char*)0x1405C9970, loadoutSelectLoadoutRead, (void**)&loadoutSelectLoadoutRead_orig);
	//MH_CreateHook((char*)0x1405C9BF0, loadoutSetCurrentLoadoutRead, (void**)&loadoutSetCurrentLoadoutRead_orig);
	//MH_CreateHook((char*)0x1405C9E80, loadoutSelectSlotRead, (void**)&loadoutSelectSlotRead_orig);
	
	// CONTAINER HOOKS:

	//MH_CreateHook((char*)0x1405FF9E0, containerEventBaseRead, (void**)&containerEventBaseRead_orig);
	//MH_CreateHook((char*)0x1405FF230, containerErrorRead, (void**)&containerErrorRead_orig);
	//MH_CreateHook((char*)0x1405FF3F0, containerAddContainerRead, (void**)&containerAddContainerRead_orig);

	
	//MH_CreateHook((char*)0x140447B70, sub_140447B70, (void**)&sub_140447B70_orig);
	//MH_CreateHook((char*)0x1405FC580, sub_1405FC580, (void**)&sub_1405FC580_orig);

	//MH_CreateHook((char*)0x1417543E0, GetContainerDefinition, (void**)&GetContainerDefinition_orig);

	// EQUIPMENT HOOKS:

	//MH_CreateHook((char*)0x1405819A0, equipmentEventBase, (void**)&equipmentEventBase_orig);
	//MH_CreateHook((char*)0x140582110, setCharacterEquipmentSlot, (void**)&setCharacterEquipmentSlot_orig);
	
	//Other

	// MH_CreateHook((char*)0x1403FD710, SpawnLightweightPc, (void**)&SpawnLightweightPc_orig);
	
	//Logging

	//tryAllocConsole();

	MH_CreateHook((char*)0x140337AE0, File__Open, (void**)&File__Open_orig);

	MH_CreateHook((char*)0x1402ED6F0, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); //hook absolutely every logging function

	// logs usually written to a file
	MH_CreateHook((char*)0x14032FA90, writeToLog, (void**)&writeToLog_orig); //hook absolutely every file logging function

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