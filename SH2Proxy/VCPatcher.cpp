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

#define CONSOLE_ENABLED

using namespace std;

static bool consoleShowing = false;

// luaVM ptr
void* L = nullptr;
static bool gameConsoleShowing = false;
static void(*executeLuaFunc_orig)(void* LuaVM, char* funcName, void* a3, void* a4);

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

	if (!CreateProcessA(
		executablePath.c_str(),             // Path to the executable
		const_cast<LPSTR>(commandLine.c_str()),  // Command line arguments
		NULL,                               // Process handle not inheritable
		NULL,                               // Thread handle not inheritable
		FALSE,                              // Set handle inheritance to FALSE
		CREATE_NO_WINDOW,                 // Create a new console window
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

	printf("\n\n\n --------- hades query\n\n");
	std::string executablePath = ".\\H1Z1_BE.exe";
	std::string commandLine = executablePath + " -assetcheck " + authTicket + " " + gatewayServer;

	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInfo;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	if (!CreateProcessA(
		executablePath.c_str(),             // Path to the executable
		const_cast<LPSTR>(commandLine.c_str()),  // Command line arguments
		NULL,                               // Process handle not inheritable
		NULL,                               // Thread handle not inheritable
		FALSE,                              // Set handle inheritance to FALSE
		CREATE_NO_WINDOW,                 // Create a new console window CREATE_NO_WINDOW
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
		handleHadesInit(buffer);
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

	// CUSTOM PACKETS:

	MH_CreateHook((char*)0x1403FE210, handleIncomingZonePackets, (void**)&handleIncomingZonePackets_orig);

	MH_CreateHook((char*)0x14163EFA0, handleIncomingLoginPackets, (void**)&handleIncomingLoginPackets_orig);
	
	MH_CreateHook((char*)0x14099DC10, onPrintConsole, (void**)&onPrintConsole_orig);

	// CUSTOM COMMANDS:
	
	MH_CreateHook((char*)0x14133F230, handleCommand, (void**)&handleCommand_orig);

	

	// ####################     Debug hooks     ####################
	#ifdef CONSOLE_ENABLED

	// testing



	MH_CreateHook((char*)0x140B339D0, GetIsContainer, (void**)&GetIsContainer_orig);

	MH_CreateHook((char*)0x14178F530, LoadoutIdValidate, (void**)&LoadoutIdValidate_orig);

	
	MH_CreateHook((char*)0x141787620, GetItemErrorMessage, (void**)&GetItemErrorMessage_orig);

	MH_CreateHook((char*)0x1405B9680, GetItemErrorMessageReturn, (void**)&GetItemErrorMessageReturn_orig);

	MH_CreateHook((char*)0x1405BC490, GetItemErrorMessageReturnReturn, (void**)&GetItemErrorMessageReturnReturn_orig);

	MH_CreateHook((char*)0x140B27400, sub_140B27400, (void**)&sub_140B27400_orig);

	MH_CreateHook((char*)0x1405FE160, sub_1405FE160, (void**)&sub_1405FE160_orig);

	// ACCESSEDCHARACTERBASE HOOKS

	MH_CreateHook((char*)0x140602BE0, BeginCharacterAccessRead, (void**)&BeginCharacterAccessRead_orig);

	MH_CreateHook((char*)0x140374DF0, ItemsReadFunc, (void**)&ItemsReadFunc_orig);

	MH_CreateHook((char*)0x140BAA8C0, sub_140BAA8C0, (void**)&sub_140BAA8C0_orig);

	// CONSTRUCTION HOOKS:

	MH_CreateHook((char*)0x140773B60, ConstructionPlacementFinalizePacket, (void**)&ConstructionPlacementFinalizePacket_orig);

	// INVENTORY HOOKS:

	MH_CreateHook((char*)0x14036C1F0, ItemAddBytesWithLengthRead, (void**)&ItemAddBytesWithLengthRead_orig);

	MH_CreateHook((char*)0x140630DA0, HandleItemAddData, (void**)&HandleItemAddData_orig);

	MH_CreateHook((char*)0x14049DBD0, ClientPlayerItemManager__CreateItem, (void**)&ClientPlayerItemManager__CreateItem_orig);
	
	MH_CreateHook((char*)0x14036FE50, ReadItemDataFromBuffer, (void**)&ReadItemDataFromBuffer_orig);
	
	// LOADOUT HOOKS:

	MH_CreateHook((char*)0x1405C9770, loadoutBaseRead, (void**)&loadoutBaseRead_orig);
	MH_CreateHook((char*)0x1405C9970, loadoutSelectLoadoutRead, (void**)&loadoutSelectLoadoutRead_orig);
	MH_CreateHook((char*)0x1405C9BF0, loadoutSetCurrentLoadoutRead, (void**)&loadoutSetCurrentLoadoutRead_orig);
	MH_CreateHook((char*)0x1405C9E80, loadoutSelectSlotRead, (void**)&loadoutSelectSlotRead_orig);
	
	// CONTAINER HOOKS:

	MH_CreateHook((char*)0x1405FF9E0, containerEventBaseRead, (void**)&containerEventBaseRead_orig);
	MH_CreateHook((char*)0x1405FF230, containerErrorRead, (void**)&containerErrorRead_orig);
	MH_CreateHook((char*)0x1405FF3F0, containerAddContainerRead, (void**)&containerAddContainerRead_orig);

	
	MH_CreateHook((char*)0x140447B70, sub_140447B70, (void**)&sub_140447B70_orig);
	MH_CreateHook((char*)0x1405FC580, sub_1405FC580, (void**)&sub_1405FC580_orig);

	MH_CreateHook((char*)0x1417543E0, GetContainerDefinition, (void**)&GetContainerDefinition_orig);

	// EQUIPMENT HOOKS:

	MH_CreateHook((char*)0x1405819A0, equipmentEventBase, (void**)&equipmentEventBase_orig);
	MH_CreateHook((char*)0x140582110, setCharacterEquipmentSlot, (void**)&setCharacterEquipmentSlot_orig);
	
	//Other

	MH_CreateHook((char*)0x1403FD710, SpawnLightweightPc, (void**)&SpawnLightweightPc_orig);
	
	MH_CreateHook((char*)0x140337AE0, File__Open, (void**)&File__Open_orig);
	
	
	//Logging
	MH_CreateHook((char*)0x1402ED6F0, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); //hook absolutely every logging function

	// logs usually written to a file
	MH_CreateHook((char*)0x14032FA90, writeToLog, (void**)&writeToLog_orig); //hook absolutely every file logging function

	

	#endif
	
	// ###################################################     End of game hooks     ############################################################

	MH_EnableHook(MH_ALL_HOOKS);

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