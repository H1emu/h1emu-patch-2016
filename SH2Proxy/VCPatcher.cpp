#include "stdafx.h"
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <winternl.h>
#include <MinHook.h>
#include <iostream>
#include <udis86.h>

#include "../H1Z1/H1Z1.exe.h"
#include "../H1Z1/enums.h"

#define CONSOLE_ENABLED

using namespace std;

static bool consoleShowing = false;

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
	//*(char*)(a1 + 0x31500 + 0x1C) = true; //BaseClient->gap31500[0x1C]
	//*(char*)(a1 + 0x31500 + 0x1D) = true; //BaseClient->gap31500[0x1D]
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

static void(*handleIncomingZonePackets_orig)(BaseClient* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6);
static void handleIncomingZonePackets(BaseClient* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6) {
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

static bool gameConsoleShowing = false;
static void(*executeLuaFunc_orig)(void* LuaVM, char* funcName, int a3, int a4);
static void executeLuaFuncStub(void* LuaVM, char* funcName, int a3, int a4) {
	void* retAddr = _ReturnAddress();
	std::string func = funcName;
	switch ((unsigned long long)retAddr) {
		case 0x1403FD30D: // OnUpdate
		case 0x140BFEEA8: // GameEvents:GetInventoryShown
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
				else if ((func == "GameEvents:OnEscape" || func == "Console:OnSwfFocus") && gameConsoleShowing) { // closes console on ~ or escape
					executeLuaFunc_orig(LuaVM, "Console:Hide", 0, 0);
					executeLuaFunc_orig(LuaVM, funcName, a3, a4); // executes normal GameEvents:OnEscape / "Console:OnSwfFocus"
					gameConsoleShowing = !gameConsoleShowing;
					return;
				}
			}
			break;
	}
	executeLuaFunc_orig(LuaVM, funcName, a3, a4);
}

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

// item def

static void(*ReadStringFromBuffer_orig)(DataLoadByPacket* buffer, __int64* destination);
static void ReadStringFromBuffer(DataLoadByPacket* buffer, __int64* destination) {
	ReadStringFromBuffer_orig(buffer, destination);
}

static void ReadValueFromBuffer(void* destination, DataLoadByPacket* buffer, size_t size) {
	if (buffer->pBuffer + size <= buffer->pBufferEnd)
	{
		memcpy(destination, buffer->pBuffer, size);
		buffer->pBuffer += size;
	}
	else
	{
		buffer->pBuffer = buffer->pBufferEnd;
		buffer->failureFlag = 1;
	}
}

static void(*ClientItemDefinitionStatsread_orig)(DataLoadByPacket* a1, void* a2);
static void ClientItemDefinitionStatsread(DataLoadByPacket* a1, void* a2) {
	printf("********ClientItemDefinitionStatsread\n\n");
	ClientItemDefinitionStatsread_orig(a1, a2);
}

static void(*ItemDefinitionReadFromBuffer_orig)(ClientItemDefinition* a1, DataLoadByPacket* buffer);
static void ItemDefinitionReadFromBuffer(ClientItemDefinition *a1, DataLoadByPacket* buffer) {
	printf("********ItemDefinitionReadFromBuffer\n\n");
	// packet reading

	ReadValueFromBuffer(&a1->baseitemdefinition0.dword8, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.bitflags[0], buffer, sizeof(char));
	ReadValueFromBuffer(&a1->baseitemdefinition0.bitflags[1], buffer, sizeof(char));
	ReadValueFromBuffer(&a1->baseitemdefinition0.NAME_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.DESCRIPTION_ID, buffer, sizeof(int));

	ReadValueFromBuffer(&a1->baseitemdefinition0.CONTENT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.IMAGE_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.TINT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.HUD_IMAGE_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.field_34, buffer, sizeof(int)); // unknownDword8
	ReadValueFromBuffer(&a1->baseitemdefinition0.qword38, buffer, sizeof(int)); // unknownDword9
	ReadValueFromBuffer(&a1->baseitemdefinition0.COST, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.ITEM_CLASS, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.PROFILE_OVERRIDE, buffer, sizeof(int));

	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.MODEL_NAME);// MODEL_NAME
	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.TEXTURE_ALIAS);// TEXTURE_ALIAS

	ReadValueFromBuffer(&a1->baseitemdefinition0.GENDER_USAGE, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.ITEM_TYPE, buffer, sizeof(int)); // unknownDword14
	ReadValueFromBuffer(&a1->baseitemdefinition0.CATEGORY_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.WEAPON_TRAIL_EFFECT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.COMPOSITE_EFFECT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.POWER_RATING, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.MIN_PROFILE_RANK, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.RARITY, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.ACTIVATABLE_ABILITY_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.ACTIVATABLE_ABILITY_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.PASSIVE_ABILITY_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.PASSIVE_ABILITY_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.MAX_STACK_SIZE, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.MIN_STACK_SIZE, buffer, sizeof(int));

	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.TINT_ALIAS);// TINT_ALIAS

	ReadValueFromBuffer(&a1->baseitemdefinition0.TINT_GROUP_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.MEMBER_DISCOUNT, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.VIP_RANK_REQUIRED, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.RACE_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.UI_MODEL_CAMERA_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.EQUIP_COUNT_MAX, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.CURRENCY_TYPE, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.DATASHEET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.unknownDword14, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.SKILL_SET_ID, buffer, sizeof(int));

	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.OVERLAY_TEXTURE);// OVERLAY_TEXTURE
	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.DECAL_SLOT);// DECAL_SLOT

	ReadValueFromBuffer(&a1->baseitemdefinition0.OVERLAY_ADJUSTMENT, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.TRIAL_DURATION_SEC, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.NEXT_TRIAL_DELAY_SEC, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.CLIENT_USE_REQUIREMENT_ID, buffer, sizeof(int));

	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.OVERRIDE_APPEARANCE);// OVERRIDE_APPEARANCE

	ReadValueFromBuffer(&a1->baseitemdefinition0.OVERRIDE_CAMERA_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.unknownDword42, buffer, sizeof(int)); // unknownDword42
	ReadValueFromBuffer(&a1->baseitemdefinition0.unknownDword43, buffer, sizeof(int)); // unknownDword43
	ReadValueFromBuffer(&a1->baseitemdefinition0.unknownDword44, buffer, sizeof(int)); // unknownDword44
	ReadValueFromBuffer(&a1->baseitemdefinition0.BULK, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.ACTIVE_EQUIP_SLOT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.PASSIVE_EQUIP_SLOT_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.PASSIVE_EQUIP_SLOT_GROUP_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.unknownDword49, buffer, sizeof(int)); // unknownDword49
	ReadValueFromBuffer(&a1->baseitemdefinition0.GRINDER_REWARD_SET_ID, buffer, sizeof(int));
	ReadValueFromBuffer(&a1->baseitemdefinition0.BUILD_BAR_GROUP_ID, buffer, sizeof(int));

	ReadStringFromBuffer_orig(buffer, &a1->baseitemdefinition0.unknownString7);// unknownString7

	char* v58 = buffer->pBuffer;
	if (v58 + 1 <= buffer->pBufferEnd)
	{
		a1->baseitemdefinition0.unknownBoolean1 = *v58 != 0;// unknownBoolean1
		++buffer->pBuffer;
	}
	else
	{
		a1->baseitemdefinition0.unknownBoolean1 = 0;
		buffer->pBuffer = buffer->pBufferEnd;
		buffer->failureFlag = 1;
	}

	char* v59 = buffer->pBuffer;
	if (v59 + 1 <= buffer->pBufferEnd)
	{
		a1->baseitemdefinition0.IS_ARMOR = *v59 != 0;// IS_ARMOR
		++buffer->pBuffer;
	}
	else
	{
		a1->baseitemdefinition0.IS_ARMOR = 0;
		buffer->pBuffer = buffer->pBufferEnd;
		buffer->failureFlag = 1;
	}
	
	ReadValueFromBuffer(&a1->qword1F0, buffer, sizeof(int)); // unknownDword52
	ReadValueFromBuffer(&a1->field_1F4, buffer, sizeof(int)); // unknownDword53
	ReadValueFromBuffer(&a1->qword1F8, buffer, sizeof(int)); // unknownDword54
	ReadValueFromBuffer(&a1->field_1FC, buffer, sizeof(int)); // unknownDword55


	ReadStringFromBuffer_orig(buffer, &a1->qword208);// unknownString8


	ReadValueFromBuffer(&a1->baseitemdefinition0.UI_MODEL_CAMERA_ID, buffer, sizeof(int)); // UI_MODEL_CAMERA_ID
	ReadValueFromBuffer(&a1->field_200, buffer, sizeof(int)); // unknownDword57
	ReadValueFromBuffer(&a1->SCRAP_VALUE_OVERRIDE, buffer, sizeof(int)); // SCRAP_VALUE_OVERRIDE

	ClientItemDefinitionStatsread_orig(buffer, &a1->qword220);// read func
	
	printf("ItemDefinition recieved - ID: %d - Flags: %d, %d\n", a1->baseitemdefinition0.dword8, a1->baseitemdefinition0.bitflags[0], a1->baseitemdefinition0.bitflags[1]);
	buffer->failureFlag = 0;
}

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
	MH_CreateHook((char*)0x1406F4540, ClientItemDefinitionStatsread, (void**)&ClientItemDefinitionStatsread_orig);//ClientItemDefinitionStats
	MH_CreateHook((char*)0x140467F40, ReadStringFromBuffer, (void**)&ReadStringFromBuffer_orig);// ReadStringFromBuffer

	// LUA:
	MH_CreateHook((char*)0x140488CC0, executeLuaFuncStub, (void**)&executeLuaFunc_orig);

	// ####################     Debug hooks     ####################
	#ifdef CONSOLE_ENABLED

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

	// EQUIPMENT HOOKS:

	MH_CreateHook((char*)0x1405819A0, equipmentEventBase, (void**)&equipmentEventBase_orig);
	MH_CreateHook((char*)0x140582110, setCharacterEquipmentSlot, (void**)&setCharacterEquipmentSlot_orig);
	
	//Other

	MH_CreateHook((char*)0x1403FD710, SpawnLightweightPc, (void**)&SpawnLightweightPc_orig);
	
	MH_CreateHook((char*)0x14039E0A0, sub_14039E0A0, (void**)&sub_14039E0A0_orig); // sanity check (Pc / Npc / Vehicle)
	
	MH_CreateHook((char*)0x140337AE0, File__Open, (void**)&File__Open_orig);
	
	MH_CreateHook((char*)0x1403FE210, handleIncomingZonePackets, (void**)&handleIncomingZonePackets_orig);
	
	//Logging
	MH_CreateHook((char*)0x1402ED6F0, logFuncCustomCallOrig, (void**)&logFuncCustomCallOrig_orig); //hook absolutely every logging function
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