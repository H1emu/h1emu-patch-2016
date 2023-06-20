enum ClientStates {
	ClientRunStateNone = 0,
	ClientRunStateAdminBackdoorLoginStart = 1,
	ClientRunStateAdminBackdoorLogin = 2,
	ClientRunStateAdminPreInitialize = 3,
	ClientRunStatePreInitialize = 4,
	ClientRunStateVerifyPsnLogin = 6,
	ClientRunStateCheckPsnChatRestrictions = 7,
	ClientRunStateWaitForPsnChatRestrictionsDialog = 8,
	ClientRunStateCheckPsnUgcRestrictions = 9,
	ClientRunStateWaitForPsnUgcRestrictionsDialog = 10,
	ClientRunStateWaitingForPsnLogin = 11,
	ClientRunStateStartingLogin = 12,
	ClientRunStateWaitForCharacterList = 13,
	ClientRunStateWaitForCharacterSelectLoad = 14,
	ClientRunStateCharacterCreateOrDelete = 15,
	ClientRunStateLoggingIn = 16,
	ClientRunStateNetInitialize = 17,
	ClientRunStateConnecting = 18,
	ClientRunStatePostInitialize = 19,
	ClientRunStateWaitForInitialDeployment = 20,
	ClientRunStatePostInitialDeployment = 21,
	ClientRunStateWaitForFirstZone = 22,
	ClientRunStateWaitForConfirmationPacket = 23,
	ClientRunStatePostWaitForFirstZone = 24,
	ClientRunStateWaitForContinue = 25,
	ClientRunStateRunning = 26,
	ClientRunStateWaitForTeleport = 27,
	ClientRunStateWaitForZoneLoad = 28,
	ClientRunStateWaitingForReloginSession = 29,
	ClientRunStateStartingRelogin = 30,
	ClientRunStateVerifyXBLiveLogin = 34,
	ClientRunStateShuttingDown = 35
};

enum H1emuPackets {
	cPacketIdPrintToConsole = 0x01,
	cPacketIdMessageBox = 0x02,
	cPacketIdInitHades = 0x03,
	cPacketIdHadesQuery = 0x04,
	cPacketIdVoiceV2Init = 0x05
};

enum H1emuLoginPackets {
	cLoginPacketIdPrintToConsole = 0x01,
	cLoginPacketIdMessageBox = 0x02
};