#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"

#if (defined(WIN32) || defined(_WIN32)) && defined(_MSC_VER)
	#include <Windows.h>
#else
	#include <sys/mman.h>
#endif

typedef void(*logprintf_t)(char* format, ...);

logprintf_t logprintf;

void **ppPluginData;

extern void *pAMXFunctions;

const DWORD CINC_Addr = 0x468EE0;
const char *CINC_Signature = "\x8B\x4C\x24\x04\x8A\x01\x84\xC0\x74\x4A\x8D\x9B\x00\x00\x00\x00";

const DWORD GPN_Intable = 0x4CF2C4;
const DWORD GPN_Addr = 0x471370;

typedef cell AMX_NATIVE_CALL(*OrigGetPlayerName)(AMX*, cell*);

bool checkNickname(char *name)
{
	int len = 0;

	while (*name)
	{
		if (!(
			*name >= '0' && *name <= '9' ||
			*name >= 'A' && *name <= 'Z' ||
			*name >= 'a' && *name <= 'z' ||

			*name >= 'À' && *name <= 'ß' ||
			*name >= 'à' && *name <= 'ÿ' ||

			*name == ']' ||
			*name == '[' ||
			*name == '_' ||
			*name == '$' ||
			*name == '=' ||
			*name == ')' ||
			*name == '(' ||
			*name == '@' ||
			*name == '.'
			)) return 1;

		name++;
		len++;
	}

	if (len < 3 || 20 < len) return 1;
	return 0;
}

void UnProtect(DWORD dwAddress, size_t sSize)
{
	// Unprotect the address
#ifdef _WIN32
	DWORD dwOldProtection;
	VirtualProtect((LPVOID)dwAddress, sSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
#else
	mprotect((void*)(((int)dwAddress / 4096) * 4096), 4096, PROT_WRITE | PROT_READ | PROT_EXEC);
#endif
}

void InstallJmpHook(DWORD dwInstallAddress, DWORD dwHookFunction)
{
	// Unprotect the address
	UnProtect(dwInstallAddress, 5);
	// Calculate the installing address
	DWORD dwFunction = dwHookFunction - (dwInstallAddress + 5);
	// Write the jmp instruction
	*(BYTE *)dwInstallAddress = 0xE9;
	// Write the hook function address
	*(DWORD *)(dwInstallAddress + 1) = dwFunction;
}

cell AMX_NATIVE_CALL GetPlayerName(AMX* amx, cell* params)
{
	cell ret = OrigGetPlayerName(GPN_Addr)(amx, params);
	cell *addr = NULL;
	amx_GetAddr(amx, params[2], &addr);
	for (int len = 0; addr[len]; len++)
	{
		if (addr[len] < 0) addr[len] += 256;
	}
	return ret;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)ppData[PLUGIN_DATA_LOGPRINTF];
	logprintf("  [allow_any_nicks]: Plugin for 0.3.DL-R1");
	if (memcmp((void*)CINC_Addr, (void*)CINC_Signature, 16) != 0)
	{
		logprintf("  [allow_any_nicks]: Invalid signature");
		return 0;
	}
	InstallJmpHook(CINC_Addr, (DWORD)checkNickname);
	*(DWORD *)GPN_Intable = (DWORD)GetPlayerName;

	logprintf("  [allow_any_nicks]: Unlock memory and enabled");
	return 1;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	logprintf("  [allow_any_nicks]: Plugin was unloaded");
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION;
}