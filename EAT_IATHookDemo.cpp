#include <stdio.h>
#include <Windows.h>
#include <ImageHlp.h>
typedef HMODULE(WINAPI* fp_LoadLibraryA) (
	_In_ LPCSTR lpLibFileName);

typedef BOOL(WINAPI* fp_PeekMessageA) (
	_Out_ LPMSG lpMsg,
	_In_opt_ HWND hWnd,
	_In_ UINT wMsgFilterMin,
	_In_ UINT wMsgFilterMax,
	_In_ UINT wRemoveMsg);


fp_LoadLibraryA orig_LoadLibraryA = NULL;
fp_PeekMessageA orig_PeekMessageA = NULL;

HMODULE WINAPI hook_LoadLibraryA(LPCSTR lpLibFileName)
{
	printf("hook_LoadLibraryA: %s \n", lpLibFileName);
	return orig_LoadLibraryA(lpLibFileName);
}

BOOL WINAPI hook_PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
	printf("hook_PeekMessageA: 0x%p \n", lpMsg);
	return orig_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

int forceWrite4Bytes(DWORD* destAddr, DWORD newOffset)
{
	DWORD oldProtect;
	VirtualProtect(destAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
	*destAddr = newOffset;
	VirtualProtect(destAddr, sizeof(DWORD), oldProtect, &oldProtect);
	return TRUE;
}

int hookIATwithName(const char* modName, const char* targetName, DWORD hookFunc, DWORD* origFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc = NULL;
	PIMAGE_THUNK_DATA         pNameTable = NULL;
	PIMAGE_THUNK_DATA         pAddressTable = NULL;
	PIMAGE_IMPORT_BY_NAME     pImportByName = NULL;
	DWORD* pImportedAddr = 0;
	char* importedName = NULL;

	hMod = GetModuleHandleA(modName);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData((PVOID)hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

	if (pImportDesc == NULL) {
		printf("ERROR: Import Directory not found\n");
		return FALSE;
	}

	while (pImportDesc->Name) {
		char* dllName = (char*)((DWORD)hMod + pImportDesc->Name);

		pNameTable = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->OriginalFirstThunk);
		pAddressTable = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);

		while (pNameTable->u1.Function) {
			pImportedAddr = &(pAddressTable->u1.Function);

			if (pNameTable->u1.AddressOfData & 0x80000000) {
				DWORD dwOrd = pNameTable->u1.AddressOfData ^ 0x80000000;
				printf("Ordinal %d (0x%x)\n", dwOrd, dwOrd);
			}
			else {
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)hMod + pNameTable->u1.AddressOfData);
				importedName = (char*)(pImportByName->Name);

				if (_stricmp(targetName, importedName) == 0) {
					goto install_hook;
				}
			}
			pNameTable++;
			pAddressTable++;
		}
		pImportDesc++;
	}
	return FALSE;

install_hook:
	if (pImportedAddr != 0 && hookFunc != NULL) {
		*origFunc = *pImportedAddr;
		forceWrite4Bytes(pImportedAddr, hookFunc);
	}
	return TRUE;
}

BOOL hookIATwithAddress(const char* modName, DWORD targetFunc, DWORD hookFunc, DWORD* origFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc = NULL;
	PIMAGE_THUNK_DATA         pNameTable = NULL;
	PIMAGE_THUNK_DATA         pAddressTable = NULL;
	PIMAGE_IMPORT_BY_NAME     pImportByName = NULL;
	DWORD* pImportedAddr = 0;
	char* importedName = NULL;

	hMod = GetModuleHandleA(modName);
	if (hMod == NULL)
		return FALSE;
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData((PVOID)hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

	if (pImportDesc == NULL) {
		printf("ERROR: Import Directory not found\n");
		return FALSE;
	}

	while (pImportDesc->Name) {
		char* dllName = (char*)((DWORD)hMod + pImportDesc->Name);

		pNameTable = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->OriginalFirstThunk);
		pAddressTable = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);

		while (pAddressTable->u1.Function) {
			pImportedAddr = &(pAddressTable->u1.Function);

			if (*pImportedAddr == targetFunc) {
				goto install_hook;
			}
			pNameTable++;
			pAddressTable++;
		}
		pImportDesc++;
	}
	return FALSE;

install_hook:
	if (pImportedAddr != 0 && hookFunc != NULL) {
		*origFunc = *pImportedAddr;
		forceWrite4Bytes(pImportedAddr, hookFunc);
	}
	return TRUE;
}

BOOL hookEATwithName(const char* modName, const char* targetName, DWORD hookFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD* pAddressTable = NULL;
	DWORD* pNameTable = NULL;
	WORD* pOrdinalTable = NULL;
	DWORD   i = 0;
	DWORD* pRelativeOffset = 0;
	DWORD  exportedAddr = 0;
	char* exportedName = NULL;

	hMod = GetModuleHandleA(modName);
	if (hMod == NULL)
		return FALSE;
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData((PVOID)hMod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	if (pExportDirectory == NULL) {
		printf("ERROR: Export Directory not found\n");
		return FALSE;
	}

	pAddressTable = (DWORD*)((DWORD)hMod + pExportDirectory->AddressOfFunctions);
	pNameTable = (DWORD*)((DWORD)hMod + pExportDirectory->AddressOfNames);
	pOrdinalTable = (WORD*)((DWORD)hMod + pExportDirectory->AddressOfNameOrdinals);

	for (i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
		exportedName = (char*)((DWORD)hMod + pNameTable[i]);
		if (_stricmp(targetName, exportedName) == 0) {
			pRelativeOffset = &pAddressTable[pOrdinalTable[i]];
			exportedAddr = (DWORD)hMod + *pRelativeOffset;
			break;
		}
	}

	if (pRelativeOffset != 0 && hookFunc != NULL) {
		DWORD newOffset = hookFunc - (DWORD)hMod;
		forceWrite4Bytes(pRelativeOffset, newOffset);
	}
	return TRUE;
}

int hookEATwithAddress(const char* modName, DWORD targetFunc, DWORD hookFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD* pAddressTable = NULL;
	DWORD* pNameTable = NULL;
	WORD* pOrdinalTable = NULL;
	DWORD   i = 0;
	DWORD* pRelativeOffset = 0;
	DWORD  exportedAddr = 0;
	char* exportedName = NULL;

	hMod = GetModuleHandleA(modName);
	if (hMod == NULL)
		return FALSE;
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData((PVOID)hMod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	if (pExportDirectory == NULL) {
		printf("ERROR: Export Directory not found\n");
		return FALSE;
	}

	pAddressTable = (DWORD*)((DWORD)hMod + pExportDirectory->AddressOfFunctions);
	pNameTable = (DWORD*)((DWORD)hMod + pExportDirectory->AddressOfNames);
	pOrdinalTable = (WORD*)((DWORD)hMod + pExportDirectory->AddressOfNameOrdinals);

	for (i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
		exportedName = (char*)((DWORD)hMod + pNameTable[i]);

		pRelativeOffset = &pAddressTable[pOrdinalTable[i]];
		exportedAddr = (DWORD)hMod + *pRelativeOffset;
		if (exportedAddr == targetFunc) {
			break;
		}
	}

	if (pRelativeOffset != 0 && hookFunc != NULL) {
		DWORD newOffset = hookFunc - (DWORD)hMod;

		forceWrite4Bytes(pRelativeOffset, newOffset);
	}
	return TRUE;
}

DWORD getApiAddress(const char* modName, const char* apiName)
{
	HMODULE hMod;
	hMod = GetModuleHandleA(modName);
	if (hMod == NULL)
		return 0;
	FARPROC fproc = GetProcAddress(hMod, apiName);

	return (DWORD)fproc;
}

int main()
{
	orig_LoadLibraryA = (fp_LoadLibraryA)getApiAddress("kernel32.dll", "LoadLibraryA");
	orig_PeekMessageA = (fp_PeekMessageA)getApiAddress("user32.dll", "PeekMessageA");
	hookEATwithName("kernel32.dll", "LoadLibraryA", (DWORD)GetModuleHandle);
	//fp_LoadLibraryA fp = (fp_LoadLibraryA) getApiAddress("kernel32.dll", "LoadLibraryA");
	//fp("kernel32.dll");

	LoadLibraryA("user32.dll");
	//printf("%s: direct  : 0x%x, hookFunc: 0x%x \n", "PeekMessageA", (DWORD) PeekMessageA, (DWORD) hook_PeekMessageA);
	//hookEATwithName("user32.dll", "PeekMessageA", (DWORD) hook_PeekMessageA);
	hookEATwithAddress("user32.dll", (DWORD)PeekMessageA, (DWORD)PostMessage);
	//fp_PeekMessageA fp2 = (fp_PeekMessageA) getApiAddress("user32.dll", "PeekMessageA");
	//fp2(NULL, NULL, 0, 0, 0);


	//printf("%s: direct  : 0x%x, orig: 0x%x, hookFunc: 0x%x \n", "LoadLibraryA", (DWORD)LoadLibraryA, (DWORD)orig_LoadLibraryA, (DWORD)hook_LoadLibraryA);
	hookIATwithName(NULL, "LoadLibraryA", (DWORD)hook_LoadLibraryA, (DWORD*)&orig_LoadLibraryA);
	//printf("%s: direct  : 0x%x, orig: 0x%x, orig first4: 0x%x \n", "LoadLibraryA", (DWORD)LoadLibraryA, (DWORD)orig_LoadLibraryA, *((DWORD*)orig_LoadLibraryA));

	LoadLibraryA("user32.dll");

	//printf("%s: direct  : 0x%x, orig: 0x%x, hookFunc: 0x%x \n", "PeekMessageA", (DWORD)PeekMessageA, (DWORD)orig_PeekMessageA, (DWORD)hook_PeekMessageA);
	hookIATwithAddress(NULL, (DWORD)PeekMessageA, (DWORD)hook_PeekMessageA, (DWORD*)&orig_PeekMessageA);
	//printf("%s: direct  : 0x%x, orig: 0x%x, orig first4: 0x%x \n", "PeekMessageA", (DWORD)PeekMessageA, (DWORD)orig_PeekMessageA, *((DWORD*)orig_PeekMessageA));


	PeekMessageA(NULL, NULL, 0, 0, 0);
	system("pause");
	return 0;
}
