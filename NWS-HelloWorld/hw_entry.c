#include <Windows.h>
#include <strsafe.h>

int WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd
)
{
	WCHAR pidString[50] = { 0 };

	StringCchPrintfW(
		pidString,
		50,
		L"Meine Prozess-ID ist: %d",
		GetCurrentProcessId()
	);

	MessageBoxW(NULL, pidString, L"Hello World!", MB_OK);

	return 0;
}