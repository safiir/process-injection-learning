#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

typedef struct _RemoteParam {
	char szMsg[12];
	DWORD dwMessageBox;
} RemoteParam, * PRemoteParam;

typedef int(__stdcall* PFN_MESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, DWORD);


DWORD __stdcall threadProc(LPVOID lParam)
{
	RemoteParam* pRP = (RemoteParam*)lParam;

	PFN_MESSAGEBOX pfnMessageBox;
	pfnMessageBox = (PFN_MESSAGEBOX)pRP->dwMessageBox;
	pfnMessageBox(NULL, pRP->szMsg, pRP->szMsg, 0);

	return 0;
}

bool enableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		CloseHandle(hToken);
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}

	return true;
}


DWORD processNameToId(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe)) {
		MessageBox(NULL,
			"The frist entry of the process list has not been copyied to the buffer",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	while (Process32Next(hSnapshot, &pe)) {
		if (!strcmp(lpszProcessName, pe.szExeFile)) {
			return pe.th32ProcessID;
		}
	}

	return 0;
}

int main(int argc, char* argv[])
{
	const DWORD dwThreadSize = 4096;
	DWORD dwWriteBytes;
	enableDebugPriv();

	char szExeName[MAX_PATH] = "target32.exe";

	DWORD dwProcessId = processNameToId(szExeName);

	if (dwProcessId == 0) {
		MessageBox(NULL, "The target process have not been found !",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return -1;
	}

	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (!hTargetProcess) {
		MessageBox(NULL, "Open target process failed !",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	void* pRemoteThread = VirtualAllocEx(hTargetProcess, 0,
		dwThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pRemoteThread) {
		MessageBox(NULL, "Alloc memory in target process failed !",
			"notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	if (!WriteProcessMemory(hTargetProcess,
		pRemoteThread, &threadProc, dwThreadSize, 0)) {
		MessageBox(NULL, "Write data to target process failed !",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}
	RemoteParam remoteData;
	ZeroMemory(&remoteData, sizeof(RemoteParam));

	HINSTANCE hUser32 = LoadLibrary("User32.dll");
	remoteData.dwMessageBox = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	strcat_s(remoteData.szMsg, "Hello＼0");

	RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(
		hTargetProcess, 0, sizeof(RemoteParam), MEM_COMMIT, PAGE_READWRITE);

	if (!pRemoteParam) {
		MessageBox(NULL, "Alloc memory failed !",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	if (!WriteProcessMemory(hTargetProcess,
		pRemoteParam, &remoteData, sizeof(remoteData), 0)) {
		MessageBox(NULL, "Write data to target process failed !",
			"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	HANDLE hRemoteThread = CreateRemoteThread(
		hTargetProcess, NULL, 0, (DWORD(__stdcall*)(void*))pRemoteThread,
		pRemoteParam, 0, &dwWriteBytes);

	if (!hRemoteThread) {
		MessageBox(NULL, "Create remote thread failed !", "Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	CloseHandle(hRemoteThread);

	FreeLibrary(hUser32);

	return 0;
}