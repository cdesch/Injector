#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>

using namespace std;

bool InjectDynamicLibrary(DWORD processId, char* dllPath)
{
	printf("Injecting\n");

	// Open a new handle to the target process
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	if (hTargetProcess) // if the handle is valid
	{
		printf("Injecting: valid process\n");
		// Kernel32.dll is always mapped to the same address in each process
		// So we can just copy the address of it & LoadLibraryA in OUR process and
		// expect it to be same in the remote process too.
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		// We must allocate more memory in the target process to hold the path for our dll in it's addresspace.
		LPVOID LoadPath = VirtualAllocEx(hTargetProcess, 0, strlen(dllPath),
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// Create a thread in the target process that will call LoadLibraryA() with the dllpath as a parameter
		HANDLE RemoteThread = CreateRemoteThread(hTargetProcess, 0, 0,
			(LPTHREAD_START_ROUTINE)LoadLibAddr, LoadPath, 0, 0);
		// Wait for the operation to complete, then continue.
		WaitForSingleObject(RemoteThread, INFINITE);

		// the path to the dll is no longer needed in the remote process, so we can just free the memory now.
		VirtualFreeEx(hTargetProcess, LoadPath, strlen(dllPath), MEM_RELEASE);
		CloseHandle(RemoteThread);
		CloseHandle(hTargetProcess);
		return true;
	}
	return false;
}

DWORD FindProcessId(wstring processName)
{
	//printf("finding process\n");
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

DWORD GetProcessBaseAddress()
{
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (Module32First(hSnapshot, &me32))
	{
		CloseHandle(hSnapshot);
		return (DWORD)me32.modBaseAddr;
	}

	CloseHandle(hSnapshot);
	return 0;
}

int main()
{
	printf("Hello World!\n");
	system("PAUSE");
	//DWORD processName = FindProcessId(L"chrome.exe");
	//string stuff = "ugh";
	//cout << "process: " << processName << endl;
	//printf("process:! $0 $1 #{0} [0] {0} \n", processName, stuff);


	//bool result = InjectDynamicLibrary(FindProcessId(L"chrome.exe"), "TargetDll.dll");
	bool result = InjectDynamicLibrary(FindProcessId(L"CheatEngineTestCpp.exe"), "TargetDll.dll");

	if (result) {
		printf("Injection true!\n");
	}
	else {
		printf("Injection false!\n");
	}
	printf("Ending!\n");
	system("PAUSE");
}