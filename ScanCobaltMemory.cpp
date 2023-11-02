#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BYTE pattern[] = { 0x49, 0xB9, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x49, 0x0F, 0xAF, 0xD1, 0x49, 0x83, 0xF8, 0x40 };
BYTE pattern_x64[] = { 0x4C, 0x8B, 0x53, 0x08, 0x45, 0x8B, 0x0A, 0x45, 0x8B, 0x5A, 0x04, 0x4D, 0x8D, 0x52, 0x08, 0x45, 0x85, 0xC9, 0x75, 0x05, 0x45, 0x85, 0xDB, 0x74, 0x33, 0x45, 0x3B, 0xCB, 0x73, 0xE6, 0x49, 0x8B, 0xF9, 0x4C, 0x8B, 0x03 };
BYTE pattern_x86[] = { 0x8B, 0x46, 0x04, 0x8B, 0x08, 0x8B, 0x50, 0x04, 0x83, 0xC0, 0x08, 0x89, 0x55, 0x08, 0x89, 0x45, 0x0C, 0x85, 0xC9, 0x75, 0x04, 0x85, 0xD2, 0x74, 0x23, 0x3B, 0xCA, 0x73, 0xE6, 0x8B, 0x06, 0x8D, 0x3C, 0x08, 0x33, 0xD2 };

void scanProcessMemory(HANDLE processHandle, BYTE* pattern, DWORD patternSize, DWORD processId) {
    MEMORY_BASIC_INFORMATION memoryInfo;
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    BYTE* buffer = NULL;
    SIZE_T bytesRead;
    for (LPVOID address = systemInfo.lpMinimumApplicationAddress; address < systemInfo.lpMaximumApplicationAddress; address = (LPVOID)((DWORD_PTR)address + memoryInfo.RegionSize)) {
        if (VirtualQueryEx(processHandle, address, &memoryInfo, sizeof(memoryInfo))) {
            if ((memoryInfo.State == MEM_COMMIT) && (memoryInfo.Protect == PAGE_EXECUTE_READWRITE || memoryInfo.Protect == PAGE_EXECUTE_READ)) {
                printDebug(0, 0, address, 0);
                buffer = (BYTE*)malloc(memoryInfo.RegionSize);
                if (ReadProcessMemory(processHandle, address, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (DWORD i = 0; i < bytesRead - patternSize + 1; ++i) {
                        if (memcmp(buffer + i, pattern, patternSize) == 0) {
                            printf("[+] Process: %lu\n", processId);
                            printf("[+] Cobaltstrike beacon found: 0x%p\n", memoryInfo.BaseAddress);
                            printf("[+] Pattern match at: 0x%p\n", address + i);
                            return;
                        }
                    }
                }
                free(buffer);
            }
        }
    }
}

void printDebug(DWORD processId, HANDLE hProcess, PVOID scanAddress, BOOL failedHandle) {
    if (verbosity) {
        if (processId) {
            printf("[*] Scanning process: %lu\n", processId);
        }
        if (hProcess) {
            printf("[*] Handle acquired: 0x%x\n", hProcess);
        }
        if (scanAddress) {
            printf("[*] Scanning address: %p\n", scanAddress);
        }
        if (failedHandle) {
            printf("[-] Failed to acquire handle: %lu\n", processId);
        }
    }
}

BOOL verbosity = TRUE;
int main()
{
	PROCESSENTRY32 ProcessEntry32;
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (! hSnapShot) {
        return 0;
    }
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
    if (! Process32First( hSnapShot, &ProcessEntry32)) {
        return 0;
    }
    do {
        DWORD patternSize = sizeof(pattern) / sizeof(pattern[0]);
        DWORD patternSize_x64 = sizeof(pattern_x64) / sizeof(pattern_x64[0]);
        DWORD patternSize_x86 = sizeof(pattern_x86) / sizeof(pattern_x86[0]);
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry32.th32ProcessID);
        if (processHandle) {
            printDebug(ProcessEntry32.th32ProcessID, processHandle, 0, 0);
            scanProcessMemory(processHandle, pattern, patternSize, ProcessEntry32.th32ProcessID);
            scanProcessMemory(processHandle, pattern_x64, patternSize_x64, ProcessEntry32.th32ProcessID);
            scanProcessMemory(processHandle, pattern_x86, patternSize_x86, ProcessEntry32.th32ProcessID);
            CloseHandle(processHandle);
        } else {
            printDebug(ProcessEntry32.th32ProcessID, 0, 0, TRUE);
        }
        if (verbosity) {
            printf("\n");
        }
    } while(Process32Next(hSnapShot, &ProcessEntry32));
  return 0;
}
