# Windows-API-for-Red-Team

This repository is a compilation of the main Windows APIs for use in PenTest, Red Team operations and Malware Analysis

## CreateToolhelp32Snapshot 

The CreateToolhelp32Snapshot API is commonly used in C++ programming to enumerate processes and modules on Windows systems. Although it is not an API directly related to cybersecurity or pen testing, it can be used to obtain information about running processes, which can be useful in security contexts.

### Example Code

C++ 
```
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int main() {
    //Create a snapshot of running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Erro ao criar o snapshot: " << GetLastError() << std::endl;
        return 1;
    }

    // Structure for storing information about a process
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Initialize the loop to enumerate the processes
    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::cout << "Processo ID: " << pe32.th32ProcessID << std::endl;
            std::cout << "Nome do processo: " << pe32.szExeFile << std::endl;
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        std::cerr << "Erro ao enumerar processos: " << GetLastError() << std::endl;
    }

    // Close the snapshot
    CloseHandle(hSnapshot);

    return 0;
}
```

## GetModuleFileName

The GetModuleFileName API in C++ is typically used to retrieve the full path of the executable file of a running process. While it may not be directly related to cybersecurity or penetration testing, it can be useful in those fields to gather information about the running processes on a system.

Here's a simple C++ code example that demonstrates how to use the GetModuleFileName API to retrieve the full path of the executable for a specified process using its Process ID (PID). This information can be valuable in security auditing and process monitoring scenarios.

### Example Code

C++
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access rights
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    char szPath[MAX_PATH];
    DWORD dwSize = GetModuleFileNameExA(hProcess, NULL, szPath, MAX_PATH);

    if (dwSize == 0) {
        std::cerr << "Failed to get module filename. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Full path of the executable: " << szPath << std::endl;

    // Close the process handle
    CloseHandle(hProcess);

    return 0;
}
```
