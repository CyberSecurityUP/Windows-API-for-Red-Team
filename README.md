# Windows-API-for-Red-Team

This repository is a compilation of the main Windows APIs for use in PenTest, Red Team operations and Malware Analysis

## CreateToolhelp32Snapshot 

The CreateToolhelp32Snapshot API is commonly used in C++ programming to enumerate processes and modules on Windows systems. Although it is not an API directly related to cybersecurity or pen testing, it can be used to obtain information about running processes, which can be useful in security contexts.

### Code Example 

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

### Code Example

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

## ShellExecuteEx 

The ShellExecuteEx API in C++ is commonly used to launch external applications and perform various file-related operations. While it may not be a direct tool for cybersecurity or penetration testing, it can be used in these fields for scripting or automation tasks, such as opening specific files or URLs as part of an assessment. Here's a simple example of using ShellExecuteEx to open a web page:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    SHELLEXECUTEINFO shellInfo = {0};
    shellInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shellInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shellInfo.lpFile = L"https://www.example.com"; // Replace with the URL you want to open
    shellInfo.lpVerb = L"open";
    shellInfo.nShow = SW_SHOWNORMAL;

    if (ShellExecuteEx(&shellInfo)) {
        WaitForSingleObject(shellInfo.hProcess, INFINITE);
        CloseHandle(shellInfo.hProcess);
        std::cout << "Web page opened successfully!" << std::endl;
    } else {
        std::cerr << "Failed to open the web page. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    return 0;
}
```

In this example, we're using ShellExecuteEx to open a web page (https://www.example.com) using the default web browser. The SEE_MASK_NOCLOSEPROCESS flag is set to obtain a handle to the launched process, and WaitForSingleObject is used to wait for the process to finish.

## GetTokenInformation 

The GetTokenInformation API in C++ is used to retrieve information about a security token associated with a process or thread. It can be valuable in cybersecurity and penetration testing when you need to gather information about the privileges, groups, or other characteristics of a user's access token. Here's an example of how to use GetTokenInformation to retrieve the groups that a user belongs to:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetTokenInformation failed (1). Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    PTOKEN_GROUPS pGroups = reinterpret_cast<PTOKEN_GROUPS>(new BYTE[dwSize]);

    if (!GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        std::cerr << "GetTokenInformation failed (2). Error code: " << GetLastError() << std::endl;
        delete[] pGroups;
        CloseHandle(hToken);
        return 1;
    }

    std::cout << "Token Groups:" << std::endl;
    for (DWORD i = 0; i < pGroups->GroupCount; ++i) {
        SID_NAME_USE sidType;
        WCHAR szName[256];
        DWORD cchName = sizeof(szName) / sizeof(szName[0]);
        if (LookupAccountSidW(NULL, pGroups->Groups[i].Sid, szName, &cchName, NULL, NULL, &sidType)) {
            std::wcout << L"Group " << i + 1 << L": " << szName << std::endl;
        }
    }

    delete[] pGroups;
    CloseHandle(hToken);

    return 0;
}
```

We open the access token associated with the current process using OpenProcessToken.

We first call GetTokenInformation with a NULL buffer to determine the required buffer size (dwSize). Then, we allocate memory for the token information structure based on this size.

We call GetTokenInformation again to retrieve the token groups information.

We iterate through the token groups and use LookupAccountSidW to convert the group's SID to a human-readable name and display it.

## AdjustTokenPrivileges 

The AdjustTokenPrivileges API in C++ is used to enable or disable privileges in an access token. It is commonly used in cybersecurity and penetration testing scenarios when you need to adjust privileges to perform specific actions with elevated permissions. Here's an example of how to use AdjustTokenPrivileges to enable a privilege for the current process:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hToken = NULL;

    // Open the access token for the current process with TOKEN_ADJUST_PRIVILEGES privilege
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Specify the privilege to enable (e.g., SE_DEBUG_NAME)
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    // Prepare the TOKEN_PRIVILEGES structure
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust the token privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
    } else {
        std::cout << "The privilege has been enabled." << std::endl;
    }

    CloseHandle(hToken);
    
    return 0;
}
```

## Toolhelp32ReadProcessMemory 

Toolhelp32ReadProcessMemory is not a standard or recognized Windows API function. It appears to be a misinterpretation or a combination of two separate functions, Toolhelp32Snapshot and ReadProcessMemory, as I mentioned earlier.

If you want to read the memory of a different process for cybersecurity or penetration testing purposes, you can use ReadProcessMemory. Here's an example of how to use ReadProcessMemory to read the memory of another process:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_VM_READ access rights
    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Define a buffer to store the read data
    SIZE_T bytesRead;
    DWORD address = 0x12345678; // Replace with the memory address you want to read
    DWORD buffer;

    // Read memory from the target process
    if (ReadProcessMemory(hProcess, (LPCVOID)address, &buffer, sizeof(DWORD), &bytesRead)) {
        std::cout << "Read value at address " << std::hex << address << ": " << std::dec << buffer << std::endl;
    } else {
        std::cerr << "ReadProcessMemory failed. Error code: " << GetLastError() << std::endl;
    }

    // Close the handle to the target process
    CloseHandle(hProcess);

    return 0;
}

```

## WriteProcessMemory 

The WriteProcessMemory API in C++ is used to write data to the memory of another process. It can be useful in cybersecurity and penetration testing scenarios when you need to modify or inject code into another process. Please be aware that modifying another process's memory can have legal and ethical implications, and you should only use this API responsibly and with proper authorization.

Here's an example of how to use WriteProcessMemory to write a value to the memory of another process:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_VM_WRITE and PROCESS_VM_OPERATION access rights
    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD address = 0x12345678; // Replace with the memory address you want to write to
    DWORD value = 42; // Replace with the value you want to write

    // Write the value to the memory of the target process
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(DWORD), &bytesWritten)) {
        if (bytesWritten == sizeof(DWORD)) {
            std::cout << "Successfully wrote value " << value << " to address " << std::hex << address << std::endl;
        } else {
            std::cerr << "Partial write: " << bytesWritten << " bytes written instead of " << sizeof(DWORD) << std::endl;
        }
    } else {
        std::cerr << "WriteProcessMemory failed. Error code: " << GetLastError() << std::endl;
    }

    // Close the handle to the target process
    CloseHandle(hProcess);

    return 0;
}
```

## WTSEnumerateProcessesEx

WTSEnumerateProcessesEx is an API used to enumerate processes on a Windows Terminal Server. It's typically used for administrative purposes rather than cybersecurity or penetration testing. However, it can be used to gather information about running processes on a remote server, which may be relevant to certain security assessments. To use this API, you'll need to include the wtsapi32.lib library.

Here's an example of how to use WTSEnumerateProcessesEx to list processes on a remote Terminal Server:

### Code Example

C++ 
```
#include <windows.h>
#include <wtsapi32.h>
#include <iostream>

int main() {
    PWTS_PROCESS_INFO_EX pProcessInfo = NULL;
    DWORD dwProcCount = 0;
    
    if (WTSEnumerateProcessesEx(WTS_CURRENT_SERVER_HANDLE, &pProcessInfo, &dwProcCount) != 0) {
        for (DWORD i = 0; i < dwProcCount; ++i) {
            std::wcout << L"Process ID: " << pProcessInfo[i].ProcessId << std::endl;
            std::wcout << L"Session ID: " << pProcessInfo[i].SessionId << std::endl;
            std::wcout << L"Process Name: " << pProcessInfo[i].pProcessName << std::endl;
            std::wcout << L"User Name: " << pProcessInfo[i].pUserSid << std::endl;
            std::wcout << L"--------------------------------------" << std::endl;
        }

        // Free the allocated memory
        WTSFreeMemory(pProcessInfo);
    } else {
        std::cerr << "WTSEnumerateProcessesEx failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    return 0;
}
```

## WTSFreeMemoryEx 

I apologize, but as of my last knowledge update in September 2021, there is no standard Windows API function named WTSFreeMemoryEx. Therefore, I cannot provide a C++ code example for this specific API.

It's possible that such an API was introduced in a newer version of Windows or as part of a third-party library. If you have specific information about WTSFreeMemoryEx or its intended usage, please provide more details, and I'll do my best to assist you with a code example.

### Code Example

C++ 
```
BOOL WTSFreeMemoryExA(
  [in] WTS_TYPE_CLASS WTSTypeClass,
  [in] PVOID          pMemory,
  [in] ULONG          NumberOfEntries
);
```

## LookupPrivilegeValue 

The LookupPrivilegeValue API in C++ is used to retrieve the locally unique identifier (LUID) that represents a privilege name on a system. This API can be helpful in cybersecurity and penetration testing when you need to work with privileges, such as enabling or disabling them for a process. Here's an example of how to use LookupPrivilegeValue to retrieve the LUID for a privilege:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cout << "LUID for SE_DEBUG_NAME: " << std::dec << luid.LowPart << ":" << luid.HighPart << std::endl;
    } else {
        std::cerr << "LookupPrivilegeValue failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    return 0;
}
```

We call LookupPrivilegeValue to retrieve the LUID for the privilege named SE_DEBUG_NAME. This privilege is often used in debugging scenarios and is an example privilege name.

If the function succeeds, it returns the LUID for the specified privilege, which consists of two parts: LowPart and HighPart. We print these values using std::cout.

If LookupPrivilegeValue fails, we print an error message with the error code obtained from GetLastError().

## GetCurrentProcess 

The GetCurrentProcess API in C++ is a simple function used to obtain a handle to the current process. While it may not have a direct application in cybersecurity or penetration testing, it can be used to gather information about the current process or to perform certain operations on it. Here's a basic example of how to use GetCurrentProcess:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hProcess = GetCurrentProcess();

    if (hProcess == NULL) {
        std::cerr << "GetCurrentProcess failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Handle to the current process: " << hProcess << std::endl;

    // Do further operations with the process handle if needed

    // Close the handle when done with it
    CloseHandle(hProcess);

    return 0;
}
```

## OpenProcessToken

The OpenProcessToken API in C++ is commonly used in cybersecurity and penetration testing when you need to obtain a handle to the access token associated with a process. Access tokens contain information about a user's security context, including their privileges, groups, and user rights. Here's an example of how to use OpenProcessToken:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess, hToken;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_QUERY_INFORMATION access rights
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Open the access token associated with the target process
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Use the access token as needed (e.g., querying privileges or groups)

    // Close the process and token handles when done
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return 0;
}
```

## LookupAccountSid

The LookupAccountSid API in C++ is used to convert a security identifier (SID) into a user or group name. This API can be helpful in cybersecurity and penetration testing when you need to identify the user or group associated with a SID. Here's an example of how to use LookupAccountSid:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>
#include <sddl.h>

int main() {
    // Replace this string with the SID you want to look up
    LPCWSTR sidString = L"S-1-5-21-3623811015-3361044348-30300820-1013";

    PSID pSid = NULL;
    if (!ConvertStringSidToSidW(sidString, &pSid)) {
        std::cerr << "ConvertStringSidToSidW failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    WCHAR szName[MAX_PATH];
    DWORD cchName = sizeof(szName) / sizeof(szName[0]);
    WCHAR szDomain[MAX_PATH];
    DWORD cchDomain = sizeof(szDomain) / sizeof(szDomain[0]);
    SID_NAME_USE sidType;

    if (LookupAccountSidW(NULL, pSid, szName, &cchName, szDomain, &cchDomain, &sidType)) {
        std::wcout << L"User/Group Name: " << szDomain << L"\\" << szName << std::endl;
    } else {
        std::cerr << "LookupAccountSidW failed. Error code: " << GetLastError() << std::endl;
    }

    LocalFree(pSid);

    return 0;
}
```

## ConvertSidToStringSidA 

The ConvertSidToStringSidA API in C++ is used to convert a security identifier (SID) into its string representation. This can be useful in cybersecurity and penetration testing when you need to display or manipulate SIDs in a human-readable format. Here's an example of how to use ConvertSidToStringSidA:


### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    // Replace this string with the SID you want to convert
    const char* sidString = "S-1-5-21-3623811015-3361044348-30300820-1013";

    PSID pSid = NULL;
    if (!ConvertStringSidToSidA(sidString, &pSid)) {
        std::cerr << "ConvertStringSidToSidA failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    LPSTR stringSid = NULL;
    if (ConvertSidToStringSidA(pSid, &stringSid)) {
        std::cout << "String representation of SID: " << stringSid << std::endl;
        LocalFree(stringSid); // Free the allocated memory
    } else {
        std::cerr << "ConvertSidToStringSidA failed. Error code: " << GetLastError() << std::endl;
    }

    LocalFree(pSid); // Free the SID structure

    return 0;
}
```

## MessageBoxA

The MessageBoxA API in C++ is used to display a message box dialog on the Windows operating system. While it's not a direct tool for cybersecurity or penetration testing, message boxes can be used for various purposes, including displaying alerts or information during testing. Here's an example of how to use MessageBoxA to display a simple message box:

### Code Example

C++ 
```
#include <windows.h>

int main() {
    // Display a message box with a "Hello, World!" message
    MessageBoxA(NULL, "Hello, World!", "Message Box Example", MB_OK | MB_ICONINFORMATION);

    return 0;
}
```

## HookedMessageBox 

Creating a HookedMessageBox API from scratch would involve implementing a custom message box function with hooking techniques, which can be quite complex. Hooking is a technique used to intercept and alter the behavior of existing functions. It's a specialized topic in the field of software development, and it is often used for debugging, monitoring, or customizing system behavior.

Below is a simplified example of how you might use function hooking to intercept and modify the behavior of the MessageBoxA function. Note that this example demonstrates the concept of hooking and is not suitable for cybersecurity or penetration testing purposes:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

// Function pointer type for the original MessageBoxA function
typedef int(WINAPI* MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);

// Function pointer to store the address of the original MessageBoxA function
MessageBoxAType originalMessageBoxA;

// Custom MessageBoxA function that intercepts and modifies the behavior
int WINAPI CustomMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Modify the message or behavior here
    std::cout << "Intercepted MessageBoxA:" << std::endl;
    std::cout << "Text: " << lpText << std::endl;
    std::cout << "Caption: " << lpCaption << std::endl;

    // Call the original MessageBoxA function
    return originalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

int main() {
    // Get the address of the original MessageBoxA function
    HMODULE user32Module = GetModuleHandle(L"user32.dll");
    if (user32Module != NULL) {
        originalMessageBoxA = reinterpret_cast<MessageBoxAType>(GetProcAddress(user32Module, "MessageBoxA"));
    }

    // Check if we successfully obtained the original function pointer
    if (originalMessageBoxA == NULL) {
        std::cerr << "Failed to obtain the address of MessageBoxA." << std::endl;
        return 1;
    }

    // Set our custom MessageBoxA function as the hook
    MessageBoxAType customMessageBoxA = CustomMessageBoxA;
    originalMessageBoxA = reinterpret_cast<MessageBoxAType>(
        SetWindowsHookEx(WH_CBT, reinterpret_cast<HOOKPROC>(customMessageBoxA), NULL, GetCurrentThreadId())
    );

    if (originalMessageBoxA == NULL) {
        std::cerr << "Failed to set the hook." << std::endl;
        return 1;
    }

    // Trigger a MessageBoxA call to see the interception
    MessageBoxA(NULL, "Hello, World!", "Original MessageBoxA", MB_OK);

    // Remove the hook
    UnhookWindowsHookEx(reinterpret_cast<HHOOK>(originalMessageBoxA));

    return 0;
}
```

We define a custom MessageBoxA function (CustomMessageBoxA) that intercepts and modifies the behavior of the original MessageBoxA function. In this case, it simply prints the message and caption to the console and then calls the original function.

We obtain the address of the original MessageBoxA function using GetProcAddress.

We use the SetWindowsHookEx function to set our custom function as a hook for MessageBoxA. This intercepts calls to MessageBoxA and directs them to our custom function.

We call MessageBoxA to trigger the hook and demonstrate the interception.

Finally, we remove the hook using UnhookWindowsHookEx.

## GetProcAddress 

The GetProcAddress API in C++ is used to retrieve the address of an exported function or variable in a dynamic-link library (DLL) or executable (EXE). It can be used in cybersecurity and penetration testing to inspect the available functions and potentially find vulnerabilities or weaknesses in a target application. Here's an example of how to use GetProcAddress:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    // Replace these values with the target DLL and function names
    const char* dllName = "user32.dll";
    const char* functionName = "MessageBoxA";

    // Load the target DLL
    HMODULE hModule = LoadLibraryA(dllName);

    if (hModule == NULL) {
        std::cerr << "Failed to load the DLL. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Get the address of the function
    FARPROC functionAddress = GetProcAddress(hModule, functionName);

    if (functionAddress == NULL) {
        std::cerr << "Failed to get the address of the function. Error code: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    std::cout << "Address of " << functionName << " in " << dllName << ": " << functionAddress << std::endl;

    // Free the loaded DLL
    FreeLibrary(hModule);

    return 0;
}
```

## CreateProcessA

The CreateProcessA API in C++ is commonly used to create a new process. It can be useful in cybersecurity and penetration testing when you need to launch a new process, such as running external tools or executing commands on the system. Here's an example of how to use CreateProcessA:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    // Replace these values with the path to the executable and command-line arguments
    const char* executablePath = "C:\\Path\\To\\YourProgram.exe";
    const char* commandLineArgs = ""; // Optional command-line arguments

    // Structure for process information
    PROCESS_INFORMATION pi;
    
    // Structure for startup information
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);

    if (CreateProcessA(
        NULL,               // Use the application name from the command line
        (LPSTR)executablePath, // Path to the executable
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        0,                  // No creation flags
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory 
        &si,                // Pointer to STARTUPINFO structure
        &pi                 // Pointer to PROCESS_INFORMATION structure
    )) {
        std::cout << "Process created successfully!" << std::endl;
        std::cout << "Process ID: " << pi.dwProcessId << std::endl;
        
        // Close process and thread handles to avoid resource leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "CreateProcessA failed. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    return 0;
}
```

Replace executablePath with the path to the executable you want to run, and commandLineArgs with any optional command-line arguments.

We define a STARTUPINFOA structure to provide information about how the process should be started, and a PROCESS_INFORMATION structure to receive information about the newly created process.

We call CreateProcessA with the specified executable path and command-line arguments. If successful, it creates a new process and returns information about it in the PROCESS_INFORMATION structure.

We print the process ID (PID) of the newly created process to the console.

Finally, we close the process and thread handles to avoid resource leaks.

## OpenProcess

The OpenProcess API in C++ is used to obtain a handle to an existing process. It can be useful in cybersecurity and penetration testing when you need to interact with or manipulate other running processes on a Windows system. Here's an example of how to use OpenProcess:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_QUERY_INFORMATION access rights
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Successfully opened the target process with handle: " << hProcess << std::endl;

    // Perform operations on the target process as needed

    // Close the handle when done with it
    CloseHandle(hProcess);

    return 0;
}
```

## DuplicateHandle

The DuplicateHandle API in C++ is used to duplicate a handle to an object such as a process, thread, or file. This can be useful in cybersecurity and penetration testing when you need to share handles between processes or perform specific operations on the duplicated handle without affecting the original one. Here's an example of how to use DuplicateHandle:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hProcess; // Replace with the source process handle
    HANDLE hDuplicateProcess = NULL;

    // Replace 'hProcess' with the source process handle you want to duplicate
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());

    if (hProcess == NULL) {
        std::cerr << "Failed to open the source process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Duplicate the handle
    if (DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hDuplicateProcess, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        std::cout << "Handle duplicated successfully!" << std::endl;
        
        // Perform operations using the duplicated handle (hDuplicateProcess) as needed

        // Close the duplicated handle when done with it
        CloseHandle(hDuplicateProcess);
    } else {
        std::cerr << "DuplicateHandle failed. Error code: " << GetLastError() << std::endl;
    }

    // Close the source process handle
    CloseHandle(hProcess);

    return 0;
}
```

Replace hProcess with the source process handle that you want to duplicate. In this example, we use OpenProcess to obtain the handle of the current process as an example.

We call OpenProcess to open the source process with PROCESS_QUERY_INFORMATION access rights. You should adjust the access rights and obtain the source process handle according to your specific needs.

We check if the OpenProcess function was successful in obtaining a handle to the source process. If it fails, we print an error message with the error code from GetLastError().

We use DuplicateHandle to duplicate the handle of the source process (hProcess) into the current process (GetCurrentProcess()). The duplicated handle is stored in hDuplicateProcess.

If DuplicateHandle succeeds, it duplicates the handle, and we can use the duplicated handle (hDuplicateProcess) to perform operations on the source process as needed.

Finally, we close both the source process handle (hProcess) and the duplicated handle (hDuplicateProcess) when done with them to release associated resources.

## VirtualAllocEx

The VirtualAllocEx API in C++ is used to allocate memory within the address space of a specified process. This can be useful in cybersecurity and penetration testing when you need to allocate memory in another process for various purposes, such as code injection or memory analysis. Here's an example of how to use VirtualAllocEx:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hProcess; // Replace with the target process handle
    LPVOID lpBaseAddress = NULL; // Request any available address
    SIZE_T dwSize = 4096; // Allocate 4 KB (adjust as needed)
    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_EXECUTE_READWRITE; // Adjust protection as needed

    // Replace 'hProcess' with the target process handle you want to allocate memory in
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234); // Replace '1234' with the target process ID

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    LPVOID lpRemoteBuffer = VirtualAllocEx(hProcess, lpBaseAddress, dwSize, flAllocationType, flProtect);

    if (lpRemoteBuffer == NULL) {
        std::cerr << "VirtualAllocEx failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Memory allocated successfully in the target process at address: " << lpRemoteBuffer << std::endl;

    // Perform operations using the allocated memory in the target process as needed

    // Free the allocated memory when done
    VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);

    // Close the target process handle
    CloseHandle(hProcess);

    return 0;
}
```

## VirtualProtectEx

The VirtualProtectEx API in C++ is used to change the protection attributes of a region of memory within the address space of a specified process. This can be useful in cybersecurity and penetration testing when you need to modify the protection attributes of memory in another process for various purposes, such as code injection or memory manipulation. Here's an example of how to use VirtualProtectEx:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hProcess; // Replace with the target process handle
    LPVOID lpAddress = nullptr; // Address of the memory region to protect
    SIZE_T dwSize = 4096; // Size of the memory region (adjust as needed)
    DWORD flNewProtect = PAGE_EXECUTE_READWRITE; // New protection attributes

    // Replace 'hProcess' with the target process handle you want to modify memory protection in
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234); // Replace '1234' with the target process ID

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    if (VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, nullptr)) {
        std::cout << "Memory protection attributes modified successfully." << std::endl;

        // Perform operations on the protected memory as needed

        // Restore the original protection attributes if necessary
        DWORD flOldProtect;
        VirtualProtectEx(hProcess, lpAddress, dwSize, flOldProtect, nullptr);
    } else {
        std::cerr << "VirtualProtectEx failed. Error code: " << GetLastError() << std::endl;
    }

    // Close the target process handle
    CloseHandle(hProcess);

    return 0;
}
```

## SetThreadContext

The SetThreadContext API in C++ is used to set the context of a specified thread, which includes register values and flags. This can be useful in cybersecurity and penetration testing for various purposes, such as modifying the behavior of a thread or altering the execution flow within a target process. However, it's important to note that using this API for unauthorized or malicious purposes can have serious legal and ethical implications. Here's an example of how to use SetThreadContext:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess, hThread;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_ALL_ACCESS access rights
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Open a thread within the target process (e.g., the primary thread)
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()); // Replace with the target thread ID

    if (hThread == NULL) {
        std::cerr << "Failed to open the target thread. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Define a CONTEXT structure to store the thread context
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL; // Retrieve full context

    // Get the current context of the target thread
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "GetThreadContext failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Modify the context as needed
    // For example, you can change register values or flags in the 'context' structure here

    // Set the modified context back to the target thread
    if (!SetThreadContext(hThread, &context)) {
        std::cerr << "SetThreadContext failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Thread context modified successfully." << std::endl;

    // Close handles when done
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

## QueueUserAPC

The QueueUserAPC (Asynchronous Procedure Call) API in C++ is used to queue a user-defined function to be executed within the address space of a specified thread. This can be useful in cybersecurity and penetration testing when you need to inject and execute code within a target process for various purposes. However, please be aware that manipulating remote processes without proper authorization can have serious legal and ethical implications. Here's an example of how to use QueueUserAPC:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

// Define a custom APC function to be executed within the target thread
VOID CALLBACK CustomAPCFunction(ULONG_PTR dwParam) {
    // Code to be executed within the target thread
    std::cout << "Custom APC function executed within the target thread." << std::endl;
}

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess, hThread;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_ALL_ACCESS access rights
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Open a thread within the target process (e.g., the primary thread)
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()); // Replace with the target thread ID

    if (hThread == NULL) {
        std::cerr << "Failed to open the target thread. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Queue the custom APC function to be executed within the target thread
    if (QueueUserAPC(CustomAPCFunction, hThread, 0)) {
        std::cout << "APC function queued successfully." << std::endl;

        // Trigger the APC by suspending and resuming the target thread
        SuspendThread(hThread);
        ResumeThread(hThread);
    } else {
        std::cerr << "QueueUserAPC failed. Error code: " << GetLastError() << std::endl;
    }

    // Close handles when done
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

## CreateRemoteThread 

The CreateRemoteThread API in C++ is used to create a new thread within the address space of a specified remote process, allowing you to inject and execute code within that process. This can be useful in cybersecurity and penetration testing when you need to manipulate or analyze the behavior of a target process. However, please be aware that manipulating remote processes without proper authorization can have serious legal and ethical implications. Here's an example of how to use CreateRemoteThread:

### Code Example

C++ 
```
#include <windows.h>
#include <iostream>

int main() {
    DWORD processId; // Replace with the target process ID
    HANDLE hProcess;

    // Replace 'processId' with the PID of the target process
    processId = 1234; // Example PID

    // Open the target process with PROCESS_ALL_ACCESS access rights
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Define the code to be executed within the target process
    // In this example, we create a simple thread that displays a message box
    const char* codeToInject = R"(
        #include <windows.h>
        int main() {
            MessageBoxA(NULL, "Injected Code", "Injection Example", MB_ICONINFORMATION);
            return 0;
        }
    )";

    // Allocate memory within the target process for the code
    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, strlen(codeToInject) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (pRemoteCode == NULL) {
        std::cerr << "Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Write the code to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteCode, codeToInject, strlen(codeToInject) + 1, NULL)) {
        std::cerr << "Failed to write code to the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread within the target process to execute the code
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);

    if (hRemoteThread == NULL) {
        std::cerr << "Failed to create a remote thread in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Remote thread created successfully." << std::endl;

    // Wait for the remote thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Close handles when done
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
```
