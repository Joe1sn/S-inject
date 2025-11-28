#include "include/app/format.hpp"
using namespace XInject::Injector;
namespace XInject
{
    namespace Format
    {
        // 获得远程进程的peb
        //  0xFFFFFFFFFFFFFFFF : 错误
        DWORD64 getRemotePebVal(DWORD pid)
        {
            DWORD64 result = 0;
            if (Injector::NtQueryInformationProcess == nullptr)
                Injector::initNtQuery();
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProcess == INVALID_HANDLE_VALUE)
                return -1;

            PROCESS_BASIC_INFORMATION pbi;
            ULONG returnLength = 0;

            NTSTATUS status = Injector::NtQueryInformationProcess(
                hProcess,
                ProcessBasicInformation, // 获取 PEB 地址
                &pbi,
                sizeof(pbi),
                &returnLength);

            if (status != 0)
                return -1;

            return reinterpret_cast<DWORD64>(pbi.PebBaseAddress);
        }

        // 通过远程进程的peb获得远程进程的loadlibrary
        // DWORD64 getRemoteLoadLibrary(HANDLE remoteProcess, DWORD64 pebAddr)
        // {
        //     if (remoteProcess == INVALID_HANDLE_VALUE)
        //         return -1;
        //     PEB peb = {0};
        //     ReadProcessMemory(remoteProcess, reinterpret_cast<LPCVOID>(pebAddr), &peb, sizeof(peb), nullptr);

        //     PEB_LDR_DATA ldr = {0};
        //     ReadProcessMemory(remoteProcess, peb.Ldr, &ldr, sizeof(ldr), nullptr);

        //     // 3. 遍历模块链表，找到 kernel32.dll 基址
        //     LIST_ENTRY *head = (LIST_ENTRY *)((BYTE *)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList));
        //     LIST_ENTRY curr = {0};
        //     ReadProcessMemory(remoteProcess, head, &curr, sizeof(curr), nullptr);

        //     while (curr.Flink != head)
        //     {
        //         LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        //         ReadProcessMemory(remoteProcess, curr.Flink, &ldrEntry, sizeof(ldrEntry), nullptr);

        //         WCHAR moduleName[MAX_PATH];
        //         ReadProcessMemory(remoteProcess, ldrEntry.BaseDllName.Buffer, moduleName,
        //                           ldrEntry.BaseDllName.Length, nullptr);

        //         if (_wcsicmp(moduleName, L"kernel32.dll") == 0)
        //         {
        //             PVOID kernel32Base = ldrEntry.DllBase;
        //             break;
        //         }
        //         curr = *ldrEntry.InLoadOrderLinks.Flink;
        //     }
        // }

    }

} // namespace XInject