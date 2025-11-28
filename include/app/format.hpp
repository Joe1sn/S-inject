#pragma once
#include <iostream>
#include <Windows.h>

#include "include/app/Injector.hpp"
#include "include/utils/error.hpp"
typedef struct _PROCESS_BASIC_INFORMATION_MIN
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_MIN;

typedef struct _THREAD_BASIC_INFORMATION_LOCAL
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION_LOCAL;

namespace XInject
{
    namespace Format
    {
        DWORD64 getRemotePebVal(DWORD pid);
        // DWORD64 getRemoteLoadLibrary(HANDLE remoteProcess, DWORD64 pebAddress);
    }

} // namespace XInject