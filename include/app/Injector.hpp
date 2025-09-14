#pragma once
#include "include/utils/query.hpp"
#include "include/utils/crypto.hpp"
#include "include/utils/helper.hpp"
#include "include/app/config.hpp"
#include "include/utils/error.hpp"
#include "include/app/S-Wisper.h"
#include "include/app/network.hpp"

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <sstream>

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

#define STATUS_SUCCESS 0x00000000L

typedef struct _ProcessInfo
{
	DWORD pid;
	std::wstring processName;
} ProcessInfo, *pProcessInfo;

namespace XInject
{
	namespace Injector
	{
		inline fnNtQuerySystemInformation NtQuerySystemInformation = nullptr;
		bool initNtQuery();

		std::vector<ProcessInfo> listInjectable();
		bool isInjectable(DWORD pid);
		DWORD getPidByName(LPCSTR procName);
		bool isFileExists(std::string filePath);

		bool remoteThreadInject(DWORD pid, int mode, std::string args = "");
		bool unInject(DWORD pid, std::string dllName);
		bool reflectInject(DWORD pid, int mode, std::string args = "");
		namespace reflector
		{
			DWORD getOffset(HANDLE Image, CHAR *FuncName);
			DWORD rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
		}
		bool apcInject(DWORD pid, int mode, std::string args = "");
		bool contextInject(DWORD pid, int mode, std::string args = "");

	}

} // namespace XInject