#pragma once

#include "utils/query.hpp"

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define STATUS_SUCCESS 0x00000000L


typedef struct _ProcessInfo
{
	DWORD pid;
	std::wstring processName;
}ProcessInfo, * pProcessInfo;

class Injector
{
public:
	typedef void (Injector::* CallbackFunction)(DWORD pid);	//»Øµ÷º¯Êý

private:
	CallbackFunction callback_;
	std::string DllPath;
	bool exist;

	HMODULE hNtDll;

	fnNtQuerySystemInformation NtQuerySystemInformation;

public:
	Injector(std::string dll_path);
	Injector();
	~Injector();
	void unInject(DWORD pid);

	void remoteThreadInject(DWORD pid);
	void reflectInject(DWORD pid);
	void apcInject(DWORD pid);

	std::vector<ProcessInfo> injectList();

	void shellcodeInject(std::string basedsc, DWORD pid);
	void apcShellcodeInject(std::string basedsc, DWORD pid);
	void contextShellcodeInject(std::string basedsc, DWORD pid);

	void dllPathSetter(std::string dll_path);
	void callBackSetter(CallbackFunction InjecMethod);

private:
	bool bFileExists(std::string filePath);
	bool bPreInjectCheck(DWORD pid);
	bool bInjectable(DWORD pid);
	bool bGetModule(DWORD pid, MODULEENTRY32& result);

	DWORD dwGetOffset(HANDLE Image, CHAR* FuncName);
	DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
};