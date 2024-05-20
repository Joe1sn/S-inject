#pragma once
#include "global.h"

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>

using std::string;

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define STATUS_SUCCESS 0x00000000L



class Injector
{
public:
	typedef void (Injector::* CallbackFunction)(DWORD pid);	//»Øµ÷º¯Êý
private:
	string DllPath;
	bool exist;
	CallbackFunction callback_;
	bool brutalmod;

public:
	Injector(string dll_path);
	Injector();
	~Injector();
	void unInject(DWORD pid);
	void unReflectInject(DWORD pid);
	void unApcInject(DWORD pid);

	void RemoteThreadInject(DWORD pid);
	void ReflectInject(DWORD pid);
	void ApcInject(DWORD pid);

	void Injectable();
	std::vector<ProcessInfo> InjectList();

	void ShellcodeInject(string basedsc, DWORD pid);
	void ApcShellcodeInject(string basedsc, DWORD pid);
	void ContextShellcodeInject(string basedsc, DWORD pid);

	DWORD GetPidName(char name[]);
	void DllPathsetter(string dll_path);
	void CallBackSetter(CallbackFunction InjecMethod);
	void BrutalSetter(bool crazy);

private:
	bool bFileExists(string filePath);
	bool bInjectable(DWORD pid);
	bool bGetModule(DWORD pid, MODULEENTRY32& result);

	DWORD dwGetOffset(HANDLE Image, CHAR* FuncName);
	DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
};

