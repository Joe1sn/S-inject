#pragma once
#include "./Injector.h"

#include <Windows.h>
#include <functional>
#include <iostream>

namespace MainWindow {
	inline Injector injector;
	inline std::vector<ProcessInfo> procInfoList;
	inline std::vector<ProcessInfo> procInfoInject;


	inline bool bWindowOpen = true;
	inline bool bRemoteThreadDll = false;
	inline bool bRefelectDll = false;
	inline bool bApcDll = false;
	inline bool bInjectSc = false;
	inline bool bApcSc = false;
	inline bool bContextSc = false;
	inline bool bList = false;
	inline bool bIninject = false;
	
	inline bool chooseDllPID = false;
	inline bool chooseShellcodePID = false;

	inline DWORD gDllPID = 0;
	inline DWORD gShellcodePID = 0;

	VOID InitWindow();
	VOID Dispatcher();

	//modName: DLL/Shellcode
	//VOID Inject(std::string modName, const char Title[], std::function<void(DWORD)>injectMenthod);
	VOID InjectDLL(const char Title[], std::function<void(DWORD)>injectMenthod);
	VOID InjectShellcode(const char Title[], std::function<void(std::string, DWORD)>injectMenthod);
	VOID RemoteDLL();
	VOID ReflectDLL();
	VOID ApcDLL();
	VOID RemoteShellcode();
	VOID ApcShellcode();
	VOID ContextShellcode();
	VOID DllList();
	VOID UnInject();
	DWORD GetPID();
}

