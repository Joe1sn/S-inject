#include "Injector.h"

#include "ext/imgui/imgui.h"
#include "ext/imgui/imgui_impl_dx11.h"
#include "ext/imgui/imgui_impl_win32.h"
#include <iostream>
#include <Windows.h>
#include <functional>

namespace MainInjector {
	inline Injector injector;
	VOID InjectDLL(const char Title[], std::function<void(DWORD)>injectMenthod);
	VOID InjectShellcode(const char Title[], std::function<void(string, DWORD)>injectMenthod);
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