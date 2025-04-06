// InjectLib.cpp : 定义 DLL 的导出函数。
//

#include "pch.h"
#include "framework.h"
#include "InjectLib.h"

//远程线程注入DLL
INJECTLIB_API bool rmtdll(const char* dllPath, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector(dllPath);
    injector.remoteThreadInject(pid);
    return true;
}

//反射式注入DLL
INJECTLIB_API bool refdll(const char* dllPath, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector(dllPath);
    injector.reflectInject(pid);
    return true;
}
//APC队列注入DLL
INJECTLIB_API bool apcdll(const char* dllPath, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector(dllPath);
    injector.apcInject(pid);
    return true;
}
//从网络加载DLL注入DLL
INJECTLIB_API bool net(const char* dllPath, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector(dllPath);
    injector.internetInject(pid, dllPath);
    return true;
}
//远程线程注入Shellcode
INJECTLIB_API bool rmtsc(const char* shellcode, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector();
    injector.shellcodeInject(shellcode, pid);
    return true;
}
//APC队列注入Shellcode
INJECTLIB_API bool apcsc(const char* shellcode, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector();
    injector.apcShellcodeInject(shellcode, pid);
    return true;
}
//上下文注入Shellcode
INJECTLIB_API bool ctxsc(const char* shellcode, DWORD pid) {
    if (pid == 0)
        return false;
    auto injector = Injector();
    injector.contextShellcodeInject(shellcode, pid);
    return true;
}

//上下文注入Shellcode
INJECTLIB_API DWORD getPID(const char* proc_name_cstr) {
    auto injector = Injector();
    return injector.getPidByName(proc_name_cstr);
}

/*
// 这是导出变量的一个示例
INJECTLIB_API int nInjectLib=0;

// 这是导出函数的一个示例。
INJECTLIB_API int fnInjectLib(void)
{
    return 0;
}

// 这是已导出类的构造函数。
CInjectLib::CInjectLib()
{
    return;
}
*/