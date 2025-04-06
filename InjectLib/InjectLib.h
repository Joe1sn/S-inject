// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 INJECTLIB_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// INJECTLIB_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef INJECTLIB_EXPORTS
#define INJECTLIB_API __declspec(dllexport)
#else
#define INJECTLIB_API __declspec(dllimport)
#endif

#include "./app/Injector.h"

#include <iostream>
#include <string>


extern "C" INJECTLIB_API bool rmtdll(const char* proc_name_cstr, DWORD pid);
extern "C" INJECTLIB_API bool refdll(const char* proc_name_cstr, DWORD pid);
extern "C" INJECTLIB_API bool apcdll(const char* proc_name_cstr, DWORD pid);
extern "C" INJECTLIB_API bool net(const char* proc_name_cstr, DWORD pid);
extern "C" INJECTLIB_API bool rmtsc(const char* shellcode, DWORD pid);
extern "C" INJECTLIB_API bool apcsc(const char* shellcode, DWORD pid);
extern "C" INJECTLIB_API bool ctxsc(const char* shellcode, DWORD pid);
extern "C" INJECTLIB_API DWORD getPID(const char* proc_name_cstr);

/*
// 此类是从 dll 导出的
class INJECTLIB_API CInjectLib {
public:
	CInjectLib(void);
	// TODO: 在此处添加方法。
};

extern INJECTLIB_API int nInjectLib;

INJECTLIB_API int fnInjectLib(void);
*/