#pragma once
#include <Windows.h>
#include <iostream>

extern float fWidth;
extern float fHeight;

typedef struct _ProcessInfo
{
	DWORD pid;
	std::wstring processName;
}ProcessInfo, * pProcessInfo;