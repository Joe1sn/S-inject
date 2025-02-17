#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <sstream>
#include <iomanip>

using namespace std;


void set_color(unsigned short forecolor, unsigned short backcolor) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, forecolor | backcolor);
}

void set_normal() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}


void banner() {
    set_color(FOREGROUND_GREEN, FOREGROUND_INTENSITY);
    cout << "\n   _____       _         _           __ " << endl;
    cout << "  / ___/      (_)___    (_)__  _____/ /_" << endl;
    cout << "  \\__ \\______/ / __ \\  / / _ \\/ ___/ __/" << endl;
    cout << " ___/ /_____/ / / / / / /  __/ /__/ /_  " << endl;
    cout << "/____/     /_/_/ /_/_/ /\\___/\\___/\\__/  " << endl;
    cout << "                  /___/                 " << endl;
    cout.flush();
    set_normal();
}

void menu() {
    set_color(FOREGROUND_RED, FOREGROUND_INTENSITY);
#ifdef _WIN64
    cout << "-----------------------------Let SysWisper...    \n";
#else
#ifdef _WIN32

#endif // _WIN32
    cout << "-----------------------------------------------\n";
#endif // _WIN64
    cout << "[1] Remote Thread Injection\n";
    cout << "[2] Reflect DLL Injection\n";
    cout << "[3] APC Dispatch Injection\n";
    cout << "[4] Shellcode Injection\n";
    cout << "[5] APC Shellcode Injection\n";
    cout << "[6] Context Injection\n";
    cout << "[7] List Injectable Process\n";
    cout.flush();
    set_normal();
}