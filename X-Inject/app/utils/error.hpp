#pragma once
#include <iostream>
#include <Windows.h>

namespace Error {

    extern std::wstring GetLastErrorAsString() {

        DWORD errorMessageID = ::GetLastError();
        if (errorMessageID == 0) {
            return L"";
        }

        LPWSTR messageBuffer = nullptr;
        size_t size = FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

        std::wstring message(messageBuffer, size);
        LocalFree(messageBuffer);

        return message;
    }

    void ErrorMsgBox(std::wstring hint) {
        std::wstring errorMessage = GetLastErrorAsString();
        if(errorMessage == L"")
            MessageBox(NULL, hint.c_str(), L"Error", MB_OK | MB_ICONERROR);
        else
            MessageBox(NULL, (hint + L"\n" + errorMessage).c_str(), L"Error", MB_OK | MB_ICONERROR);
    }

    void WarnMsgBox(std::wstring message) {
        MessageBox(NULL, message.c_str(), L"Error", MB_OK | MB_ICONWARNING);

    }


}

