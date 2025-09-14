#pragma once
#include <iostream>
#include <Windows.h>

#include "include/app/config.hpp"

namespace Error
{

    extern std::wstring GetLastErrorAsString();
    void ErrorMsgBox(std::wstring hint);
    void WarnMsgBox(std::wstring message);

    void error(std::wstring msg);
    void warn(std::wstring msg);

}
