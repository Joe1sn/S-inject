#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>

#include "include/utils/error.hpp"

namespace XInject
{
    std::string ReadFileToString(const std::string &filename);
    std::string ReadFileToStringW(const std::wstring &filename);
} // namespace XInject