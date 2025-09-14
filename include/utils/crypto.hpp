#pragma once

#include <iostream>
#include <Windows.h>
#include <vector>
#include "include/app/config.hpp"
#include "include/utils/error.hpp"

namespace XInject
{
    namespace Crypto
    {
        std::string Base64Decode(std::string EncodedStr);
        std::string Base64Encode(const std::vector<BYTE> &data);
        std::string WstringToUTF8(const std::wstring &wstr);
    }
}