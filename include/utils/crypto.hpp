#pragma once

#include "error.hpp"

#include <iostream>
#include <Windows.h>
#include <vector>

namespace Crypto
{
    std::string Base64Decode(std::string EncodedStr)
    {
        DWORD decodedSize = 0;
        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr))
        {
            Error::WarnMsgBox(L"CryptStringToBinary failed");
            return "";
        }

        std::vector<BYTE> decodedData(decodedSize);

        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, decodedData.data(), &decodedSize, nullptr, nullptr))
        {
            Error::WarnMsgBox(L"CryptStringToBinary failed");
            return "";
        }
        return std::string(decodedData.begin(), decodedData.end());
    }

    std::string Base64Encode(const std::vector<BYTE> &data)
    {
        DWORD encodedSize = 0;
        if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedSize))
        {
            Error::WarnMsgBox(L"Error calculating encoded size");
            return "";
        }

        std::vector<char> encodedData(encodedSize);
        if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encodedData.data(), &encodedSize))
        {
            Error::WarnMsgBox(L"Error encoding data to Base64");
            return "";
        }

        return std::string(encodedData.data(), encodedSize);
    }
}