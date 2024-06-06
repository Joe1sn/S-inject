#pragma once

#include "error.hpp"

#include <iostream>
#include <Windows.h>
#include <vector>

namespace Crypto {
    std::string Base64Decode(std::string EncodedStr) {
        DWORD decodedSize = 0;

        // 获取解码后的数据大小
        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
            Error::WarnMsgBox(L"CryptStringToBinary failed");
            return "";
        }

        std::vector<BYTE> decodedData(decodedSize);

        // 解码
        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, decodedData.data(), &decodedSize, nullptr, nullptr)) {
            Error::WarnMsgBox(L"CryptStringToBinary failed");
            return "";
        }
        return std::string(decodedData.begin(), decodedData.end());
    }
}