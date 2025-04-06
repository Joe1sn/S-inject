#pragma once

#include <iostream>
#include <Windows.h>
#include <vector>
#include <wincrypt.h>


namespace Crypto {
    std::string Base64Decode(std::string EncodedStr) {
        DWORD decodedSize = 0;

        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
            return "";
        }

        std::vector<BYTE> decodedData(decodedSize);

        if (!CryptStringToBinaryA(EncodedStr.c_str(), 0, CRYPT_STRING_BASE64, decodedData.data(), &decodedSize, nullptr, nullptr)) {
            return "";
        }
        return std::string(decodedData.begin(), decodedData.end());
    }

    std::string Base64Encode(const std::vector<BYTE>& data) {
        DWORD encodedSize = 0;
        if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedSize)) {
            return "";
        }

        std::vector<char> encodedData(encodedSize);
        if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encodedData.data(), &encodedSize)) {
            return "";
        }

        return std::string(encodedData.data(), encodedSize);
    }
}