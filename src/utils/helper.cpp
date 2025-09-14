#include "include/utils/helper.hpp"

namespace XInject
{
    std::string ReadFileToString(const std::string &filename)
    {
        HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        std::string buffer = "";
        if (hFile == INVALID_HANDLE_VALUE)
        {
            Error::error(L"Create File Failed");
            return buffer;
        }
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        DWORD dwReadSize = 0;
        if (dwFileSize == 0)
        {
            Error::error(L"File Size is Zero!");
            CloseHandle(hFile);
            return buffer;
        }

        std::vector<char> tempBuffer(dwFileSize);
        if (::ReadFile(hFile, tempBuffer.data(), dwFileSize, &dwReadSize, NULL) == FALSE)
        {
            Error::error(L"Failed to read the file.");
            CloseHandle(hFile);
            return buffer;
        }
        buffer.assign(tempBuffer.begin(), tempBuffer.end());
        CloseHandle(hFile);

        return buffer;
    }

    std::string ReadFileToStringW(const std::wstring &filename)
    {
        HANDLE hFile = CreateFileW(filename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        std::string buffer = "";
        if (hFile == INVALID_HANDLE_VALUE)
        {
            Error::error(L"Create File Failed");
            return buffer;
        }
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        DWORD dwReadSize = 0;
        if (dwFileSize == 0)
        {
            Error::error(L"File Size is Zero!");
            CloseHandle(hFile);
            return buffer;
        }

        std::vector<char> tempBuffer(dwFileSize);
        if (::ReadFile(hFile, tempBuffer.data(), dwFileSize, &dwReadSize, NULL) == FALSE)
        {
            Error::error(L"Failed to read the file.");
            CloseHandle(hFile);
            return buffer;
        }
        buffer.assign(tempBuffer.begin(), tempBuffer.end());
        return buffer;
    }
} // namespace XInject