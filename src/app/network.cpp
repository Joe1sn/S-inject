#include "include/app/network.hpp"

namespace XInject
{
    namespace net
    {
        std::string downloadFile(std::string url)
        {
            std::string buffer = "";

            try
            {
                HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                if (hInternet == NULL)
                {
                    throw "";
                }

                HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
                if (hConnect == NULL)
                {
                    throw "";
                }
                char tempBuffer[4096];
                DWORD bytesRead = 0;
                while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0)
                {
                    buffer.append(tempBuffer, bytesRead);
                }
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
            }
            catch (...)
            {
                Error::error(L"Failed Download DLL From URL");
            }
            return buffer;
        }
    }
}
