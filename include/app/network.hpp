#pragma once
#include "include/utils/error.hpp"

#include <iostream>
#include <Windows.h>
#include <wininet.h>

namespace XInject
{
    namespace net
    {
        std::string downloadFile(std::string url);
    }
}