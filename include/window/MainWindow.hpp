#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>

#include "extern/ImGui/imgui.h"
#include "extern/ImGui/imgui_impl_win32.h"
#include "extern/ImGui/imgui_impl_dx11.h"

#include "include/utils/constant.hpp"
#include "include/app/Injector.hpp"
#include "include/app/format.hpp"
#include "include/utils/crypto.hpp"
#include "include/window/draw.hpp"

using namespace XInject::constant;

namespace XInject
{
    namespace MainWindow
    {
        inline bool mainwndOpen = true;
        inline bool debugWnd = false;
        inline int method;
        inline int poolpartyMethod; //max = 7
        inline bool needSeDebug;
        inline int type;
        inline int pid;
        inline DWORD chosenPid;

        enum class TestState { Pending, Running, Success, Failed };
        inline TestState testStates[5] = { TestState::Pending };
        inline bool testAllRunning = false;

        static char args[constant::maxStrSize] = {};
        bool setupUi();
        void doInject();
        void doTestAll();
    } // namespace MainWindow

} // namespace XInject
