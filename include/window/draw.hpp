#pragma once
#include <iostream>
#include <Windows.h>

#include "extern/ImGui/imgui.h"
#include "extern/ImGui/imgui_impl_win32.h"
#include "extern/ImGui/imgui_impl_dx11.h"


namespace XInject
{
    namespace Drawer
    {
        void drawCircle(ImU32 color = IM_COL32(128, 128, 128, 255));
    }
}