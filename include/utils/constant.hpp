#pragma once
#include <iostream>
#include <windows.h>
#include "extern/ImGui/imgui.h"

namespace XInject
{
    namespace constant
    {
        constexpr unsigned int maxStrSize = 0x1000;

        // 创建铺满窗口的标志组合
        inline ImGuiWindowFlags fullWindowFlags =
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoNavFocus;

    } // namespace constant

} // namespace XInject
