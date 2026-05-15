#include "include/window/draw.hpp"

namespace XInject
{
    namespace Drawer
    {
        void drawCircle(ImU32 color) {
            float textHeight = ImGui::GetTextLineHeight();
            ImVec2 pos = ImGui::GetCursorScreenPos();
            ImVec2 center(pos.x + textHeight * 0.5f, pos.y + textHeight * 0.5f);
            ImGui::GetWindowDrawList()->AddCircleFilled(center, textHeight * 0.5f, color);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + textHeight + ImGui::GetStyle().ItemSpacing.x);
        }
    }
}