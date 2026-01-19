#include "include/window/MainWindow.hpp"

using namespace XInject::constant;
using namespace XInject::Crypto;
using namespace XInject::Injector;
namespace XInject
{
    namespace MainWindow
    {
        bool setupUi()
        {
            bool chooseFile = false;
            static char filePath[0x1000] = { 0 };
            OPENFILENAMEA ofn;

            ImGuiIO& io = ImGui::GetIO();

            if (MainWindow::mainwndOpen) {  //主窗口没有退出
                ImGui::Begin("X-inject", &MainWindow::mainwndOpen);
                ImGui::Text("Method    ");
                ImGui::SameLine();
                if (ImGui::Combo("##method", &MainWindow::method, "Remote Thread\0APC Queue\0Reflective\0Context(thread hijack)\0", 4))
                    type = 0;
                // 如果有人开始选择方法
                // 0. remote thread inject
                // 1. apc inject
                // 2. reflect inject
                // 3. context inject (thread hijack)
                ImGui::Text("Type         ");
                ImGui::SameLine();
                switch (MainWindow::method)
                {
                case 0: // remote thread injection
                case 1: // apc inject   只能注入dll文件和shellcode
                {
                    ImGui::Combo("##type", &MainWindow::type, "DLL file\0shellcode\0shellcode file\0", 3);
                    break;
                }
                case 2: // 反射式注入不能注入shellcode
                {
                    ImGui::Combo("##type", &MainWindow::type, "DLL file\0url\0", 2);
                    break;
                }
                case 3: // 线程劫持只能注入shellcode
                {
                    ImGui::Combo("##type", &MainWindow::type, "shellcode\0shellcode file\0", 2);
                    break;
                }

                default:
                    ImGui::Combo("##type", &MainWindow::type, "\0", 0);
                    break;
                }

                ImGui::Text("Process");
                ImGui::SameLine();

                // 假设你的状态变量
                static std::vector<std::string> itemList; // 存储选项的列表
                if (ImGui::BeginCombo("##process", itemList.empty() ? "choose process" : itemList[pid].c_str()))
                {
                    std::vector<ProcessInfo> infoList = Injector::listInjectable();
                    // 检测下拉窗口是否刚刚出现（即用户刚刚点开）
                    if (ImGui::IsWindowAppearing())
                    {
                        itemList.clear(); // 清空原有列表
                        std::vector<ProcessInfo> infoList = Injector::listInjectable();
                        for (auto info : infoList)
                        {
                            if (unsigned int(info.pid / 10) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"         " + info.processName));
                            else if (unsigned int(info.pid / 100) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"        " + info.processName));
                            else if (unsigned int(info.pid / 100) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"       " + info.processName));
                            else if (unsigned int(info.pid / 1000) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"      " + info.processName));
                            else if (unsigned int(info.pid / 10000) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"     " + info.processName));
                            else if (unsigned int(info.pid / 100000) == 0)
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"    " + info.processName));
                            else
                                itemList.push_back(Crypto::WstringToUTF8(std::to_wstring(info.pid) + L"   " + info.processName));
                        }
                    }

                    // 渲染下拉项列表
                    for (int i = 0; i < itemList.size(); ++i)
                    {
                        bool isSelected = (pid == i);
                        if (ImGui::Selectable(itemList[i].c_str(), isSelected))
                        {
                            pid = i; // 用户选择了某一项
                            chosenPid = infoList[i].pid;
                        }
                        if (isSelected)
                        {
                            ImGui::SetItemDefaultFocus(); // 设置初始焦点
                        }
                    }
                    ImGui::EndCombo();
                    // return true;
                }

                ImGui::Text("Args         ");
                ImGui::SameLine();
                ImGui::InputText("##arg", MainWindow::args, constant::maxStrSize);
                ImGui::SameLine();
                chooseFile = ImGui::Button("file");
                if (chooseFile)
                {
                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = NULL;
                    ofn.lpstrFilter = "All Files\0*.*\0";
                    ofn.lpstrFile = args;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
                    ofn.lpstrDefExt = "";
                    if (GetOpenFileNameA(&ofn)) {}
                }

                if (ImGui::Button("Inject")) // 点击注入
                {
                    MainWindow::doInject();
                    MainWindow::debugWnd = !MainWindow::debugWnd;
                }

                ImGui::End();
                return true;
            }

            else
                return false;
        }

        void doInject()
        {
            switch (method)
            {
            case 0:
                Injector::remoteThreadInject(chosenPid, type, args);
                break;
            case 1:
                Injector::apcInject(chosenPid, type, args);
                break;
            case 2:
                Injector::reflectInject(chosenPid, type, args);
                break;
            case 3:
                Injector::contextInject(chosenPid, type, args);
                break;

            default:
                break;
            }
        }
    } // namespace MainWindow

} // namespace XInject
