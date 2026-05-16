#include "include/window/MainWindow.hpp"
#include <thread>

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

            if (mainwndOpen) {  //主窗口没有退出
                ImGui::Begin("X-inject", &mainwndOpen);
                ImGui::Text("Method       ");
                ImGui::SameLine();
                if (ImGui::Combo("##method", &method, \
                    "Remote Thread\0"
                    "APC Queue\0"
                    "Reflective\0"
                    "Context(thread hijack)\0"
                    "Poolparty\0"
                    "Test all\0", 6))
                    type = 0;
                if (method == 4) {
                    ImGui::Text("PoolParty");
                    ImGui::SameLine();
                    ImGui::Combo("##poolparty_type", &poolpartyMethod, \
                        "WorkerFactoryStartRoutineOverwrite\0"
                        "RemoteTpWorkInsertion\0"
                        "RemoteTpWaitInsertion\0"
                        "RemoteTpIoInsertion\0"
                        "RemoteTpAlpcInsertion\0"
                        "RemoteTpJobInsertion\0"
                        "RemoteTpDirectInsertion\0"
                        "RemoteTpTimerInsertion\0", 5);
                    ImGui::SameLine();
                    ImGui::Checkbox("SeDebug", &needSeDebug);
                }

                // 如果有人开始选择方法
                if (method != 5) { // 非测试模式
                    // 0. remote thread inject
                    // 1. apc inject
                    // 2. reflect inject
                    // 3. context inject (thread hijack)
                    ImGui::Text("Type            ");
                    ImGui::SameLine();
                    switch (method)
                    {
                    case 0: // remote thread injection
                    case 1: // apc inject   只能注入dll文件和shellcode
                    {
                        ImGui::Combo("##type", &type, "DLL file\0shellcode\0shellcode file\0", 3);
                        break;
                    }
                    case 2: // 反射式注入不能注入shellcode
                    {
                        ImGui::Combo("##type", &type, "DLL file\0url\0", 2);
                        break;
                    }
                    case 3: // 线程劫持只能注入shellcode
                    {
                        ImGui::Combo("##type", &type, "shellcode\0shellcode file\0", 2);
                        break;
                    }
                    case 4:
                    {
                        // ImGui::Combo("##type", &type, "DLL file\0url\0shellcode\0shellcode file\0", 4);
                        ImGui::Combo("##type", &type, "shellcode\0shellcode file\0", 2);
                        break;
                    }
                    default:
                        ImGui::Combo("##type", &type, "\0", 0);
                        break;
                    }
                }


                ImGui::Text("Process   ");
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
                // TODO: 测试所有方法的结果展示函数
                if (method == 5) {
                    ImGui::Text("Test All Functions Mode");

                    ImGui::Text("Args            ");
                    ImGui::SameLine();
                    ImGui::InputText("##arg", args, constant::maxStrSize);
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

                    auto drawTestLine = [](int idx, const char* name, const char* hint) {
                        ImU32 color;
                        const char* status;
                        switch (testStates[idx]) {
                        case TestState::Pending: color = IM_COL32(128, 128, 128, 255); status = "Pending"; break;
                        case TestState::Running: color = IM_COL32(255, 255, 0, 255); status = "Running..."; break;
                        case TestState::Success: color = IM_COL32(0, 255, 0, 255); status = "OK"; break;
                        case TestState::Failed:  color = IM_COL32(255, 0, 0, 255); status = "Failed"; break;
                        }
                        XInject::Drawer::drawCircle(color);
                        ImGui::Text("%s", name);
                        ImGui::SameLine();
                        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(color), "[%s]", status);
                        ImGui::SameLine();
                        ImGui::TextDisabled("(%s)", hint);
                        };

                    drawTestLine(0, "Remote Thread", "DLL file");
                    drawTestLine(1, "APC Queue", "DLL file");
                    drawTestLine(2, "Reflective", "DLL file");
                    // drawTestLine(3, "Context(thread hijack)", "shellcode file");
                    // drawTestLine(4, "Poolparty", "shellcode file");

                    ImGui::Separator();

                    if (testAllRunning) {
                        ImGui::BeginDisabled();
                        ImGui::Button("Testing...");
                        ImGui::EndDisabled();
                    }
                    else {
                        if (ImGui::Button("Test All")) {
                            MainWindow::doTestAll();
                        }
                    }
                }
                else {
                    ImGui::Text("Args            ");
                    ImGui::SameLine();
                    ImGui::InputText("##arg", args, constant::maxStrSize);
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
                    }

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
            case 4: {
                Injector::poolPartyInject(chosenPid, type, poolpartyMethod, args, needSeDebug);
                break;
            }

            default:
                break;
            }
        }

        void doTestAll()
        {
            testAllRunning = true;
            for (int i = 0; i < 5; i++)
                testStates[i] = TestState::Pending;

            DWORD pid = chosenPid;
            std::string arg(args);

            std::thread([pid, arg]() {
                // 0: Remote Thread — DLL file
                testStates[0] = TestState::Running;
                testStates[0] = Injector::remoteThreadInject(pid, 0, arg) ? TestState::Success : TestState::Failed;

                // 1: APC Queue — DLL file
                testStates[1] = TestState::Running;
                testStates[1] = Injector::apcInject(pid, 0, arg) ? TestState::Success : TestState::Failed;

                // 2: Reflective — DLL file
                testStates[2] = TestState::Running;
                testStates[2] = Injector::reflectInject(pid, 0, arg) ? TestState::Success : TestState::Failed;

                // 3: Context (thread hijack) — shellcode file
                // testStates[3] = TestState::Running;
                // testStates[3] = Injector::contextInject(pid, 1, arg) ? TestState::Success : TestState::Failed;

                // // 4: Poolparty — shellcode file, WorkerFactoryStartRoutineOverwrite
                // testStates[4] = TestState::Running;
                // testStates[4] = Injector::poolPartyInject(pid, 1, 0, arg, false) ? TestState::Success : TestState::Failed;

                testAllRunning = false;
                }).detach();
        }
    } // namespace MainWindow

} // namespace XInject
