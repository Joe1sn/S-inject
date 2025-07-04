// application for DirectX 11

#include "include/app/window.h"
#include "include/utils/helper.hpp"
#include "include/utils/theme.hpp"

#include "include/imgui/imgui.h"
#include "include/imgui/imgui_impl_win32.h"
#include "include/imgui/imgui_impl_dx11.h"

#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <iostream>
#include <fstream>

// Data
static ID3D11Device *g_pd3dDevice = nullptr;
static ID3D11DeviceContext *g_pd3dDeviceContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView *g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
void GenConfigIniFile();
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Main code
int WINAPI WinMain(HINSTANCE instance, HINSTANCE pInstance, LPSTR lpCmd, int cmdShow)
{
    bool needGui = true;
    std::string commandLine = lpCmd;
    if (!commandLine.empty())
        needGui = false;

    if (!needGui)
    { // 不需要GUI界面
        std::vector<std::string> words = {};
        std::string word = "";

        bool intoRef = false;      // 是否处于 `"` 中
        for (auto c : commandLine) // 对命令行分词处理，得到参数
        {
            if (c == ' ')
            { // 下一个参数
                if (!intoRef)
                { // 不在`"`中，开始的到下一个参数
                    if (!word.empty())
                    {
                        words.push_back(word);
                        word.clear();
                    }
                }
                else
                {
                    word.append(1, c);
                }
                continue;
            }
            else if (c == '\n')
            { // 命令行结束
                if (!word.empty())
                {
                    words.push_back(word);
                    word.clear();
                }
                break;
            }
            else if (c == '"')
            { // 设置`"`状态
                intoRef = !intoRef;
            }
            else
                word.append(1, c);
        }
        words.push_back(word);
        word.clear();

        std::string method = "";    // 使用的方法
        std::string path = "";      // 相关文件的dll url shellcode
        DWORD pid = 0;              // 进程号
        std::string procName = "";  // 进程名字
        auto injector = Injector(); // 注入实例

        for (size_t i = 0; i < words.size(); i++)
        { // 设置参数
            if (words[i].starts_with("-method"))
            {
                method = words[++i];
            }
            else if (words[i].starts_with("-path"))
            {
                path = words[++i];
            }
            else if (words[i].starts_with("-pid"))
            {
                pid = std::stoul(words[++i]);
            }
            else if (words[i].starts_with("-proc"))
            {
                procName = words[++i];
            }
        }

        if (!procName.empty())                             // 进程名字不为空
            pid = injector.getPidByName(procName.c_str()); // 通过进程名字得到pid
        if (pid == 0)
        { // pid不能为空
            MessageBoxA(NULL, "No Such Process Can be injected", "error", MB_OK | MB_ICONERROR);
            return 0;
        }

        if (method == "net") // 使用http get请求反射式加载dll
            injector.internetInject(pid, path);
        else if (method == "rmtdll")
        { // 远程线程注入
            injector.dllPathSetter(path);
            injector.remoteThreadInject(pid);
        }
        else if (method == "refdll")
        { // 反射式注入
            injector.reflectInject(pid);
            injector.remoteThreadInject(pid);
        }
        else if (method == "apcdll")
        { // apc队列注入
            injector.apcInject(pid);
            injector.remoteThreadInject(pid);
        }
        else if (method == "rmtsc") // 远程线程注入shellcode
            injector.shellcodeInject(path, pid);
        else if (method == "apcsc") // apc队列注入shellcode
            injector.apcShellcodeInject(path, pid);
        else if (method == "ctxsc") // 上下文注入(线程劫持)shellcode
            injector.contextShellcodeInject(path, pid);
        else
            MessageBoxA(NULL, "No Such Method", "error", MB_OK | MB_ICONERROR);
    }
    else
    {                       // 使用GUI界面
        GenConfigIniFile(); // imgui相关的窗口参数
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.lpfnWndProc = WndProc;
        wc.lpszClassName = L"X-inject";
        // wc.hInstance = instance;

        wc.style = CS_HREDRAW | CS_VREDRAW;

        ::RegisterClassExW(&wc);
        HWND hwnd = CreateWindowExW(0, L"X-inject", L"X-inject",
                                    WS_POPUP | WS_EX_TRANSPARENT, CW_USEDEFAULT, CW_USEDEFAULT,
                                    GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, NULL, NULL); // 创建windows窗口
        SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
        SetLayeredWindowAttributes(hwnd, RGB(255, 255, 255), 255, LWA_COLORKEY); // 设置全局透明
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);           // 设置初始位置

        // Imgui Initialize Direct3D
        if (!CreateDeviceD3D(hwnd))
        {
            CleanupDeviceD3D();
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return 1;
        }

        // Show the window
        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);

        // Setup context
        // IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows

        // Setup Dear ImGui style
        // ImGui::StyleColorsDark();
        ImGui::StyleColorsLight();
        Theme::purpeDragon();

        // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
        ImGuiStyle &style = ImGui::GetStyle();
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        // Setup Platform/Renderer backends
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        // Load Fonts
        io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\Deng.ttf", 18, nullptr, io.Fonts->GetGlyphRangesChineseFull());

        // Main loop
        bool done = false;
        while (!done)
        {
            // Poll and handle messages (inputs, window resize, etc.)
            // See the WndProc() function below for our to dispatch events to the Win32 backend.
            MSG msg;
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    done = true;
            }
            if (done)
                break;

            // Start the Dear ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            ////////////  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS

            MainWindow::InitWindow(); // 单次初始化窗口
            MainWindow::Dispatcher(); // 刷新窗口

            ////////////  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS

            // Rendering
            ImGui::Render();
            // Rendering Method
            const float clear_color_with_alpha[4] = {1, 1, 1, 1};
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            // Update and Render additional Platform Windows
            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault();
            }

            // Present
            HRESULT hr = g_pSwapChain->Present(1, 0); // Present with vsync
            // HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
            g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
        }

        // Cleanup
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    }

    return 0;
}

// Helper functions
void GenConfigIniFile()
{
    DWORD attrib = GetFileAttributesA("imgui.ini");
    if (attrib != INVALID_FILE_ATTRIBUTES)
    {
        return;
    }
    else
    {
        std::ofstream file("imgui.ini", std::ios::binary);
        if (!file.is_open())
            return;
        file << "[Window][Debug##Default]\n";
        file << "Pos=60,60\n";
        file << "Size=400,400\n";
        file << "Collapsed=0\n";

        file << "[Window][Hello, world!]\n";
        file << "Pos=1038,449\n";
        file << "Size=494,422\n";
        file << "Collapsed=0\n";

        file << "[Window][Another Window]\n";
        file << "Pos=701,395\n";
        file << "Size=404,360\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000002,1\n";

        file << "[Window][���]\n";
        file << "Pos=631,519\n";
        file << "Size=583,286\n";
        file << "Collapsed=0\n";

        file << "[Window][你好]\n";
        file << "Pos=701,395\n";
        file << "Size=404,360\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000002,0\n";

        file << "[Window][S-inject GUI Version]\n";
        file << "Pos=639,321\n";
        file << "Size=543,339\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000005,0\n";

        file << "[Window][Remote DLL Inject]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,3\n";

        file << "[Window][Reflect DLL Inject]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,2\n";

        file << "[Window][APC DLL Inject]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,1\n";

        file << "[Window][Remote Shellcode Inject]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,1\n";

        file << "[Window][APC Shellcode Inject]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,0\n";

        file << "[Window][Context Shellcode Inject]\n";
        file << "Pos=592,708\n";
        file << "Size=774,146\n";
        file << "Collapsed=0\n";

        file << "[Window][UnInject DLL]\n";
        file << "Pos=592,322\n";
        file << "Size=365,384\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000005,1\n";

        file << "[Window][Injectable Process]\n";
        file << "Pos=959,322\n";
        file << "Size=407,384\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000003,0\n";

        file << "[Window][S-inject x64]\n";
        file << "Pos=592,322\n";
        file << "Size=389,410\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000005,0\n";

        file << "[Window][pid]\n";
        file << "ViewportPos=60,60\n";
        file << "ViewportId=0x5550C4ED\n";
        file << "Size=635,1034\n";
        file << "Collapsed=0\n";

        file << "[Window][process id]\n";
        file << "Pos=983,322\n";
        file << "Size=383,410\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000006,0\n";

        file << "[Window][S-inject x32]\n";
        file << "Pos=375,464\n";
        file << "Size=404,370\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000005,0\n";

        file << "[Window][Inject From Internet]\n";
        file << "Pos=592,734\n";
        file << "Size=774,120\n";
        file << "Collapsed=0\n";
        file << "DockId=0x0000000A,0\n";

        file << "[Window][shellcode process id]\n";
        file << "Pos=981,322\n";
        file << "Size=385,410\n";
        file << "Collapsed=0\n";
        file << "DockId=0x00000008,0\n";

        file << "[Docking][Data]\n";
        file << "DockNode          ID=0x00000002 Pos=701,395 Size=404,360 Selected=0x96791837\n";
        file << "DockNode          ID=0x00000007 Pos=592,322 Size=774,532 Split=Y\n";
        file << "DockNode        ID=0x00000009 Parent=0x00000007 SizeRef=774,410 Split=X\n";
        file << "DockNode      ID=0x00000001 Parent=0x00000009 SizeRef=415,177 Split=X\n";
        file << "DockNode    ID=0x00000004 Parent=0x00000001 SizeRef=232,533 Split=X Selected=0xD3F790C7\n";
        file << "DockNode  ID=0x00000005 Parent=0x00000004 SizeRef=387,410 Selected=0xD3F790C7\n";
        file << "DockNode  ID=0x00000008 Parent=0x00000004 SizeRef=385,410 Selected=0xB3407F9B\n";
        file << "DockNode    ID=0x00000006 Parent=0x00000001 SizeRef=229,533 Selected=0x8AC5C89D\n";
        file << "DockNode      ID=0x00000003 Parent=0x00000009 SizeRef=462,177 Selected=0x8E2C745A\n";
        file << "DockNode        ID=0x0000000A Parent=0x00000007 SizeRef=774,120 Selected=0x7F6CE61D\n";

        file.close();
    }
}

bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    // createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain)
    {
        g_pSwapChain->Release();
        g_pSwapChain = nullptr;
    }
    if (g_pd3dDeviceContext)
    {
        g_pd3dDeviceContext->Release();
        g_pd3dDeviceContext = nullptr;
    }
    if (g_pd3dDevice)
    {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
}

void CreateRenderTarget()
{
    ID3D11Texture2D *pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView)
    {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_DPICHANGED:
        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
        {
            // const int dpi = HIWORD(wParam);
            // printf("WM_DPICHANGED to %d (%.0f%%)\n", dpi, (float)dpi / 96.0f * 100.0f);
            const RECT *suggested_rect = (RECT *)lParam;
            ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
