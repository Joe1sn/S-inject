// application for DirectX 11

#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

#include "extern/ImGui/imgui.h"
#include "extern/ImGui/imgui_impl_win32.h"
#include "extern/ImGui/imgui_impl_dx11.h"

#include "include/window/MainWindow.hpp"
#include "include/window/resources.h"
#include "include/app/config.hpp"
#include "include/utils/error.hpp"

#define IDI_MAIN_ICON 101

using namespace XInject::config;
using namespace XInject::Injector;
// Data
static ID3D11Device *g_pd3dDevice = nullptr;
static ID3D11DeviceContext *g_pd3dDeviceContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView *g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Main code
int WINAPI WinMain(HINSTANCE instance, HINSTANCE pInstance, LPSTR lpCmd, int cmdShow)
{
    std::string commandLine = lpCmd;
    if (!commandLine.empty())
        XInject::config::useGui = false;

    if (!XInject::config::useGui)
    { // 不需要GUI界面
        Error::error(L"TEST");

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

        std::string method = "";   // 使用的方法
        std::string args = "";     // 相关文件的dll url shellcode
        DWORD pid = 0;             // 进程号
        std::string procName = ""; // 进程名字

        for (size_t i = 0; i < words.size(); i++)
        { // 设置参数
            if (words[i].starts_with("-method"))
            {
                method = words[++i];
            }
            else if (words[i].starts_with("-args"))
            {
                args = words[++i];
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

        if (!procName.empty())                                       // 进程名字不为空
            pid = XInject::Injector::getPidByName(procName.c_str()); // 通过进程名字得到pid
        if (pid == 0)
        { // pid不能为空
            Error::error(L"No Such Process Can be injected");
            return 0;
        }

        if (method == "net") // 使用http get请求反射式加载dll
            XInject::Injector::reflectInject(pid, 1, args);
        else if (method == "rmtdll")
            XInject::Injector::remoteThreadInject(pid, 0, args);
        else if (method == "refdll")
            XInject::Injector::reflectInject(pid, 0, args);
        else if (method == "apcdll")
            XInject::Injector::apcInject(pid, 0, args);
        else if (method == "rmtsc") // 远程线程注入shellcode
            XInject::Injector::remoteThreadInject(pid, 1, args);
        else if (method == "apcsc") // apc队列注入shellcode
            XInject::Injector::apcInject(pid, 1, args);
        else if (method == "ctxsc") // 上下文注入(线程劫持)shellcode
            XInject::Injector::contextInject(pid, 0, args);

        else if (method == "rmtfile") // 上下文注入(线程劫持)shellcode
            XInject::Injector::remoteThreadInject(pid, 2, args);
        else if (method == "apcfile") // 上下文注入(线程劫持)shellcode
            XInject::Injector::apcInject(pid, 2, args);
        else if (method == "ctxfile") // 上下文注入(线程劫持)shellcode
            XInject::Injector::contextInject(pid, 1, args);
        else
            Error::error(L"No Such Method");
    }
    else
    {
        // Make process DPI aware and obtain main monitor scale
        ImGui_ImplWin32_EnableDpiAwareness();
        float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY));

        // Create application window
        WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"X-inject", nullptr};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.hIcon = LoadIcon(instance, MAKEINTRESOURCE(IDI_ICON1));
        wc.hIconSm = LoadIcon(instance, MAKEINTRESOURCE(IDI_ICON1));
        // wc.hInstance = instance;
        wc.style = CS_HREDRAW | CS_VREDRAW;
        ::RegisterClassExW(&wc);
        HWND hwnd = CreateWindowExW(0, L"X-inject", L"X-inject",
                                    WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
                                    700, 350, NULL, NULL, wc.hInstance, NULL); // 创建windows窗口

        // Initialize Direct3D
        if (!CreateDeviceD3D(hwnd))
        {
            CleanupDeviceD3D();
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return 1;
        }

        // Show the window
        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);

        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls

        // Setup Dear ImGui style
        // ImGui::StyleColorsDark();
        ImGui::StyleColorsLight();

        // Setup scaling
        ImGuiStyle &style = ImGui::GetStyle();
        style.ScaleAllSizes(main_scale); // Bake a fixed style scale. (until we have a solution for dynamic style scaling, changing this requires resetting Style + calling this again)
        style.FontScaleDpi = main_scale; // Set initial font scale. (using io.ConfigDpiScaleFonts=true makes this unnecessary. We leave both here for documentation purpose)

        // Setup Platform/Renderer backends
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        // Load Fonts
        HRSRC hRes = FindResource(instance, MAKEINTRESOURCE(IDR_FONT1), RT_RCDATA);
        if (hRes)
        {
            HGLOBAL hMem = LoadResource(instance, hRes);
            void *pData = LockResource(hMem);
            DWORD size = SizeofResource(instance, hRes);

            // DWORD nFonts = 0;
            // AddFontMemResourceEx(pData, size, NULL, &nFonts);
            io.Fonts->AddFontFromMemoryTTF(pData, size, 16, nullptr, io.Fonts->GetGlyphRangesChineseSimplifiedCommon());
        }

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

            // Handle window being minimized or screen locked
            if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                ::Sleep(10);
                continue;
            }
            g_SwapChainOccluded = false;

            // Handle window resize (we don't resize directly in the WM_SIZE handler)
            if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
            {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
                g_ResizeWidth = g_ResizeHeight = 0;
                CreateRenderTarget();
            }

            // Start the Dear ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            ////////////  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS

            {
                XInject::MainWindow::setupUi();
            }

            ////////////  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS

            // Rendering
            ImGui::Render();
            const float clear_color_with_alpha[4] = {1, 1, 1, 1};
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

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
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
