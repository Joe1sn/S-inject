//application for DirectX 11

#include "global.h"
#include "app/window.h"
#include "app/utils/helper.hpp"
#include "app/utils/theme.hpp"

#include "./ext/imgui.h"
#include "./ext/imgui_impl_win32.h"
#include "./ext/imgui_impl_dx11.h"


#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <iostream>

// Data
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
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

    if (!needGui) { //不需要GUI界面
        //处理命令行
        std::vector<std::string>words = {};
        std::string word = "";
        
        bool intoRef = false;
        for (auto c: commandLine)   //切割参数
        {
            if (c == ' ') {
                if (!intoRef) {
                    if (!word.empty()) {
                        words.push_back(word);
                        word.clear();
                    }
                }
                else {
                    word.append(1, c);
                }

                continue;
            }
            else if (c == '\n') {
                if (!word.empty()) {
                    words.push_back(word);
                    word.clear();
                }
                break;
            }
            else if (c == '"') {
                intoRef = !intoRef;
                
            }
            else
                word.append(1, c);
        }
        words.push_back(word);
        word.clear();

        std::string method = "";
        std::string path = "";
        DWORD pid = 0;
        std::string procName = "";
        auto injector = Injector();

        for (size_t i = 0; i < words.size(); i++) {  //解析参数
            if (words[i].starts_with("-method")) {
                method = words[++i];
            }
            else if (words[i].starts_with("-path")) {
                path = words[++i];
            }
            else if (words[i].starts_with("-pid")) {
                pid = std::stoul(words[++i]);
            }
            else if (words[i].starts_with("-proc")) {
                procName = words[++i];
            }
        }
        
        
        //std::string report = "method: " + method;
        //report += "\npath: " + path;
        //report += "\nproc: " + procName;
        //report += "\npid:  " + std::to_string(pid);
        //MessageBoxA(NULL, report.c_str(), "debug", MB_OK);

        if (!procName.empty())
            pid = injector.getPidByName(procName.c_str());
        if (pid == 0) {
            MessageBoxA(NULL, "No Such Process Can be injected", "error", MB_OK | MB_ICONERROR);
            return 0;
        }

        if (method == "net")
            injector.internetInject(pid, path);
        else if (method == "rmtdll") {
            injector.dllPathSetter(path);
            injector.remoteThreadInject(pid);
        }
        else if (method == "refdll") {
            injector.reflectInject(pid);
            injector.remoteThreadInject(pid);
        }
        else if (method == "apcdll") {
            injector.apcInject(pid);
            injector.remoteThreadInject(pid);
        }
        else if (method == "rmtsc")
            injector.shellcodeInject(path, pid);
        else if (method == "apcsc")
            injector.apcShellcodeInject(path, pid);
        else if (method == "ctxsc")
            injector.contextShellcodeInject(path, pid);
        else
            MessageBoxA(NULL, "No Such Method", "error", MB_OK | MB_ICONERROR);


    }
    else {          //需要GUI界面
        WNDCLASSEXW wc = { };
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.lpfnWndProc = WndProc;
        wc.lpszClassName = L"X-inject";
        //wc.hInstance = instance;

        wc.style = CS_HREDRAW | CS_VREDRAW;

        ::RegisterClassExW(&wc);
        HWND hwnd = CreateWindowExW(0, L"X-inject", L"X-inject",
            WS_POPUP | WS_EX_TRANSPARENT, CW_USEDEFAULT, CW_USEDEFAULT,
            GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, NULL, NULL
        );
        SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
        SetLayeredWindowAttributes(hwnd, RGB(255, 255, 255), 255, LWA_COLORKEY);
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);

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

        // Setup context
        //IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows

        // Setup Dear ImGui style
        //ImGui::StyleColorsDark();
        ImGui::StyleColorsLight();
        Theme::purpeDragon();

        // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
        ImGuiStyle& style = ImGui::GetStyle();
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

            MainWindow::InitWindow();
            MainWindow::Dispatcher();

            ////////////  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS  WINDOWS



            // Rendering
            ImGui::Render();
            // Rendering Method
            const float clear_color_with_alpha[4] = { g_status::clear_color.x * g_status::clear_color.w, g_status::clear_color.y * g_status::clear_color.w,g_status::clear_color.z * g_status::clear_color.w, g_status::clear_color.w };
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
            HRESULT hr = g_pSwapChain->Present(1, 0);   // Present with vsync
            //HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
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
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
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
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
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
            //const int dpi = HIWORD(wParam);
            //printf("WM_DPICHANGED to %d (%.0f%%)\n", dpi, (float)dpi / 96.0f * 100.0f);
            const RECT* suggested_rect = (RECT*)lParam;
            ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}






