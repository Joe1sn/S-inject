#include "method.h"
#include "global.h"


#include "ext/imgui/imgui.h"
#include "ext/imgui/imgui_impl_dx11.h"
#include "ext/imgui/imgui_impl_win32.h"


#include <iostream>
#include <iomanip>
#include <thread>
#include <codecvt>
#include <dwmapi.h>
#include <d3d11.h>
#include <windowsx.h>
#include <vector>
#include <algorithm>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

bool g_WindowOpen = true;

bool g_remote_thread = false;
bool g_refelect_dll = false;
bool g_apc_dll = false;
bool g_sc_inject = false;
bool g_apc_sc = false;
bool g_context_sc = false;
bool g_list = false;
bool g_uninject = false;

int __stdcall WinMain(HINSTANCE instance, HINSTANCE pInstance, LPSTR lpCmd, int cmdShow) {
	LPCWSTR CLASS_NAME = L"window class";
	WNDCLASSEX wc = {};
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.lpfnWndProc = WndProc;
	wc.lpszClassName = CLASS_NAME;
	wc.hInstance = instance;
	wc.style = CS_HREDRAW | CS_VREDRAW;
	RegisterClassEx(&wc);
	HWND hwnd = NULL;
#ifdef _WIN64
	hwnd = CreateWindowExW(0, CLASS_NAME, L"S-inject x64",
		WS_POPUP | WS_EX_TRANSPARENT, CW_USEDEFAULT, CW_USEDEFAULT,
		GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, instance, NULL
	);
#elif _WIN32
	hwnd = CreateWindowExW(0, CLASS_NAME, L"S-inject x32",
		WS_POPUP | WS_EX_TRANSPARENT, CW_USEDEFAULT, CW_USEDEFAULT,
		GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, instance, NULL
	);
#endif // _WIN64

	if (!hwnd) {
		MessageBox(NULL, L"Error in allocate window", L"Error", NULL);
		return 1;
	}

	SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
	SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
	SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
	ShowWindow(hwnd, cmdShow);
	UpdateWindow(hwnd);

	DXGI_SWAP_CHAIN_DESC sd{};
	sd.BufferDesc.RefreshRate.Numerator = 60U;
	sd.BufferDesc.RefreshRate.Denominator = 1U;
	sd.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	sd.SampleDesc.Count = 1U;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.BufferCount = 2U;
	sd.OutputWindow = hwnd;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

	constexpr D3D_FEATURE_LEVEL levels[2]{
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_0,
	};

	ID3D11Device* device = nullptr;
	ID3D11DeviceContext* context = nullptr;
	IDXGISwapChain* swap_chain = nullptr;
	ID3D11RenderTargetView* render_target_view = nullptr;
	D3D_FEATURE_LEVEL level = {};

	D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0U, levels, 2U, D3D11_SDK_VERSION, &sd, &swap_chain, &device, &level, &context);

	ID3D11Texture2D* back_buffer = nullptr;
	swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
	if (back_buffer) {
		device->CreateRenderTargetView(back_buffer, nullptr, &render_target_view);
		back_buffer->Release();
	}
	else
		return 0;

	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
	ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\Deng.ttf", 18.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
	ImGui::StyleColorsDark();

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(device, context);



	float circle_radius = 50.0f;
	bool running = true;
	bool show_another_window = true;
	while (running) {
		MSG msg;
		while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);

			if (msg.message == WM_QUIT)
				running = false;
		}

		if (!running)
			break;

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		/////////////////////////////////////////////////
		ImGui::Begin("S-inject GUI Version", &g_WindowOpen, ImGuiWindowFlags_NoCollapse);
		ImGui::Text("https://github.com/Joe1sn/S-inject");
		if (!g_WindowOpen)
			return 0;

		ImGui::Checkbox("Remote Thread DLL Inject", &g_remote_thread);
		ImGui::Checkbox("Reflect DLL Inject", &g_refelect_dll);
		ImGui::Checkbox("APC DLL Inject", &g_apc_dll);
		ImGui::Checkbox("Remote Shellcode Inject", &g_sc_inject);
		ImGui::Checkbox("APC Shellcode Inject", &g_apc_sc);
		ImGui::Checkbox("Context Shellcode Inject", &g_context_sc);
		ImGui::Checkbox("List Injectable Process", &g_list);

		if (g_remote_thread) {
			MainInjector::RemoteDLL();
		}
		if (g_refelect_dll) {
			MainInjector::ReflectDLL();
		}
		if (g_apc_dll) {
			MainInjector::ApcDLL();
		}

		if (g_sc_inject) {
			MainInjector::RemoteShellcode();
		}
		if (g_apc_sc) {
			MainInjector::ApcShellcode();
		}
		if (g_context_sc) {
			MainInjector::ContextShellcode();
		}

		if (g_uninject) {
			MainInjector::UnInject();
		}
		if (g_list) {
			MainInjector::DllList();
		}


		/////////////////////////////////////////////////
		ImGui::End();
		ImGui::Render();
		float color[4] = { 0,0,0,0 };

		context->OMSetRenderTargets(1, &render_target_view, nullptr);

		context->ClearRenderTargetView(render_target_view, color);

		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		swap_chain->Present(0, 0);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();

	ImGui::DestroyContext();
	if (swap_chain) {
		swap_chain->Release();
	}
	if (context) {
		context->Release();
	}
	if (device) {
		device->Release();
	}
	if (render_target_view) {
		render_target_view->Release();
	}

	DestroyWindow(hwnd);
	UnregisterClassW(wc.lpszClassName, wc.hInstance);

}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {

	static HDC hdcBuffer = NULL;
	static HBITMAP hbmBuffer = NULL;

	if (ImGui_ImplWin32_WndProcHandler(hwnd, message, wParam, lParam))
		return true;

	switch (message)
	{
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		::PostQuitMessage(0);
		return 0;
	}
	return ::DefWindowProcW(hwnd, message, wParam, lParam);
}


