/*
 * Imgui window manager
 */
#include "window.h"
#include "include/imgui/imgui.h"

#include <iostream>
#include <thread>
#include <wininet.h>
#include <string>

VOID MainWindow::InitWindow()
{
#ifdef _WIN64
	ImGui::Begin("S-inject x64", &MainWindow::bWindowOpen, ImGuiWindowFlags_NoCollapse);
#else
#ifdef _WIN32
	ImGui::Begin("S-inject x32", &MainWindow::bWindowOpen, ImGuiWindowFlags_NoCollapse);
#endif // _WIN32
#endif // _WIN64
	ImGui::Text("https://github.com/Joe1sn/S-inject");
	if (!MainWindow::bWindowOpen)
		exit(0);

	ImGui::Checkbox("Remote Thread DLL Inject", &MainWindow::bRemoteThreadDll);
	ImGui::Checkbox("Reflect DLL Inject", &MainWindow::bRefelectDll);
	ImGui::Checkbox("APC DLL Inject", &MainWindow::bApcDll);
	ImGui::Checkbox("Online DLL Inject", &MainWindow::bNetDll);
	ImGui::Checkbox("Remote Shellcode Inject", &MainWindow::bInjectSc);
	ImGui::Checkbox("APC Shellcode Inject", &MainWindow::bApcSc);
	ImGui::Checkbox("Context Shellcode Inject", &MainWindow::bContextSc);
	ImGui::Checkbox("List Injectable Process", &MainWindow::bList);
	ImGui::Checkbox("Unject Process", &MainWindow::bIninject);
	ImGui::End();
}

VOID MainWindow::Dispatcher()
{
	if (MainWindow::bRemoteThreadDll)
	{
		MainWindow::RemoteDLL();
	}
	if (MainWindow::bRefelectDll)
	{
		MainWindow::ReflectDLL();
	}
	if (MainWindow::bApcDll)
	{
		MainWindow::ApcDLL();
	}
	if (MainWindow::bNetDll)
	{
		MainWindow::NetDLL();
	}

	if (MainWindow::bInjectSc)
	{
		MainWindow::RemoteShellcode();
	}
	if (MainWindow::bApcSc)
	{
		MainWindow::ApcShellcode();
	}
	if (MainWindow::bContextSc)
	{
		MainWindow::ContextShellcode();
	}

	if (MainWindow::bIninject)
	{
		MainWindow::UnInject();
	}

	if (MainWindow::bList)
	{
		MainWindow::DllList();
	}
	else if (!MainWindow::bList)
	{
		if (!procInfoList.empty())
			procInfoList.clear();
	}

	if (MainWindow::chooseDllPID)
	{
		gDllPID = GetDllPID();
	}
	else if (!MainWindow::chooseDllPID)
	{
		gDllPID = 0;
		if (!procInfoInjectDll.empty())
			procInfoInjectDll.clear();
	}

	if (MainWindow::chooseShellcodePID)
	{
		gShellcodePID = GetShellcodePID();
	}
	else if (!MainWindow::chooseShellcodePID)
	{
		gShellcodePID = 0;
		if (!procInfoInjectShellcode.empty())
			procInfoInjectShellcode.clear();
	}

	if (MainWindow::choosenNetPID)
	{
		gNetPID = GetNetPID();
	}
	else if (!MainWindow::choosenNetPID)
	{
		gNetPID = 0;
		if (!procInfoInjectNet.empty())
			procInfoInjectNet.clear();
	}
}

// ע��dll�Ĵ���
VOID MainWindow::InjectDLL(const char Title[], std::function<void(DWORD)> injectMenthod)
{
	OPENFILENAMEA ofn;
	static char filePath[0x1000] = {0};
	static char test[0x1000] = {0};
	static int PID = 0;

	bool chooseFile = false;
	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("FilePath", filePath, IM_ARRAYSIZE(filePath)); // Imgui�õ�����
	ImGui::SameLine();
	chooseFile = ImGui::Button("Choose File");
	ImGui::InputInt("PID", &PID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &MainWindow::chooseDllPID);
	inject = ImGui::Button("Inject");

	if (chooseFile)
	{ // ѡ��dll�ļ�
		ZeroMemory(&ofn, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = NULL;
		ofn.lpstrFilter = "All Files\0*.*\0";
		ofn.lpstrFile = filePath;
		ofn.nMaxFile = MAX_PATH;
		ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
		ofn.lpstrDefExt = "";
		if (GetOpenFileNameA(&ofn))
		{
		}
	}
	if (MainWindow::chooseDllPID)
	{ // ���pid
		PID = gDllPID;
		gDllPID = 0;
		if (PID != 0)
			MainWindow::chooseDllPID = false;
	}
	if (inject && PID != 0)
	{
		injector.dllPathSetter(filePath);
		std::string temp = filePath;
		if (temp.size() != 0)
		{
			injectMenthod(PID);
		}
	}
	ImGui::End();
}

// 注入dll的选择窗口
VOID MainWindow::InjectDLL(const char Title[], std::function<void(DWORD, std::string)> injectMenthod)
{
	static char url[0x1000] = {0};
	static int PID = 0;

	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("URL", url, IM_ARRAYSIZE(url));

	ImGui::InputInt("PID", &PID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &MainWindow::choosenNetPID);
	inject = ImGui::Button("Inject");

	if (MainWindow::choosenNetPID)
	{
		PID = gNetPID;
		gNetPID = 0;
		if (PID != 0)
			MainWindow::choosenNetPID = false;
	}
	if (inject && PID != 0)
	{
		std::string temp = url;
		if (temp.size() != 0)
		{
			injectMenthod(PID, url);
		}
	}
	ImGui::End();
}

// 注入shellcode的选择窗口
VOID MainWindow::InjectShellcode(const char Title[], std::function<void(std::string, DWORD)> injectMenthod)
{
	static char Shellcode[0x1000] = {0};
	static int scPID = 0;

	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("Shellcode", Shellcode, IM_ARRAYSIZE(Shellcode));
	ImGui::InputInt("PID       ", &scPID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &MainWindow::chooseShellcodePID);
	inject = ImGui::Button("Inject");

	if (MainWindow::chooseShellcodePID)
	{
		scPID = gShellcodePID;
		gShellcodePID = 0;
		if (scPID != 0)
			MainWindow::chooseShellcodePID = false;
	}
	if (inject && scPID != 0)
	{
		std::string temp = Shellcode;
		if (temp.size() != 0)
		{
			injectMenthod(temp, scPID);
		}
	}
	ImGui::End();
}

VOID MainWindow::RemoteDLL()
{
	auto func = [&](DWORD x)
	{
		injector.remoteThreadInject(x);
	};
	MainWindow::InjectDLL("Remote DLL Inject", func);
}

VOID MainWindow::ReflectDLL()
{
	auto func = [&](DWORD x)
	{
		injector.reflectInject(x);
	};
	MainWindow::InjectDLL("Reflect DLL Inject", func);
}

VOID MainWindow::ApcDLL()
{
	auto func = [&](DWORD x)
	{
		injector.apcInject(x);
	};
	MainWindow::InjectDLL("APC DLL Inject", func);
}

VOID MainWindow::NetDLL()
{
	auto func = [&](DWORD x, std::string dllContent)
	{
		injector.internetInject(x, dllContent);
	};
	MainWindow::InjectDLL("Inject From Internet", func);
}

VOID MainWindow::UnInject()
{
	auto func = [&](DWORD x)
	{
		injector.unInject(x);
	};
	MainWindow::InjectDLL("UnInject DLL", func);
}

VOID MainWindow::RemoteShellcode()
{
	auto func = [&](std::string shellcode, DWORD x)
	{
		injector.shellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("Remote Shellcode Inject", func);
}

VOID MainWindow::ApcShellcode()
{
	auto func = [&](std::string shellcode, DWORD x)
	{
		injector.apcShellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("APC Shellcode Inject", func);
}

VOID MainWindow::ContextShellcode()
{
	auto func = [&](std::string shellcode, DWORD x)
	{
		injector.contextShellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("Context Shellcode Inject", func);
}

VOID MainWindow::DllList()
{
	ImGui::Begin("Injectable Process", nullptr, ImGuiWindowFlags_NoCollapse);

	// TODO:
	if (procInfoList.empty())
		procInfoList = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();
	// Table data
	for (int i = 0; i < procInfoList.size(); i++)
	{
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImGui::Text("%d", procInfoList[i].pid);
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfoList[i].processName.c_str());
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
}

DWORD MainWindow::GetDllPID()
{
	bool click = false;
	ImGui::Begin("process id", nullptr, ImGuiWindowFlags_NoCollapse);

	if (procInfoInjectDll.empty())
		procInfoInjectDll = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();

	// Table data

	for (int i = 0; i < procInfoInjectDll.size(); i++)
	{
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		click = ImGui::Button(std::to_string(procInfoInjectDll[i].pid).c_str());
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfoInjectDll[i].processName.c_str());
		if (click)
		{
			ImGui::EndTable();
			ImGui::End();
			return procInfoInjectDll[i].pid;
		}
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
	return 0;
}

DWORD MainWindow::GetShellcodePID()
{
	bool click = false;
	ImGui::Begin("shellcode process id", nullptr, ImGuiWindowFlags_NoCollapse);

	if (procInfoInjectShellcode.empty())
		procInfoInjectShellcode = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();

	// Table data

	for (int i = 0; i < procInfoInjectShellcode.size(); i++)
	{
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		click = ImGui::Button(std::to_string(procInfoInjectShellcode[i].pid).c_str());
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfoInjectShellcode[i].processName.c_str());
		if (click)
		{
			ImGui::EndTable();
			ImGui::End();
			return procInfoInjectShellcode[i].pid;
		}
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
	return 0;
}

DWORD MainWindow::GetNetPID()
{
	bool click = false;
	ImGui::Begin("process id", nullptr, ImGuiWindowFlags_NoCollapse);

	if (procInfoInjectNet.empty())
		procInfoInjectNet = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();

	// Table data

	for (int i = 0; i < procInfoInjectNet.size(); i++)
	{
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		click = ImGui::Button(std::to_string(procInfoInjectNet[i].pid).c_str());
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfoInjectNet[i].processName.c_str());
		if (click)
		{
			ImGui::EndTable();
			ImGui::End();
			return procInfoInjectNet[i].pid;
		}
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
	return 0;
}
