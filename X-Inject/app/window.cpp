#include "window.h"


#include "../ext/imgui.h"
#include "../global.h"

#include <iostream>
#include <thread>

VOID MainWindow::InitWindow() {
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
	ImGui::Checkbox("Remote Shellcode Inject", &MainWindow::bInjectSc);
	ImGui::Checkbox("APC Shellcode Inject", &MainWindow::bApcSc);
	ImGui::Checkbox("Context Shellcode Inject", &MainWindow::bContextSc);
	ImGui::Checkbox("List Injectable Process", &MainWindow::bList);
	ImGui::Checkbox("Unject Process", &MainWindow::bIninject);
	ImGui::End();
}

VOID MainWindow::Dispatcher() {
	if (MainWindow::bRemoteThreadDll) {
		MainWindow::RemoteDLL();
	}
	if (MainWindow::bRefelectDll) {
		MainWindow::ReflectDLL();
	}
	if (MainWindow::bApcDll) {
		MainWindow::ApcDLL();
	}

	if (MainWindow::bInjectSc) {
		MainWindow::RemoteShellcode();
	}
	if (MainWindow::bApcSc) {
		MainWindow::ApcShellcode();
	}
	if (MainWindow::bContextSc) {
		MainWindow::ContextShellcode();
	}

	if (MainWindow::bIninject) {
		MainWindow::UnInject();
	}
	if (MainWindow::bList) {
		MainWindow::DllList();
	}
}

VOID MainWindow::InjectDLL(const char Title[], std::function<void(DWORD)>injectMenthod) {
	OPENFILENAMEA ofn;
	static char filePath[0x1000] = { 0 };
	static char test[0x1000] = { 0 };
	static bool choosePID = false;
	static int PID = 0;

	bool chooseFile = false;
	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("FilePath", filePath, IM_ARRAYSIZE(filePath));
	ImGui::SameLine();
	chooseFile = ImGui::Button("Choose File       ");
	ImGui::InputInt("PID       ", &PID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &choosePID);
	inject = ImGui::Button("Inject");

	if (chooseFile) {
		ZeroMemory(&ofn, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = NULL;
		ofn.lpstrFilter = "All Files\0*.*\0";
		ofn.lpstrFile = filePath;
		ofn.nMaxFile = MAX_PATH;
		ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
		ofn.lpstrDefExt = "";
		if (GetOpenFileNameA(&ofn)) {}
	}
	if (choosePID) {
		PID = GetPID();
		if (PID != 0)
			choosePID = false;
	}
	if (inject && PID != 0) {
		injector.dllPathSetter(filePath);
		std::string temp = filePath;
		if (temp.size() != 0) {
			injectMenthod(PID);
		}
	}
	ImGui::End();

}

VOID MainWindow::InjectShellcode(const char Title[], std::function<void(std::string, DWORD)>injectMenthod) {
	static char Shellcode[0x1000] = { 0 };
	static bool choosePID = false;
	static int PID = 0;

	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("Shellcode", Shellcode, IM_ARRAYSIZE(Shellcode));
	ImGui::InputInt("PID       ", &PID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &choosePID);
	inject = ImGui::Button("Inject");

	if (choosePID) {
		PID = GetPID();
		if (PID != 0)
			choosePID = false;
	}
	if (inject && PID != 0) {
		std::string temp = Shellcode;
		if (temp.size() != 0) {
			injectMenthod(temp, PID);
		}
	}
	ImGui::End();

}

VOID MainWindow::RemoteDLL() {
	auto func = [&](DWORD x) {
		injector.remoteThreadInject(x);
	};
	MainWindow::InjectDLL("Remote DLL Inject", func);
}

VOID MainWindow::ReflectDLL() {
	auto func = [&](DWORD x) {
		injector.reflectInject(x);
	};
	MainWindow::InjectDLL("Reflect DLL Inject", func);
}

VOID MainWindow::ApcDLL() {
	auto func = [&](DWORD x) {
		injector.apcInject(x);
	};
	MainWindow::InjectDLL("APC DLL Inject", func);
}

VOID MainWindow::UnInject() {
	auto func = [&](DWORD x) {
		injector.unInject(x);
	};
	MainWindow::InjectDLL("UnInject DLL", func);
}






VOID MainWindow::RemoteShellcode() {
	auto func = [&](std::string shellcode, DWORD x) {
		injector.shellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("Remote Shellcode Inject", func);
}

VOID MainWindow::ApcShellcode() {
	auto func = [&](std::string shellcode, DWORD x) {
		injector.apcShellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("APC Shellcode Inject", func);
}

VOID MainWindow::ContextShellcode() {
	auto func = [&](std::string shellcode, DWORD x) {
		injector.contextShellcodeInject(shellcode, x);
	};
	MainWindow::InjectShellcode("Context Shellcode Inject", func);
}
//TODO

VOID MainWindow::DllList() {
	ImGui::Begin("Injectable Process", nullptr, ImGuiWindowFlags_NoCollapse);
	std::vector<ProcessInfo> procInfo = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();
	// Table data
	for (int i = 0; i < procInfo.size(); i++) {
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImGui::Text("%d", procInfo[i].pid);
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfo[i].processName.c_str());
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
}

DWORD MainWindow::GetPID() {
	DWORD retPid = 0;
	bool click = false;
	ImGui::Begin("process id", nullptr, ImGuiWindowFlags_NoCollapse);

	std::vector<ProcessInfo> procInfo = injector.injectList();
	ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders);

	// Table header
	ImGui::TableSetupColumn("PID");
	ImGui::TableSetupColumn("ProcessName");
	ImGui::TableHeadersRow();

	// Table data

	for (int i = 0; i < procInfo.size(); i++) {
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		click = ImGui::Button(std::to_string(procInfo[i].pid).c_str());
		ImGui::TableNextColumn();
		ImGui::Text("%ws", procInfo[i].processName.c_str());
		if (click) {
			ImGui::EndTable();
			ImGui::End();
			return procInfo[i].pid;
		}
	}
	

	// End table
	ImGui::EndTable();
	ImGui::End();
	return retPid;
}
