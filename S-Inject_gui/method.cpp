#include "method.h"
#include <string>

VOID MainInjector::InjectDLL(const char Title[], std::function<void(DWORD)>injectMenthod) {
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
	inject = ImGui::Button("                !Start!                ");

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
		//ImGui::Begin("choose", nullptr, ImGuiWindowFlags_NoCollapse);
		PID = GetPID();
		if (PID != 0)
			choosePID = false;
	}
	if (inject && PID != 0) {
		injector.DllPathsetter(filePath);
		string temp = filePath;
		if (temp.size() != 0) {
			injectMenthod(PID);
		}
	}
	ImGui::End();

}

VOID MainInjector::InjectShellcode(const char Title[], std::function<void(string, DWORD)>injectMenthod) {
	static char Shellcode[0x1000] = { 0 };
	static bool choosePID = false;
	static int PID = 0;

	bool inject = false;

	ImGui::Begin(Title, nullptr, ImGuiWindowFlags_NoCollapse);

	ImGui::InputText("Shellcode", Shellcode, IM_ARRAYSIZE(Shellcode));
	ImGui::InputInt("PID       ", &PID);
	ImGui::SameLine();
	ImGui::Checkbox("Choose Process", &choosePID);
	inject = ImGui::Button("                !Start!                ");

	if (choosePID) {
		PID = GetPID();
		if (PID != 0)
			choosePID = false;
	}
	if (inject && PID != 0) {
		string temp = Shellcode;
		if (temp.size() != 0) {
			injectMenthod(temp, PID);
		}
	}
	ImGui::End();

}

VOID MainInjector::RemoteDLL() {
	auto func = [&](DWORD x) {
		injector.RemoteThreadInject(x);
	};
	MainInjector::InjectDLL("Remote DLL Inject", func);
}

VOID MainInjector::ReflectDLL() {
	auto func = [&](DWORD x) {
		injector.ReflectInject(x);
	};
	MainInjector::InjectDLL("Reflect DLL Inject", func);
}

VOID MainInjector::ApcDLL() {
	auto func = [&](DWORD x) {
		injector.ApcInject(x);
	};
	MainInjector::InjectDLL("APC DLL Inject", func);
}

VOID MainInjector::UnInject() {
	auto func = [&](DWORD x) {
		injector.unInject(x);
	};
	MainInjector::InjectDLL("UnInject DLL", func);
}






VOID MainInjector::RemoteShellcode() {
	auto func = [&](string shellcode, DWORD x) {
		injector.ShellcodeInject(shellcode, x);
	};
	MainInjector::InjectShellcode("Remote Shellcode Inject", func);
}

VOID MainInjector::ApcShellcode() {
	auto func = [&](string shellcode, DWORD x) {
		injector.ApcShellcodeInject(shellcode, x);
	};
	MainInjector::InjectShellcode("APC Shellcode Inject", func);
}

VOID MainInjector::ContextShellcode() {
	auto func = [&](string shellcode, DWORD x) {
		injector.ContextShellcodeInject(shellcode, x);
	};
	MainInjector::InjectShellcode("Context Shellcode Inject", func);
}

VOID MainInjector::DllList() {
	ImGui::Begin("Injectable Process", nullptr, ImGuiWindowFlags_NoCollapse);
	std::vector<ProcessInfo> procInfo = injector.InjectList();
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

DWORD MainInjector::GetPID() {
	DWORD retPid = 0;
	bool click = false;
	ImGui::Begin("choose pid", nullptr, ImGuiWindowFlags_NoCollapse);
	std::vector<ProcessInfo> procInfo = injector.InjectList();
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
		if (click)
			return procInfo[i].pid;
	}

	// End table
	ImGui::EndTable();
	ImGui::End();
	return retPid;
}