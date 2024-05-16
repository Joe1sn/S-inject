#include <iostream>
#include <string>

#include "Helper.h"
#include "Injector.h"

using namespace std;

int main(int argc, char* argv[])
{
	banner();
	menu();
	Injector injector;
	if (argc == 2) {
		set_color(FOREGROUND_RED | FOREGROUND_GREEN, BACKGROUND_INTENSITY);
		cout << ">>>!BackArg Found!<<<\n";
		cout << ">>><USING BRUTAL MOD><<<\n";
		cout << ">>>If the pid=0, injector will inject all injectable process<<<\n";
		cout << "!!!Maybe harmful to system!!!\n";
		cout << "!!!Maybe harmful to system!!!\n";
		cout << "!!!Maybe harmful to system!!!\n";
		set_normal();
		injector.BrutalSetter(TRUE);
	}

	unsigned int index = 0;
	cout << "index: ";
	scanf_s("%d", &index);
	cout << "[*]index: " << index << endl;
	cin.ignore();

	string DllPath = "";
	DWORD pid = 0;
	string sc = "";
	if (index < 4) {
		cout << "[+] DLL Path: ";
		getline(cin, DllPath);
		if (DllPath.size() == 0) {
			cout << "[*] DLL path is empty\n";
			return 0;
		}
		cout << "[*] DLL path received: " << DllPath << endl;
		cout << "[+] PID: ";
		scanf_s("%d", &pid);
		cout << "[*] PID received: " << pid << endl;
		cout << "[*] ---start injection---\n";
		injector.DllPathsetter(DllPath);
	}
	else if (index < 7) {
		cout << "[+] PID: ";
		scanf_s("%d", &pid);
		cout << "[*] PID received: " << pid << endl;
		cin.ignore();
		cout << "[+] Shellcode: \n";
		getline(cin, sc);
		cout << "[*] Shellcode received\n";
	}

	switch (index)
	{
	case 1: {
		if (pid == 0) {
			cout << "[*] PID is 0. Next> Run Auto Injection!\n";
			injector.CallBackSetter(&Injector::RemoteThreadInject);
			injector.Injectable();
			break;
		}
		injector.RemoteThreadInject(pid);
		cout << "[*] Remote Injection Complete\n";
		cout << "[?] Uninject DLL? Y/N\n";
		cin.ignore();
		char choice = 0;
		scanf_s("%c", &choice, 1);
		cout << choice << endl;
		if (choice == 'Y') {
			injector.unInject(pid);
			cout << "[*] Uninject Remote DLL with FreeLib\n";
		}
		break;
	}
	case 2: {
		if (pid == 0) {
			cout << "[*] PID is 0. Next> Run Auto Injection!\n";
			injector.CallBackSetter(&Injector::ReflectInject);
			injector.Injectable();
			break;
		}
		injector.ReflectInject(pid);
		injector.unReflectInject(pid);
		cout << "[*] Reflect Injection Complete\n";
		break;
	}
	case 3: {
		if (pid == 0) {
			cout << "[*] PID is 0. Next> Run Auto Injection!\n";
			cout << "[*] THIS IS APC BOOMING!\n";
			injector.CallBackSetter(&Injector::ApcInject);
			injector.Injectable();
			break;
		}
		injector.ApcInject(pid);
		//APC 注入只有Apc调度结束才能被回收DLL.
		//这里就是要关闭DLL弹出的窗口后，进行回收才能真正回收到
		//其实APC回收挺没有意义的
		//getchar();
		//getchar();
		//injector.unInject(pid);
		cout << "[*] APC Injection Complete\n";
		break;
	}
	case 4: {
		injector.ShellcodeInject(sc, pid);
		cout << "[*] Shellcode Injected\n";
		break;
	}
	case 5: {
		injector.ApcShellcodeInject(sc, pid);
		cout << "[*] APC Shellcode Injected\n";
		break;
	}
	case 6: {
		injector.ContextShellcodeInject(sc, pid);
		cout << "[*] APC Shellcode Injected\n";
		break;
	}
	case 7: {
		injector.Injectable();
		break;
	}
	default:
		break;
	}

	return 0;
}
