#include <iostream>
#include <string>

#include "Helper.h"
#include "Injector.h"

using namespace std;

int main()
{
	banner();
	menu();
	unsigned int index = 0;
	cout << "index: ";
	scanf_s("%d", &index);
	cout << "[*]index: " << index << endl;
	cin.ignore();
	Injector injector;

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
		injector.setter(DllPath);
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
		injector.RemoteThreadInject(pid);
		injector.unInject(pid);
		cout << "[*] Remote Injection Complete\n";
		break;
	}
	case 2: {
		injector.ReflectInject(pid);
		injector.unReflectInject(pid);
		cout << "[*] Reflect Injection Complete\n";
		break;
	}
	case 3: {
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
