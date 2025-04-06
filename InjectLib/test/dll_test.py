import ctypes

# 加载 DLL（路径根据实际情况）
dll = ctypes.WinDLL("./InjectLib.dll")

# 声明函数：GetPIDByProcessName
dll.getPID.argtypes = [ctypes.c_char_p]     # 参数是 const char*
dll.getPID.restype = ctypes.c_uint32        # 返回 DWORD（uint32）
# 传入进程名，比如 notepad.exe
process_name = b"x64dbg"  # 注意要是 bytes 类型
pid = dll.getPID(process_name)

print(f"PID of {process_name.decode()}: {pid}")
