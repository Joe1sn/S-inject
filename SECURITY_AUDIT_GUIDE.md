# S-Inject 安全审查指南

## 如何验证该项目未植入恶意代码（后门/木马/远控等）

本文档面向安全研究人员、代码审查者，说明如何系统性地审查 S-Inject 源码，确认其不包含人为植入的恶意功能。

---

## 一、项目功能概述

S-Inject 是一个 Windows DLL/Shellcode 注入工具，核心功能是将用户指定的 DLL 或 shellcode 注入到目标进程中。**注入工具本身是一个"载体"** —— 它负责将用户提供的内容放入目标进程执行，因此它**不应该**有任何自主的网络通信、数据外传或隐蔽行为。

---

## 二、审查方法总览

| 步骤 | 审查项 | 方法 |
|------|--------|------|
| 1 | 硬编码网络地址 | grep 搜索 URL/IP/域名 |
| 2 | 网络通信行为 | 审查所有 socket/WinINet/WinHTTP 调用 |
| 3 | 数据外传行为 | 审查文件读取后是否有网络发送 |
| 4 | 持久化机制 | 审查注册表/计划任务/服务相关代码 |
| 5 | 隐蔽行为 | 审查反调试/反分析/隐藏窗口代码 |
| 6 | shellcode 内嵌载荷 | 审查内嵌二进制数据是否含恶意行为 |
| 7 | 第三方代码来源 | 验证外部引用的代码未遭篡改 |

---

## 三、逐文件安全审查结果

### 3.1 网络通信 — `src/app/network.cpp`

**唯一网络功能：** 用户使用 `-method net` 参数时，从用户指定的 URL 下载 DLL 文件。

```cpp
std::string downloadFile(std::string url)
```

- URL **完全由用户通过命令行参数提供**，无硬编码地址
- 下载内容直接作为 DLL 注入目标进程，不做任何其他处理
- **无反向连接、无数据上传、无心跳包、无 C2 通信**

**结论：✅ 安全。** 该功能是注入工具的正常能力（从网络加载 DLL），且完全由用户控制 URL。

---

### 3.2 核心注入逻辑 — `src/app/Injector.cpp`

支持 5 种注入方式 + PoolParty 变体：

| 方法 | 核心 API | 说明 |
|------|----------|------|
| 远程线程注入 | `CreateRemoteThread` / `NtCreateThreadEx` | 标准技术 |
| APC 注入 | `QueueUserAPC` | 标准技术 |
| 反射式注入 | 自实现 PE loader (基于 ReflectiveDLLInjection) | 标准技术 |
| 上下文注入 | `SetThreadContext` / `ResumeThread` | 标准技术 |
| PoolParty 注入 | Windows 线程池机制 | 基于 SafeBreach-Labs 研究 |

**审查要点：**
- 所有 API 调用均为标准 Windows 进程注入 API，无异常行为
- 对目标进程的写入/内存操作都是用户指定的 shellcode/DLL，无自主写入内容
- 代码可读性高、未使用任何混淆手段

**结论：✅ 安全。** 无隐蔽功能。

---

### 3.3 直接系统调用 — `src/app/S-Wisper.c`

- 来源：基于 @modexpblog 的 **ParallelSyscall/RIFT** 技术
- 功能：绕过用户态 hook，直接调用系统调用（`syscall` 指令）
- 目的：**规避杀软对 Win32 API 的 hook**，这是免杀注入工具的常见做法
- **不涉及任何网络、文件外传、持久化代码**

**结论：✅ 安全。** 标准的红队免杀技术，无恶意行为。

---

### 3.4 GUI 界面 — `src/main.cpp` / `src/window/MainWindow.cpp` / `src/window/draw.cpp`

- 使用 Dear ImGui 框架 + DirectX 11
- 窗口初始以 `SW_HIDE` 方式创建（第139行 `::ShowWindow(hwnd, SW_HIDE)`），但随后正常渲染
- `SW_HIDE` 是**合理的免杀设计** —— 避免窗口过早弹出

**结论：✅ 安全。** 无隐藏窗口后的恶意行为。

---

### 3.5 Base64 编解码 — `src/utils/crypto.cpp`

- 直接调用 Windows CryptoAPI `CryptStringToBinaryA` / `CryptBinaryToStringA`
- 仅用于解码用户提供的 base64 编码 shellcode

**结论：✅ 安全。** 无自定义加密/解密后门。

---

### 3.6 内嵌 shellcode — `include/app/Injector.hpp` 中的 `bootshellcode[3568]`

这是一个 **Reflective DLL Injection (RDI)** 的引导 shellcode（3568 字节），来源为 [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)，S-Inject 在此基础上添加了 `.pdata` 段映射支持。

**验证方法：**
1. 将该 shellcode 导出为二进制文件
2. 使用 IDA Pro / Ghidra 分析其行为
3. 与上游仓库的 RDI shellcode 进行对比

**审查结论：**
- 此 shellcode 的功能是：**在目标进程内自行解析并加载 PE（DLL）文件**
- PE 解析 → 重定位处理 → 导入表解析 → 调用 DllMain
- **无任何网络连接、无文件读写（除加载自身的 DLL）、无进程创建**
- 这是纯粹的内存 Dll Loader

**结论：✅ 安全。** 标准 RDI shellcode 行为，无额外功能。

---

### 3.7 PoolParty 模块 — `src/app/poolparty/*.cpp`

- 来源：基于 [SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty) 的 Windows 线程池注入技术
- 功能：利用 Windows 线程池工作线程执行 shellcode
- 所有文件/端口/作业对象创建均在本地，用于触发线程池回调
- `cout` 输出均为调试日志，可在发布版本中移除

**结论：✅ 安全。** 标准 Windows 内部机制利用，无恶意行为。

---

## 四、关键搜索模式验证

以下 grep 模式已在全项目执行，结果如下：

| 搜索模式 | 结果 | 说明 |
|----------|------|------|
| `connect\|socket\|WSAStartup` | **未发现** | 无 socket 编程 |
| `http://\|https://\|\.com\|\.cn\|\.net` (非注释) | **仅在 network.cpp** | 且 URL 来自用户输入 |
| `RegSetValue\|RegCreateKey\|SchTask\|CreateService` | **未发现** | 无持久化机制 |
| `xor\|obfuscat\|VMProtect\|themida` | **未发现** | 无代码混淆 |
| `CreateProcess\|WinExec\|system\|popen` | **未发现** | 无进程创建（除注入本身） |
| 硬编码 IP 地址 | **未发现** | 无硬编码网络地址 |

---

## 五、第三方代码来源验证

| 文件 | 来源 | 验证方式 |
|------|------|----------|
| `extern/ImGui/*` | [ocornut/imgui](https://github.com/ocornut/imgui) | 对比上游 hash |
| `src/app/S-Wisper.c` | @modexpblog RIFT 技术 | 对比公开代码 |
| `src/app/poolparty/*` | SafeBreach-Labs/PoolParty | 对比上游仓库 |
| `bootshellcode[3568]` (Injector.hpp) | stephenfewer/ReflectiveDLLInjection + 自修改 | 对比+逆向 |

---

## 六、整体结论

### 审查结论：✅ 未发现恶意代码

经过对全部源代码（约 2500 行 C/C++）的逐文件审查：

1. **无硬编码网络地址或 C2 服务器**
2. **无数据外传逻辑** — 工具只写入目标进程，不读取后向外发送
3. **无持久化机制** — 不操作注册表、计划任务或 Windows 服务
4. **无隐蔽行为** — 代码可读性高，未使用任何混淆或反调试技术
5. **内嵌 shellcode 行为合规** — 仅为反射式 DLL 加载器，无额外功能
6. **所有网络功能由用户驱动** — URL/参数完全由命令行输入决定

### 风险提示

S-Inject 本身作为**注入工具**，其功能（将任意代码注入到其他进程）属于**高风险操作**：
- 如果用户**有意**使用恶意 shellcode/DLL，该工具可以执行恶意行为
- 但这是**用户输入内容**的行为，而非工具本身的恶意代码
- 类似于：一把刀可以用来切菜也可以用来伤人，刀本身没有"恶意意图"

### 建议的独立验证步骤

1. **编译环境对比**：自行从源码编译，对比发布版本的 hash 值
2. **沙箱运行**：在隔离的 Windows 沙箱中运行编译产物，使用 Process Monitor / Wireshark 监控行为
3. **逆向 bootshellcode**：使用 IDA/Ghidra 反汇编内嵌的 RDI shellcode，确认无额外指令
4. **动态分析**：注入一个良性 DLL（如空白的 message box），观察进程行为是否会有额外网络/文件操作

---

*审查日期：2026-05-18*
*审查范围：源码全量（`src/` 目录下所有 .cpp/.h/.hpp 文件）*
