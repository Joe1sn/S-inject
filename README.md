![](./assets/joe1sn-S_inject-green.svg+xml)  ![](./assets/windows-C++-yellow.svg+xml)

<h1><p align="center">S-inject</p></h1>

<p align="center">DLL+Shellcode的Windows注入免杀工具</p>

<p align="center"><img src="./assets/image-20240205141410967.png"></p>

只是罗列各种方法，免杀推荐搭配其他技巧，要具体灵活使用

**须知：**

1. 反射式注入参考了著名github项目：https://github.com/stephenfewer/ReflectiveDLLInjection
   该项目为反射式注入支持的DLL
2. Shellcode使用base64编码后的shellcode
3. 相关测试的DLL文件在`Test Files`文件夹中

**免责声明：** 本工具仅供教育和授权测试目的使用。开发者及贡献者不支持、不鼓励也不赞成任何非法或未经授权的使用。 用户有责任确保其使用本工具的行为符合所有适用的法律法规。严禁将本工具用于任何未经授权的活动。 开发者及贡献者对使用本工具造成的任何损害或后果不承担责任。使用前请自行承担风险。 通过使用本工具，您同意这些条款，并对您的行为承担全部责任。

![image-20250914204952974](./assets/image-20250914204952974.png)

![image-20250914210256156](./assets/image-20250914210256156.png)

# Update

- **[2025-9-14]** 更新界面操作逻辑，优化代码结构，更新了imgui，新增 [issue 8](https://github.com/Joe1sn/S-inject/issues/8) 的功能， **该版本暂时不持支纯终端使用**。

  v1.0版本 readme: [README](./doc/version1.0_README.md)

  v2.0版本 readme: [README](./doc/version2.0_README.md)

- **[2025-7-1]** 修改为cmake项目，在项目中新建`build`目录后，使用`cmake ..`后`cmake .. -G "Visual Studio 17 2022" -A x64` 可以生成64位的sln项目，之后使用`cmake --build . --config Release`可以直接编译

# 免杀效果

远程shellcode注入等功能可免杀火绒，VNC无感，可注册表添加开机自启动

![image-20240216112653373](./assets/image-20240216112653373.png)

![image-20240216113029381](./assets/image-20240216113029381.png)

![image-20240216113432922](./assets/image-20240216113432922.png)

![image-20240216113917066](./assets/image-20240216113917066.png)
