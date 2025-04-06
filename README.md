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

- **[2025-4-6]** **重要：** 新创建分支(branch)：mcp，今后的MCP server和lib(dll)版本在这个分支下

