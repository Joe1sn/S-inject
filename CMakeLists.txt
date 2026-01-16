cmake_minimum_required(VERSION 3.11)
project(S-Inject LANGUAGES C CXX ASM_MASM RC)
enable_language(ASM_MASM)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(extern/ImGui)

set(SINJECT_INCLUDE
    include/app/Injector.hpp
    include/app/S-Wisper.h
    include/app/config.hpp
    include/app/network.hpp
    include/app/format.hpp

    include/window/MainWindow.hpp
    include/window/resources.h

    include/utils/constant.hpp
    include/utils/crypto.hpp
    include/utils/error.hpp
    include/utils/helper.hpp
    include/utils/query.hpp
)
set(SINJECT_SOURCE
    src/main.cpp
    src/winres.rc

    src/window/MainWindow.cpp

    src/app/S-Wisper.c
    src/app/injector.cpp
    src/app/network.cpp
    src/app/format.cpp

    src/utils/crypto.cpp
    src/utils/error.cpp
    src/utils/helper.cpp
)

set(APP_RES src/winres.rc)

# if(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
add_library(sw3_asm OBJECT src/app/S-Wisper-asm.x64.asm)

# endif()

# Specify MSVC UTF-8 encoding
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# make sure link .lib
link_libraries("wininet.lib")
link_libraries("d3d11.lib")
link_libraries("Crypt32.lib")

add_executable(${PROJECT_NAME} ${SINJECT_INCLUDE} ${SINJECT_SOURCE})
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)

# target_link_libraries(${PROJECT_NAME} PRIVATE wininet d3d11 Crypt32 imgui)
target_link_libraries(${PROJECT_NAME} PRIVATE wininet d3d11 Crypt32 imgui $<TARGET_OBJECTS:sw3_asm>)
