cmake_minimum_required(VERSION 3.11)
project(SINJECT LANGUAGES C CXX ASM_MASM)
enable_language(ASM_MASM)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include/imgui)
include_directories(include/app)
include_directories(include/utils)

set (IMGUI_INCLUDE
    include/imgui/imconfig.h
    include/imgui/imgui_impl_dx11.h
    include/imgui/imgui_impl_win32.h
    include/imgui/imgui_internal.h
    include/imgui/imgui.h
    include/imgui/imstb_rectpack.h
    include/imgui/imstb_textedit.h
    include/imgui/imstb_truetype.h
)
set (IMGUI_SOURCE
    include/imgui/imgui_demo.cpp
    include/imgui/imgui_draw.cpp
    include/imgui/imgui_impl_dx11.cpp
    include/imgui/imgui_impl_win32.cpp
    include/imgui/imgui_tables.cpp
    include/imgui/imgui_widgets.cpp
    include/imgui/imgui.cpp

)
set(SINJECT_INCLUDE
    
)
set(SINJECT_SOURCE
    src/main.cpp

    src/app/Injector.cpp
    src/app/window.cpp
    src/app/S-Wisper.c
)

add_library(sw3_asm OBJECT src/app/S-Wisper-asm.x64.asm)

# Specify MSVC UTF-8 encoding
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
# make sure link .lib
link_libraries("wininet.lib")
link_libraries("d3d11.lib")
link_libraries("Crypt32.lib")
add_executable(${PROJECT_NAME} WIN32  ${SINJECT_INCLUDE} ${SINJECT_SOURCE} ${IMGUI_INCLUDE} ${IMGUI_SOURCE})
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)
target_link_libraries(${PROJECT_NAME} PRIVATE wininet d3d11 Crypt32 $<TARGET_OBJECTS:sw3_asm>)