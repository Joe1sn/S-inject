cmake_minimum_required(VERSION 3.11)
project(imgui)

set(IMGUI_SOURCES
    imgui.cpp
    imgui_demo.cpp
    imgui_draw.cpp
    imgui_impl_dx11.cpp
    imgui_impl_win32.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    )

set(IMGUI_INCLUDE
    imconfig.h
    imgui.h
    imgui_impl_dx11.h
    imgui_impl_win32.h
    imgui_internal.h
    imstb_rectpack.h
    imstb_textedit.h
    imstb_truetype.h
    )

add_library(${PROJECT_NAME} STATIC
    ${IMGUI_SOURCES}
    ${IMGUI_INCLUDE}
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)