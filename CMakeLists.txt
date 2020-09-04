cmake_minimum_required(VERSION 3.10)

project(REDasm)

set(QT_VERSION_REQ "5.9")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(PORTABLE_MODE "Enable Portable Mode" OFF)

string(TIMESTAMP REDASM_BUILD_TIMESTAMP "%Y%m%d")
set(REDASM_GIT_VERSION "unknown")
set(REDASM_VERSION_BASE "3.0")

if(PORTABLE_MODE)
    add_definitions(-DREDASM_PORTABLE_MODE=1)
endif()

if(UNIX)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    set(CMAKE_INSTALL_RPATH ".")
endif()

find_package(Qt5Core       CONFIG REQUIRED)
find_package(Qt5Gui        CONFIG REQUIRED)
find_package(Qt5Widgets    CONFIG REQUIRED)
find_package(Git)

if(GIT_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    OUTPUT_VARIABLE REDASM_GIT_VERSION
                    ERROR_QUIET
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    message(STATUS "Git not found, setting version to ${REDASM_GIT_VERSION}")
endif()

set(REDASM_BUILD_VERSION "${REDASM_BUILD_TIMESTAMP}.${REDASM_GIT_VERSION}")
add_definitions(-DREDASM_VERSION="${REDASM_VERSION_BASE}-${REDASM_BUILD_VERSION}")

add_subdirectory(LibREDasm)
add_subdirectory(QHexView)

# FindREDasm.config
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/LibREDasm/rdapi")

add_subdirectory(submodules/plugins)
add_subdirectory(submodules/assemblers)
add_subdirectory(submodules/loaders)

if((CMAKE_BUILD_TYPE MATCHES Debug) OR (CMAKE_BUILD_TYPE MATCHES RelWithDebInfo))
    add_subdirectory(unittest)
endif()

QT5_WRAP_UI(UI_HDRS ${UI_FILES})

# Widgets
file(GLOB_RECURSE WIDGETS_HEADERS widgets/*.h)
file(GLOB_RECURSE WIDGETS_SOURCES widgets/*.cpp)
file(GLOB_RECURSE WIDGETS_UIS     widgets/*.ui)

# Dialogs
file(GLOB_RECURSE DIALOGS_HEADERS dialogs/*.h)
file(GLOB_RECURSE DIALOGS_SOURCES dialogs/*.cpp)
file(GLOB_RECURSE DIALOGS_UIS     dialogs/*.ui)

# Models
file(GLOB_RECURSE MODELS_HEADERS models/*.h)
file(GLOB_RECURSE MODELS_SOURCES models/*.cpp)

# Delegates
file(GLOB_RECURSE DELEGATES_HEADERS delegates/*.h)
file(GLOB_RECURSE DELEGATES_SOURCES delegates/*.cpp)

# Renderer
file(GLOB_RECURSE RENDERER_HEADERS renderer/*.h)
file(GLOB_RECURSE RENDERER_SOURCES renderer/*.cpp)

# Hooks
file(GLOB_RECURSE HOOKS_HEADERS hooks/*.h)
file(GLOB_RECURSE HOOKS_SOURCES hooks/*.cpp)

# UI
file(GLOB_RECURSE UI_HEADERS ui/*.h)
file(GLOB_RECURSE UI_SOURCES ui/*.cpp)
file(GLOB_RECURSE UI_UIS ui/*.ui)

SET(HEADERS
    ${QHEXVIEW_HEADERS}
    ${REDASM_TEST_HEADERS}
    ${WIDGETS_HEADERS}
    ${DIALOGS_HEADERS}
    ${MODELS_HEADERS}
    ${DELEGATES_HEADERS}
    ${HOOKS_HEADERS}
    ${RENDERER_HEADERS}
    ${UI_HEADERS}
    mainwindow.h
    themeprovider.h
    redasmsettings.h
    redasmfonts.h)

SET(SOURCES
    ${QHEXVIEW_SOURCES}
    ${REDASM_TEST_SOURCES}
    ${WIDGETS_SOURCES}
    ${DIALOGS_SOURCES}
    ${MODELS_SOURCES}
    ${DELEGATES_SOURCES}
    ${HOOKS_SOURCES}
    ${RENDERER_SOURCES}
    ${UI_SOURCES}
    main.cpp
    mainwindow.cpp
    themeprovider.cpp
    redasmsettings.cpp
    redasmfonts.cpp)

set(FORMS
    ${WIDGETS_UIS}
    ${DIALOGS_UIS}
    ${UI_UIS}
    mainwindow.ui)

set(RESOURCES
    resources.qrc
    themes.qrc)

if(WIN32)
    SET(GUI_TYPE WIN32)
endif()

add_executable(${PROJECT_NAME} ${GUI_TYPE}
               ${SOURCES}
               ${HEADERS}
               ${FORMS}
               ${RESOURCES}
               ${CMAKE_SOURCE_DIR}/res/windows/resources.rc)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} LibREDasm QHexEdit)
add_dependencies(${PROJECT_NAME} LibREDasm)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} Qt5::Core Qt5::Gui Qt5::Widgets LibREDasm)
else()
    target_link_libraries(${PROJECT_NAME} Qt5::Core Qt5::Gui Qt5::Widgets pthread LibREDasm)
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wno-missing-braces)
endif()

# Post build commands
set(LIBREDASM_BIN ${CMAKE_BINARY_DIR}/LibREDasm/LibREDasm${CMAKE_SHARED_LIBRARY_SUFFIX})
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${LIBREDASM_BIN} ${CMAKE_BINARY_DIR})
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E create_symlink submodules plugins)
