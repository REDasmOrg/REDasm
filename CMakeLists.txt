cmake_minimum_required(VERSION 3.10)
 
project(REDasm)

set(QT_VERSION_REQ "5.9")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wno-missing-braces")
endif()

string(TIMESTAMP REDASM_BUILD_TIMESTAMP "%Y%m%d")
set(REDASM_GIT_VERSION "unknown")

if(UNIX)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    set(CMAKE_INSTALL_RPATH ".")
endif()

find_package(Qt5Core CONFIG REQUIRED)
find_package(Qt5Gui CONFIG REQUIRED)
find_package(Qt5Widgets CONFIG REQUIRED)
find_package(Qt5WebEngine CONFIG REQUIRED)
find_package(Qt5WebEngineWidgets CONFIG REQUIRED)
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
add_definitions(-DREDASM_VERSION="${REDASM_BUILD_VERSION}")

add_subdirectory(LibREDasm)
add_subdirectory(QHexView)

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

# Renderer
file(GLOB_RECURSE RENDERER_HEADERS renderer/*.h)
file(GLOB_RECURSE RENDERER_SOURCES renderer/*.cpp)

SET(HEADERS
    ${QHEXVIEW_HEADERS}
    ${REDASM_TEST_HEADERS}
    ${WIDGETS_HEADERS}
    ${DIALOGS_HEADERS}
    ${MODELS_HEADERS}
    ${RENDERER_HEADERS}
    mainwindow.h
    themeprovider.h
    redasmsettings.h)

SET(SOURCES
    ${QHEXVIEW_SOURCES}
    ${REDASM_TEST_SOURCES}
    ${WIDGETS_SOURCES}
    ${DIALOGS_SOURCES}
    ${MODELS_SOURCES}
    ${RENDERER_SOURCES}
    main.cpp
    mainwindow.cpp
    themeprovider.cpp
    redasmsettings.cpp)

set(FORMS
    ${WIDGETS_UIS}
    ${DIALOGS_UIS}
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

target_include_directories(${PROJECT_NAME} PUBLIC LibREDasm QHexEdit)
add_dependencies(${PROJECT_NAME} LibREDasm)

target_link_libraries(${PROJECT_NAME}
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::WebEngine
    Qt5::WebEngineWidgets
    LibREDasm)

if(WIN32)
    set(LIB_REDASM_BIN ${CMAKE_BINARY_DIR}/LibREDasm/LibREDasm.dll)
else()
    set(LIB_REDASM_BIN ${CMAKE_BINARY_DIR}/LibREDasm/LibREDasm.so)
endif()

# Post build commands
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy ${LIB_REDASM_BIN} ${CMAKE_BINARY_DIR})

