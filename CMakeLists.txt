cmake_minimum_required(VERSION 3.10)
 
project(REDasm)

set(QT_VERSION_REQ "5.10")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
set(REDASM_BUILD_VERSION "unknown")

if(LINUX)
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
                    OUTPUT_VARIABLE REDASM_BUILD_VERSION
                    ERROR_QUIET
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    message(STATUS "git not found, setting version to ${REDASM_BUILD_VERSION}")
endif()

add_definitions(-DGIT_VERSION="${REDASM_BUILD_VERSION}")

add_subdirectory(LibREDasm)
add_subdirectory(QHexEdit)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_subdirectory(unittest)
endif()

QT5_WRAP_UI(UI_HDRS ${UI_FILES})

SET(SOURCES
    ${QHEXEDIT_SOURCES}
    ${REDASM_TEST_SOURCES}
    main.cpp
    mainwindow.cpp
    widgets/disassemblerview/disassemblerview.cpp
    models/disassemblermodel.cpp
    models/segmentsmodel.cpp
    widgets/listingmap.cpp
    models/referencesmodel.cpp
    dialogs/referencesdialog.cpp
    dialogs/gotodialog.cpp
    dialogs/databasedialog.cpp
    models/databasemodel.cpp
    dialogs/aboutdialog.cpp
    dialogs/manualloaddialog.cpp
    themeprovider.cpp
    widgets/graphview/graphview.cpp
    models/listingitemmodel.cpp
    models/symboltablemodel.cpp
    models/listingfiltermodel.cpp
    models/callgraphmodel.cpp
    renderer/listingtextrenderer.cpp
    renderer/listingrenderercommon.cpp
    renderer/listinggraphrenderer.cpp
    widgets/disassemblergraphview/disassemblergraphview.cpp
    widgets/disassemblergraphview/disassemblerwebchannel.cpp
    widgets/disassemblerpopup/disassemblerpopup.cpp
    widgets/disassemblerpopup/disassemblerpopupwidget.cpp
    renderer/listingpopuprenderer.cpp
    redasmsettings.cpp
    dialogs/settingsdialog.cpp
    widgets/disassemblerlistingview/disassemblerlistingview.cpp
    widgets/disassemblerlistingview/disassemblertextview.cpp
    widgets/disassemblerlistingview/disassemblercolumnview.cpp)

SET(HEADERS
    ${QHEXEDIT_HEADERS}
    ${REDASM_TEST_HEADERS}
    mainwindow.h
    widgets/disassemblerview/disassemblerview.h
    models/disassemblermodel.h
    models/segmentsmodel.h
    widgets/listingmap.h
    models/referencesmodel.h
    dialogs/referencesdialog.h
    dialogs/gotodialog.h
    dialogs/databasedialog.h
    models/databasemodel.h
    dialogs/aboutdialog.h
    dialogs/manualloaddialog.h
    themeprovider.h
    widgets/graphview/graphview.h
    models/listingitemmodel.h
    models/symboltablemodel.h
    models/listingfiltermodel.h
    models/callgraphmodel.h
    renderer/listingtextrenderer.h
    renderer/listingrenderercommon.h
    renderer/listinggraphrenderer.h
    widgets/disassemblergraphview/disassemblergraphview.h
    widgets/disassemblergraphview/disassemblerwebchannel.h
    widgets/disassemblerpopup/disassemblerpopup.h
    widgets/disassemblerpopup/disassemblerpopupwidget.h
    renderer/listingpopuprenderer.h
    redasmsettings.h
    dialogs/settingsdialog.h
    widgets/disassemblerlistingview/disassemblerlistingview.h
    widgets/disassemblerlistingview/disassemblertextview.h
    widgets/disassemblerlistingview/disassemblercolumnview.h)

set(FORMS
    mainwindow.ui
    widgets/disassemblerview/disassemblerview.ui
    dialogs/referencesdialog.ui
    dialogs/gotodialog.ui
    dialogs/databasedialog.ui
    dialogs/aboutdialog.ui
    dialogs/manualloaddialog.ui
    dialogs/settingsdialog.ui)

set(RESOURCES
    resources.qrc
    themes.qrc)

add_executable(${PROJECT_NAME}
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

set(REDASM_DATABASE_SRC ${CMAKE_SOURCE_DIR}/database)
set(REDASM_DATABASE_DEST ${CMAKE_BINARY_DIR}/database)

if(WIN32)
    set(LIB_REDASM_BIN ${CMAKE_BINARY_DIR}/LibREDasm/LibREDasm.dll)
else()
    set(LIB_REDASM_BIN ${CMAKE_BINARY_DIR}/LibREDasm/LibREDasm.so)
endif()

# Post build commands
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E make_directory ${REDASM_DATABASE_DEST})

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy_directory ${REDASM_DATABASE_SRC} ${REDASM_DATABASE_DEST})

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy ${LIB_REDASM_BIN} ${CMAKE_BINARY_DIR})

