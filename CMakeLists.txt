cmake_minimum_required(VERSION 3.12)

project(REDasm)

set(QT_VERSION_REQ "5.9")
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include(${CMAKE_SOURCE_DIR}/LibREDasm/cmake/sanitizers.cmake)
option(BUILD_TESTS "Build tests" OFF)

string(TIMESTAMP REDASM_BUILD_TIMESTAMP "%Y%m%d")
set(REDASM_GIT_VERSION "unknown")
set(REDASM_VERSION_BASE "3.0")

find_package(Qt5 5.9 REQUIRED COMPONENTS Widgets)
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
add_subdirectory(submodules/database)
QT5_WRAP_UI(UI_HDRS ${UI_FILES})

# Widgets
file(GLOB_RECURSE WIDGETS_HEADERS CONFIGURE_DEPENDS widgets/*.h )
file(GLOB_RECURSE WIDGETS_SOURCES CONFIGURE_DEPENDS widgets/*.cpp)
file(GLOB_RECURSE WIDGETS_UIS CONFIGURE_DEPENDS widgets/*.ui)

# Dialogs
file(GLOB_RECURSE DIALOGS_HEADERS CONFIGURE_DEPENDS dialogs/*.h)
file(GLOB_RECURSE DIALOGS_SOURCES CONFIGURE_DEPENDS dialogs/*.cpp)
file(GLOB_RECURSE DIALOGS_UIS CONFIGURE_DEPENDS dialogs/*.ui)

# Models
file(GLOB_RECURSE MODELS_HEADERS CONFIGURE_DEPENDS models/*.h)
file(GLOB_RECURSE MODELS_SOURCES CONFIGURE_DEPENDS models/*.cpp)

# Delegates
file(GLOB_RECURSE DELEGATES_HEADERS CONFIGURE_DEPENDS delegates/*.h)
file(GLOB_RECURSE DELEGATES_SOURCES CONFIGURE_DEPENDS delegates/*.cpp)

# Renderer
file(GLOB_RECURSE RENDERER_HEADERS CONFIGURE_DEPENDS renderer/*.h)
file(GLOB_RECURSE RENDERER_SOURCES CONFIGURE_DEPENDS renderer/*.cpp)

# Hooks
file(GLOB_RECURSE HOOKS_HEADERS CONFIGURE_DEPENDS hooks/*.h)
file(GLOB_RECURSE HOOKS_SOURCES CONFIGURE_DEPENDS hooks/*.cpp)

# UI
file(GLOB_RECURSE UI_HEADERS CONFIGURE_DEPENDS ui/*.h)
file(GLOB_RECURSE UI_SOURCES CONFIGURE_DEPENDS ui/*.cpp)
file(GLOB_RECURSE UI_UIS CONFIGURE_DEPENDS ui/*.ui)

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
    redasmfonts.h
)

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
    redasmfonts.cpp
)

set(FORMS
    ${WIDGETS_UIS}
    ${DIALOGS_UIS}
    ${UI_UIS}
    mainwindow.ui
)

set(RESOURCES
    resources.qrc
    themes.qrc
)

if(WIN32)
    set(GUI_TYPE WIN32)
endif()

add_executable(${PROJECT_NAME} ${GUI_TYPE}
               ${SOURCES}
               ${HEADERS}
               ${FORMS}
               ${RESOURCES}
               ${CMAKE_SOURCE_DIR}/res/windows/resources.rc
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS OFF)

# TODO: refactor this to target_include_directories(target PUBLIC ...) in the submodules
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        LibREDasm
        QHexEdit
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    LibREDasm
)

# Include Threads
# TODO: perhaps this should be a PUBLIC dependency of LibREDasm?
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_THREAD_LIBS_INIT})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wno-missing-braces)
endif()

# Post build commands
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:LibREDasm> ${CMAKE_BINARY_DIR})
if(NOT WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E create_symlink submodules plugins)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

# Deploy Qt DLLs on Windows
# https://stackoverflow.com/a/41199492/1806760
if(Qt5_FOUND AND WIN32 AND TARGET Qt5::qmake AND NOT TARGET Qt5::windeployqt)
    get_target_property(_qt5_qmake_location Qt5::qmake IMPORTED_LOCATION)

    execute_process(
        COMMAND "${_qt5_qmake_location}" -query QT_INSTALL_PREFIX
        RESULT_VARIABLE return_code
        OUTPUT_VARIABLE qt5_install_prefix
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(imported_location "${qt5_install_prefix}/bin/windeployqt.exe")

    if(EXISTS ${imported_location})
        add_executable(Qt5::windeployqt IMPORTED)

        set_target_properties(Qt5::windeployqt PROPERTIES
            IMPORTED_LOCATION ${imported_location}
        )
    endif()
endif()

if(TARGET Qt5::windeployqt)
    # execute windeployqt in a tmp directory after build
    add_custom_command(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND Qt5::windeployqt "$<TARGET_FILE:${PROJECT_NAME}>"
    )

    # TODO: installation
endif()
