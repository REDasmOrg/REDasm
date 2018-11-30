project(REDasmTest)

set(REDASM_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/unittest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/disassemblertest.cpp
    PARENT_SCOPE)

set(REDASM_TEST_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/unittest.h
    ${CMAKE_CURRENT_SOURCE_DIR}/disassemblertest.h
    PARENT_SCOPE)
