DEPENDS_ROOT       = $$PWD

# =================== CMake Generators =====================
win32 {
    CMAKE_GENERATOR = -G \"NMake Makefiles\"
}
else {
    CMAKE_GENERATOR =
}
# ==========================================================


# ================ Single Header Libraries =================
INCLUDEPATH += $$shell_path($$DEPENDS_ROOT/include)
# ==========================================================

# ======================== Capstone ========================
CAPSTONE_SRC       = $$shell_path($$DEPENDS_ROOT/capstone)
CAPSTONE_BUILD     = $$shell_path($$OUT_PWD/capstone)

lib_capstone.commands += @echo "Compiling Capstone..." &&
lib_capstone.commands += $$sprintf($$QMAKE_MKDIR_CMD, $$CAPSTONE_BUILD) &&
lib_capstone.commands += cd $$CAPSTONE_BUILD &&
lib_capstone.commands += cmake $$CMAKE_GENERATOR $$CAPSTONE_SRC -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC=ON -DCAPSTONE_BUILD_TESTS=OFF &&
lib_capstone.commands += $(MAKE)

INCLUDEPATH += $$shell_path($$CAPSTONE_SRC/include/capstone)
LIBS += -L$$CAPSTONE_BUILD -lcapstone
PRE_TARGETDEPS += lib_capstone
QMAKE_EXTRA_TARGETS += lib_capstone

# ==========================================================
