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

lib_capstone.commands = @echo "Compiling Capstone..." $$escape_expand(\n\t) \
                        $$sprintf($$QMAKE_MKDIR_CMD, $$CAPSTONE_BUILD) $$escape_expand(\n\t) \
                        cd $$CAPSTONE_BUILD && cmake $$CMAKE_GENERATOR $$CAPSTONE_SRC -DCMAKE_BUILD_TYPE=Release  \
                                                                                      -DCAPSTONE_BUILD_SHARED=OFF \
                                                                                      -DCAPSTONE_BUILD_STATIC=ON  \
                                                                                      -DCAPSTONE_BUILD_TESTS=OFF $$escape_expand(\n\t) \
                        cd $$CAPSTONE_BUILD && $(MAKE)

INCLUDEPATH += $$shell_path($$CAPSTONE_SRC/include/capstone)
LIBS += -L$$CAPSTONE_BUILD -lcapstone
PRE_TARGETDEPS += lib_capstone
QMAKE_EXTRA_TARGETS += lib_capstone

# ==========================================================
