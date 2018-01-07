DEPENDS_ROOT       = $$PWD

# =================== CMake Generators =====================
win32 {
    CMAKE_GENERATOR = -G quote(MinGW Makefiles)
}
else {
    CMAKE_GENERATOR =
}
# ==========================================================


# ================ Single Header Libraries =================
INCLUDEPATH += $$DEPENDS_ROOT/include
# ==========================================================

# ======================== Capstone ========================
CAPSTONE_SRC       = $$DEPENDS_ROOT/capstone
CAPSTONE_BUILD     = $$OUT_PWD/capstone

lib_capstone.commands = @echo "Compiling Capstone..."; \
                        $(MKDIR) $$CAPSTONE_BUILD && \
                        cd $$CAPSTONE_BUILD && \
                        cmake $$CMAKE_GENERATOR $$CAPSTONE_SRC -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC=ON -DCAPSTONE_BUILD_TESTS=OFF && \
                        $(MAKE)

INCLUDEPATH += $$CAPSTONE_SRC/include
LIBS += -L$$CAPSTONE_BUILD -lcapstone
PRE_TARGETDEPS += lib_capstone
QMAKE_EXTRA_TARGETS += lib_capstone

# ==========================================================
