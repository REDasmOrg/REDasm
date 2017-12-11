DEPENDS_ROOT       = $$PWD

# ================ Single Header Libraries =================
INCLUDEPATH += $$DEPENDS_ROOT/include
# ==========================================================

# ======================== Capstone ========================
CAPSTONE_SRC       = $$DEPENDS_ROOT/capstone
CAPSTONE_BUILD     = $$OUT_PWD/capstone

lib_capstone.commands = @echo "Compiling Capstone..."; \
                        $(MKDIR) $$CAPSTONE_BUILD && \
                        cd $$CAPSTONE_BUILD && \
                        cmake $$CAPSTONE_SRC -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC=ON -DCAPSTONE_BUILD_TESTS=OFF && \
                        $(MAKE)

INCLUDEPATH += $$CAPSTONE_SRC/include
LIBS += -L$$CAPSTONE_BUILD -lcapstone
PRE_TARGETDEPS += lib_capstone
QMAKE_EXTRA_TARGETS += lib_capstone

# ==========================================================

# ========================== OGDF ==========================
OGDF_SRC       = $$DEPENDS_ROOT/ogdf
OGDF_BUILD     = $$OUT_PWD/ogdf

lib_ogdf.commands = @echo "Compiling OGDF..."; \
                    $(MKDIR) $$OGDF_BUILD && \
                    cd $$OGDF_BUILD && \
                    cmake $$OGDF_SRC -DOGDF_DEBUG_MODE=OFF && \
                    $(MAKE)

INCLUDEPATH += $$OGDF_SRC/include $$OGDF_BUILD/include
LIBS += -L$$OGDF_BUILD -lOGDF -lCOIN
PRE_TARGETDEPS += lib_ogdf
QMAKE_EXTRA_TARGETS += lib_ogdf
# ==========================================================
