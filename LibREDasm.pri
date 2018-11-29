win32: CMAKE_GENERATOR = -G \"NMake Makefiles\"
else:  CMAKE_GENERATOR =

LIBREDASM_ROOT  = $$shell_path($$PWD/LibREDasm)
LIBREDASM_BUILD = $$shell_path($$OUT_PWD/LibREDasm)

LibREDasm.commands = @echo "Compiling LibREDasm..." $$escape_expand(\n\t) \
                     $$sprintf($$QMAKE_MKDIR_CMD, $$LIBREDASM_BUILD) $$escape_expand(\n\t) \
                     cd $$LIBREDASM_BUILD && cmake $$CMAKE_GENERATOR $$LIBREDASM_ROOT -DCMAKE_BUILD_TYPE=Release $$escape_expand(\n\t) \
                     cd $$LIBREDASM_BUILD && $(MAKE)

LibREDasm_Install.commands = $(COPY_DIR) $$shell_path($$LIBREDASM_BUILD/*.so) $$shell_path("../")

INCLUDEPATH += $$shell_path($$LIBREDASM_ROOT/depends/capstone/include/capstone) # Why I need this?!?
INCLUDEPATH += $$LIBREDASM_ROOT
LIBS += -L$$LIBREDASM_BUILD -lREDasm
QMAKE_EXTRA_TARGETS += LibREDasm LibREDasm_Install
