#-------------------------------------------------
#
# Project created by QtCreator 2017-05-15T14:14:34
#
#-------------------------------------------------

QT       += core gui xml
CONFIG   += c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets webengine webenginewidgets

TARGET = REDasm
TEMPLATE = app

include(depends/depends.pri)
include(widgets/QHexEdit/QHexEdit.pri)
debug: include(unittest/unittest.pri)

DEFINES += GIT_VERSION='\\\"'$$system("git rev-parse --short HEAD")'\\\"'

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

win32
{
    RC_FILE = $$PWD/res/windows/resources.rc
}

SOURCES += main.cpp\
        mainwindow.cpp \
    redasm/plugins/plugins.cpp \
    redasm/plugins/format.cpp \
    widgets/disassemblerview/disassemblerview.cpp \
    widgets/disassemblertextview/disassemblertextview.cpp \
    models/disassemblermodel.cpp \
    models/segmentsmodel.cpp \
    redasm/analyzer/analyzer.cpp \
    redasm/disassembler/disassembler.cpp \
    widgets/listingmap.cpp \
    models/referencesmodel.cpp \
    dialogs/referencesdialog.cpp \
    redasm/formats/psxexe/psxexe.cpp \
    redasm/formats/psxexe/psxexe_analyzer.cpp \
    redasm/formats/pe/pe.cpp \
    redasm/plugins/assembler/printer.cpp \
    redasm/formats/pe/pe_analyzer.cpp \
    redasm/formats/pe/pe_utils.cpp \
    dialogs/gotodialog.cpp \
    redasm/formats/elf/elf.cpp \
    redasm/support/utils.cpp \
    redasm/support/demangler.cpp \
    redasm/assemblers/mips/mips.cpp \
    redasm/assemblers/x86/x86.cpp \
    redasm/formats/pe/vb/vb_analyzer.cpp \
    redasm/formats/pe/vb/vb_components.cpp \
    redasm/formats/pe/pe_imports.cpp \
    redasm/disassembler/disassemblerbase.cpp \
    redasm/disassembler/types/referencetable.cpp \
    redasm/disassembler/types/symboltable.cpp \
    redasm/support/coff/coff_symboltable.cpp \
    dialogs/databasedialog.cpp \
    redasm/support/hash.cpp \
    redasm/signatures/patparser.cpp \
    models/databasemodel.cpp \
    redasm/support/serializer.cpp \
    redasm/signatures/signaturedb.cpp \
    dialogs/aboutdialog.cpp \
    redasm/redasm.cpp \
    redasm/formats/pe/pe_resources.cpp \
    redasm/formats/pe/borland/borland_version.cpp \
    dialogs/manualloaddialog.cpp \
    redasm/formats/binary/binary.cpp \
    redasm/assemblers/chip8/chip8.cpp \
    redasm/support/endianness.cpp \
    redasm/vmil/vmil_instructions.cpp \
    redasm/vmil/vmil_emulator.cpp \
    redasm/vmil/vmil_printer.cpp \
    redasm/assemblers/mips/mips_quirks.cpp \
    redasm/assemblers/mips/mips_printer.cpp \
    redasm/assemblers/x86/x86_printer.cpp \
    redasm/assemblers/chip8/chip8_printer.cpp \
    redasm/assemblers/chip8/chip8_emulator.cpp \
    redasm/assemblers/mips/mips_emulator.cpp \
    redasm/formats/dex/dex.cpp \
    redasm/assemblers/dalvik/dalvik.cpp \
    redasm/assemblers/dalvik/dalvik_printer.cpp \
    redasm/formats/dex/dex_statemachine.cpp \
    redasm/formats/dex/dex_utils.cpp \
    themeprovider.cpp \
    widgets/graphview/graphview.cpp \
    redasm/formats/elf/elf_analyzer.cpp \
    redasm/disassembler/disassemblerapi.cpp \
    redasm/assemblers/cil/cil.cpp \
    redasm/formats/pe/dotnet/dotnet.cpp \
    redasm/formats/pe/dotnet/dotnet_reader.cpp \
    redasm/disassembler/graph/functiongraph.cpp \
    redasm/formats/xbe/xbe.cpp \
    redasm/support/ordinals.cpp \
    redasm/formats/gba/gba.cpp \
    redasm/formats/gba/gba_analyzer.cpp \
    redasm/assemblers/metaarm/metaarm.cpp \
    redasm/assemblers/metaarm/metaarm_printer.cpp \
    redasm/assemblers/metaarm/metaarm_emulator.cpp \
    redasm/assemblers/metaarm/arm.cpp \
    redasm/assemblers/metaarm/armthumb.cpp \
    redasm/assemblers/metaarm/arm_common.cpp \
    redasm/disassembler/algorithm/controlflow.cpp \
    redasm/plugins/assembler/assembler.cpp \
    redasm/plugins/disassembler/algorithm.cpp \
    redasm/disassembler/algorithm/linearsweep.cpp \
    redasm/disassembler/listing/listingdocument.cpp \
    redasm/disassembler/listing/instructionpool.cpp \
    redasm/disassembler/listing/listingrenderer.cpp \
    redasm/support/timer.cpp \
    models/listingitemmodel.cpp \
    models/symboltablemodel.cpp \
    models/listingfiltermodel.cpp \
    redasm/disassembler/listing/listingcursor.cpp \
    models/callgraphmodel.cpp \
    renderer/listingtextrenderer.cpp \
    renderer/listingrenderercommon.cpp \
    renderer/listinggraphrenderer.cpp \
    widgets/disassemblergraphview/disassemblergraphview.cpp \
    redasm/graph/graph.cpp \
    widgets/disassemblergraphview/disassemblerwebchannel.cpp \
    redasm/plugins/disassembler/statemachine.cpp \
    redasm/emulator/emulatorbase.cpp \
    redasm/emulator/emulator.cpp \
    redasm/formats/dex/dex_algorithm.cpp

HEADERS  += mainwindow.h \
    redasm/redasm.h \
    redasm/plugins/format.h \
    redasm/plugins/base.h \
    redasm/plugins/plugins.h \
    widgets/disassemblerview/disassemblerview.h \
    widgets/disassemblertextview/disassemblertextview.h \
    models/disassemblermodel.h \
    models/segmentsmodel.h \
    redasm/analyzer/analyzer.h \
    redasm/disassembler/disassembler.h \
    widgets/listingmap.h \
    models/referencesmodel.h \
    dialogs/referencesdialog.h \
    redasm/formats/psxexe/psxexe.h \
    redasm/formats/psxexe/psxexe_analyzer.h \
    redasm/formats/pe/pe.h \
    redasm/formats/pe/pe_constants.h \
    redasm/formats/pe/pe_headers.h \
    redasm/plugins/assembler/printer.h \
    redasm/formats/pe/pe_analyzer.h \
    redasm/formats/pe/pe_utils.h \
    dialogs/gotodialog.h \
    redasm/formats/elf/elf.h \
    redasm/formats/elf/elf64_header.h \
    redasm/formats/elf/elf32_header.h \
    redasm/formats/elf/elf_common.h \
    redasm/support/demangler.h \
    redasm/support/utils.h \
    redasm/assemblers/mips/mips.h \
    redasm/assemblers/x86/x86.h \
    redasm/formats/pe/vb/vb_analyzer.h \
    redasm/formats/pe/vb/vb_header.h \
    redasm/formats/pe/vb/vb_components.h \
    redasm/formats/pe/pe_imports.h \
    redasm/disassembler/disassemblerbase.h \
    redasm/disassembler/types/referencetable.h \
    redasm/disassembler/types/symboltable.h \
    redasm/support/coff/coff_symboltable.h \
    redasm/support/coff/coff_types.h \
    redasm/support/coff/coff_constants.h \
    redasm/support/cachemap.h \
    dialogs/databasedialog.h \
    redasm/support/hash.h \
    redasm/signatures/patparser.h \
    models/databasemodel.h \
    redasm/support/serializer.h \
    redasm/signatures/signaturedb.h \
    dialogs/aboutdialog.h \
    redasm/formats/pe/pe_resources.h \
    redasm/formats/pe/borland/borland_types.h \
    redasm/formats/pe/borland/borland_version.h \
    dialogs/manualloaddialog.h \
    redasm/formats/binary/binary.h \
    redasm/assemblers/chip8/chip8.h \
    redasm/support/endianness.h \
    redasm/vmil/vmil_instructions.h \
    redasm/vmil/vmil_types.h \
    redasm/vmil/vmil_emulator.h \
    redasm/vmil/vmil_printer.h \
    redasm/assemblers/mips/mips_printer.h \
    redasm/assemblers/mips/mips_quirks.h \
    redasm/assemblers/x86/x86_printer.h \
    redasm/assemblers/chip8/chip8_emulator.h \
    redasm/assemblers/chip8/chip8_printer.h \
    redasm/assemblers/chip8/chip8_registers.h \
    redasm/assemblers/mips/mips_emulator.h \
    redasm/formats/dex/dex.h \
    redasm/formats/dex/dex_constants.h \
    redasm/formats/dex/dex_header.h \
    redasm/assemblers/dalvik/dalvik.h \
    redasm/assemblers/dalvik/dalvik_printer.h \
    redasm/assemblers/dalvik/dalvik_metadata.h \
    redasm/assemblers/dalvik/dalvik_opcodes.h \
    redasm/formats/dex/dex_statemachine.h \
    redasm/formats/dex/dex_utils.h \
    redasm/formats/pe/pe_debug.h \
    redasm/formats/pe/pe_common.h \
    themeprovider.h \
    widgets/graphview/graphview.h \
    redasm/formats/elf/elf_analyzer.h \
    redasm/disassembler/disassemblerapi.h \
    redasm/formats/pe/dotnet/dotnet_header.h \
    redasm/assemblers/cil/cil.h \
    redasm/formats/pe/dotnet/dotnet.h \
    redasm/formats/pe/dotnet/dotnet_tables.h \
    redasm/formats/pe/dotnet/dotnet_reader.h \
    redasm/disassembler/graph/functiongraph.h \
    redasm/support/genetic.h \
    redasm/formats/xbe/xbe.h \
    redasm/formats/xbe/xbe_header.h \
    redasm/support/ordinals.h \
    redasm/formats/gba/gba.h \
    redasm/formats/gba/gba_analyzer.h \
    redasm/assemblers/metaarm/metaarm.h \
    redasm/assemblers/metaarm/metaarm_printer.h \
    redasm/assemblers/metaarm/metaarm_emulator.h \
    redasm/assemblers/metaarm/arm.h \
    redasm/assemblers/metaarm/armthumb.h \
    redasm/assemblers/metaarm/arm_common.h \
    redasm/disassembler/algorithm/controlflow.h \
    redasm/plugins/assembler/assembler.h \
    redasm/plugins/disassembler/algorithm.h \
    redasm/disassembler/algorithm/linearsweep.h \
    redasm/disassembler/listing/listingdocument.h \
    redasm/disassembler/listing/instructionpool.h \
    redasm/disassembler/listing/listingrenderer.h \
    redasm/support/timer.h \
    models/listingitemmodel.h \
    models/symboltablemodel.h \
    models/listingfiltermodel.h \
    redasm/support/event.h \
    redasm/disassembler/listing/listingcursor.h \
    models/callgraphmodel.h \
    renderer/listingtextrenderer.h \
    renderer/listingrenderercommon.h \
    renderer/listinggraphrenderer.h \
    widgets/disassemblergraphview/disassemblergraphview.h \
    redasm/graph/graph.h \
    widgets/disassemblergraphview/disassemblerwebchannel.h \
    redasm/plugins/disassembler/statemachine.h \
    redasm/emulator/emulatorbase.h \
    redasm/emulator/emulator.h \
    redasm/formats/dex/dex_algorithm.h

FORMS    += mainwindow.ui \
    widgets/disassemblerview/disassemblerview.ui \
    dialogs/referencesdialog.ui \
    dialogs/gotodialog.ui \
    dialogs/databasedialog.ui \
    dialogs/aboutdialog.ui \
    dialogs/manualloaddialog.ui

RESOURCES += \
    resources.qrc \
    themes.qrc

DISTFILES += \
    themes/application/flat.json \
    runtime.pri
