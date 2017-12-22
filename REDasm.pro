#-------------------------------------------------
#
# Project created by QtCreator 2017-05-15T14:14:34
#
#-------------------------------------------------

QT       += core gui xml
CONFIG   += c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = REDasm
TEMPLATE = app

include(depends/depends.pri)
include(widgets/QHexEdit/QHexEdit.pri)
debug: include(unittest/unittest.pri)

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += main.cpp\
        mainwindow.cpp \
    redasm/plugins/plugins.cpp \
    redasm/plugins/format.cpp \
    widgets/disassemblerview/disassemblerview.cpp \
    widgets/disassemblertextview/disassemblertextview.cpp \
    models/symboltablemodel.cpp \
    models/symboltablefiltermodel.cpp \
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
    widgets/disassemblerview/disassemblerthread.cpp \
    redasm/plugins/processor/printer.cpp \
    redasm/processors/mips/mipsprinter.cpp \
    redasm/processors/mips/mipsquirks.cpp \
    redasm/formats/pe/pe_analyzer.cpp \
    redasm/formats/pe/pe_utils.cpp \
    dialogs/gotodialog.cpp \
    redasm/formats/elf/elf.cpp \
    redasm/support/utils.cpp \
    redasm/support/demangler.cpp \
    redasm/processors/mips/mips.cpp \
    redasm/processors/x86/x86.cpp \
    redasm/plugins/processor/processor.cpp \
    redasm/formats/pe/vb/vb_analyzer.cpp \
    redasm/formats/pe/vb/vb_components.cpp \
    redasm/formats/pe/pe_imports.cpp \
    redasm/processors/arm/arm.cpp \
    redasm/processors/arm/armprinter.cpp \
    redasm/disassembler/disassemblerfunctions.cpp \
    redasm/disassembler/disassemblerbase.cpp \
    redasm/disassembler/types/listing.cpp \
    redasm/disassembler/types/referencetable.cpp \
    redasm/disassembler/types/symboltable.cpp \
    redasm/processors/x86/x86printer.cpp \
    redasm/support/coff/coff_symboltable.cpp \
    widgets/disassemblertextview/disassemblerhighlighter.cpp \
    dialogs/databasedialog.cpp \
    redasm/support/hash.cpp \
    redasm/signatures/patparser.cpp \
    models/databasemodel.cpp \
    redasm/support/serializer.cpp \
    redasm/signatures/signaturedb.cpp \
    dialogs/aboutdialog.cpp \
    widgets/disassemblergraphview/disassemblergraphview.cpp \
    widgets/disassemblerview/disassemblerdocument.cpp \
    widgets/disassemblertextview/disassemblertextdocument.cpp \
    widgets/disassemblergraphview/disassemblergraphdocument.cpp \
    widgets/disassemblergraphview/functionblockitem.cpp \
    redasm/disassembler/graph/graphbuilder.cpp \
    redasm/redasm.cpp \
    redasm/formats/pe/pe_ordinals.cpp \
    redasm/formats/pe/pe_resources.cpp \
    redasm/formats/pe/borland/borland_version.cpp \
    dialogs/manualloaddialog.cpp \
    redasm/formats/binary/binary.cpp

HEADERS  += mainwindow.h \
    redasm/redasm.h \
    redasm/plugins/format.h \
    redasm/plugins/base.h \
    redasm/plugins/plugins.h \
    widgets/disassemblerview/disassemblerview.h \
    widgets/disassemblertextview/disassemblertextview.h \
    models/symboltablemodel.h \
    models/symboltablefiltermodel.h \
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
    widgets/disassemblerview/disassemblerthread.h \
    redasm/plugins/processor/printer.h \
    redasm/processors/mips/mipsprinter.h \
    redasm/processors/mips/mipsquirks.h \
    redasm/formats/pe/pe_analyzer.h \
    redasm/formats/pe/pe_utils.h \
    dialogs/gotodialog.h \
    redasm/formats/elf/elf.h \
    redasm/formats/elf/elf64_header.h \
    redasm/formats/elf/elf32_header.h \
    redasm/formats/elf/elf_common.h \
    redasm/support/demangler.h \
    redasm/support/utils.h \
    redasm/processors/mips/mips.h \
    redasm/processors/x86/x86.h \
    redasm/plugins/processor/processor.h \
    redasm/formats/pe/vb/vb_analyzer.h \
    redasm/formats/pe/vb/vb_header.h \
    redasm/formats/pe/vb/vb_components.h \
    redasm/formats/pe/pe_imports.h \
    redasm/processors/arm/arm.h \
    redasm/processors/arm/armprinter.h \
    redasm/disassembler/disassemblerfunctions.h \
    redasm/disassembler/disassemblerbase.h \
    redasm/disassembler/types/listing.h \
    redasm/disassembler/types/referencetable.h \
    redasm/disassembler/types/symboltable.h \
    redasm/processors/x86/x86printer.h \
    redasm/support/coff/coff_symboltable.h \
    redasm/support/coff/coff_types.h \
    redasm/support/coff/coff_constants.h \
    redasm/support/cachemap.h \
    widgets/disassemblertextview/disassemblerhighlighter.h \
    dialogs/databasedialog.h \
    redasm/support/hash.h \
    redasm/signatures/patparser.h \
    models/databasemodel.h \
    redasm/support/serializer.h \
    redasm/signatures/signaturedb.h \
    dialogs/aboutdialog.h \
    widgets/disassemblergraphview/disassemblergraphview.h \
    widgets/disassemblerview/disassemblerdocument.h \
    widgets/disassemblertextview/disassemblertextdocument.h \
    widgets/disassemblergraphview/disassemblergraphdocument.h \
    widgets/disassemblergraphview/functionblockitem.h \
    redasm/disassembler/graph/graphbuilder.h \
    redasm/disassembler/graph/graphnode.h \
    redasm/formats/pe/pe_ordinals.h \
    redasm/formats/pe/pe_resources.h \
    redasm/formats/pe/borland/borland_types.h \
    redasm/formats/pe/borland/borland_version.h \
    dialogs/manualloaddialog.h \
    redasm/formats/binary/binary.h

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
