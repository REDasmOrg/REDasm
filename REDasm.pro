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

include(depends.pri)
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
    widgets/disassemblertextview/disassemblerdocument.cpp \
    models/symboltablemodel.cpp \
    models/symboltablefiltermodel.cpp \
    models/disassemblermodel.cpp \
    models/segmentsmodel.cpp \
    redasm/analyzer/analyzer.cpp \
    redasm/analyzer/signatures.cpp \
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
    redasm/formats/pe/ordinals/msvbvm60.cpp \
    redasm/formats/pe/ordinals/msvbvm50.cpp

HEADERS  += mainwindow.h \
    redasm/redasm.h \
    redasm/plugins/format.h \
    redasm/plugins/base.h \
    redasm/plugins/plugins.h \
    widgets/disassemblerview/disassemblerview.h \
    widgets/disassemblertextview/disassemblertextview.h \
    widgets/disassemblertextview/disassemblerdocument.h \
    models/symboltablemodel.h \
    models/symboltablefiltermodel.h \
    models/disassemblermodel.h \
    models/segmentsmodel.h \
    redasm/analyzer/analyzer.h \
    redasm/analyzer/signatures.h \
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
    redasm/formats/pe/ordinals/pe_ordinals_types.h \
    redasm/processors/arm/arm.h \
    redasm/processors/arm/armprinter.h \
    redasm/disassembler/disassemblerfunctions.h \
    redasm/disassembler/disassemblerbase.h \
    redasm/disassembler/types/listing.h \
    redasm/disassembler/types/referencetable.h \
    redasm/disassembler/types/symboltable.h \
    redasm/processors/x86/x86printer.h \
    redasm/formats/pe/ordinals/msvbvm60.h \
    redasm/formats/pe/ordinals/msvbvm50.h

FORMS    += mainwindow.ui \
    widgets/disassemblerview/disassemblerview.ui \
    dialogs/referencesdialog.ui \
    dialogs/gotodialog.ui

RESOURCES += \
    resources.qrc \
    themes.qrc
