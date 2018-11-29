#-------------------------------------------------
#
# Project created by QtCreator 2017-05-15T14:14:34
#
#-------------------------------------------------

QT       += core gui xml
CONFIG   += c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets webengine webenginewidgets

!versionAtLeast(QT_VERSION, 5.10): error("Qt >= 5.10 required")

TARGET = REDasm
TEMPLATE = app

include(LibREDasm.pri)
include($$PWD/QHexEdit/QHexEdit.pri)
debug: include(unittest/unittest.pri)

PRE_TARGETDEPS += LibREDasm

unix:{
    # suppress the default RPATH if you wish
    QMAKE_LFLAGS_RPATH=
    # add your own with quoting gyrations to make sure $ORIGIN gets to the command line unexpanded
    QMAKE_LFLAGS += "-Wl,-rpath,\'\$$ORIGIN\'"
}

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
    widgets/disassemblerview/disassemblerview.cpp \
    models/disassemblermodel.cpp \
    models/segmentsmodel.cpp \
    widgets/listingmap.cpp \
    models/referencesmodel.cpp \
    dialogs/referencesdialog.cpp \
    dialogs/gotodialog.cpp \
    dialogs/databasedialog.cpp \
    models/databasemodel.cpp \
    dialogs/aboutdialog.cpp \
    dialogs/manualloaddialog.cpp \
    themeprovider.cpp \
    widgets/graphview/graphview.cpp \
    models/listingitemmodel.cpp \
    models/symboltablemodel.cpp \
    models/listingfiltermodel.cpp \
    models/callgraphmodel.cpp \
    renderer/listingtextrenderer.cpp \
    renderer/listingrenderercommon.cpp \
    renderer/listinggraphrenderer.cpp \
    widgets/disassemblergraphview/disassemblergraphview.cpp \
    widgets/disassemblergraphview/disassemblerwebchannel.cpp \
    widgets/disassemblerpopup/disassemblerpopup.cpp \
    widgets/disassemblerpopup/disassemblerpopupwidget.cpp \
    renderer/listingpopuprenderer.cpp \
    redasmsettings.cpp \
    dialogs/settingsdialog.cpp \
    widgets/disassemblerlistingview/disassemblerlistingview.cpp \
    widgets/disassemblerlistingview/disassemblertextview.cpp \
    widgets/disassemblerlistingview/disassemblercolumnview.cpp

HEADERS  += mainwindow.h \
    widgets/disassemblerview/disassemblerview.h \
    models/disassemblermodel.h \
    models/segmentsmodel.h \
    widgets/listingmap.h \
    models/referencesmodel.h \
    dialogs/referencesdialog.h \
    dialogs/gotodialog.h \
    dialogs/databasedialog.h \
    models/databasemodel.h \
    dialogs/aboutdialog.h \
    dialogs/manualloaddialog.h \
    themeprovider.h \
    widgets/graphview/graphview.h \
    models/listingitemmodel.h \
    models/symboltablemodel.h \
    models/listingfiltermodel.h \
    models/callgraphmodel.h \
    renderer/listingtextrenderer.h \
    renderer/listingrenderercommon.h \
    renderer/listinggraphrenderer.h \
    widgets/disassemblergraphview/disassemblergraphview.h \
    widgets/disassemblergraphview/disassemblerwebchannel.h \
    widgets/disassemblerpopup/disassemblerpopup.h \
    widgets/disassemblerpopup/disassemblerpopupwidget.h \
    renderer/listingpopuprenderer.h \
    redasmsettings.h \
    dialogs/settingsdialog.h \
    widgets/disassemblerlistingview/disassemblerlistingview.h \
    widgets/disassemblerlistingview/disassemblertextview.h \
    widgets/disassemblerlistingview/disassemblercolumnview.h

FORMS    += mainwindow.ui \
    widgets/disassemblerview/disassemblerview.ui \
    dialogs/referencesdialog.ui \
    dialogs/gotodialog.ui \
    dialogs/databasedialog.ui \
    dialogs/aboutdialog.ui \
    dialogs/manualloaddialog.ui \
    dialogs/settingsdialog.ui

RESOURCES += resources.qrc \
    themes.qrc
