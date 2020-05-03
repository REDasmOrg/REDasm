#pragma once

#include <QMainWindow>
#include <rdapi/rdapi.h>
#include "icommandtab.h"

class OutputDock;
class DisassemblerTabs;
class DisassemblerView;
class ListingItemModel;
class TableTab;
struct RDDisassembler;
struct RDBuffer;

class DisassemblerHooks: public QObject
{
    Q_OBJECT

    private:
        enum { Action_Rename = 0, Action_XRefs, Action_Follow, Action_FollowPointerHexDump,
               Action_CallGraph, Action_Goto, Action_HexDump, Action_HexDumpFunction, Action_Comment, Action_CreateFunction,
               Action_Back, Action_Forward, Action_Copy,
               Action_ItemInformation };

    private:
        DisassemblerHooks(QObject* parent = nullptr);

    public:
        static void initialize(QMainWindow* mainwindow);
        static DisassemblerHooks* instance();

    public slots:
        void log(const QString& m_mnuviews);
        void clearLog();
        void resetLayout();
        void open();
        void close();
        void save();
        void saveAs();
        void settings();
        void about();
        void exit();

    public:
        TableTab* showSegments(ICommandTab* commandtab, Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        TableTab* showFunctions(ICommandTab* commandtab, Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        TableTab* showExports(ICommandTab* commandtab, Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        TableTab* showImports(ICommandTab* commandtab, Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        TableTab* showStrings(ICommandTab* commandtab, Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        QMenu* createActions(IDisassemblerCommand* command);
        void focusOn(QWidget* w);
        void showReferences(IDisassemblerCommand* command, address_t address);
        void showGoto(IDisassemblerCommand* command);
        void showDevGraphs();
        void showDevBlocks();

    public:
        QWidget* currentTab() const;
        bool openDatabase(const QString& filepath);
        void enableCommands(QWidget* w);
        void updateCommandStates(QWidget* w) const;
        void statusAddress(const IDisassemblerCommand* command) const;
        void load(const QString& filepath);
        void tab(QWidget* w);
        void tabify(QDockWidget* first, QDockWidget* second);
        void dock(Qt::DockWidgetArea area, QWidget* w);
        void undock(QDockWidget* dw);

    private slots:
        void adjustActions();
        void onBackClicked();
        void onForwardClicked();
        void onGotoClicked();
        void onFilterClicked();

    private:
        TableTab* createTable(ICommandTab* commandtab, ListingItemModel* model, const QString& title);
        OutputDock* outputDock() const;
        void close(bool showwelcome);
        void clearOutput();
        void enableViewCommands(bool enable);
        void enableMenu(QMenu* menu, bool enable);
        void loadDisassemblerView(RDDisassembler* disassembler, const RDLoaderBuildRequest& req);
        void showLoaders(const QString& filepath, RDBuffer* buffer);
        void addWelcomeTab();
        void loadRecents();
        void hook();

    private:
        QMainWindow* m_mainwindow{nullptr};
        QToolBar* m_toolbar{nullptr};
        QMenu *m_mnuviews{nullptr}, *m_mnudev{nullptr};
        DisassemblerView* m_disassemblerview{nullptr};
        DisassemblerTabs* m_disassemblertabs{nullptr};
        static DisassemblerHooks m_instance;
};
